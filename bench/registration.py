"""Cost of identity registration (Section V-B) and consent re-keying (Section V-I).

    python3 -m bench.registration [--reps 20] [--records 20]
        -> results/registration.csv

Rows (median and p95 over --reps runs, in-process ledger, one core):
  reg/patient-client   OTP authentication + PoP signature on the device
  reg/patient-aa       AA: verify assertion and PoP, derive psi, sign Reg_P
  reg/patient-check    chaincode validation of Reg_P
  reg/clinician-aa     AA: verify HPR assertion and PoP, sign the credential
  rec/key-derive       per-record owner key, purpose key and salt from s_P
  rekey/header-only    one record: new M', tau', re-wrap the same DEK, RecordTx with retires
  rekey/strict         one record: new DEK, re-encrypt CT_data, new header, RecordTx with retires
  check/rekey          chaincode validation of a re-key RecordTx (two BLS verifications)
Sizes (bytes of the canonical transaction) are reported in the "bytes" column.
"""
import argparse
import copy
import csv
import os
import statistics
import time

from pledge.fhir import samples
from pledge.ledger import chaincode as cc
from pledge.system.actors import Deployment, Patient

CARD = samples.CARDIOLOGY


def timed(fn, reps):
    out, res = [], None
    for _ in range(reps):
        t0 = time.perf_counter()
        res = fn()
        out.append((time.perf_counter() - t0) * 1000)
    out.sort()
    return statistics.median(out), out[min(len(out) - 1, int(0.95 * len(out)))], res


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--reps", type=int, default=20)
    ap.add_argument("--records", type=int, default=20)
    ap.add_argument("--out", default="results/registration.csv")
    a = ap.parse_args()
    rows = []

    def row(name, med, p95, nbytes=""):
        rows.append({"op": name, "median_ms": f"{med:.2f}", "p95_ms": f"{p95:.2f}", "bytes": nbytes})
        print(f"{name:22s} {med:8.2f} ms  p95 {p95:8.2f}  {nbytes}")

    dep = Deployment()
    pat = Patient("p0", dep, samples.paper_consent(), register=False)
    idp = dep.abdm.idp

    def client():
        txn, code = idp.request_otp(pat.abha)
        nonce = os.urandom(8).hex()
        asr = idp.verify_otp(txn, code, nonce)
        pop = pat.signer.sign(cc.digest("patient-pop", {"vk": pat.signer.vk_bytes.hex(),
                                                       "box_pk": pat.box.pk.hex(), "nonce": nonce}))
        return asr, nonce, pop
    m, p, (asr, nonce, pop) = timed(client, a.reps)
    row("reg/patient-client", m, p)
    certify = lambda: dep.certify_patient("H1", asr, nonce, pat.box.pk, pat.signer.vk_bytes, pat.psi_salt, pop)
    tx = certify()                       # first registration; later calls produce rotations (same work)
    m, p, _ = timed(certify, a.reps)
    row("reg/patient-aa", m, p, len(cc.canon(tx.to_wire())))
    st = dep.ledger.state
    m, p, _ = timed(lambda: cc.check(st, tx, dep.ledger.now), a.reps)
    row("reg/patient-check", m, p)
    dep.ledger.submit(tx); dep.ledger.flush(); pat.cert = tx.to_wire()

    hprs = [dep.abdm.hpr.register(f"Dr {i}", "NMC", f"R-{i}") for i in range(a.reps)]
    ts = []
    for i, h in enumerate(hprs):
        t0 = time.perf_counter()
        dep.enroll(f"dr-x{i}", "doctor", CARD, hospital="H2", hpr=h)
        ts.append((time.perf_counter() - t0) * 1000)
    ts.sort()
    row("reg/clinician-aa", statistics.median(ts), ts[int(0.95 * len(ts))])

    taus = [os.urandom(16).hex() for _ in range(a.reps)]
    it = iter(taus)
    def derive():
        t = next(it)
        return pat._owner_key(t).vk_bytes, pat._purpose_key(t).pk, pat._salt(t)
    m, p, _ = timed(derive, a.reps)
    row("rec/key-derive", m, p)

    # re-keying: a patient with --records records, narrowed consent
    for strict in (False, True):
        d = Deployment()
        pt = Patient("p1", d, samples.paper_consent())
        res = [dict(samples.observation(), id=f"bp-{i}") for i in range(a.records)]
        for r in res:
            pt.upload(r)
        d.ledger.flush()
        narrowed = samples.paper_consent()
        narrowed["provision"]["provision"] = narrowed["provision"]["provision"][1:]
        wide = samples.paper_consent()
        ts, sizes = [], []
        for i in range(a.reps):
            new = narrowed if i % 2 == 0 else wide
            t0 = time.perf_counter()
            pt.update_consent(new, strict=strict)
            ts.append((time.perf_counter() - t0) * 1000 / a.records)
            d.ledger.flush()
        ts.sort()
        last = d.ledger.state.records[pt.taus[f"Observation/bp-0"]]
        row("rekey/strict" if strict else "rekey/header-only", statistics.median(ts),
            ts[int(0.95 * len(ts))], len(cc.canon(last.to_wire())))

    # validation of one re-key transaction
    rid = "Observation/bp-0"
    old_tau = pt.taus[rid]
    rec, compiled = pt._encrypt(res[0], d.store.get(rid).version + 1)
    side = compiled.side
    tx = cc.RecordTx(rec.tau, rec.header_hash, side.purpose_codes(), [], pt._salt(rec.tau), side.period,
                     side.emergency, pt._owner_key(rec.tau).vk_bytes, pt._purpose_key(rec.tau).pk,
                     retires=old_tau)
    tx.sig = pt._owner_key(rec.tau).sign(tx.body())
    tx.retire_sig = pt._owner_key(old_tau).sign(tx.body())
    m, p, _ = timed(lambda: cc.check(d.ledger.state, tx, d.ledger.now), a.reps)
    row("check/rekey", m, p, len(cc.canon(tx.to_wire())))

    os.makedirs(os.path.dirname(a.out), exist_ok=True)
    with open(a.out, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["op", "median_ms", "p95_ms", "bytes"])
        w.writeheader()
        w.writerows(rows)


if __name__ == "__main__":
    main()
