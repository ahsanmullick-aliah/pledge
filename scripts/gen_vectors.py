"""Cross-language test vectors: Python decides each case; the Go chaincode must agree.

    python3 scripts/gen_vectors.py fabric/pkg/pledgecc/testdata/vectors.json
"""
import copy
import json
import sys

sys.path.insert(0, ".")
from pledge.crypto import sig as bls                       # noqa: E402
from pledge.crypto.pairing import g1_bytes, g2_bytes, g1_pow, fr_rand   # noqa: E402
from pledge.fhir import samples                            # noqa: E402
from pledge.ledger import chaincode as cc                  # noqa: E402
from pledge.system.actors import Deployment, Patient       # noqa: E402


def state_json(st):
    return {
        "config": {"aa_keys": {k: g2_bytes(v).hex() for k, v in st.aa_keys.items()},
                   "regulator_purpose_pk": g1_bytes(st.regulator_purpose_pk).hex(), "n": st.n, "k": st.k},
        "credentials": {g: {"vk": g2_bytes(vk).hex(), "aa": aa} for g, (vk, aa) in st.credentials.items()},
        "revoked": sorted(st.revoked),
        "records": {t: {**r.to_wire(), **({"retired": True} if t in st.retired else {})}
                    for t, r in st.records.items()},
        "patients": sorted(st.patients),
        "nonces": sorted([list(x) for x in st.nonces]),
        "entries": {eid: tx.gid for eid, (_, tx) in st.entries.items()},
    }


def verdict(st, tx, now):
    try:
        cc.check(st, tx, now)
        return True, ""
    except cc.Reject as e:
        return False, str(e)


def main(out):
    dep = Deployment()
    pat = Patient("p1", dep, samples.paper_consent(deny_practitioners=("rn-99",)))
    for r in (samples.observation(), samples.medication(), samples.restricted_condition()):
        pat.upload(r)
    dep.ledger.flush()
    dr = dep.enroll("dr-card", "doctor", samples.CARDIOLOGY, hospital="H2")
    rn = dep.enroll("rn-99", "nurse", hospital="H1", dept="ICU")
    em = dep.enroll("dr-em", "doctor", hospital="H4", emergency=True)
    co = dep.enroll("dr-co", "doctor", hospital="H4")
    rv = dep.enroll("dr-rev", "doctor", samples.CARDIOLOGY)
    dep.revoke("dr-rev")
    dep.ledger.flush()
    first = dr.request(["Observation/bp-1"])           # committed: gives a nonce + entry
    st = dep.ledger.state
    now = dep.ledger.now
    cases = []

    def add(name, tx, t=now, state=None):
        s = state or st
        ok, why = verdict(s, tx, t)
        cases.append({"name": name, "kind": tx.KIND, "tx": tx.to_wire(), "now": t,
                      "state": state_json(s), "ok": ok, "reason": why})

    # access entries
    good = dr.build_request(["Observation/bp-1"])
    add("access/valid", good)
    add("access/bundle", dr.build_request(["Observation/bp-1", "MedicationRequest/med-1"]))
    t = copy.deepcopy(good); t.nonce = "tampered"; add("access/tampered-body", t)
    add("access/stale-ts", good, t=now + 1000)
    add("access/replay", first)
    bad_s = dr.build_request(["Observation/bp-1"], S=(1,)); add("access/bad-S", bad_s)
    add("access/deny-listed", rn.build_request(["Observation/bp-1"]))
    forged = dr.build_request(["Observation/bp-1"]); forged.items[0].proof.branches.reverse()
    forged.sig = dr.signer.sign(forged.body()); add("access/forged-purpose-proof", forged)
    dep.ledger.now = 1_860_000_000                     # build the request "in 2028"
    oop = dr.build_request(["Observation/bp-1"])
    dep.ledger.now = now
    add("access/out-of-period", oop, t=1_860_000_000)
    bg = em.build_request(["Condition/cond-1"], purpose="ETREAT", breakglass=True)
    bg.cosigner = co.gid; bg.sig = em.signer.sign(bg.body()); bg.cosig = co.signer.sign(bg.body())
    add("access/breakglass-valid", bg)
    bg2 = copy.deepcopy(bg); bg2.cosig = em.signer.sign(bg2.body()); add("access/breakglass-bad-cosig", bg2)
    rvtx = cc.AccessTx("dr-rev", good.items, now, "n-rev", good.S); rvtx.sig = rv.signer.sign(rvtx.body())
    add("access/revoked", rvtx)
    rt = dr.build_request(["Observation/bp-1"], retry_of=first.entry_id); add("access/retry-valid", rt)
    rt2 = dr.build_request(["Observation/bp-1"], retry_of="00" * 32); add("access/retry-unknown", rt2)
    # credentials / revocations / records
    c = cc.CredentialTx("dr-new", bls.SigningKey.generate().vk_bytes, "council")
    c.sig = dep.council_signer.sign(c.body()); add("cred/valid", c)
    c2 = copy.deepcopy(c); c2.sig = dep.hospital_signer["H1"].sign(c2.body()); add("cred/wrong-signer", c2)
    r = cc.RevokeTx("dr-card", "council"); r.sig = dep.council_signer.sign(r.body()); add("revoke/valid", r)
    rec = st.records[pat.taus["Observation/bp-1"]]
    owner = pat._owner_key(rec.tau)
    upd = copy.copy(rec); upd.purposes = [1]; upd.sig = owner.sign(upd.body()); add("record/owner-update", upd)
    hij = copy.copy(rec); hij.purposes = [5]; mallory = bls.SigningKey.generate()
    hij.owner_vk = mallory.vk_bytes; hij.sig = mallory.sign(hij.body()); add("record/hijack", hij)

    # patient registration (Reg_P)
    reg = st.patients[pat.cert["psi"]]
    fresh = cc.PatientRegTx("cd" * 32, pat.box.pk, pat.signer.vk_bytes, "2031-12-31", "H2")
    fresh.sig = dep.hospital_signer["H2"].sign(fresh.body()); add("patient/valid", fresh)
    dbl = copy.copy(reg); dbl.sig = dep.hospital_signer[reg.aa].sign(dbl.body()); add("patient/already-bound", dbl)
    rot = copy.copy(reg); rot.rotate = True; rot.vk = bls.SigningKey.generate().vk_bytes
    rot.sig = dep.hospital_signer[reg.aa].sign(rot.body()); add("patient/rotate-valid", rot)
    rot2 = copy.copy(fresh); rot2.rotate = True; rot2.sig = dep.hospital_signer["H2"].sign(rot2.body())
    add("patient/rotate-unbound", rot2)
    bad = copy.copy(fresh); bad.sig = bls.SigningKey.generate().sign(bad.body()); add("patient/unknown-signer", bad)
    # re-keying (Section V-I)
    old_tau = pat.taus["MedicationRequest/med-1"]
    newrec, compiled = pat._encrypt(samples.medication(), 1)
    side = compiled.side
    def rk(tau, retires, sign_old=True):
        t = cc.RecordTx(tau, newrec.header_hash, side.purpose_codes(), [], pat._salt(tau), side.period,
                        side.emergency, pat._owner_key(tau).vk_bytes, pat._purpose_key(tau).pk, retires=retires)
        t.sig = pat._owner_key(tau).sign(t.body())
        if retires is not None:
            t.retire_sig = (pat._owner_key(retires) if sign_old else bls.SigningKey.generate()).sign(t.body())
        return t
    rekey = rk(newrec.tau, old_tau); add("record/rekey-valid", rekey)
    add("record/rekey-bad-retire-sig", rk(newrec.tau, old_tau, sign_old=False))
    add("record/rekey-unknown-old", rk(newrec.tau, "ee" * 16))
    add("record/retire-self", rk(old_tau, old_tau))
    dep.ledger.submit(rekey); dep.ledger.flush()       # now old_tau is retired
    st = dep.ledger.state
    add("record/update-retired", rk(old_tau, None))
    stale = dr.build_request(["MedicationRequest/med-1"])  # the store still holds the old header
    assert stale.items[0].tau == old_tau
    add("access/retired-tag", stale)

    with open(out, "w") as f:
        json.dump(cases, f, indent=1)
    print(f"{len(cases)} vectors, {sum(c['ok'] for c in cases)} valid")


if __name__ == "__main__":
    main(sys.argv[1])
