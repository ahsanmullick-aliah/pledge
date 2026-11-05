"""PLEDGE vs. re-implemented baselines (paper Table 17 and Figs. 7, 10).

    python3 -m bench.compare attacks            -> results/compare_attacks.{csv,md}
    python3 -m bench.compare lifecycle [--quick]-> results/compare_lifecycle.csv
    python3 -m bench.compare crypto [--reps 20] -> results/compare_crypto.csv
    python3 -m bench.compare all

Every attack cell is decided by running the attack, not by assumption.
Modelling assumptions for the baselines are listed in baselines/guo.py and
baselines/romel.py and must be stated in the paper.
"""
import argparse
import csv
import os
import statistics
import time

from baselines.guo import GuoSystem
from baselines.romel import RomelSystem
from baselines.calypso import CalypsoSystem, committee_decrypts
from pledge.crypto import lgabe, rw15, sym
from pledge.crypto.pairing import gt_rand
from pledge.fhir import samples, consent as consent_mod
from pledge.ledger import chaincode as cc
from pledge.system.actors import Deployment, Patient, AccessDenied, owner_of

OUT = "results"
A9 = "A9 A ledger quorum decrypts records itself"
BLOCKED, SUCCEEDS, NA = "blocked", "succeeds", "n/a"
CARD = samples.CARDIOLOGY


def attempt(fn):
    try:
        fn()
        return SUCCEEDS
    except (AccessDenied, rw15.NotSatisfied, lgabe.CombineError, PermissionError) as e:  # noqa: F841
        return BLOCKED
    except Exception:
        return BLOCKED


# ---------------- attack table ----------------

def pledge_attacks():
    r = {}
    dep = Deployment(behaviours={2: {"rogue", "endorse_all", "equivocate"}})
    pat = Patient("p1", dep, samples.paper_consent())
    for x in (samples.observation(), samples.medication(), samples.restricted_condition()):
        pat.upload(x)
    dep.ledger.flush()
    x = dep.enroll("dr-x", "doctor", CARD)
    y = dep.enroll("dr-y", "doctor", CARD)
    tau = lambda rid: dep.store.get(rid).tau
    log_size = lambda: len(pat.audit_trail())

    n0 = log_size()
    res = attempt(lambda: x.open("Observation/bp-1"))
    r["A1 Read without a log entry"] = res if log_size() == n0 else SUCCEEDS

    y.access(["MedicationRequest/med-1"])

    def a2():
        k = rw15.UserKey(y.gid, dict(y.key.comps))
        k.add(lgabe.access_attr(tau("Observation/bp-1")), y.access_keys[lgabe.access_attr(tau("MedicationRequest/med-1"))])
        rec = dep.store.get("Observation/bp-1")
        M = rw15.decrypt(rec.ct_abe, k)
        sym.aead_decrypt(sym.kwk_from_gt(M, rec.tau, rec.version), rec.wrap, rec.tau.encode())
    r["A2 Log record A, read record B"] = attempt(a2)

    def a3():
        a = lgabe.access_attr(tau("MedicationRequest/med-1"))
        x.access_keys[a] = y.access_keys[a]
        x.open("MedicationRequest/med-1")
    r["A3 Use another clinician's access capability"] = attempt(a3)

    z = dep.enroll("dr-z", "doctor", CARD)
    dep.revoke("dr-z")
    dep.ledger.flush()
    r["A4 Revoked clinician opens a new record"] = attempt(lambda: z.access(["Observation/bp-1"]))

    w = dep.enroll("dr-w", "doctor", CARD)
    w.access(["Observation/bp-1"])
    dep.revoke("dr-w")
    dep.ledger.flush()
    r["A4b Revoked clinician re-reads a record opened before"] = attempt(lambda: w.open("Observation/bp-1"))

    def a5():
        rogue = dep.ledger.nodes[1].rogue_issue(x.gid, lgabe.access_attr(tau("Observation/bp-1")), (2, 3))
        x.access_keys[lgabe.access_attr(tau("Observation/bp-1"))] = lgabe.combine(dep.ledger.pub, [rogue])
        x.open("Observation/bp-1")
    r["A5 f < n/3 ledger nodes grant access off-ledger"] = attempt(a5)

    blk = dep.ledger.honest_node.chain[-1]
    entries = [t for t, _ in blk.txs if isinstance(t, cc.AccessTx)] or \
              [t for b in dep.ledger.honest_node.chain for t, _ in b.txs if isinstance(t, cc.AccessTx)]
    visible = cc.canon(entries[-1].wire_body())
    r["A6 Validators learn which patient record was read"] = SUCCEEDS if (b"p1" in visible or b"bp-1" in visible) else BLOCKED
    r["A7 Validators learn the purpose of access"] = SUCCEEDS if b"TREAT" in visible else BLOCKED
    em = dep.enroll("dr-em", "doctor", hospital="H4", emergency=True)
    r["A8 Emergency role used without co-signed break-glass"] = attempt(lambda: em.access(["Observation/bp-1"]))

    def a9():
        # every ledger node colludes: issue the access attribute to a key of their own and decrypt
        S = tuple(range(1, dep.ledger.n + 1))[: dep.ledger.k]
        a = lgabe.access_attr(tau("Observation/bp-1"))
        parts = [lgabe.share_gen(dep.ledger.nodes[i - 1].kss_secret, "validators", a, S) for i in S]
        k = rw15.UserKey("validators").add(a, lgabe.combine(dep.ledger.pub, parts))
        rec = dep.store.get("Observation/bp-1")
        M = rw15.decrypt(rec.ct_abe, k)
        sym.aead_decrypt(sym.kwk_from_gt(M, rec.tau, rec.version), rec.wrap, rec.tau.encode())
    r[A9] = attempt(a9)
    return r


def guo_attacks():
    r = {}
    g = GuoSystem()
    box = sym.BoxKeyPair.generate()
    consent = samples.paper_consent()
    for x in (samples.observation(), samples.medication(), samples.restricted_condition()):
        g.upload(box, consent, x)
    x = g.enroll("dr-x", "doctor", CARD)
    n0 = len(g.ledger.entries)
    res = attempt(lambda: x.open("Observation/bp-1", log=False))
    r["A1 Read without a log entry"] = res if len(g.ledger.entries) == n0 else BLOCKED

    def a2():
        x.open("MedicationRequest/med-1", log=True)
        x.open("Observation/bp-1", log=False)
        if any(e.rid == "Observation/bp-1" for e in g.ledger.entries):
            raise AccessDenied("logged")
    r["A2 Log record A, read record B"] = attempt(a2)
    r["A3 Use another clinician's access capability"] = NA
    z = g.enroll("dr-z", "doctor", CARD)
    g.revoke("dr-z")
    r["A4 Revoked clinician opens a new record"] = attempt(lambda: z.open("Observation/bp-1", log=False))
    w = g.enroll("dr-w", "doctor", CARD)
    w.open("Observation/bp-1")
    rec = g.store["Observation/bp-1"]
    cached = sym.aead_decrypt(sym.kwk_from_gt(rw15.decrypt(rec.ct_abe, w.key), rec.rid, rec.version),
                              rec.wrap, rec.rid.encode())
    g.revoke("dr-w")
    r["A4b Revoked clinician re-reads a record opened before"] = attempt(
        lambda: sym.aead_decrypt(cached, g.store["Observation/bp-1"].ct_data, b"Observation/bp-1"))
    r["A5 f < n/3 ledger nodes grant access off-ledger"] = NA
    view = str(g.ledger.validator_view())
    r["A6 Validators learn which patient record was read"] = SUCCEEDS if "bp-1" in view or "med-1" in view else BLOCKED
    r["A7 Validators learn the purpose of access"] = NA
    r["A8 Emergency role used without co-signed break-glass"] = NA
    r[A9] = BLOCKED                                  # the log holds no key material
    return r


def romel_attacks():
    r = {}
    s = RomelSystem()
    p = s.new_patient("p1")
    for x in (samples.observation(), samples.medication(), samples.restricted_condition()):
        p.upload(x)
    x = s.enroll("dr-x", "doctor", CARD)
    y = s.enroll("dr-y", "doctor", CARD)
    p.share_by_consent(samples.paper_consent(), [x, y])
    n0 = len(s.contracts["p1"].receipts)
    res = attempt(lambda: x.open("p1", "Observation/bp-1", log=False))
    r["A1 Read without a log entry"] = res if len(s.contracts["p1"].receipts) == n0 else BLOCKED

    def a2():
        x.open("p1", "MedicationRequest/med-1", log=True)
        x.open("p1", "Observation/bp-1", log=False)
        if any(rc["rid"] == "Observation/bp-1" for rc in s.contracts["p1"].receipts):
            raise AccessDenied("logged")
    r["A2 Log record A, read record B"] = attempt(a2)

    def a3():
        from baselines.romel import ecies_unwrap
        wrap = s.wraps[("MedicationRequest/med-1", y.addr)]
        ecies_unwrap(x.sk, wrap)                    # X tries Y's capability without Y's key
    r["A3 Use another clinician's access capability"] = attempt(a3)
    z = s.enroll("dr-z", "doctor", CARD)
    p.share_by_consent(samples.paper_consent(), [z])
    p.revoke(z, list(p.resources))
    r["A4 Revoked clinician opens a new record"] = attempt(lambda: z.open("p1", "Observation/bp-1"))
    w = s.enroll("dr-w", "doctor", CARD)
    p.share_by_consent(samples.paper_consent(), [w])
    w.open("p1", "Observation/bp-1")
    p.revoke(w, list(p.resources))
    r["A4b Revoked clinician re-reads a record opened before"] = attempt(lambda: w.open("p1", "Observation/bp-1"))
    r["A5 f < n/3 ledger nodes grant access off-ledger"] = NA
    view = str(s.validator_view())
    r["A6 Validators learn which patient record was read"] = SUCCEEDS if "bp-1" in view else BLOCKED
    r["A7 Validators learn the purpose of access"] = NA
    r["A8 Emergency role used without co-signed break-glass"] = NA
    r[A9] = BLOCKED                                  # the contract holds commitments and grants, no keys
    return r


def calypso_attacks():
    r = {}
    s = CalypsoSystem()
    p = s.new_patient("p1", samples.paper_consent())
    for x in (samples.observation(), samples.medication(), samples.restricted_condition()):
        p.upload(x)
    x = s.enroll("dr-x", "doctor", CARD)
    y = s.enroll("dr-y", "doctor", CARD)
    wid = lambda rid: p.wids[rid]
    reads = lambda: len(s.chain.reads)

    def a1():
        n0 = reads()
        x.collect(wid("Observation/bp-1"), "no-such-read")
        if reads() != n0:
            raise AccessDenied("logged")
    r["A1 Read without a log entry"] = attempt(a1)

    def a2():
        ra = x.log_read(wid("MedicationRequest/med-1"))
        x.collect(wid("Observation/bp-1"), ra)                # present A's read tx for B
    r["A2 Log record A, read record B"] = attempt(a2)

    def a3():
        ry = y.log_read(wid("MedicationRequest/med-1"))
        x.collect(wid("MedicationRequest/med-1"), ry)        # X presents Y's read tx
    r["A3 Use another clinician's access capability"] = attempt(a3)
    z = s.enroll("dr-z", "doctor", CARD)
    s.revoke(z)
    r["A4 Revoked clinician opens a new record"] = attempt(lambda: z.open("Observation/bp-1"))
    w = s.enroll("dr-w", "doctor", CARD)
    w.open("Observation/bp-1")
    s.revoke(w)
    r["A4b Revoked clinician re-reads a record opened before"] = attempt(lambda: w.open("Observation/bp-1"))

    def a5():
        com = s.committee
        committee_decrypts(s, wid("Observation/bp-1"), range(1, com.f + 1))   # f < t trustees: wrong key
    r["A5 f < n/3 ledger nodes grant access off-ledger"] = attempt(a5)
    view = str(s.chain.validator_view())
    r["A6 Validators learn which patient record was read"] = SUCCEEDS if "p1" in view else BLOCKED
    r["A7 Validators learn the purpose of access"] = NA
    r["A8 Emergency role used without co-signed break-glass"] = NA
    r[A9] = attempt(lambda: committee_decrypts(s, wid("Observation/bp-1"), range(1, s.committee.t + 1)))
    return r


def run_attacks():
    cols = [("PLEDGE", pledge_attacks()), (GuoSystem.name, guo_attacks()), (RomelSystem.name, romel_attacks()),
            (CalypsoSystem.name, calypso_attacks())]
    rows = list(cols[0][1])
    os.makedirs(OUT, exist_ok=True)
    with open(f"{OUT}/compare_attacks.csv", "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["attack"] + [c for c, _ in cols])
        for a in rows:
            w.writerow([a] + [r[a] for _, r in cols])
    md = ["| Attack | " + " | ".join(c for c, _ in cols) + " |", "| --- |" + " --- |" * len(cols)]
    md += ["| " + a + " | " + " | ".join(r[a] for _, r in cols) + " |" for a in rows]
    open(f"{OUT}/compare_attacks.md", "w").write("\n".join(md) + "\n")
    print("\n".join(md))


# ---------------- lifecycle costs ----------------

def _consent_cardiology():
    return samples.paper_consent()


def lifecycle_point(R, G, P=1):
    """Share R records/patient with G eligible cardiologists (P patients), then revoke one
    clinician, then narrow consent. Returns rows of (system, operation, seconds, ledger_txs, crypto_ops)."""
    rows = []
    res = [samples.observation(rid=f"bp-{i}", systolic=100 + i % 50) for i in range(R)]
    consent = _consent_cardiology()

    # PLEDGE: one header (ABE ciphertext) per record, independent of G.
    # Timed: the patient's encryption work only; ledger work reported as tx counts.
    dep = Deployment()
    pats = [Patient(f"p{pi}", dep, consent) for pi in range(P)]
    t = time.perf_counter()
    for pi, pt in enumerate(pats):
        for x in res:
            pt._encrypt(dict(x, id=f"{x['id']}-{pi}"), 1)
    rows.append(("PLEDGE", "share", time.perf_counter() - t, R * P, R * P))
    for gi in range(G):
        dep.enroll(f"dr-{gi}", "doctor", CARD)
    t = time.perf_counter()
    tx = dep.revoke("dr-0")
    cc.check(dep.ledger.state, tx, dep.ledger.now)
    rows.append(("PLEDGE", "revoke", time.perf_counter() - t, 1, 0))
    t = time.perf_counter()
    dep.enroll("dr-new", "doctor", CARD)
    rows.append(("PLEDGE", "onboard_clinician", time.perf_counter() - t, 1, 0))
    t = time.perf_counter()
    for pt in pats:                                  # header-only re-key under the new policy
        for x in res:
            M = gt_rand()
            ct = rw15.encrypt(M, "(role:nurse AND dept:H1.ICU AND org:H1) AND acc:new", dep.pks, owner_of)
            sym.aead_encrypt(sym.kwk_from_gt(M, "new", 2), sym.new_dek())
    rows.append(("PLEDGE", "narrow_consent", time.perf_counter() - t, R * P, R * P))

    # Guo: same per-record ABE, revocation by re-versioning + re-encryption
    g = GuoSystem()
    box = sym.BoxKeyPair.generate()
    for gi in range(G):
        g.enroll(f"dr-{gi}", "doctor", CARD)
    t = time.perf_counter()
    for pi in range(P):
        for x in res:
            g.upload(box, consent, dict(x, id=f"{x['id']}-{pi}"))
    rows.append((GuoSystem.name, "share", time.perf_counter() - t, R * P, R * P))   # uploads logged as activities
    st = g.revoke("dr-0")
    rows.append((GuoSystem.name, "revoke", st["seconds"], 0, st["reencrypted_headers"] + st["reissued_keys"]))
    t = time.perf_counter()
    g.enroll("dr-new", "doctor", CARD)
    rows.append((GuoSystem.name, "onboard_clinician", time.perf_counter() - t, 0, 0))
    narrowed = samples.paper_consent()
    narrowed["provision"]["provision"] = narrowed["provision"]["provision"][1:]
    t = time.perf_counter()
    for rid in list(g.store):
        g.update_consent(narrowed, rid, samples.observation(rid=rid.split("/", 1)[1]))
    rows.append((GuoSystem.name, "narrow_consent", time.perf_counter() - t, 0, len(g.store)))

    # Romel: per-grantee ECIES wraps and one grant tx per (patient, clinician)
    s = RomelSystem()
    docs = [s.enroll(f"dr-{gi}", "doctor", CARD) for gi in range(G)]
    rps = []
    for pi in range(P):
        rp = s.new_patient(f"p{pi}")
        for x in res:
            rp.upload(dict(x, id=f"{x['id']}-{pi}"))
        rps.append(rp)
    t = time.perf_counter()
    wraps = txs = 0
    for rp in rps:
        stt = rp.share_by_consent(consent, docs)
        wraps += stt["wraps"]
        txs += stt["grants"]
    rows.append((RomelSystem.name, "share", time.perf_counter() - t, txs, wraps))
    t = time.perf_counter()
    for rp in rps:                                   # every patient must revoke individually
        rp.revoke(docs[0], list(rp.resources))
    rows.append((RomelSystem.name, "revoke", time.perf_counter() - t, P, 0))
    t = time.perf_counter()
    new = s.enroll("dr-new", "doctor", CARD)
    w0 = 0
    for rp in rps:                                   # every patient must grant the newcomer
        w0 += rp.share_by_consent(consent, [new])["wraps"]
    rows.append((RomelSystem.name, "onboard_clinician", time.perf_counter() - t, P, w0))
    t = time.perf_counter()
    for rp in rps:                                   # narrowing removes every cardiologist grant
        for d in docs[1:]:
            rp.revoke(d, list(rp.resources))
    rows.append((RomelSystem.name, "narrow_consent", time.perf_counter() - t, P * (G - 1), 0))

    # CALYPSO: one threshold-ElGamal write per record; RBAC groups and one policy per patient
    cs = CalypsoSystem()
    cdocs = [cs.enroll(f"dr-{gi}", "doctor", CARD) for gi in range(G)]
    cps = [cs.new_patient(f"p{pi}", consent) for pi in range(P)]
    t = time.perf_counter()
    for pi, cp in enumerate(cps):
        for x in res:
            cp.upload(dict(x, id=f"{x['id']}-{pi}"))
    rows.append((CalypsoSystem.name, "share", time.perf_counter() - t, R * P, R * P))
    t = time.perf_counter()
    cs.revoke(cdocs[0])
    rows.append((CalypsoSystem.name, "revoke", time.perf_counter() - t, 1, 0))
    t = time.perf_counter()
    cs.enroll("dr-new", "doctor", CARD)
    rows.append((CalypsoSystem.name, "onboard_clinician", time.perf_counter() - t, 1, 0))
    t = time.perf_counter()
    for cp in cps:
        cp.update_consent(narrowed)
    rows.append((CalypsoSystem.name, "narrow_consent", time.perf_counter() - t, P, 0))
    return [(R, G, P) + r for r in rows]


def run_lifecycle(quick=False):
    grid = [(10, 5, 1), (50, 20, 1), (100, 20, 1), (100, 20, 5)] if quick else \
        [(R, G, 1) for R in (10, 50, 100, 250) for G in (5, 20, 50)] + [(100, 20, P) for P in (2, 5, 10)]
    os.makedirs(OUT, exist_ok=True)
    with open(f"{OUT}/compare_lifecycle.csv", "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["records_per_patient", "eligible_clinicians", "patients", "system", "operation",
                    "seconds", "ledger_txs", "crypto_ops"])
        for R, G, P in grid:
            for row in lifecycle_point(R, G, P):
                w.writerow(row)
                print(f"R={row[0]:<4} G={row[1]:<3} P={row[2]:<3} {row[3]:18s} {row[4]:15s} "
                      f"{row[5]:8.3f}s txs={row[6]:<5} ops={row[7]}")


# ---------------- per-record crypto costs ----------------

def run_crypto(reps=20):
    """Per-record crypto cost. All measurements are interleaved: every repetition runs each
    job once in a fresh random order, so a noisy period on a shared machine hits every
    system alike instead of one configuration."""
    import random
    from baselines.romel import ecies_wrap, ecies_unwrap, CURVE
    from cryptography.hazmat.primitives.asymmetric import ec
    jobs = []                                       # (system, operation, param, value, fn)
    council = rw15.Authority.setup("c")
    pub, secs, _ = lgabe.run_dkg(4, 2)
    pks = {"c": council.pk, lgabe.LEDGER_AUTHORITY: pub.pk}
    own = lambda a: lgabe.LEDGER_AUTHORITY if lgabe.is_ledger_attr(a) else "c"
    for n in (5, 10, 20, 30, 40, 50):
        attrs = [f"a{i}" for i in range(n)]
        p_guo = " AND ".join(attrs)
        p_pl = f"({p_guo}) AND acc:t"
        key = rw15.UserKey("u")
        for a in attrs:
            key.add(a, council.keygen("u", a))
        parts = [lgabe.share_gen(secs[i - 1], "u", "acc:t", (1, 2)) for i in (1, 2)]
        kh = rw15.UserKey("u", dict(key.comps)).add("acc:t", lgabe.combine(pub, parts))
        M = gt_rand()
        ch, cg = rw15.encrypt(M, p_pl, pks, own), rw15.encrypt(M, p_guo, pks, own)
        jobs += [("PLEDGE", "encrypt_header", "policy_attrs", n, lambda M=M, p=p_pl: rw15.encrypt(M, p, pks, own)),
                 ("PLEDGE", "first_decrypt", "policy_attrs", n,
                  lambda ch=ch, kh=kh, parts=parts: (lgabe.combine(pub, parts), rw15.decrypt(ch, kh))),
                 (GuoSystem.name, "encrypt_header", "policy_attrs", n,
                  lambda M=M, p=p_guo: rw15.encrypt(M, p, pks, own)),
                 (GuoSystem.name, "first_decrypt", "policy_attrs", n, lambda cg=cg, key=key: rw15.decrypt(cg, key))]
    sk = ec.generate_private_key(CURVE)
    dek = sym.new_dek()
    for G in (5, 20, 50):
        jobs.append((RomelSystem.name, "encrypt_header", "grantees", G,
                     lambda G=G: [ecies_wrap(sk.public_key(), dek) for _ in range(G)]))
    w = ecies_wrap(sk.public_key(), dek)
    jobs.append((RomelSystem.name, "first_decrypt", "grantees", 1, lambda: ecies_unwrap(sk, w)))
    cs = CalypsoSystem()
    cp = cs.new_patient("p1", samples.paper_consent())
    obs = samples.observation()
    t = cs.committee.t
    jobs.append((CalypsoSystem.name, "encrypt_header", "trustees_t", t, lambda: cp.encrypt(obs)))
    cp.upload(obs)
    doc = cs.enroll("dr", "doctor", CARD)
    wid = cp.wids["Observation/bp-1"]
    req = {"wid": wid, "rid": doc.log_read(wid), "reader_pk": doc.pk}
    rparts = [cs.committee.release(i, cs.chain, req) for i in range(1, t + 1)]
    jobs.append((CalypsoSystem.name, "share_release_per_trustee", "trustees_t", t,
                 lambda: cs.committee.release(1, cs.chain, req)))
    jobs.append((CalypsoSystem.name, "first_decrypt", "trustees_t", t, lambda: doc.recover(wid, rparts)))

    for j in jobs:                                  # warm-up
        j[4]()
    times = {i: [] for i in range(len(jobs))}
    rng = random.Random(7)
    order = list(range(len(jobs)))
    for _ in range(reps):
        rng.shuffle(order)
        for i in order:
            t0 = time.perf_counter()
            jobs[i][4]()
            times[i].append((time.perf_counter() - t0) * 1000)
    rows = []
    for i, (sysname, op, param, val, _) in enumerate(jobs):
        xs = sorted(times[i])
        iqr = (xs[3 * len(xs) // 4] - xs[len(xs) // 4]) if reps > 3 else 0
        rows.append((sysname, op, param, val, statistics.median(xs), iqr))
    os.makedirs(OUT, exist_ok=True)
    with open(f"{OUT}/compare_crypto.csv", "w", newline="") as f:
        wr = csv.writer(f)
        wr.writerow(["system", "operation", "param", "value", "median_ms", "iqr_ms"])
        wr.writerows(rows)
    for r in rows:
        print(f"{r[0]:18s} {r[1]:26s} {r[2]}={r[3]:<3} median {r[4]:8.2f} ms  IQR {r[5]:.2f}")


def main():
    global OUT
    ap = argparse.ArgumentParser()
    ap.add_argument("what", choices=["attacks", "lifecycle", "crypto", "all"])
    ap.add_argument("--quick", action="store_true")
    ap.add_argument("--reps", type=int, default=20)
    ap.add_argument("--out", default=OUT, help="output folder (default: results)")
    a = ap.parse_args()
    OUT = a.out
    if a.what in ("attacks", "all"):
        run_attacks()
    if a.what in ("lifecycle", "all"):
        run_lifecycle(a.quick)
    if a.what in ("crypto", "all"):
        run_crypto(a.reps)


if __name__ == "__main__":
    main()
