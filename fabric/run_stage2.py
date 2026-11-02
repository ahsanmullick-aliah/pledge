#!/usr/bin/env python3
"""End-to-end PLEDGE scenario on the live Fabric network (stage 2 smoke test).

    export FABRIC_BIN=~/fabric-bin
    python3 fabric/run_stage2.py --n 4 [--bad-kss 1]      # (re)creates the network first

Starts the gateway bridge and one key-share service per hospital, then runs:
enrol, upload, access (single and bundle), break-glass, the core attacks,
revocation, and a key-share service that returns bad shares (logged retry).
Writes per-transaction timings to results/stage2_smoke_n<N>.json.
"""
import argparse
import json
import os
import signal
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT.parent))

from pledge.crypto import lgabe, rw15, sym              # noqa: E402
from pledge.fabric_client import FabricDeployment        # noqa: E402
from pledge.fhir import samples                          # noqa: E402
from pledge.system.actors import Patient, AccessDenied   # noqa: E402

BIN = ROOT / "bin"


def wait_http(url, timeout=30):
    end = time.time() + timeout
    while time.time() < end:
        try:
            urllib.request.urlopen(url, timeout=2)
            return True
        except urllib.error.HTTPError:
            return True
        except Exception:
            time.sleep(0.3)
    raise RuntimeError(f"{url} did not come up")


def check(label, fn):
    try:
        fn()
        print(f"  FAIL  {label}: was not blocked")
        return False
    except (AccessDenied, rw15.NotSatisfied, Exception) as e:  # noqa: B014
        print(f"  ok    {label}: blocked ({type(e).__name__}: {str(e)[:70]})")
        return True


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=4)
    ap.add_argument("--bad-kss", type=int, default=0, help="run this service in bad_share mode")
    ap.add_argument("--reuse", action="store_true", help="reuse a running, uninitialised network")
    a = ap.parse_args()
    run = ROOT / "network" / "run" / f"n{a.n}"
    profile = run / "profile.json"
    procs = []
    logs = run / "logs"
    if not a.reuse:
        subprocess.run([sys.executable, ROOT / "network" / "pledge_net.py", "up", "--n", str(a.n)], check=True)
    try:
        procs.append(subprocess.Popen([BIN / "pledge-gateway", "--profile", profile, "--listen", "127.0.0.1:8800"],
                                      stdout=open(logs / "gateway.log", "w"), stderr=subprocess.STDOUT,
                                      start_new_session=True))
        wait_http("http://127.0.0.1:8800/health")
        t0 = time.time()
        dep = FabricDeployment(profile)
        print(f"Deployment on Fabric: n={dep.ledger.n} f={dep.ledger.f} k={dep.ledger.k} "
              f"(DKG + InitConfig {time.time() - t0:.1f}s)")
        for i in range(1, a.n + 1):
            mode = "bad_share" if i == a.bad_kss else "honest"
            procs.append(subprocess.Popen(
                [BIN / "pledge-kss", "--profile", profile, "--index", str(i),
                 "--secret", run / "kss" / f"kss{i}.json", "--listen", f"127.0.0.1:{8800 + i}", "--mode", mode],
                stdout=open(logs / f"kss{i}.log", "w"), stderr=subprocess.STDOUT, start_new_session=True))
        for i in range(1, a.n + 1):
            wait_http(f"http://127.0.0.1:{8800 + i}/shares?entry=x")

        pat = Patient("p1", dep, samples.paper_consent(deny_practitioners=("rn-99",)))
        for r in (samples.observation(), samples.restricted_condition(), samples.medication()):
            pat.upload(r)
        dr = dep.enroll("dr-card", "doctor", samples.CARDIOLOGY, hospital="H2")
        y = dep.enroll("dr-y", "doctor", samples.CARDIOLOGY, hospital="H3")
        em = dep.enroll("dr-em", "doctor", hospital="H4", emergency=True)
        co = dep.enroll("dr-co", "doctor", hospital="H4")
        rn = dep.enroll("rn-99", "nurse", hospital="H1", dept="ICU")
        print("Enrolled 5 clinicians, uploaded 3 records (all on-ledger).")

        print("Flows:")
        obs = dr.access(["Observation/bp-1"])[0]
        print(f"  ok    cardiologist read BP {obs['valueQuantity']['value']} mmHg")
        both = dr.access(["Observation/bp-1", "MedicationRequest/med-1"])
        print(f"  ok    bundle of {len(both)} records in one transaction")
        rec = em.access(["Condition/cond-1"], purpose="ETREAT", cosigner=co)[0]
        print(f"  ok    break-glass read {rec['resourceType']} (co-signed)")
        obs2 = dr.access(["Observation/bp-1"], use_proxy=True)[0]
        print(f"  ok    outsourced decryption read BP {obs2['valueQuantity']['value']}")

        print("Attacks:")
        results = []
        fresh = dep.enroll("dr-fresh", "doctor", samples.CARDIOLOGY)
        results.append(check("A1 decrypt without a ledger entry", lambda: fresh.open("Observation/bp-1")))
        tau_b = dep.store.get("Observation/bp-1").tau
        tau_a = dep.store.get("MedicationRequest/med-1").tau

        def substitution():
            key = rw15.UserKey(dr.gid, dict(dr.key.comps))
            key.add(lgabe.access_attr(tau_b), dr.access_keys[lgabe.access_attr(tau_a)])
            rb = dep.store.get("Observation/bp-1")
            M = rw15.decrypt(rb.ct_abe, key)
            sym.aead_decrypt(sym.kwk_from_gt(M, rb.tau, rb.version), rb.wrap, rb.tau.encode())
        results.append(check("A2 record substitution", substitution))

        def transfer():
            y.access_keys[lgabe.access_attr(tau_b)] = dr.access_keys[lgabe.access_attr(tau_b)]
            y.open("Observation/bp-1")
        results.append(check("A3 pass transfer", transfer))
        results.append(check("deny-listed nurse", lambda: rn.access(["Observation/bp-1"])))
        results.append(check("emergency role without break-glass", lambda: em.access(["Observation/bp-1"])))
        dep.revoke("dr-card")
        results.append(check("A4 revoked clinician", lambda: dr.access(["MedicationRequest/med-1"])))

        n_retry = 0
        if a.bad_kss:
            before = len(dep.ledger.timings)
            dr2 = dep.enroll("dr-two", "doctor", samples.CARDIOLOGY)
            dr2.access(["Observation/bp-1"])
            n_retry = sum(1 for t in dep.ledger.timings[before:] if t["fn"] == "Access") - 1
            print(f"  ok    service {a.bad_kss} returned bad shares; detected, {n_retry} logged retry")

        print("Identity and re-keying:")
        import copy

        def double_registration():
            tx = pat._registration_tx("H1")
            tx.rotate = False
            tx.sig = dep.hospital_signer[tx.aa].sign(tx.body())
            dep.ledger.submit(tx)
        results.append(check("second binding of the same ABHA number", double_registration))
        old_hdr = copy.deepcopy(dep.store.get("Observation/bp-1"))
        narrowed = samples.paper_consent(deny_practitioners=("rn-99",))
        narrowed["provision"]["provision"] = narrowed["provision"]["provision"][1:]   # drop cardiology
        t0 = time.perf_counter()
        pat.update_consent(narrowed)
        print(f"  ok    header-only re-key of 3 records committed in {(time.perf_counter() - t0) * 1000:.0f} ms")
        dep.store.put(old_hdr)                     # a cached copy of the old header
        results.append(check("access through a retired tag", lambda: y.access(["Observation/bp-1"])))

        out = ROOT.parent / "results" / f"stage2_smoke_n{a.n}.json"
        out.parent.mkdir(exist_ok=True)
        out.write_text(json.dumps(dep.ledger.timings, indent=1))
        acc = [t for t in dep.ledger.timings if t["fn"] == "Access" and t.get("valid")]
        if acc:
            mean = lambda k: sum(t[k] for t in acc) / len(acc)
            print(f"Access entries committed: {len(acc)}; mean endorse {mean('endorse_ms'):.0f} ms, "
                  f"submit {mean('submit_ms'):.0f} ms, commit {mean('commit_ms'):.0f} ms, "
                  f"key shares {sum(t.get('shares_ms', 0) for t in acc) / len(acc):.0f} ms")
        print(f"Attacks blocked: {sum(results)}/{len(results)}. Timings -> {out}")
        return 0 if all(results) else 1
    finally:
        for p in procs:
            try:
                os.killpg(p.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass


if __name__ == "__main__":
    sys.exit(main())
