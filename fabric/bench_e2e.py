#!/usr/bin/env python3
"""End-to-end latency on Fabric with HAPI FHIR as the encrypted store (paper Fig. 11).

    export FABRIC_BIN=~/fabric-bin
    python3 fabric/bench_e2e.py --n 4 --synthea <dir>/fhir --trials 40 --charts 1,10,25,50,100

A first access is split into the stages a clinician waits for:
  fetch       FHIR reads of the encrypted record (header + ciphertext)
  side        chaincode query for the record's side record (purposes, period)
  build       purpose proof, sealed audit fields, BLS signature (client)
  endorse     k-of-n endorsement (chaincode checks)
  order       submit + SmartBFT ordering + commit at the gateway's peer
  shares      until k key-share services have released their partial keys
  verify      ShareVerify + Combine (client)
  decrypt     ABE decryption + key unwrap + AES-GCM (client)
Every stage is timed on the real path the Clinician class takes; nothing is estimated.
"""
import argparse
import json
import os
import signal
import statistics
import subprocess
import sys
import time
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT.parent))
sys.path.insert(0, str(ROOT))

from pledge import fabric_client                            # noqa: E402
from pledge.crypto import lgabe, rw15, sym                  # noqa: E402
from pledge.fabric_client import FabricDeployment           # noqa: E402
from pledge.fhir import samples                             # noqa: E402
from pledge.fhir.store import FhirEncryptedStore            # noqa: E402
from pledge.fhir.datasets import load_patients               # noqa: E402
from pledge.system.actors import Patient                    # noqa: E402
from run_stage2 import wait_http                            # noqa: E402

BIN = ROOT / "bin"
T = defaultdict(float)
ACTIVE = set()


def timed(stage, fn):
    """Accumulate wall time per stage; nested calls of the same stage are counted once."""
    def w(*a, **k):
        if stage in ACTIVE:
            return fn(*a, **k)
        ACTIVE.add(stage)
        t = time.perf_counter()
        try:
            return fn(*a, **k)
        finally:
            T[stage] += (time.perf_counter() - t) * 1000
            ACTIVE.discard(stage)
    return w


def instrument(dep):
    dep.store.get = timed("fetch", dep.store.get)
    view = dep.ledger.state.records
    view.get = timed("side", view.get)
    lgabe.share_verify = timed("verify", lgabe.share_verify)
    lgabe.combine = timed("verify", lgabe.combine)
    rw15.decrypt = timed("decrypt", rw15.decrypt)
    sym.aead_decrypt = timed("decrypt", sym.aead_decrypt)
    sub = dep.ledger.submit

    def submit(tx):
        t = time.perf_counter()
        out = sub(tx)
        wall = (time.perf_counter() - t) * 1000
        f = tx._fabric
        T["endorse"] += f["endorse_ms"]
        T["order"] += wall - f["endorse_ms"]          # submit + ordering + commit, as the client waits
        return out
    dep.ledger.submit = submit
    sh = dep.ledger.shares_for
    dep.ledger.shares_for = timed("shares", sh)


def one_access(dr, rids):
    T.clear()
    t = time.perf_counter()
    dr.access(rids)
    total = (time.perf_counter() - t) * 1000
    row = {k: round(v, 3) for k, v in T.items()}
    known = sum(T.values())
    row["build"] = round(total - known, 3)
    row["total"] = round(total, 3)
    return row


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=4)
    ap.add_argument("--data", "--synthea", dest="data", required=True)
    ap.add_argument("--fhir", default="http://127.0.0.1:8080/baseR4")
    ap.add_argument("--records", type=int, default=120)
    ap.add_argument("--trials", type=int, default=40)
    ap.add_argument("--charts", default="1,10,25,50,100")
    ap.add_argument("--out", default=str(ROOT.parent / "results" / "e2e_fabric.json"))
    a = ap.parse_args()
    run = ROOT / "network" / "run" / f"n{a.n}"
    profile, logs = run / "profile.json", run / "logs"
    subprocess.run([sys.executable, ROOT / "network" / "pledge_net.py", "up", "--n", str(a.n)], check=True)
    procs = [subprocess.Popen([BIN / "pledge-gateway", "--profile", profile, "--listen", "127.0.0.1:8800"],
                              stdout=open(logs / "gateway.log", "w"), stderr=subprocess.STDOUT,
                              start_new_session=True)]
    try:
        wait_http("http://127.0.0.1:8800/health")
        dep = FabricDeployment(profile)
        for i in range(1, a.n + 1):
            procs.append(subprocess.Popen(
                [BIN / "pledge-kss", "--profile", profile, "--index", str(i), "--secret", run / "kss" / f"kss{i}.json",
                 "--listen", f"127.0.0.1:{8800 + i}"],
                stdout=open(logs / f"kss{i}.log", "w"), stderr=subprocess.STDOUT, start_new_session=True))
        for i in range(1, a.n + 1):
            wait_http(f"http://127.0.0.1:{8800 + i}/shares?entry=x")
        dep.store = FhirEncryptedStore(a.fhir)
        pid, resources = next(load_patients(a.data, limit=1, max_resources=1000))
        pat = Patient(pid, dep, samples.paper_consent(patient=pid))
        rids = []
        for res in resources[-a.records:]:
            rec = pat.upload(res)
            if rec.ct_abe is not None:
                rids.append(rec.resource_id)
        print(f"uploaded {len(rids)} readable records of patient {pid[:8]} to HAPI + Fabric")
        instrument(dep)
        doctors = [dep.enroll(f"dr-{j}", "doctor", samples.CARDIOLOGY, hospital=f"H{1 + j % a.n}")
                   for j in range(a.trials)]
        single = []
        for j, dr in enumerate(doctors):              # every trial: a fresh clinician, a record new to them
            single.append(one_access(dr, [rids[j % len(rids)]]))
        charts = []
        for m in [int(x) for x in a.charts.split(",")]:
            for rep in range(3):
                dr = dep.enroll(f"chart-{m}-{rep}", "doctor", samples.CARDIOLOGY, hospital="H2")
                row = one_access(dr, rids[:m])
                row.update({"records": m, "rep": rep})
                charts.append(row)
                print(f"chart of {m:>3}: {row['total']:.0f} ms")
        stages = ["fetch", "side", "build", "endorse", "order", "shares", "verify", "decrypt"]
        med = {s: statistics.median(r.get(s, 0) for r in single) for s in stages + ["total"]}
        print("first access, median ms: " + ", ".join(f"{s} {med[s]:.1f}" for s in stages + ["total"]))
        Path(a.out).write_text(json.dumps({"n": a.n, "single": single, "single_median": med, "charts": charts},
                                          indent=1))
        print(f"-> {a.out}")
    finally:
        for p in procs:
            try:
                os.killpg(p.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass


if __name__ == "__main__":
    main()
