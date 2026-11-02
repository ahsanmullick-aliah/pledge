#!/usr/bin/env python3
"""Ledger benchmarks on Fabric (planned paper Section VII-D/G).

    export FABRIC_BIN=~/fabric-bin
    python3 fabric/bench_ledger.py --n 4 --rates 10,25,50,100 --duration 30
    python3 fabric/bench_ledger.py --n 4 --rates 20 --bundles 1,10,50 --duration 30

For every point it pre-signs fresh access entries in Python (real BLS
signatures, purpose proofs and sealed audit payloads), then the Go load
generator releases them open-loop at the target rate across all hospitals'
gateways and records endorse/submit/commit latency plus the time until the
k key-share services have released their partial keys.

Run on the paper's hardware, not on a laptop: every hospital's orderer, peer
and key-share service shares the same machine here.
"""
import argparse
import json
import os
import random
import re
import signal
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT.parent))

from pledge.fabric_client import FabricDeployment          # noqa: E402
from pledge.fhir import samples                            # noqa: E402
from pledge.ledger import chaincode as cc                  # noqa: E402
from pledge.system.actors import Patient, COUNCIL          # noqa: E402
from pledge.crypto.pairing import g1_bytes, g2_bytes      # noqa: E402
from pledge.fabric_client import _post                    # noqa: E402

BIN = ROOT / "bin"
sys.path.insert(0, str(ROOT))
from run_stage2 import wait_http                         # noqa: E402


def _guo_setup(dep, clinicians):
    """Initialise the baseline log chaincode and register the same clinicians there."""
    cfg = {"aa_keys": {k: g2_bytes(v).hex() for k, v in dep.aa_keys.items()},
           "regulator_purpose_pk": g1_bytes(dep.regulator.purpose_key.pk).hex(),
           "n": dep.ledger.n, "k": dep.ledger.k}
    st, body = _post("http://127.0.0.1:8800/submit", {"fn": "InitConfig", "arg": json.dumps(cfg), "cc": "guolog"})
    assert st == 200 and body.get("valid"), body
    for c in clinicians:
        tx = cc.CredentialTx(c.gid, c.signer.vk_bytes, COUNCIL)
        tx.sig = dep.council_signer.sign(tx.body())
        st, body = _post("http://127.0.0.1:8800/submit", {"fn": "RegisterCredential",
                                                         "arg": cc.canon(tx.to_wire()).decode(), "cc": "guolog"})
        assert st == 200 and body.get("valid"), body


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=4)
    ap.add_argument("--rates", default="10,25,50")
    ap.add_argument("--bundles", default="1")
    ap.add_argument("--duration", type=float, default=20)
    ap.add_argument("--clinicians", type=int, default=20)
    ap.add_argument("--records", type=int, default=60)
    ap.add_argument("--batch-ms", type=int, default=50)
    ap.add_argument("--out", default=str(ROOT.parent / "results"))
    ap.add_argument("--reuse", action="store_true")
    ap.add_argument("--systems", default="pledge", help="comma list: pledge,guo")
    ap.add_argument("--guo-threshold", type=int, default=0,
                    help="endorsement threshold for the Guo log chaincode (default: same k as PLEDGE; Guo et al. used 1-3)")
    a = ap.parse_args()
    systems = a.systems.split(",")
    run = ROOT / "network" / "run" / f"n{a.n}"
    if not a.reuse:
        k = (a.n - 1) // 3 + 1
        subprocess.run([sys.executable, ROOT / "network" / "pledge_net.py", "up", "--n", str(a.n),
                        "--batch-ms", str(a.batch_ms),
                        "--guo", str((a.guo_threshold or k) if "guo" in systems else 0)], check=True)
    profile = run / "profile.json"
    logs = run / "logs"
    procs = [subprocess.Popen([BIN / "pledge-gateway", "--profile", profile, "--listen", "127.0.0.1:8800"],
                              stdout=open(logs / "gateway.log", "w"), stderr=subprocess.STDOUT,
                              start_new_session=True)]
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    summary = []
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
        t = time.time()
        clinicians = [dep.enroll(f"dr-{j}", "doctor", samples.CARDIOLOGY, hospital=f"H{1 + j % a.n}")
                      for j in range(a.clinicians)]
        pat = Patient("p-bench", dep, samples.paper_consent())
        rids = []
        for j in range(a.records):
            r = pat.upload(samples.observation(rid=f"bp-{j}", systolic=110 + j % 40))
            rids.append(r.resource_id)
        print(f"setup: {a.clinicians} clinicians, {a.records} records in {time.time() - t:.0f}s")
        rng = random.Random(1)
        if "guo" in systems:
            _guo_setup(dep, clinicians)
        for bundle in [int(x) for x in a.bundles.split(",")] if "pledge" in systems else []:
            for rate in [float(x) for x in a.rates.split(",")]:
                count = max(1, int(rate * a.duration))
                t = time.time()
                path = out / f"load_n{a.n}_r{rate:g}_b{bundle}.jsonl"
                with open(path, "w") as f:
                    for _ in range(count):
                        c = rng.choice(clinicians)
                        S = tuple(sorted(rng.sample(range(1, a.n + 1), dep.ledger.k)))
                        tx = c.build_request(rng.sample(rids, bundle), S=S)
                        f.write(json.dumps({"fn": "Access", "arg": cc.canon(tx.to_wire()).decode()}) + "\n")
                gen = time.time() - t
                csv = out / f"ledger_n{a.n}_r{rate:g}_b{bundle}.csv"
                r = subprocess.run([BIN / "pledge-loadgen", "--profile", profile, "--input", path,
                                    "--rate", str(rate), "--out", csv], capture_output=True, text=True)
                line = r.stdout.strip().splitlines()[-1] if r.stdout.strip() else r.stderr[-300:]
                print(f"n={a.n} bundle={bundle} {line}  (signing {gen:.1f}s)")
                m = dict(re.findall(r"(\w+)=([\d.]+)", line))
                summary.append({"system": "pledge", "n": a.n, "bundle": bundle, "rate": rate, **m,
                                "csv": str(csv)})
                path.unlink()
        if "guo" in systems:
            for rate in [float(x) for x in a.rates.split(",")]:
                count = max(1, int(rate * a.duration))
                path = out / f"guo_n{a.n}_r{rate:g}.jsonl"
                with open(path, "w") as f:
                    for _ in range(count):
                        c = rng.choice(clinicians)
                        body = {"gid": c.gid, "rid": rng.choice(rids), "ts": int(time.time())}
                        sig = c.signer.sign(cc.digest("guolog", body))
                        f.write(json.dumps({"fn": "GuoLog",
                                            "arg": cc.canon({**body, "sig": g1_bytes(sig).hex()}).decode()}) + "\n")
                csv = out / f"guo_n{a.n}_r{rate:g}.csv"
                r = subprocess.run([BIN / "pledge-loadgen", "--profile", profile, "--input", path, "--rate", str(rate),
                                    "--out", csv, "--chaincode", "guolog", "--kss-base", "0"],
                                   capture_output=True, text=True)
                line = r.stdout.strip().splitlines()[-1] if r.stdout.strip() else r.stderr[-300:]
                print(f"n={a.n} GUO-LOG {line}")
                m = dict(re.findall(r"(\w+)=([\d.]+)", line))
                summary.append({"system": "guo", "n": a.n, "bundle": 1, "rate": rate, **m, "csv": str(csv)})
                path.unlink()
        (out / f"ledger_summary_n{a.n}.json").write_text(json.dumps(summary, indent=1))
        print(f"summary -> {out / f'ledger_summary_n{a.n}.json'}")
    finally:
        for p in procs:
            try:
                os.killpg(p.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass


if __name__ == "__main__":
    main()
