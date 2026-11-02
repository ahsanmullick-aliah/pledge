"""Synthea workload against a real FHIR server (HAPI FHIR R4) as the encrypted store.

    java -jar synthea.jar -p 50 --exporter.fhir.export true ...       # generate patients
    hapi-fhir-cli run-server -v r4 -p 8080                            # start HAPI (Java 11)
    python3 -m bench.fhir_workload --data <dir>/fhir --patients 50 --out results/fhir_workload.csv
    python3 -m bench.fhir_workload --data data/mimic-iv-fhir-demo --patients 100 --out results/fhir_workload_mimic.csv

Per patient it measures: encryption time per resource, FHIR-server write time,
storage expansion (stored bytes / plaintext bytes), how many resources were
labelled restricted, and the time for a cardiologist to open the patient's
whole accessible chart as one bundled, logged request (ledger + key shares +
FHIR reads + decryption). The ledger here is the in-process simulator; use
fabric/bench_ledger.py for ledger latency on Fabric.
"""
import argparse
import csv
import json
import os
import statistics
import time

from pledge.fhir import samples
from pledge.fhir.store import FhirEncryptedStore, record_to_json
from pledge.fhir.datasets import load_patients
from pledge.system.actors import Deployment, Patient


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", "--synthea", dest="data", required=True,
                    help="Synthea FHIR bundle folder, or MIMIC-IV on FHIR folder (Mimic*.ndjson.gz)")
    ap.add_argument("--patients", type=int, default=20)
    ap.add_argument("--fhir", default="http://127.0.0.1:8080/baseR4")
    ap.add_argument("--max-resources", type=int, default=300, help="cap per patient (most recent first)")
    ap.add_argument("--out", default="results/fhir_workload.csv")
    a = ap.parse_args()

    dep = Deployment(batch_size=500)
    dep.store = FhirEncryptedStore(a.fhir)
    dr = dep.enroll("dr-card", "doctor", samples.CARDIOLOGY, hospital="H2")
    rows = []
    for pid, resources in load_patients(a.data, limit=a.patients, max_resources=a.max_resources):
        pat = Patient(pid, dep, samples.paper_consent(patient=pid))
        local = {}
        enc_ms, put0 = [], dep.store.stats["put_ms"]
        plain = stored = binary = restricted = 0
        t0 = time.perf_counter()
        for res in resources:
            t = time.perf_counter()
            rec, compiled = pat._encrypt(res, 1)
            enc_ms.append((time.perf_counter() - t) * 1000)
            dep.store.put(rec)
            local[rec.resource_id] = rec
            dep.patient_boxes[rec.resource_id] = pat.box.pk
            pat.resources[rec.resource_id] = res
            pat.taus[rec.resource_id] = rec.tau
            if rec.tau:
                pat._register(rec, compiled)
            plain += len(json.dumps(res).encode())
            stored += len(record_to_json(rec))
            binary += (len(rec.ct_data) + len(rec.patient_wrap) + len(rec.wrap or b"")
                       + (rec.ct_abe.size_bytes() if rec.ct_abe is not None else 0) + 32)
            restricted += any(s.get("code") == "R" for s in res.get("meta", {}).get("security", []))
        dep.ledger.flush()
        upload_s = time.perf_counter() - t0
        chart = [rid for rid in pat.resources
                 if local[rid].ct_abe is not None
                 and local[rid].ct_abe.matrix.solve(dr.key.attrs | {f"acc:{pat.taus[rid]}"}) is not None]
        get0, gets0 = dep.store.stats["get_ms"], dep.store.stats["gets"]
        t = time.perf_counter()
        opened = dr.access(chart) if chart else []
        access_s = time.perf_counter() - t
        assert [o["id"] for o in opened] == [pat.resources[r]["id"] for r in chart]
        rows.append({
            "patient": pid, "resources": len(resources), "restricted": restricted, "chart": len(chart),
            "upload_s": round(upload_s, 3), "encrypt_ms_median": round(statistics.median(enc_ms), 3),
            "fhir_put_ms_mean": round((dep.store.stats["put_ms"] - put0) / max(1, len(resources)), 3),
            "plaintext_bytes": plain, "stored_bytes": stored, "expansion": round(stored / max(1, plain), 2),
            "binary_bytes": binary, "binary_expansion": round(binary / max(1, plain), 2),
            "chart_access_s": round(access_s, 3),
            "fhir_get_ms_mean": round((dep.store.stats["get_ms"] - get0) / max(1, dep.store.stats["gets"] - gets0), 3),
        })
        r = rows[-1]
        print(f"{pid[:8]} res={r['resources']:<4} R={r['restricted']:<3} chart={r['chart']:<4} "
              f"enc={r['encrypt_ms_median']:.1f}ms put={r['fhir_put_ms_mean']:.1f}ms x{r['expansion']} "
              f"chart_open={r['chart_access_s']:.2f}s")
    os.makedirs(os.path.dirname(a.out) or ".", exist_ok=True)
    with open(a.out, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)
    tot = lambda k: sum(r[k] for r in rows)
    print(f"\n{len(rows)} patients, {tot('resources')} resources ({tot('restricted')} restricted), "
          f"median encryption {statistics.median(r['encrypt_ms_median'] for r in rows):.1f} ms/resource, "
          f"storage expansion x{tot('stored_bytes') / tot('plaintext_bytes'):.2f} as stored "
          f"(x{tot('binary_bytes') / tot('plaintext_bytes'):.2f} in binary encoding), "
          f"median chart open {statistics.median(r['chart_access_s'] for r in rows):.2f} s "
          f"for a median chart of {statistics.median(r['chart'] for r in rows)} resources -> {a.out}")


if __name__ == "__main__":
    main()
