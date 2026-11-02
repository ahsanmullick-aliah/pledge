"""FHIR workload loaders: Synthea bundles and MIMIC-IV on FHIR (real, de-identified data)."""
import json
import tempfile
import unittest
from pathlib import Path

from pledge.fhir import consent as C, samples
from pledge.fhir.datasets import detect, load_patients
from pledge.system.actors import Deployment, Patient

MIMIC = Path(__file__).parent / "data" / "mimic_sample"


class MimicLoaderTest(unittest.TestCase):
    def test_groups_by_patient_and_caps(self):
        self.assertEqual(detect(MIMIC), "mimic")
        pats = list(load_patients(MIMIC, max_resources=20))
        self.assertEqual(len(pats), 3)
        for pid, res in pats:
            self.assertLessEqual(len(res), 20)
            for r in res:
                self.assertTrue(r["subject"]["reference"].endswith(pid))
                self.assertIn(r["resourceType"], ("Observation", "Condition", "Procedure", "MedicationRequest"))

    def test_quota_keeps_every_type(self):
        for pid, res in load_patients(MIMIC, max_resources=12):
            types = {r["resourceType"] for r in res}
            full = {r["resourceType"] for _, rr in load_patients(MIMIC, max_resources=10_000) if _ == pid for r in rr}
            self.assertEqual(types, full)          # a small cap still keeps diagnoses and procedures

    def test_real_records_encrypt_and_open(self):
        dep = Deployment()
        pid, res = next(load_patients(MIMIC, limit=1, max_resources=15))
        pat = Patient(pid, dep, samples.paper_consent(patient=pid))
        for r in res:
            pat.upload(r)
        dep.ledger.flush()
        dr = dep.enroll("dr-card", "doctor", samples.CARDIOLOGY, hospital="H2")
        readable = [rid for rid, r in pat.resources.items()
                    if not any(s.get("code") == "R" for s in r.get("meta", {}).get("security", []))]
        opened = dr.access(readable)
        self.assertEqual([o["id"] for o in opened], [pat.resources[r]["id"] for r in readable])

    def test_sensitive_conditions_labelled(self):
        labelled = [r for _, rr in load_patients(MIMIC, max_resources=10_000) for r in rr
                    if any(s.get("code") == "R" for s in r.get("meta", {}).get("security", []))]
        for r in labelled:
            self.assertEqual(r["resourceType"], "Condition")
            out = C.compile_consent(samples.paper_consent(patient="p"), C.Resource.from_fhir(r))
            self.assertIsNone(out.policy)                       # nobody but the patient (and break-glass)


class DetectTest(unittest.TestCase):
    def test_synthea_folder(self):
        with tempfile.TemporaryDirectory() as d:
            Path(d, "Alice_1.json").write_text(json.dumps({"resourceType": "Bundle", "entry": []}))
            self.assertEqual(detect(d), "synthea")


if __name__ == "__main__":
    unittest.main()
