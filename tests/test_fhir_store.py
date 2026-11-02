"""Round trip through a real FHIR server; skipped when none is running."""
import os
import unittest
import urllib.request

from pledge.fhir import samples
from pledge.fhir.store import FhirEncryptedStore
from pledge.system.actors import Deployment, Patient

BASE = os.environ.get("PLEDGE_FHIR", "http://127.0.0.1:8080/baseR4")


def _up():
    try:
        with urllib.request.urlopen(f"{BASE}/metadata", timeout=3) as r:
            return r.status == 200
    except Exception:
        return False


@unittest.skipUnless(_up(), "no FHIR server at " + BASE)
class FhirStoreTest(unittest.TestCase):
    def test_upload_access_via_fhir(self):
        dep = Deployment()
        dep.store = FhirEncryptedStore(BASE)
        p = Patient("p-fhir", dep, samples.paper_consent(patient="p-fhir"))
        p.upload(samples.observation())
        dep.ledger.flush()
        dr = dep.enroll("dr-fhir", "doctor", samples.CARDIOLOGY, hospital="H2")
        self.assertEqual(dr.access(["Observation/bp-1"])[0]["id"], "bp-1")
        self.assertEqual(p.read_own("Observation/bp-1")["id"], "bp-1")


if __name__ == "__main__":
    unittest.main()
