"""Turn Synthea FHIR R4 bundles into PLEDGE upload workloads."""
import json
import re
from pathlib import Path

TYPES = ("Observation", "Condition", "MedicationRequest", "Procedure", "Immunization",
         "AllergyIntolerance", "DiagnosticReport")
# Diagnoses a patient would typically restrict (security label R)
SENSITIVE = re.compile(r"depress|anxiety|psych|substance|alcohol|opioid|drug|hiv|suicid|schizo|bipolar",
                       re.IGNORECASE)
R_LABEL = {"system": "http://terminology.hl7.org/CodeSystem/v3-Confidentiality", "code": "R"}


def _display(res):
    cc = res.get("code", {})
    return " ".join([cc.get("text", "")] + [c.get("display", "") for c in cc.get("coding", [])])


def load_patients(directory, limit=None, types=TYPES):
    """Yields (patient id, [resources]) with sensitive conditions labelled R."""
    files = sorted(p for p in Path(directory).glob("*.json")
                   if not p.name.startswith(("hospital", "practitioner")))
    for n, path in enumerate(files):
        if limit is not None and n >= limit:
            break
        bundle = json.loads(path.read_text())
        pid, out = None, []
        for e in bundle.get("entry", []):
            res = e["resource"]
            if res["resourceType"] == "Patient":
                pid = res["id"]
            elif res["resourceType"] in types:
                res = {k: v for k, v in res.items() if k not in ("text",)}
                if res["resourceType"] == "Condition" and SENSITIVE.search(_display(res)):
                    res.setdefault("meta", {}).setdefault("security", []).append(R_LABEL)
                out.append(res)
        if pid:
            yield pid, out
