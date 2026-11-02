"""Sample FHIR R4 resources and consents used by tests, demos and benchmarks."""
from .consent import SYS_ROLE, SYS_SNOMED, SYS_DEPT, SYS_PURPOSE

CARDIOLOGY = "394579002"


def actor(role=None, spec=None, org=None, dept=None, practitioner=None):
    a, codings = {}, []
    if role:
        codings.append({"system": SYS_ROLE, "code": role})
    if spec:
        codings.append({"system": SYS_SNOMED, "code": spec})
    if dept:
        codings.append({"system": SYS_DEPT, "code": dept})
    if codings:
        a["role"] = {"coding": codings}
    if org:
        a["reference"] = {"reference": f"Organization/{org}"}
    if practitioner:
        a["reference"] = {"reference": f"Practitioner/{practitioner}"}
    return a


def paper_consent(patient="p1", deny_practitioners=()):
    """Section V-B example: cardiologists anywhere, ICU nurses at H1, never records labelled R."""
    nurse_rule = {"type": "permit", "actor": [actor(role="nurse", org="H1", dept="ICU")],
                  "provision": [{"type": "deny", "securityLabel": [{"code": "R"}]}]}
    for g in deny_practitioners:
        nurse_rule["provision"].append({"type": "deny", "actor": [actor(practitioner=g)]})
    return {
        "resourceType": "Consent", "id": f"consent-{patient}", "status": "active",
        "patient": {"reference": f"Patient/{patient}"},
        "provision": {"type": "deny", "period": {"start": "2026-01-01", "end": "2027-12-31"}, "provision": [
            {"type": "permit", "actor": [actor(role="doctor", spec=CARDIOLOGY)],
             "purpose": [{"system": SYS_PURPOSE, "code": "TREAT"}],
             "provision": [{"type": "deny", "securityLabel": [{"code": "R"}]}]},
            nurse_rule,
        ]},
    }


def observation(rid="bp-1", patient="p1", systolic=128, date="2026-03-02"):
    return {"resourceType": "Observation", "id": rid, "status": "final",
            "subject": {"reference": f"Patient/{patient}"},
            "code": {"coding": [{"system": "http://loinc.org", "code": "8480-6", "display": "Systolic BP"}]},
            "effectiveDateTime": date,
            "valueQuantity": {"value": systolic, "unit": "mmHg"}}


def restricted_condition(rid="cond-1", patient="p1"):
    return {"resourceType": "Condition", "id": rid, "subject": {"reference": f"Patient/{patient}"},
            "meta": {"security": [{"system": "http://terminology.hl7.org/CodeSystem/v3-Confidentiality",
                                   "code": "R"}]},
            "code": {"text": "restricted diagnosis"}, "recordedDate": "2026-02-10"}


def medication(rid="med-1", patient="p1"):
    return {"resourceType": "MedicationRequest", "id": rid, "status": "active", "intent": "order",
            "subject": {"reference": f"Patient/{patient}"},
            "medicationCodeableConcept": {"text": "atorvastatin 20 mg"}, "authoredOn": "2026-03-02"}
