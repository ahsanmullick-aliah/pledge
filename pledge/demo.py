"""Walk-through of PLEDGE on the paper's running example:  python3 -m pledge.demo"""
from pledge.crypto import lgabe, rw15
from pledge.fhir import samples
from pledge.system.actors import Deployment, Patient, AccessDenied


def main():
    dep = Deployment()
    L = dep.ledger
    print(f"Ledger: n={L.n} hospitals, tolerates f={L.f} Byzantine, key threshold k={L.k}, quorum {L.q}")
    pat = Patient("p1", dep, samples.paper_consent())
    for res in (samples.observation(), samples.restricted_condition(), samples.medication()):
        pat.upload(res)
    L.flush()
    print("Patient uploaded 3 FHIR resources; policies:")
    for rid, rec in dep.store.records.items():
        print(f"  {rid:28s} {rec.ct_abe.policy[:90] + '...' if rec.ct_abe else '(patient only)'}")

    dr = dep.enroll("dr-card", "doctor", samples.CARDIOLOGY, hospital="H2")
    print("\n1. Cardiologist without an access entry:")
    try:
        dr.open("Observation/bp-1")
    except AccessDenied as e:
        print("   denied:", e)
    print("2. Cardiologist requests access (logged), receives k partial keys, decrypts:")
    obs = dr.access(["Observation/bp-1"])[0]
    print(f"   read {obs['code']['coding'][0]['display']} = {obs['valueQuantity']['value']} mmHg")

    print("3. Restricted Condition (label R):")
    try:
        dr.access(["Condition/cond-1"])
    except AccessDenied as e:
        print("   denied:", e)

    em = dep.enroll("dr-em", "doctor", hospital="H4", emergency=True)
    co = dep.enroll("dr-co", "doctor", hospital="H4")
    rec = em.access(["Condition/cond-1"], purpose="ETREAT", cosigner=co)[0]
    print(f"4. Break-glass by dr-em co-signed by dr-co: read {rec['resourceType']}/{rec['id']}")

    dep.revoke("dr-card")
    L.flush()
    try:
        dr.access(["MedicationRequest/med-1"])
    except AccessDenied as e:
        print("5. After revocation (next block):", e)

    print("\nPatient's verified audit trail:")
    for t in pat.audit_trail():
        flag = "  [BREAK-GLASS]" if t["breakglass"] else ""
        print(f"   block {t['block']:>2}  {t['clinician']:8s} {t['resource']:22s} {t['purpose']}{flag}")
    print(f"\nPublic anchors: {len(L.public_anchor)}; blocks: {L.height}; view changes: {L.view_changes}")


if __name__ == "__main__":
    main()
