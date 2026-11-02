"""Curated specialty hierarchy and ancestor closure (paper Section V-C).

Specialty codes come from FHIR PractitionerRole.specialty (SNOMED CT practice
setting codes). SNOMED's practice-code value set is flat, so the parent/child
structure below is a curated map. It is an illustrative input to the system:
a deployment would load the national medical council's register instead.
Codes marked "pledge:" are local placeholders for sub-specialties.
[VERIFY: confirm every SNOMED code against the release in use.]
"""

PARENT = {
    # SNOMED CT practice setting codes (FHIR c80-practice-codes value set)
    "394579002": "419192003",   # Cardiology            -> Internal medicine
    "394584008": "419192003",   # Gastroenterology      -> Internal medicine
    "394583002": "419192003",   # Endocrinology         -> Internal medicine
    "394589003": "419192003",   # Nephrology            -> Internal medicine
    "394591006": None,          # Neurology
    "394587001": None,          # Psychiatry
    "394582007": None,          # Dermatology
    "394609007": None,          # General surgery
    "419192003": None,          # Internal medicine
    # local sub-specialties
    "pledge:interventional-cardiology": "394579002",
    "pledge:electrophysiology": "394579002",
    "pledge:hepatology": "394584008",
}

LABEL = {
    "394579002": "Cardiology", "394584008": "Gastroenterology", "394583002": "Endocrinology",
    "394589003": "Nephrology", "394591006": "Neurology", "394587001": "Psychiatry",
    "394582007": "Dermatology", "394609007": "General surgery", "419192003": "Internal medicine",
    "pledge:interventional-cardiology": "Interventional cardiology",
    "pledge:electrophysiology": "Cardiac electrophysiology", "pledge:hepatology": "Hepatology",
}


def ancestors(code: str):
    out, seen = [], set()
    cur = PARENT.get(code)
    while cur is not None:
        if cur in seen:
            raise ValueError("cycle in specialty hierarchy")
        seen.add(cur)
        out.append(cur)
        cur = PARENT.get(cur)
    return out


def closure(code: str):
    """Specialty attributes issued for `code`: the code itself plus every ancestor."""
    if code not in PARENT:
        raise KeyError(f"unknown specialty code {code}")
    return [code] + ancestors(code)


def depth(code: str) -> int:
    return len(ancestors(code))
