"""One entry point for the FHIR workloads: Synthea (the paper's cohort) or MIMIC-IV on FHIR (real data)."""
from pathlib import Path


def detect(directory) -> str:
    d = Path(directory)
    if list(d.glob("Mimic*.ndjson*")):
        return "mimic"
    if list(d.glob("*.json")):
        return "synthea"
    raise FileNotFoundError(f"{d}: neither Synthea bundles (*.json) nor MIMIC files (Mimic*.ndjson.gz)")


def load_patients(directory, limit=None, max_resources=300, kind=None):
    """Yields (patient id, [resources]); at most max_resources per patient."""
    kind = kind or detect(directory)
    if kind == "mimic":
        from .mimic import load_patients as mimic
        yield from mimic(directory, limit=limit, max_resources=max_resources)
    else:
        from .synthea import load_patients as synthea
        for pid, res in synthea(directory, limit=limit):
            yield pid, res[-max_resources:] if max_resources else res
