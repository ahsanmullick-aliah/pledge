"""Turn the MIMIC-IV Clinical Database Demo on FHIR (v2.1.0) into PLEDGE upload workloads.

The dataset is real, de-identified ICU data of 100 patients (Beth Israel Deaconess
Medical Center), published open access on PhysioNet under the ODbL 1.0 licence:
    https://physionet.org/content/mimic-iv-fhir-demo/2.1.0/
It is distributed as gzipped NDJSON files, one per MIMIC profile
(MimicObservationLabevents.ndjson.gz, MimicCondition.ndjson.gz, ...).

We keep the same resource types as the Synthea workload of the paper (MIMIC has
Observation, Condition, MedicationRequest and Procedure among them) and label
Conditions whose diagnosis text matches the same sensitive value set with the
security label R.

A MIMIC patient can have tens of thousands of charted observations, so the
loader caps each patient at `max_resources`. The cap is split evenly over the
resource types the patient has, filling each type with its most recent records
first and handing unused quota to the other types, so that a capped chart still
contains diagnoses, medications and procedures and not only vital signs.
Dates in MIMIC are shifted into the future (years 2110-2210) for de-identification;
that does not affect PLEDGE, whose consent periods apply to the time of access.
"""
import gzip
import heapq
import json
from collections import defaultdict
from pathlib import Path

from .synthea import R_LABEL, SENSITIVE, TYPES, _display

DATE_FIELDS = ("effectiveDateTime", "performedDateTime", "authoredOn", "recordedDate", "onsetDateTime",
               "issued", "occurrenceDateTime")
FILES = (  # name, SHA-256 from the dataset's SHA256SUMS.txt
    ("MimicPatient.ndjson.gz", "f64c61f64aaed317ddb013276515deaf9ca69815d5c0d70ca372f2a75284ce16"),
    ("MimicCondition.ndjson.gz", "6be462199daf68c7ffc72f3a6f71eae803e5b69c2ecdb2c6c82c5f52aec08ec8"),
    ("MimicConditionED.ndjson.gz", "82e0ef0f68b53aa92a9d8d0ff47cbad630751ef361becb904610eecca1b58eed"),
    ("MimicMedicationRequest.ndjson.gz", "3f446cd92a820dff3623c674f4d1f13ea6cc7f3c157f3584e9c17d8502f33456"),
    ("MimicProcedure.ndjson.gz", "1b24c38a3ad87ab4c1706a5c4848bffb0c64091c1ce0eeffdb88d157e9ee3f98"),
    ("MimicProcedureED.ndjson.gz", "4e08331a4942456af66bbe5687859f23e3f51065cb2b59bbd5e4b6bca00e0792"),
    ("MimicProcedureICU.ndjson.gz", "0491ea7c87f8e1d45633477353e34e850700d73c8a716a52efcf200ce28b2db8"),
    ("MimicObservationLabevents.ndjson.gz", "89dcedb9bcddd6e2dff442bb1b4ed84c2a4b21e64cd3bbecb070a263acb154cb"),
    ("MimicObservationChartevents.ndjson.gz", "8222f1cbd5f62b9568c5efa69fa7890be1d604bb503699c82d69fd1fd59c4887"),
    ("MimicObservationED.ndjson.gz", "fb5bfc78fa8022e538f33d65f0aa1235f607e4c73ead8c1fad8de07f354f3f22"),
    ("MimicObservationVitalSignsED.ndjson.gz", "389451325750c1aacde2fca67c8501ca959855640ae1a007358a67120500b19b"),
    ("MimicObservationMicroTest.ndjson.gz", "7b37da4326c09ccb90f135b26c9603b61c404547682dad2da9e2c415f668bbce"),
    ("MimicObservationDatetimeevents.ndjson.gz", "675c78a67b8872b54bcc9bb74f2bc4beee254a8931ca35f7a0851a1947602a01"),
    ("MimicObservationOutputevents.ndjson.gz", "ffbe0f6dccdf8551225e45452837ecd64a154a4bf4c87e5285aa8876fe7faf96"),
)
BASE_URL = "https://physionet.org/files/mimic-iv-fhir-demo/2.1.0/fhir/"


def _open(path: Path):
    return gzip.open(path, "rt", encoding="utf-8") if path.suffix == ".gz" else open(path, encoding="utf-8")


def _files(directory):
    d = Path(directory)
    found = sorted(d.glob("Mimic*.ndjson.gz")) + sorted(d.glob("Mimic*.ndjson"))
    if not found:
        raise FileNotFoundError(f"no Mimic*.ndjson(.gz) files in {d}")
    return found


def _date(res):
    for k in DATE_FIELDS:
        if res.get(k):
            return str(res[k])
    p = res.get("effectivePeriod") or res.get("performedPeriod") or {}
    return str(p.get("start", ""))


def patient_ids(directory):
    for path in _files(directory):
        if path.name.startswith("MimicPatient."):
            with _open(path) as f:
                return sorted(json.loads(line)["id"] for line in f if line.strip())
    raise FileNotFoundError("MimicPatient.ndjson(.gz) is missing")


def load_patients(directory, limit=None, types=TYPES, max_resources=300):
    """Yields (patient id, [resources]) for the first `limit` patients (sorted by id)."""
    pids = patient_ids(directory)
    if limit is not None:
        pids = pids[:limit]
    wanted = set(pids)
    per_type = max(1, max_resources)
    # keep, per (patient, type), the per_type most recent records: a min-heap on (date, seq)
    heaps = defaultdict(list)
    counts = defaultdict(int)
    seq = 0
    for path in _files(directory):
        if path.name.startswith("MimicPatient."):
            continue
        with _open(path) as f:
            for line in f:
                if not line.strip():
                    continue
                res = json.loads(line)
                rt = res.get("resourceType")
                if rt not in types:
                    continue
                ref = (res.get("subject") or {}).get("reference", "")
                pid = ref.split("/", 1)[1] if "/" in ref else ""
                if pid not in wanted:
                    continue
                key = (pid, rt)
                counts[key] += 1
                seq += 1
                item = (_date(res), seq, line)
                h = heaps[key]
                if len(h) < per_type:
                    heapq.heappush(h, item)
                elif item > h[0]:
                    heapq.heapreplace(h, item)
    for pid in pids:
        rts = sorted(rt for (p, rt) in heaps if p == pid)
        if not rts:
            continue
        pools = {rt: sorted(heaps[(pid, rt)], reverse=True) for rt in rts}   # most recent first
        quota, chosen = max_resources, {rt: [] for rt in rts}
        while quota > 0 and any(pools.values()):                            # even split, redistribute
            live = [rt for rt in rts if pools[rt]]
            share = max(1, quota // len(live))
            for rt in live:
                take = pools[rt][:min(share, quota)]
                pools[rt] = pools[rt][len(take):]
                chosen[rt] += take
                quota -= len(take)
                if quota <= 0:
                    break
        picked = sorted((it for rt in rts for it in chosen[rt]), key=lambda it: (it[0], it[1]))
        out = []
        for _, _, line in picked:
            res = json.loads(line)
            res = {k: v for k, v in res.items() if k != "text"}
            if res["resourceType"] == "Condition" and SENSITIVE.search(_display(res)):
                res.setdefault("meta", {}).setdefault("security", []).append(R_LABEL)
            out.append(res)
        yield pid, out
