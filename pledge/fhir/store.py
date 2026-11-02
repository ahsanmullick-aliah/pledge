"""Encrypted store on a real FHIR server (HAPI FHIR R4).

Each encrypted record is a FHIR ``Binary`` resource whose id is derived from
the resource id. The server sees only ciphertext plus the record tag and
policy in the header, exactly the ES of the paper's system model.
"""
import base64
import json
import time
import urllib.error
import urllib.request

from ..crypto import rw15
from ..system.actors import StoredRecord

CONTENT_TYPE = "application/x-pledge-record+json"


def _hx(b):
    return None if b is None else b.hex()


def _bx(s):
    return None if s is None else bytes.fromhex(s)


def record_to_json(rec: StoredRecord) -> bytes:
    return json.dumps({
        "resource_id": rec.resource_id, "tau": rec.tau, "version": rec.version,
        "ct_abe": rw15.ct_to_dict(rec.ct_abe) if rec.ct_abe is not None else None,
        "wrap": _hx(rec.wrap), "ct_data": rec.ct_data.hex(), "patient_wrap": rec.patient_wrap.hex(),
        "header_hash": _hx(rec.header_hash)}, separators=(",", ":")).encode()


def record_from_json(b: bytes) -> StoredRecord:
    d = json.loads(b)
    return StoredRecord(d["resource_id"], d["tau"], d["version"],
                        rw15.ct_from_dict(d["ct_abe"]) if d["ct_abe"] else None,
                        _bx(d["wrap"]), bytes.fromhex(d["ct_data"]), bytes.fromhex(d["patient_wrap"]),
                        _bx(d["header_hash"]))


def binary_id(resource_id: str) -> str:
    return resource_id.replace("/", "-")[:64]


class FhirEncryptedStore:
    """Drop-in replacement for EncryptedStore backed by a FHIR server."""

    def __init__(self, base="http://127.0.0.1:8080/baseR4"):
        self.base = base.rstrip("/")
        self.index = []
        self.stats = {"puts": 0, "gets": 0, "put_ms": 0.0, "get_ms": 0.0, "bytes": 0}

    def _req(self, method, path, body=None):
        req = urllib.request.Request(f"{self.base}/{path}", data=body, method=method,
                                     headers={"Content-Type": "application/fhir+json",
                                              "Accept": "application/fhir+json"})
        with urllib.request.urlopen(req, timeout=60) as r:
            return json.loads(r.read() or b"{}")

    def put(self, rec: StoredRecord):
        payload = record_to_json(rec)
        res = {"resourceType": "Binary", "id": binary_id(rec.resource_id), "contentType": CONTENT_TYPE,
               "data": base64.b64encode(payload).decode()}
        t = time.perf_counter()
        self._req("PUT", f"Binary/{res['id']}", json.dumps(res).encode())
        self.stats["put_ms"] += (time.perf_counter() - t) * 1000
        self.stats["puts"] += 1
        self.stats["bytes"] += len(payload)
        if rec.resource_id not in self.index:
            self.index.append(rec.resource_id)

    def get(self, resource_id) -> StoredRecord:
        t = time.perf_counter()
        try:
            res = self._req("GET", f"Binary/{binary_id(resource_id)}")
        except urllib.error.HTTPError as e:
            raise KeyError(resource_id) from e
        self.stats["get_ms"] += (time.perf_counter() - t) * 1000
        self.stats["gets"] += 1
        return record_from_json(base64.b64decode(res["data"]))

    @property
    def records(self):
        return {rid: self.get(rid) for rid in self.index}
