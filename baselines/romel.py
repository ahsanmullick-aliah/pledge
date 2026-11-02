"""Baseline 2: Romel et al., arXiv:2511.17464 (2025), patient-centric blockchain EHR
framework decoupling storage from access control, re-implemented for comparison.

What the paper describes and we reproduce
  * FHIR resources encrypted with AES-256-GCM and stored off-chain.
  * Data keys wrapped per grantee with ECIES on secp256k1.
  * One contract per patient on a public chain holding commitments to the
    ciphertexts and patient-signed, time-bounded permissions (EIP-712).
  * Read receipts via an optional logAccess call.
Modelling choices (marked ASSUMED in results)
  * EIP-712 hashing uses SHA3-256 in place of Keccak-256 (same cost class;
    Keccak is not in the standard library here).
  * The storage service is honest: it releases a grantee's key wrap only while
    the on-chain permission is valid.
  * The scheme has no role-based policies, so a consent such as "all
    cardiologists" is realised by granting every eligible clinician individually,
    decided with PLEDGE's own reference consent evaluator.
"""
import hashlib
import json
import os
import time
from dataclasses import dataclass, field
from datetime import date

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from pledge.crypto import sym
from pledge.fhir import consent as consent_mod
from pledge.system.actors import AccessDenied

CURVE = ec.SECP256K1()


def _pub_bytes(pk):
    return pk.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.CompressedPoint)


def address(pk) -> str:
    return hashlib.sha3_256(_pub_bytes(pk)).hexdigest()[-40:]


def ecies_wrap(pk, data: bytes) -> bytes:
    eph = ec.generate_private_key(CURVE)
    shared = eph.exchange(ec.ECDH(), pk)
    key = HKDF(hashes.SHA256(), 32, None, b"romel-ecies").derive(shared)
    n = os.urandom(12)
    return _pub_bytes(eph.public_key()) + n + AESGCM(key).encrypt(n, data, None)


def ecies_unwrap(sk, blob: bytes) -> bytes:
    epk = ec.EllipticCurvePublicKey.from_encoded_point(CURVE, blob[:33])
    key = HKDF(hashes.SHA256(), 32, None, b"romel-ecies").derive(sk.exchange(ec.ECDH(), epk))
    return AESGCM(key).decrypt(blob[33:45], blob[45:], None)


def eip712_digest(kind: str, fields: dict) -> bytes:
    return hashlib.sha3_256(b"\x19\x01" + kind.encode() + json.dumps(fields, sort_keys=True).encode()).digest()


def sign(sk, digest: bytes) -> bytes:
    return sk.sign(digest, ec.ECDSA(hashes.SHA256()))


def verify(pk, digest: bytes, sig: bytes) -> bool:
    try:
        pk.verify(sig, digest, ec.ECDSA(hashes.SHA256()))
        return True
    except Exception:
        return False


@dataclass
class PatientContract:
    """Per-patient contract state on the public chain (fully visible to everyone)."""
    owner: object                                  # patient public key
    commitments: dict = field(default_factory=dict)   # rid -> H(ct)
    permissions: dict = field(default_factory=dict)   # (grantee addr, rid) -> expiry (unix)
    receipts: list = field(default_factory=list)      # optional read receipts
    txs: int = 0

    def apply(self, kind, fields, sig, signer_pk):
        if not verify(signer_pk, eip712_digest(kind, fields), sig):
            raise AccessDenied("bad EIP-712 signature")
        if kind in ("commit", "grant", "revoke") and _pub_bytes(signer_pk) != _pub_bytes(self.owner):
            raise AccessDenied("only the patient may change permissions")
        if kind == "commit":
            self.commitments[fields["rid"]] = fields["h"]
        elif kind == "grant":
            for rid in fields["rids"]:
                self.permissions[(fields["grantee"], rid)] = fields["expiry"]
        elif kind == "revoke":
            for rid in fields["rids"]:
                self.permissions.pop((fields["grantee"], rid), None)
        elif kind == "receipt":
            if (address(signer_pk), fields["rid"]) not in self.permissions:
                raise AccessDenied("receipt from non-grantee")
            self.receipts.append(fields)
        self.txs += 1


class RomelSystem:
    name = "Romel et al. 2025"

    def __init__(self):
        self.contracts = {}          # patient id -> PatientContract
        self.storage = {}            # rid -> ciphertext
        self.wraps = {}              # (rid, grantee addr) -> ECIES wrap
        self.clinicians = {}
        self.now = 1_780_000_000

    def enroll(self, gid, role, specialty_code=None, hospital=None, dept=None, emergency=False):
        c = RomelClinician(gid, self, role, specialty_code, hospital, dept)
        self.clinicians[gid] = c
        return c

    def new_patient(self, pid):
        p = RomelPatient(pid, self)
        self.contracts[pid] = PatientContract(p.sk.public_key())
        return p

    # honest storage: serves a wrap only under a valid, unexpired on-chain permission
    def fetch_wrap(self, pid, rid, grantee_addr):
        exp = self.contracts[pid].permissions.get((grantee_addr, rid))
        if exp is None or exp < self.now:
            raise AccessDenied("no valid on-chain permission")
        return self.wraps[(rid, grantee_addr)]

    def validator_view(self):
        """Everything on the public chain is readable."""
        return {pid: {"grants": sorted({g for (g, _r) in c.permissions}),
                      "records": sorted(c.commitments), "receipts": list(c.receipts)}
                for pid, c in self.contracts.items()}


class RomelPatient:
    def __init__(self, pid, system: RomelSystem):
        self.pid, self.sys = pid, system
        self.sk = ec.generate_private_key(CURVE)
        self.box = sym.BoxKeyPair.generate()
        self.deks = {}
        self.resources = {}

    def _tx(self, kind, fields):
        self.sys.contracts[self.pid].apply(kind, fields, sign(self.sk, eip712_digest(kind, fields)),
                                           self.sk.public_key())

    def upload(self, res_json):
        rid = f'{res_json["resourceType"]}/{res_json["id"]}'
        dek = sym.new_dek()
        ct = sym.aead_encrypt(dek, json.dumps(res_json).encode(), rid.encode())
        self.sys.storage[rid] = ct
        self.deks[rid] = dek
        self.resources[rid] = res_json
        self._tx("commit", {"rid": rid, "h": hashlib.sha256(ct).hexdigest()})
        return rid

    def grant(self, clinician, rids, days=365):
        for rid in rids:
            self.sys.wraps[(rid, clinician.addr)] = ecies_wrap(clinician.sk.public_key(), self.deks[rid])
        self._tx("grant", {"grantee": clinician.addr, "rids": list(rids), "expiry": self.sys.now + days * 86400})

    def revoke(self, clinician, rids):
        self._tx("revoke", {"grantee": clinician.addr, "rids": list(rids)})

    def share_by_consent(self, consent, directory, on=date(2026, 6, 1)):
        """Role-based consent realised as individual grants to every eligible clinician."""
        stats = {"grants": 0, "wraps": 0}
        for c in directory:
            eligible = [rid for rid, res in self.resources.items()
                        if consent_mod.evaluate(consent, consent_mod.Resource.from_fhir(res),
                                                c.attrs, c.gid, "TREAT", on)]
            if eligible:
                self.grant(c, eligible)
                stats["grants"] += 1
                stats["wraps"] += len(eligible)
        return stats


class RomelClinician:
    def __init__(self, gid, system, role, specialty_code, hospital, dept):
        from pledge.fhir import specialty
        self.gid, self.sys = gid, system
        self.sk = ec.generate_private_key(CURVE)
        self.addr = address(self.sk.public_key())
        self.attrs = {consent_mod.CLINICIAN_ATTR, f"role:{role}", f"id:{gid}"}
        if specialty_code:
            self.attrs |= {f"spec:{s}" for s in specialty.closure(specialty_code)}
        if hospital:
            self.attrs |= {f"org:{hospital}"} | ({f"dept:{hospital}.{dept}"} if dept else set())
        self.cache = {}             # rid -> DEK already unwrapped

    def open(self, pid, rid, log=False):
        """Fetch the key wrap (storage checks the permission), unwrap, decrypt.
        The read receipt is optional in the original design."""
        if rid not in self.cache:
            self.cache[rid] = ecies_unwrap(self.sk, self.sys.fetch_wrap(pid, rid, self.addr))
        out = json.loads(sym.aead_decrypt(self.cache[rid], self.sys.storage[rid], rid.encode()))
        if log:
            fields = {"rid": rid, "ts": self.sys.now}
            self.sys.contracts[pid].apply("receipt", fields, sign(self.sk, eip712_digest("receipt", fields)),
                                          self.sk.public_key())
        return out
