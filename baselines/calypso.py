"""Baseline 3: CALYPSO (Kokoris-Kogias et al., PVLDB 14(4):586-599, 2021), on-chain
secrets with long-term secrets (LTS), re-implemented for comparison.

What the paper describes and we reproduce
  * A secret-management committee of n trustees holds a threshold ElGamal key
    (X = g^x, shares x_i, threshold t = f+1) created by a DKG.
  * Write: the writer encrypts the record under a symmetric key k, encrypts k
    under X with threshold ElGamal (U = g^r, V = K + X^r, k = H(K)) and attaches a
    NIZK of correct encryption; the chain verifies the proof and logs txw.
  * Read: the reader logs a read transaction txr naming txw, authorised against
    the current policy. Trustees release their share only for a logged txr, each
    re-encrypted to the reader's public key; the reader recovers X^r and then k.
  * Access control is SIAM, a decentralised RBAC: identity, federated (group /
    role) and resource-policy skipchains. Removing a member from a group revokes
    future reads atomically.
Modelling choices (marked ASSUMED in results)
  * SIAM groups are modelled generously as the same attribute sets PLEDGE
    clinicians hold, and each patient's resource policy is the patient's FHIR
    Consent, evaluated by the chain with PLEDGE's reference evaluator. One policy
    object per patient, so narrowing a consent is one policy update.
  * Group membership changes (onboarding, revocation) are one transaction each.
  * The NIZK is a Schnorr proof of knowledge of r bound to (U, V, policy).
  * Reader blinding (optional in CALYPSO) is off; it would hide the reader but
    not the writer, i.e. not which patient's record was read.
  * The committee and the access-control chain run on the same BFT federation
    of hospitals as PLEDGE (n = 3f+1, t = f+1), on the same curve (BLS12-381 G1).
"""
import hashlib
import json
import secrets
import time
from dataclasses import dataclass, field
from datetime import date

from pledge.crypto import sym
from pledge.crypto import sig as bls
from pledge.crypto._mcl_base import (fr_rand, fr_int, fr_add, fr_mul, fr_hash, fr_neg,
                                     g1_mul, g1_add, g1_neg, g1_eq, g1_bytes, G1_GEN)
from pledge.crypto.pairing import g1_pow, g1_identity, lagrange_at_zero
from pledge.fhir import consent as consent_mod, specialty
from pledge.system.actors import AccessDenied


def _kdf(K) -> bytes:
    return hashlib.sha256(b"CALYPSO|k|" + g1_bytes(K)).digest()


def _chal(*parts) -> object:
    return fr_hash(b"CALYPSO|nizk|" + b"|".join(parts))


# ---------------- committee (threshold ElGamal, Shamir-dealt DKG) ----------------

class Committee:
    def __init__(self, n=4):
        self.n, self.f = n, (n - 1) // 3
        self.t = self.f + 1
        coeffs = [fr_rand() for _ in range(self.t)]
        ev = lambda i: _eval(coeffs, i)
        self.shares = {i: ev(i) for i in range(1, n + 1)}       # trustee i holds x_i
        self.X = g1_pow(coeffs[0])
        self.colluding = set()

    def release(self, i, chain, req):
        """Trustee i: verify the request against the chain, return its share re-encrypted to the reader."""
        txw, txr = chain.writes.get(req["wid"]), chain.reads.get(req["rid"])
        if txw is None or txr is None or not txr["committed"]:
            raise AccessDenied("read transaction not logged on-chain")
        if txr["wid"] != req["wid"]:
            raise AccessDenied("read transaction names a different secret")
        if txr["reader_pk"] != req["reader_pk"]:
            raise AccessDenied("share is released only to the reader named in the read transaction")
        s = fr_rand()
        return i, g1_pow(s), g1_add(g1_mul(txw["U"], self.shares[i]), g1_mul(req["reader_pk"], s))


def _eval(coeffs, x):
    acc, xp = fr_int(0), fr_int(1)
    for c in coeffs:
        acc = fr_add(acc, fr_mul(c, xp))
        xp = fr_mul(xp, fr_int(x))
    return acc


# ---------------- access-control chain (SIAM-like) ----------------

@dataclass
class Chain:
    writes: dict = field(default_factory=dict)        # wid -> txw (public)
    reads: dict = field(default_factory=dict)         # rid -> txr (public)
    groups: dict = field(default_factory=dict)        # reader pk bytes -> attribute set (federated identities)
    policies: dict = field(default_factory=dict)      # patient id -> consent (resource policy skipchain)
    txs: int = 0

    def write(self, txw):
        A, z = txw["proof"]
        c = _chal(g1_bytes(txw["U"]), g1_bytes(txw["V"]), g1_bytes(A), txw["policy"].encode())
        if not g1_eq(g1_pow(z), g1_add(A, g1_mul(txw["U"], c))):
            raise AccessDenied("bad proof of correct encryption")
        self.writes[txw["wid"]] = txw
        self.txs += 1

    def read(self, txr, sig, vk, now=date(2026, 6, 1)):
        if not bls.verify(vk, json.dumps({k: txr[k] for k in ("wid", "gid")}).encode(), sig):
            raise AccessDenied("bad signature on read transaction")
        txw = self.writes[txr["wid"]]
        attrs = self.groups.get(g1_bytes(txr["reader_pk"]))
        if attrs is None:
            raise AccessDenied("reader not in any group (revoked)")
        if not consent_mod.evaluate(self.policies[txw["policy"]], txw["resource_view"], attrs,
                                    txr["gid"], "TREAT", now):
            raise AccessDenied("policy does not authorise this reader")
        rid = secrets.token_hex(16)
        self.reads[rid] = dict(txr, committed=True)
        self.txs += 1
        return rid

    def set_membership(self, reader_pk, attrs):
        self.groups[g1_bytes(reader_pk)] = attrs
        self.txs += 1

    def remove_member(self, reader_pk):
        self.groups.pop(g1_bytes(reader_pk), None)
        self.txs += 1

    def set_policy(self, pid, consent):
        self.policies[pid] = consent
        self.txs += 1

    def validator_view(self):
        return {"writes": [{"writer": w["writer"], "policy": w["policy"], "wid": w["wid"]} for w in self.writes.values()],
                "reads": [{"wid": r["wid"], "reader": r["gid"]} for r in self.reads.values()]}


# ---------------- system ----------------

class CalypsoSystem:
    name = "CALYPSO 2021"

    def __init__(self, n=4):
        self.committee = Committee(n)
        self.chain = Chain()
        self.storage = {}                 # wid -> (record id, ciphertext)

    def new_patient(self, pid, consent):
        p = CalypsoPatient(pid, self)
        self.chain.set_policy(pid, consent)
        return p

    def enroll(self, gid, role, specialty_code=None, hospital=None, dept=None, emergency=False):
        c = CalypsoClinician(gid, self)
        attrs = {consent_mod.CLINICIAN_ATTR, f"role:{role}", f"id:{gid}"}
        if specialty_code:
            attrs |= {f"spec:{s}" for s in specialty.closure(specialty_code)}
        if hospital:
            attrs |= {f"org:{hospital}"} | ({f"dept:{hospital}.{dept}"} if dept else set())
        if emergency:
            attrs.add(consent_mod.EMERGENCY_ATTR)
        self.chain.set_membership(c.pk, attrs)          # one group-membership transaction
        return c

    def revoke(self, clinician):
        self.chain.remove_member(clinician.pk)           # one transaction, no re-encryption


class CalypsoPatient:
    def __init__(self, pid, system: CalypsoSystem):
        self.pid, self.sys = pid, system
        self.wids = {}                                    # record id -> wid
        self.resources = {}

    def encrypt(self, res_json):
        """Writer side: AES-GCM under k, threshold ElGamal of K, Schnorr proof. Returns (txw, ct)."""
        rid = f'{res_json["resourceType"]}/{res_json["id"]}'
        X = self.sys.committee.X
        m, r, w = fr_rand(), fr_rand(), fr_rand()
        K = g1_pow(m)
        U, V = g1_pow(r), g1_add(K, g1_mul(X, r))
        A = g1_pow(w)
        c = _chal(g1_bytes(U), g1_bytes(V), g1_bytes(A), self.pid.encode())
        z = fr_add(w, fr_mul(c, r))
        ct = sym.aead_encrypt(_kdf(K), json.dumps(res_json).encode(), rid.encode())
        wid = hashlib.sha256(g1_bytes(U) + g1_bytes(V) + hashlib.sha256(ct).digest()).hexdigest()
        txw = {"wid": wid, "writer": self.pid, "policy": self.pid, "U": U, "V": V, "proof": (A, z),
               "ct_hash": hashlib.sha256(ct).hexdigest(),
               "resource_view": consent_mod.Resource.from_fhir(res_json)}
        return rid, txw, ct

    def upload(self, res_json):
        rid, txw, ct = self.encrypt(res_json)
        self.sys.chain.write(txw)
        self.sys.storage[txw["wid"]] = (rid, ct)
        self.wids[rid] = txw["wid"]
        self.resources[rid] = res_json
        return rid

    def update_consent(self, consent):
        self.sys.chain.set_policy(self.pid, consent)    # one policy-skipchain update


class CalypsoClinician:
    def __init__(self, gid, system: CalypsoSystem):
        self.gid, self.sys = gid, system
        self.sk = fr_rand()
        self.pk = g1_pow(self.sk)
        self.signer = bls.SigningKey.generate()
        self.cache = {}                                    # wid -> k

    def log_read(self, wid):
        body = {"wid": wid, "gid": self.gid}
        sig = self.signer.sign(json.dumps(body).encode())
        return self.sys.chain.read(dict(body, reader_pk=self.pk), sig, self.signer.vk)

    def collect(self, wid, read_id, trustees=None):
        com = self.sys.committee
        req = {"wid": wid, "rid": read_id, "reader_pk": self.pk}
        S = trustees or list(range(1, com.t + 1))
        parts = [com.release(i, self.sys.chain, req) for i in S]
        return self.recover(wid, parts)

    def recover(self, wid, parts):
        S = [i for i, _, _ in parts]
        XR = g1_identity()
        for i, c1, c2 in parts:
            share = g1_add(c2, g1_neg(g1_mul(c1, self.sk)))          # U^{x_i}
            XR = g1_add(XR, g1_mul(share, lagrange_at_zero(i, S)))
        txw = self.sys.chain.writes[wid]
        return _kdf(g1_add(txw["V"], g1_neg(XR)))

    def open(self, pid_or_rid, rid=None):
        rid = rid or pid_or_rid
        wid = next(w for w, (r, _) in self.sys.storage.items() if r == rid)
        if wid not in self.cache:
            self.cache[wid] = self.collect(wid, self.log_read(wid))
        _, ct = self.sys.storage[wid]
        return json.loads(sym.aead_decrypt(self.cache[wid], ct, rid.encode()))


def committee_decrypts(system: CalypsoSystem, wid, colluders):
    """t colluding trustees combine their shares directly: no read transaction, no reader key."""
    txw = system.chain.writes[wid]
    S = sorted(colluders)
    XR = g1_identity()
    for i in S:
        XR = g1_add(XR, g1_mul(g1_mul(txw["U"], system.committee.shares[i]), lagrange_at_zero(i, S)))
    rid, ct = system.storage[wid]
    return json.loads(sym.aead_decrypt(_kdf(g1_add(txw["V"], g1_neg(XR))), ct, rid.encode()))
