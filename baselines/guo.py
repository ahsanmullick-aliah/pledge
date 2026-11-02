"""Baseline 1: Guo et al., IEEE TNSM 2022 (hybrid blockchain-edge EHR management
with attribute-based cryptographic mechanisms), re-implemented for comparison.

What the paper describes and we reproduce
  * EHRs encrypted with multi-authority ABE (OpenABE MA-ABE). We use the same
    Rouselakis-Waters MA-CP-ABE as PLEDGE, so only the protocol differs.
  * EHR activities and access events recorded as Hyperledger Fabric
    transactions with an n-of-any endorsement policy (1/2/3-of-any in the paper).
What the paper does not specify, and how we fill it (marked ASSUMED in results)
  * Who writes the log entry: the accessing client, after decrypting (the
    paper's flow records access activity; nothing makes decryption depend on it).
  * Revocation: the standard ABE approach -- the authority re-versions each
    attribute the revoked user held, re-issues it to every remaining holder,
    and re-encrypts the header of every record whose policy uses it.
  * Log contents: clinician id and record id in clear.
Not reproduced (orthogonal to the comparison): attribute-based signature
aggregation (ABSA) and Paillier homomorphic computation.
"""
import json
import secrets
import time
from dataclasses import dataclass, field

from pledge.crypto import lsss, rw15, sig as bls, sym
from pledge.crypto.pairing import gt_rand
from pledge.fhir import consent as consent_mod, specialty
from pledge.system.actors import AccessDenied

COUNCIL = "council"


def _owner(attr):
    base = attr.split("#", 1)[0]
    if base.startswith("org:"):
        return base[4:]
    if base.startswith("dept:"):
        return base[5:].split(".", 1)[0]
    return COUNCIL


@dataclass
class GuoLogEntry:
    gid: str
    rid: str
    ts: int
    sig: object

    def body(self):
        return json.dumps([self.gid, self.rid, self.ts]).encode()


class GuoLedger:
    """Fabric channel with an n-of-any endorsement policy; the access chaincode only
    checks the signature on the reported access event."""

    def __init__(self, endorse_k=1):
        self.endorse_k = endorse_k
        self.entries = []
        self.keys = {}

    def submit(self, e: GuoLogEntry):
        vk = self.keys.get(e.gid)
        if vk is None or not bls.verify(vk, e.body(), e.sig):
            raise AccessDenied("bad log signature")
        self.entries.append(e)

    def validator_view(self):
        return [{"gid": e.gid, "record": e.rid, "ts": e.ts} for e in self.entries]


@dataclass
class GuoRecord:
    rid: str
    policy_base: str | None      # policy on unversioned attribute names
    ct_abe: object | None
    wrap: bytes | None
    ct_data: bytes
    patient_wrap: bytes
    version: int = 1


class GuoSystem:
    name = "Guo et al. 2022"

    def __init__(self, hospitals=("H1", "H2", "H3", "H4"), endorse_k=1):
        self.auth = {COUNCIL: rw15.Authority.setup(COUNCIL)}
        self.auth.update({h: rw15.Authority.setup(h) for h in hospitals})
        self.ledger = GuoLedger(endorse_k)
        self.store = {}
        self.attr_version = {}        # base attribute -> current version
        self.holders = {}             # base attribute -> set of gids
        self.clinicians = {}
        self._dek_escrow = {}         # custodian copy of DEKs, required by re-encryption revocation
        self.now = 1_780_000_000

    # -------- attribute versioning (needed for revocation) --------
    def _v(self, attr):
        return f"{attr}#v{self.attr_version.get(attr, 1)}"

    def _versioned_policy(self, base_policy):
        tree = lsss.parse(base_policy)

        def rename(node):
            if node[0] == "attr":
                return ("attr", self._v(node[1]))
            return (node[0], [rename(k) for k in node[1]])
        return lsss.to_string(rename(tree))

    @property
    def pks(self):
        return {n: a.pk for n, a in self.auth.items()}

    # -------- enrolment --------
    def enroll(self, gid, role, specialty_code=None, hospital=None, dept=None, emergency=False):
        c = GuoClinician(gid, self)
        attrs = [consent_mod.CLINICIAN_ATTR, f"role:{role}", f"id:{gid}"]
        if specialty_code:
            attrs += [f"spec:{s}" for s in specialty.closure(specialty_code)]
        if hospital:
            attrs += [f"org:{hospital}"] + ([f"dept:{hospital}.{dept}"] if dept else [])
        for a in attrs:
            self._issue(c, a)
        self.ledger.keys[gid] = c.signer.vk
        self.clinicians[gid] = c
        return c

    def _issue(self, c, base):
        va = self._v(base)
        c.key.add(va, self.auth[_owner(base)].keygen(c.gid, va))
        c.base_attrs.add(base)
        self.holders.setdefault(base, set()).add(c.gid)

    # -------- data --------
    def upload(self, patient_box, consent, res_json):
        rid = f'{res_json["resourceType"]}/{res_json["id"]}'
        compiled = consent_mod.compile_consent(consent, consent_mod.Resource.from_fhir(res_json))
        dek = sym.new_dek()
        ad = rid.encode()
        rec = GuoRecord(rid, compiled.policy, None, None, sym.aead_encrypt(dek, json.dumps(res_json).encode(), ad),
                        sym.seal(patient_box.pk, dek, ad))
        self._encrypt_header(rec, dek)
        self.store[rid] = rec
        self._dek_escrow[rid] = dek
        return rec

    def _encrypt_header(self, rec, dek):
        if rec.policy_base is None:
            return
        M = gt_rand()
        rec.ct_abe = rw15.encrypt(M, self._versioned_policy(rec.policy_base), self.pks, _owner)
        rec.wrap = sym.aead_encrypt(sym.kwk_from_gt(M, rec.rid, rec.version), dek, rec.rid.encode())

    # -------- lifecycle --------
    def revoke(self, gid):
        """Re-version every attribute the user held; re-issue to remaining holders;
        re-encrypt the header of every record whose policy uses one of them.
        The authority (custodian) holds the records' DEKs for this purpose."""
        c = self.clinicians.pop(gid)
        stats = {"reissued_keys": 0, "reencrypted_headers": 0}
        t = time.perf_counter()
        changed = set()
        for base in sorted(c.base_attrs):
            if base == f"id:{gid}":
                continue
            self.attr_version[base] = self.attr_version.get(base, 1) + 1
            self.holders[base].discard(gid)
            changed.add(base)
            for other in self.holders[base]:
                self._issue(self.clinicians[other], base)
                stats["reissued_keys"] += 1
        for rec in self.store.values():
            if rec.policy_base and changed & lsss.attributes(lsss.parse(rec.policy_base)):
                dek = self._custodian_dek(rec)
                rec.version += 1
                self._encrypt_header(rec, dek)
                stats["reencrypted_headers"] += 1
        stats["seconds"] = time.perf_counter() - t
        return stats

    def _custodian_dek(self, rec):
        return self._dek_escrow[rec.rid]

    def update_consent(self, consent, rid, res_json):
        rec = self.store[rid]
        rec.policy_base = consent_mod.compile_consent(consent, consent_mod.Resource.from_fhir(res_json)).policy
        rec.version += 1
        t = time.perf_counter()
        self._encrypt_header(rec, self._dek_escrow[rid])
        return time.perf_counter() - t


class GuoClinician:
    def __init__(self, gid, system: GuoSystem):
        self.gid, self.sys = gid, system
        self.signer = bls.SigningKey.generate()
        self.key = rw15.UserKey(gid)
        self.base_attrs = set()

    def open(self, rid, log=True):
        """Decrypt with standing keys; an honest client then reports the access."""
        rec = self.sys.store[rid]
        if rec.ct_abe is None:
            raise AccessDenied("patient-only record")
        try:
            M = rw15.decrypt(rec.ct_abe, self.key)
            dek = sym.aead_decrypt(sym.kwk_from_gt(M, rec.rid, rec.version), rec.wrap, rec.rid.encode())
        except rw15.NotSatisfied as e:
            raise AccessDenied(str(e)) from e
        except Exception as e:
            raise AccessDenied("decryption failed") from e
        out = json.loads(sym.aead_decrypt(dek, rec.ct_data, rec.rid.encode()))
        if log:
            e = GuoLogEntry(self.gid, rid, self.sys.now, None)
            e.sig = self.signer.sign(e.body())
            self.sys.ledger.submit(e)
        return out
