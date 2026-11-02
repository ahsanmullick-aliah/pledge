"""World state, transactions and the PLEDGE access chaincode.

Every check here is deterministic, so endorsing peers (before ordering) and
committing peers (after ordering) reach the same verdict on the same state.
Committing peers re-run the checks, which catches races such as a revocation
ordered before an already-endorsed access request.
"""
import hashlib
import json
from dataclasses import dataclass, field
from datetime import date, datetime, timezone

from ..crypto import sig as bls, sigma
from ..crypto.pairing import g2_load, g1_bytes, g1_load, fr_bytes, fr_load, g1_bytes as _g1b

CLOCK_SKEW = 300          # seconds a request timestamp may differ from ledger time


def H(*parts) -> bytes:
    """Local (Python-only) hash for block headers and record header hashes."""
    h = hashlib.sha256()
    for p in parts:
        h.update(p if isinstance(p, bytes) else str(p).encode())
        h.update(b"\x1f")
    return h.digest()


# ---------------- canonical wire format (shared with the Go chaincode) ----------------
#
# A transaction travels as JSON. Its *body* is the JSON object without the
# signature fields, serialized canonically (sorted keys, no whitespace, ASCII);
# the signed digest is SHA-256("PLEDGE|<kind>|" || body). The Go chaincode
# re-serializes the received object the same way, so both sides hash the same
# bytes. All binary values are lowercase hex strings.

SIG_FIELDS = ("sig", "cosig", "retire_sig")


def canon(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def digest(kind: str, body: dict) -> bytes:
    return hashlib.sha256(b"PLEDGE|" + kind.encode() + b"|" + canon(body)).digest()


def purpose_ctx(gid: str, tau: str, nonce: str) -> bytes:
    return digest("purpose-ctx", {"gid": gid, "tau": tau, "nonce": nonce})


def deny_tag(salt: bytes, gid: str, tau: str) -> str:
    return digest("deny", {"salt": salt.hex(), "gid": gid, "tau": tau}).hex()


def _sig_hex(s):
    return None if s is None else _g1b(s).hex()


# ---------------- transactions ----------------

@dataclass
class CredentialTx:
    gid: str
    vk: bytes                 # clinician BLS verification key (G2 bytes)
    aa: str
    sig: object = None
    KIND = "cred"

    def wire_body(self):
        return {"gid": self.gid, "vk": self.vk.hex(), "aa": self.aa}

    def body(self):
        return digest(self.KIND, self.wire_body())

    def to_wire(self):
        return {**self.wire_body(), "sig": _sig_hex(self.sig)}


@dataclass
class RevokeTx:
    gid: str
    aa: str
    sig: object = None
    KIND = "revoke"

    def wire_body(self):
        return {"gid": self.gid, "aa": self.aa}

    def body(self):
        return digest(self.KIND, self.wire_body())

    def to_wire(self):
        return {**self.wire_body(), "sig": _sig_hex(self.sig)}


@dataclass
class RecordTx:
    """Registers (or updates) a record tag tau with its header hash and side record."""
    tau: str
    header_hash: bytes
    purposes: list            # allowed purpose codes (ints)
    deny: list                # salted deny tags (hex)
    salt: bytes
    period: tuple             # (start ISO, end ISO) or Nones
    emergency: bool
    owner_vk: bytes           # per-record update key vk_tau (Section V-B), fixed at first registration
    patient_purpose_pk: object  # per-record G1 ElGamal key the purpose is encrypted to
    retires: str | None = None  # re-key: the old tag this registration retires (Section V-I)
    sig: object = None
    retire_sig: object = None   # signature by the old tag's update key over the same body
    KIND = "record"

    def wire_body(self):
        return {"tau": self.tau, "header_hash": self.header_hash.hex(),
                "purposes": sorted(int(p) for p in self.purposes), "deny": sorted(self.deny),
                "salt": self.salt.hex(), "period": [self.period[0], self.period[1]],
                "emergency": bool(self.emergency), "owner_vk": self.owner_vk.hex(),
                "patient_purpose_pk": g1_bytes(self.patient_purpose_pk).hex(),
                "retires": self.retires}

    def body(self):
        return digest(self.KIND, self.wire_body())

    def to_wire(self):
        return {**self.wire_body(), "sig": _sig_hex(self.sig), "retire_sig": _sig_hex(self.retire_sig)}


@dataclass
class PatientRegTx:
    """Reg_P (Section V-B): binds a salted pseudonym psi_P to the patient's keys,
    certified by the registering hospital's AA. rotate=True replaces a binding."""
    psi: str                  # hex of H(HID || s_P)
    box_pk: bytes             # patient's X25519 key (E_aud, W_p)
    vk: bytes                 # patient's BLS key vk_P (G2)
    expiry: str               # ISO date
    aa: str
    rotate: bool = False
    sig: object = None        # cert_P: signature by the AA
    KIND = "patient"

    def wire_body(self):
        return {"psi": self.psi, "box_pk": self.box_pk.hex(), "vk": self.vk.hex(),
                "expiry": self.expiry, "aa": self.aa, "rotate": bool(self.rotate)}

    def body(self):
        return digest(self.KIND, self.wire_body())

    def to_wire(self):
        return {**self.wire_body(), "sig": _sig_hex(self.sig)}


@dataclass
class AccessItem:
    tau: str
    purpose_ct: tuple         # ElGamal ciphertext (a1, b1, a2, b2) in G1
    proof: object             # sigma.PurposeProof
    aud_patient: bytes        # sealed (resource id, type, purpose) for the patient
    aud_regulator: bytes      # same, for the regulator

    def wire(self):
        return {"tau": self.tau,
                "purpose_ct": [g1_bytes(e).hex() for e in self.purpose_ct],
                "proof": [[fr_bytes(c).hex(), fr_bytes(a).hex(), fr_bytes(b).hex()]
                          for c, a, b in self.proof.branches],
                "aud_patient": self.aud_patient.hex(), "aud_regulator": self.aud_regulator.hex()}

    @classmethod
    def from_wire(cls, w):
        ct = tuple(g1_load(bytes.fromhex(x)) for x in w["purpose_ct"])
        pr = sigma.PurposeProof([tuple(fr_load(bytes.fromhex(x)) for x in b) for b in w["proof"]])
        return cls(w["tau"], ct, pr, bytes.fromhex(w["aud_patient"]), bytes.fromhex(w["aud_regulator"]))

    def size_bytes(self):
        return len(canon(self.wire())) // 2


@dataclass
class AccessTx:
    gid: str
    items: list               # [AccessItem], one per record (a bundle = several)
    ts: int
    nonce: str
    S: tuple                  # designated key-share services (size k)
    breakglass: bool = False
    cosigner: str | None = None
    retry_of: str | None = None
    sig: object = None
    cosig: object = None
    KIND = "access"

    def wire_body(self):
        return {"gid": self.gid, "items": [it.wire() for it in self.items], "ts": int(self.ts),
                "nonce": self.nonce, "S": [int(i) for i in sorted(self.S)],
                "breakglass": bool(self.breakglass), "cosigner": self.cosigner, "retry_of": self.retry_of}

    def body(self):
        return digest(self.KIND, self.wire_body())

    def to_wire(self):
        return {**self.wire_body(), "sig": _sig_hex(self.sig), "cosig": _sig_hex(self.cosig)}

    @classmethod
    def from_wire(cls, w):
        tx = cls(w["gid"], [AccessItem.from_wire(i) for i in w["items"]], w["ts"], w["nonce"],
                 tuple(w["S"]), w["breakglass"], w["cosigner"], w["retry_of"])
        tx.sig = g1_load(bytes.fromhex(w["sig"])) if w.get("sig") else None
        tx.cosig = g1_load(bytes.fromhex(w["cosig"])) if w.get("cosig") else None
        return tx

    @property
    def entry_id(self) -> str:
        return self.body().hex()

    def size_bytes(self):
        return len(canon(self.to_wire()))

    def ctx(self, tau: str) -> bytes:
        return purpose_ctx(self.gid, tau, self.nonce)


# ---------------- state ----------------

@dataclass
class WorldState:
    aa_keys: dict                         # aa name -> BLS vk (G2)
    regulator_purpose_pk: object          # G1
    n: int
    k: int
    credentials: dict = field(default_factory=dict)   # gid -> (vk G2, aa)
    revoked: set = field(default_factory=set)
    records: dict = field(default_factory=dict)       # tau -> RecordTx
    nonces: set = field(default_factory=set)
    entries: dict = field(default_factory=dict)       # entry_id -> (height, AccessTx)
    retired: set = field(default_factory=set)         # record tags retired by a re-key
    patients: dict = field(default_factory=dict)      # psi -> PatientRegTx (current binding)

    def snapshot(self):
        return WorldState(self.aa_keys, self.regulator_purpose_pk, self.n, self.k,
                          dict(self.credentials), set(self.revoked), dict(self.records),
                          set(self.nonces), dict(self.entries), set(self.retired), dict(self.patients))


class Reject(Exception):
    pass


def _in_period(now_day: date, period):
    s, e = period
    return (s is None or now_day >= date.fromisoformat(s[:10])) and (e is None or now_day <= date.fromisoformat(e[:10]))


def check(state: WorldState, tx, now: int):
    """Raises Reject(reason) if `tx` is invalid on `state` at ledger time `now` (unix seconds)."""
    if isinstance(tx, CredentialTx):
        vk = state.aa_keys.get(tx.aa)
        if vk is None or not bls.verify(vk, tx.body(), tx.sig):
            raise Reject("credential not signed by a known authority")
        if tx.gid in state.credentials:
            raise Reject("GID already registered")
        return
    if isinstance(tx, RevokeTx):
        vk = state.aa_keys.get(tx.aa)
        if vk is None or not bls.verify(vk, tx.body(), tx.sig):
            raise Reject("revocation not signed by a known authority")
        if tx.gid not in state.credentials:
            raise Reject("unknown GID")
        return
    if isinstance(tx, PatientRegTx):
        vk = state.aa_keys.get(tx.aa)
        if vk is None or not bls.verify(vk, tx.body(), tx.sig):
            raise Reject("patient registration not certified by a known authority")
        if tx.rotate and tx.psi not in state.patients:
            raise Reject("rotation for an unregistered patient")
        if not tx.rotate and tx.psi in state.patients:
            raise Reject("patient pseudonym already bound")
        return
    if isinstance(tx, RecordTx):
        prev = state.records.get(tx.tau)
        if tx.tau in state.retired:
            raise Reject("record tag retired by a re-key")
        owner = prev.owner_vk if prev else tx.owner_vk
        if not bls.verify(g2_load(owner), tx.body(), tx.sig):
            raise Reject("record update not signed by its owner")
        if tx.retires is not None and tx.retires == tx.tau:
            if prev is None:                       # retire without successor: owner-signed above
                raise Reject("unknown record tag")
        elif tx.retires is not None:
            old = state.records.get(tx.retires)
            if prev is not None or old is None:
                raise Reject("a re-key must register a new tag and retire an existing one")
            if tx.retires in state.retired:
                raise Reject("record tag already retired")
            if not bls.verify(g2_load(old.owner_vk), tx.body(), tx.retire_sig):
                raise Reject("retirement not signed by the old tag's owner")
        return
    if isinstance(tx, AccessTx):
        _check_access(state, tx, now)
        return
    raise Reject("unknown transaction type")


def _clinician_ok(state, gid):
    if gid not in state.credentials:
        raise Reject(f"unregistered clinician {gid}")
    if gid in state.revoked:
        raise Reject(f"revoked clinician {gid}")
    return state.credentials[gid][0]


def _check_access(state: WorldState, tx: AccessTx, now: int):
    vk = _clinician_ok(state, tx.gid)
    body = tx.body()
    if not bls.verify(vk, body, tx.sig):
        raise Reject("bad clinician signature")
    if abs(tx.ts - now) > CLOCK_SKEW:
        raise Reject("stale or future timestamp")
    if (tx.gid, tx.nonce) in state.nonces:
        raise Reject("replayed nonce")
    S = tuple(tx.S)
    if len(set(S)) != state.k or not all(1 <= i <= state.n for i in S):
        raise Reject("designated set S must name k distinct services")
    if tx.retry_of is not None:
        prev = state.entries.get(tx.retry_of)
        if prev is None or prev[1].gid != tx.gid:
            raise Reject("retry must reference the clinician's own committed entry")
    if tx.breakglass:
        if not tx.cosigner or tx.cosigner == tx.gid:
            raise Reject("break-glass needs a second clinician")
        cvk = _clinician_ok(state, tx.cosigner)
        if not bls.verify(cvk, body, tx.cosig):
            raise Reject("bad co-signature")
    if not tx.items:
        raise Reject("empty request")
    today = datetime.fromtimestamp(now, tz=timezone.utc).date()   # UTC, as in the Go chaincode
    for it in tx.items:
        rec = state.records.get(it.tau)
        if rec is None:
            raise Reject(f"unknown record tag {it.tau[:8]}")
        if it.tau in state.retired:
            raise Reject("record tag retired by a re-key")
        if deny_tag(rec.salt, tx.gid, it.tau) in rec.deny:
            raise Reject("clinician is on the record's deny list")
        if tx.breakglass:
            if not rec.emergency:
                raise Reject("patient opted out of emergency access")
            allowed = [sigma.PURPOSES["ETREAT"]]
        else:
            if not _in_period(today, rec.period):
                raise Reject("outside the consent period")
            allowed = rec.purposes
        if not sigma.verify_purpose(it.purpose_ct, it.proof, rec.patient_purpose_pk,
                                    state.regulator_purpose_pk, allowed, tx.ctx(it.tau)):
            raise Reject("purpose proof invalid or purpose not allowed")


def apply(state: WorldState, tx, height: int):
    if isinstance(tx, CredentialTx):
        state.credentials[tx.gid] = (g2_load(tx.vk), tx.aa)
    elif isinstance(tx, RevokeTx):
        state.revoked.add(tx.gid)
    elif isinstance(tx, PatientRegTx):
        state.patients[tx.psi] = tx
    elif isinstance(tx, RecordTx):
        prev = state.records.get(tx.tau)
        if prev is not None:
            tx.owner_vk = prev.owner_vk
        state.records[tx.tau] = tx
        if tx.retires is not None:
            state.retired.add(tx.retires)
    elif isinstance(tx, AccessTx):
        state.nonces.add((tx.gid, tx.nonce))
        state.entries[tx.entry_id] = (height, tx)


def tx_digest(tx) -> bytes:
    return tx.body()
