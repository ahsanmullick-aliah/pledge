"""Simulated national health-ID registries (paper Section 5.2).

Modelled on India's Ayushman Bharat Digital Mission (ABDM):

  HealthIdProvider       ABHA numbers (14 digits); authenticates a person with a
                         one-time password and signs an assertion of the health ID
  ProfessionalRegistry   HPR IDs (14 digits) for professionals whose record the
                         council and the state verifier have checked
  FacilityRegistry       HFR IDs (12 digits) for health facilities

Assertions are BLS signatures over the canonical digest used by the ledger, bound
to a caller-chosen nonce so that a captured assertion cannot be replayed to a
different registration. The real ABDM APIs differ; only their trust role matters
here: a registry vouches that a person or facility is who they claim to be, and
never sees keys or records.
"""
import secrets
import time
from dataclasses import dataclass, field

from ..crypto import sig as bls
from ..ledger.chaincode import digest


@dataclass
class Assertion:
    kind: str            # "abha" | "hpr" | "hfr"
    subject: str         # the registry ID
    claims: dict         # e.g. {"status": "verified", "council": "NMC"}
    nonce: str
    ts: int
    sig: object = None

    def body(self) -> bytes:
        return digest("assert-" + self.kind, {"subject": self.subject, "claims": self.claims,
                                               "nonce": self.nonce, "ts": self.ts})


def _digits(n: int) -> str:
    return str(secrets.randbelow(9) + 1) + "".join(str(secrets.randbelow(10)) for _ in range(n - 1))


class _Registry:
    KIND = ""
    DIGITS = 14

    def __init__(self):
        self.signer = bls.SigningKey.generate()
        self.records = {}                       # id -> claims

    @property
    def vk(self):
        return self.signer.vk

    def _issue(self, subject, nonce):
        a = Assertion(self.KIND, subject, dict(self.records[subject]), nonce, int(time.time()))
        a.sig = self.signer.sign(a.body())
        return a

    def verify(self, a: Assertion, nonce: str, max_age: int = 600) -> bool:
        return (a.kind == self.KIND and a.nonce == nonce and abs(time.time() - a.ts) <= max_age
                and bls.verify(self.vk, a.body(), a.sig))


class HealthIdProvider(_Registry):
    """ABHA: enrolment and OTP-based authentication of a person."""
    KIND = "abha"

    def __init__(self):
        super().__init__()
        self._otp = {}                          # txn -> (abha, code)

    def enrol(self, name: str) -> str:
        abha = _digits(14)
        self.records[abha] = {"name": name, "status": "active"}
        return abha

    def request_otp(self, abha: str):
        """Sends a code to the registered mobile number; the simulation returns it
        so that the caller can play the person reading their phone."""
        if abha not in self.records:
            raise KeyError("unknown ABHA number")
        txn, code = secrets.token_hex(8), f"{secrets.randbelow(10**6):06d}"
        self._otp[txn] = (abha, code)
        return txn, code

    def verify_otp(self, txn: str, code: str, nonce: str) -> Assertion:
        abha, want = self._otp.pop(txn, (None, None))
        if abha is None or not secrets.compare_digest(code, want):
            raise PermissionError("OTP verification failed")
        return self._issue(abha, nonce)


class ProfessionalRegistry(_Registry):
    """HPR: professionals whose council registration the council and state verified."""
    KIND = "hpr"

    def register(self, name: str, council: str, reg_no: str, verified: bool = True) -> str:
        hpr = _digits(14)
        self.records[hpr] = {"name": name, "council": council, "reg_no": reg_no,
                             "status": "verified" if verified else "pending"}
        return hpr

    def assert_record(self, hpr: str, nonce: str) -> Assertion:
        return self._issue(hpr, nonce)


class FacilityRegistry(_Registry):
    KIND = "hfr"
    DIGITS = 12

    def register(self, name: str) -> str:
        hfr = _digits(12)
        self.records[hfr] = {"name": name, "status": "verified"}
        return hfr

    def assert_record(self, hfr: str, nonce: str) -> Assertion:
        return self._issue(hfr, nonce)


@dataclass
class ABDM:
    idp: HealthIdProvider = field(default_factory=HealthIdProvider)
    hpr: ProfessionalRegistry = field(default_factory=ProfessionalRegistry)
    hfr: FacilityRegistry = field(default_factory=FacilityRegistry)
