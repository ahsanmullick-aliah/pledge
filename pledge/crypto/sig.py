"""BLS signatures on BLS12-381 (signatures in G1, public keys in G2).

Used for clinicians' access entries, authority postings and BFT votes.
"""
from dataclasses import dataclass

from .pairing import fr_rand, g1_hash, g1_mul, g1_neg, g2_pow, multi_pairing, G2_GEN, g2_bytes, g1_bytes
from ._mcl_base import _lib  # noqa: F401  (ensures library is initialised)


def _hm(msg: bytes):
    return g1_hash(b"PLEDGE|SIG|" + msg)


@dataclass
class SigningKey:
    sk: object

    @classmethod
    def generate(cls):
        return cls(fr_rand())

    @property
    def vk(self):
        return g2_pow(self.sk)

    @property
    def vk_bytes(self) -> bytes:
        return g2_bytes(self.vk)

    def sign(self, msg: bytes):
        return g1_mul(_hm(msg), self.sk)


def verify(vk, msg: bytes, sig) -> bool:
    # e(sig, g2) == e(H(m), vk)  <=>  e(sig, g2) * e(-H(m), vk) == 1
    from .pairing import gt_eq, gt_one
    try:
        return gt_eq(multi_pairing([sig, g1_neg(_hm(msg))], [G2_GEN, vk]), gt_one())
    except Exception:
        return False


def sig_bytes(sig) -> bytes:
    return g1_bytes(sig)
