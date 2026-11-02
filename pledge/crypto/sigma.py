"""Purpose-of-use privacy: exponential ElGamal in G1 plus a Fiat-Shamir CDS OR-proof.

A clinician encrypts its purpose code m to the patient's key P and the
regulator's key R:

    c = (a1, b1, a2, b2) = (g^r1, P^r1 g^m, g^r2, R^r2 g^m)

and proves, without revealing m, that both halves encrypt the *same* m and
that m is in the allowed set from the consent side record. Chaincode verifies
the proof; validators never learn the purpose.
"""
from dataclasses import dataclass

from .pairing import (
    fr_rand, fr_int, fr_add, fr_sub, fr_mul, fr_hash, fr_eq, fr_bytes,
    g1_pow, g1_mul, g1_add, g1_neg, g1_eq, g1_bytes, G1_GEN,
)

# HL7 v3 PurposeOfUse codes used by PLEDGE (subset)
PURPOSES = {"TREAT": 1, "ETREAT": 2, "HPAYMT": 3, "HOPERAT": 4, "HRESCH": 5, "PUBHLTH": 6, "PATRQT": 7}
PURPOSE_NAMES = {v: k for k, v in PURPOSES.items()}


@dataclass
class ElGamalKey:
    x: object

    @classmethod
    def generate(cls):
        return cls(fr_rand())

    @property
    def pk(self):
        return g1_pow(self.x)

    def decrypt_small(self, a, b, domain=PURPOSES.values()):
        mg = g1_add(b, g1_neg(g1_mul(a, self.x)))       # b / a^x = g^m
        for m in domain:
            if g1_eq(mg, g1_pow(fr_int(m))):
                return m
        return None


@dataclass
class PurposeProof:
    branches: list        # [(c_j, s1_j, s2_j)] aligned with `allowed`


def _sub_mg(b, m):
    return g1_add(b, g1_neg(g1_pow(fr_int(m))))


def _commitments(ct, P, R, m, c, s1, s2):
    a1, b1, a2, b2 = ct
    return (g1_add(g1_pow(s1), g1_neg(g1_mul(a1, c))),
            g1_add(g1_mul(P, s1), g1_neg(g1_mul(_sub_mg(b1, m), c))),
            g1_add(g1_pow(s2), g1_neg(g1_mul(a2, c))),
            g1_add(g1_mul(R, s2), g1_neg(g1_mul(_sub_mg(b2, m), c))))


def _challenge(ctx, ct, P, R, allowed, Ts):
    buf = [b"PLEDGE|purpose|", ctx, g1_bytes(P), g1_bytes(R)]
    buf += [g1_bytes(e) for e in ct]
    buf += [",".join(str(int(m)) for m in sorted(allowed)).encode()]
    for T in Ts:
        buf += [g1_bytes(e) for e in T]
    return fr_hash(b"".join(buf))


def encrypt_purpose(m: int, P, R, allowed, ctx: bytes):
    allowed = list(allowed)
    if m not in allowed:
        raise ValueError("purpose not allowed by consent")
    r1, r2 = fr_rand(), fr_rand()
    ct = (g1_pow(r1), g1_add(g1_mul(P, r1), g1_pow(fr_int(m))),
          g1_pow(r2), g1_add(g1_mul(R, r2), g1_pow(fr_int(m))))
    real = allowed.index(m)
    k1, k2 = fr_rand(), fr_rand()
    sims, Ts = {}, []
    for j, mj in enumerate(allowed):
        if j == real:
            Ts.append((g1_pow(k1), g1_mul(P, k1), g1_pow(k2), g1_mul(R, k2)))
        else:
            cj, s1, s2 = fr_rand(), fr_rand(), fr_rand()
            sims[j] = (cj, s1, s2)
            Ts.append(_commitments(ct, P, R, mj, cj, s1, s2))
    c = _challenge(ctx, ct, P, R, allowed, Ts)
    ci = c
    for cj, _, _ in sims.values():
        ci = fr_sub(ci, cj)
    branches = []
    for j in range(len(allowed)):
        if j == real:
            branches.append((ci, fr_add(k1, fr_mul(ci, r1)), fr_add(k2, fr_mul(ci, r2))))
        else:
            branches.append(sims[j])
    return ct, PurposeProof(branches)


def verify_purpose(ct, proof: PurposeProof, P, R, allowed, ctx: bytes) -> bool:
    allowed = list(allowed)
    if len(proof.branches) != len(allowed):
        return False
    Ts, csum = [], None
    for mj, (cj, s1, s2) in zip(allowed, proof.branches):
        Ts.append(_commitments(ct, P, R, mj, cj, s1, s2))
        csum = cj if csum is None else fr_add(csum, cj)
    return fr_eq(csum, _challenge(ctx, ct, P, R, allowed, Ts))


def ct_bytes(ct) -> bytes:
    return b"".join(g1_bytes(e) for e in ct)


def proof_bytes(p: PurposeProof) -> bytes:
    return b"".join(fr_bytes(c) + fr_bytes(a) + fr_bytes(b) for c, a, b in p.branches)
