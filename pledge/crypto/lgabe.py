"""Ledger-gated multi-authority ABE: the threshold ledger authority theta*.

theta* owns every access attribute ``acc:<tau>``. Its secret (alpha*, y*) is
Shamir-shared among the n key-share services (KSS) with threshold k = f + 1,
created by a dealer-free Feldman-style DKG (commitments in GT for alpha and in
G2 for y). A KSS releases its partial key only for a committed, valid access
entry (enforced by the ledger layer, not here).

  ShareGen   : K_i = g1^{L_iS alpha_i} H(GID)^{L_iS y_i} F(acc:tau)^{t_i},  K'_i = g2^{t_i}
  ShareVerify: e(K_i, g2) = ( e(g1,g2)^{alpha_i} )^{L_iS} * e(H(GID)^{L_iS}, g2^{y_i}) * e(F(acc:tau), K'_i)
  Combine    : K = prod K_i, K' = prod K'_i  -> a normal RW15 key with t = sum t_i
"""
from dataclasses import dataclass, field

from .pairing import (
    fr_rand, fr_int, fr_add, fr_mul, fr_zero, fr_neg, gt_pow, gt_mul, gt_one, gt_eq,
    g1_pow, g1_mul, g1_add, g2_pow, g2_mul, g2_add, g2_eq, g2_identity, g1_neg,
    multi_pairing, lagrange_at_zero, H_gid, F_attr, E_GG, G2_GEN,
)
from .rw15 import AuthorityPK

LEDGER_AUTHORITY = "ledger"
ACC_PREFIX = "acc:"


EACC_PREFIX = "eacc:"


def access_attr(tau: str) -> str:
    return ACC_PREFIX + tau


def emergency_attr(tau: str) -> str:
    """Access attribute of the break-glass branch; issued only for break-glass entries."""
    return EACC_PREFIX + tau


def is_ledger_attr(attr: str) -> bool:
    return attr.startswith(ACC_PREFIX) or attr.startswith(EACC_PREFIX)


# ---------------- DKG ----------------

def _poly(k):
    return [fr_rand() for _ in range(k)]


def _eval(coeffs, x: int):
    acc, xp = fr_zero(), fr_int(1)
    for c in coeffs:
        acc = fr_add(acc, fr_mul(c, xp))
        xp = fr_mul(xp, fr_int(x))
    return acc


@dataclass
class KSSSecret:
    index: int          # 1..n
    alpha: object       # alpha_i
    y: object           # y_i


@dataclass
class LedgerPublic:
    n: int
    k: int
    pk: AuthorityPK                         # (e(g1,g2)^alpha*, g2^y*)
    vk: dict = field(default_factory=dict)  # i -> (e(g1,g2)^alpha_i, g2^y_i)


class DKGError(Exception):
    pass


def run_dkg(n: int, k: int, cheaters=()):
    """Simulates the DKG among n services. Dealers in `cheaters` hand out bad
    shares; honest receivers detect them against the commitments and the
    dealer is excluded from the qualified set (QUAL)."""
    if not 1 <= k <= n:
        raise DKGError("need 1 <= k <= n")
    deals = {}
    for j in range(1, n + 1):
        a, b = _poly(k), _poly(k)
        CA = [gt_pow(E_GG, c) for c in a]
        CB = [g2_pow(c) for c in b]
        shares = {i: (_eval(a, i), _eval(b, i)) for i in range(1, n + 1)}
        if j in cheaters:
            shares[1] = (fr_rand(), shares[1][1])     # corrupt one share
        deals[j] = (CA, CB, shares)

    def ok(CA, CB, i, sa, sb):
        ea, eb = gt_one(), g2_identity()
        ip = fr_int(1)
        for ca, cb in zip(CA, CB):
            ea = gt_mul(ea, gt_pow(ca, ip))
            eb = g2_add(eb, g2_mul(cb, ip))
            ip = fr_mul(ip, fr_int(i))
        return gt_eq(gt_pow(E_GG, sa), ea) and g2_eq(g2_pow(sb), eb)

    qual = [j for j, (CA, CB, sh) in deals.items()
            if all(ok(CA, CB, i, *sh[i]) for i in range(1, n + 1))]
    if len(qual) < k:
        raise DKGError("too few qualified dealers")

    secrets = []
    for i in range(1, n + 1):
        sa, sb = fr_zero(), fr_zero()
        for j in qual:
            sa = fr_add(sa, deals[j][2][i][0])
            sb = fr_add(sb, deals[j][2][i][1])
        secrets.append(KSSSecret(i, sa, sb))

    # aggregate commitments -> public key and per-node verification keys
    CA = [gt_one() for _ in range(k)]
    CB = [g2_identity() for _ in range(k)]
    for j in qual:
        for l in range(k):
            CA[l] = gt_mul(CA[l], deals[j][0][l])
            CB[l] = g2_add(CB[l], deals[j][1][l])
    pub = LedgerPublic(n, k, AuthorityPK(LEDGER_AUTHORITY, CA[0], CB[0]))
    for i in range(1, n + 1):
        ea, eb, ip = gt_one(), g2_identity(), fr_int(1)
        for l in range(k):
            ea = gt_mul(ea, gt_pow(CA[l], ip))
            eb = g2_add(eb, g2_mul(CB[l], ip))
            ip = fr_mul(ip, fr_int(i))
        pub.vk[i] = (ea, eb)
    return pub, secrets, qual


# ---------------- partial keys ----------------

@dataclass
class PartialKey:
    index: int
    S: tuple
    gid: str
    attr: str
    K: object
    Kp: object


def share_gen(sec: KSSSecret, gid: str, attr: str, S) -> PartialKey:
    S = tuple(sorted(S))
    if sec.index not in S:
        raise ValueError("service not in the designated set S")
    L = lagrange_at_zero(sec.index, S)
    t = fr_rand()
    K = g1_add(g1_add(g1_pow(fr_mul(L, sec.alpha)), g1_mul(H_gid(gid), fr_mul(L, sec.y))),
               g1_mul(F_attr(attr), t))
    return PartialKey(sec.index, S, gid, attr, K, g2_pow(t))


def share_verify(pub: LedgerPublic, pk: PartialKey) -> bool:
    if pk.index not in pk.S or len(set(pk.S)) != pub.k:
        return False
    e_alpha_i, g2_y_i = pub.vk[pk.index]
    L = lagrange_at_zero(pk.index, pk.S)
    # e(K_i, g2) * e(H^{-L}, g2^{y_i}) * e(F^{-1}, K'_i) == (e(g1,g2)^{alpha_i})^L
    lhs = multi_pairing(
        [pk.K, g1_neg(g1_mul(H_gid(pk.gid), L)), g1_neg(F_attr(pk.attr))],
        [G2_GEN, g2_y_i, pk.Kp])
    return gt_eq(lhs, gt_pow(e_alpha_i, L))


class CombineError(Exception):
    pass


def combine(pub: LedgerPublic, parts, verify=True):
    """Combine k partial keys for the same (GID, attr, S) into an RW15 key component."""
    if not parts:
        raise CombineError("no partial keys")
    S, gid, attr = parts[0].S, parts[0].gid, parts[0].attr
    idx = sorted(p.index for p in parts)
    if tuple(idx) != S or len(idx) != pub.k:
        raise CombineError("partial keys do not cover the designated set S")
    for p in parts:
        if (p.S, p.gid, p.attr) != (S, gid, attr):
            raise CombineError("partial keys are for different requests")
        if verify and not share_verify(pub, p):
            raise CombineError(f"invalid partial key from service {p.index}")
    K, Kp = parts[0].K, parts[0].Kp
    for p in parts[1:]:
        K, Kp = g1_add(K, p.K), g2_add(Kp, p.Kp)
    return K, Kp
