"""BLS12-381 group operations used by PLEDGE (Type-3 pairing e: G1 x G2 -> GT).

Thin layer over herumi/mcl through ctypes (see _mcl_base.py). Everything the
schemes need lives here so the rest of the code reads like the paper's math.

Conventions
-----------
* Hashes H(GID) and F(attribute) map into G1 with domain separation.
* Public generator g1 in G1, g2 in G2, e(g1, g2) = E_GG.
"""
import ctypes

from . import _mcl_base as _b
from ._mcl_base import (  # re-export the primitives that already exist
    Fr, G1, G2, GT, fr_rand, fr_int, fr_hash, fr_add, fr_sub, fr_mul, fr_neg,
    fr_inv, fr_eq, fr_bytes, g1_hash, g2_hash, g1_mul, g2_mul, g1_add, g2_add,
    g1_neg, g2_neg, g1_eq, g1_mulvec, g1_bytes, g2_bytes, pairing,
    multi_pairing, gt_mul, gt_inv, gt_pow, gt_eq, gt_one, gt_bytes, gt_kdf,
    G1_GEN, G2_GEN, E_GG, SIZES,
)

_lib = _b._lib
_byref = ctypes.byref

for _f, _r in (("mclBnFr_isZero", ctypes.c_int), ("mclBnG2_isEqual", ctypes.c_int),
               ("mclBnG1_deserialize", ctypes.c_size_t), ("mclBnG2_deserialize", ctypes.c_size_t),
               ("mclBnGT_deserialize", ctypes.c_size_t), ("mclBnFr_deserialize", ctypes.c_size_t)):
    getattr(_lib, _f).restype = _r


# ---------- scalars ----------

def fr_zero():
    return fr_int(0)


def fr_one():
    return fr_int(1)


def fr_is_zero(a):
    return bool(_lib.mclBnFr_isZero(_byref(a)))


def fr_from_bytes(b: bytes):
    """Deterministic map from arbitrary bytes into Z_p (little-endian, reduced)."""
    x = Fr()
    _lib.mclBnFr_setLittleEndianMod(_byref(x), b, len(b))
    return x


def fr_sum(xs):
    z = fr_zero()
    for x in xs:
        z = fr_add(z, x)
    return z


def fr_load(b: bytes):
    x = Fr()
    if _lib.mclBnFr_deserialize(_byref(x), b, len(b)) == 0:
        raise ValueError("bad Fr encoding")
    return x


# ---------- G1 / G2 ----------

def H_gid(gid: str) -> G1:
    """H(GID): binds every key component of one user together (collusion resistance)."""
    return g1_hash(b"PLEDGE|H|" + gid.encode())


def F_attr(attr: str) -> G1:
    """F(u): large-universe attribute hash."""
    return g1_hash(b"PLEDGE|F|" + attr.encode())


def g1_pow(s):
    return g1_mul(G1_GEN, s)


def g2_pow(s):
    return g2_mul(G2_GEN, s)


def g1_identity():
    return g1_mul(G1_GEN, fr_zero())


def g2_identity():
    return g2_mul(G2_GEN, fr_zero())


def g2_eq(a, b):
    return bool(_lib.mclBnG2_isEqual(_byref(a), _byref(b)))


def g1_prod(points):
    z = g1_identity()
    for p in points:
        z = g1_add(z, p)
    return z


def g2_prod(points):
    z = g2_identity()
    for p in points:
        z = g2_add(z, p)
    return z


def g1_load(b: bytes):
    x = G1()
    if _lib.mclBnG1_deserialize(_byref(x), b, len(b)) == 0:
        raise ValueError("bad G1 encoding")
    return x


def g2_load(b: bytes):
    x = G2()
    if _lib.mclBnG2_deserialize(_byref(x), b, len(b)) == 0:
        raise ValueError("bad G2 encoding")
    return x


def gt_load(b: bytes):
    x = GT()
    if _lib.mclBnGT_deserialize(_byref(x), b, len(b)) == 0:
        raise ValueError("bad GT encoding")
    return x


# ---------- GT ----------

def gt_rand():
    """Uniform element of the target subgroup: e(g1,g2)^r."""
    return gt_pow(E_GG, fr_rand())


def gt_div(a, b):
    return gt_mul(a, gt_inv(b))


def gt_prod(xs):
    z = gt_one()
    for x in xs:
        z = gt_mul(z, x)
    return z


def lagrange_at_zero(i: int, S):
    """L_{i,S}(0) = prod_{j in S, j != i} j / (j - i) over Z_p (party indices are 1..n)."""
    num, den = fr_one(), fr_one()
    for j in S:
        if j == i:
            continue
        num = fr_mul(num, fr_int(j))
        den = fr_mul(den, fr_sub(fr_int(j), fr_int(i)))
    return fr_mul(num, fr_inv(den))
