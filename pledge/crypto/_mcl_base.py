"""Thin ctypes wrapper around herumi/mcl (BLS12-381, Type-3 pairing).

Only the operations the schemes need. Every value is a ctypes struct;
helpers return new objects so code reads like math.
"""
import ctypes, os, hashlib

_DIR = os.path.dirname(os.path.abspath(__file__))
if os.name == "nt":                          # Windows: mcl.dll (statically linked, no other DLLs needed)
    os.add_dll_directory(_DIR)
    _lib = ctypes.CDLL(os.path.join(_DIR, "mcl.dll"))
else:
    _lib = ctypes.CDLL(os.path.join(_DIR, "libmcl.so"))

FP_UNIT, FR_UNIT = 6, 4                      # MCL_FP_BIT=384, MCL_FR_BIT=256
MCL_BLS12_381 = 5
COMPILED_TIME_VAR = FR_UNIT * 10 + FP_UNIT    # 46


class Fp(ctypes.Structure):
    _fields_ = [("d", ctypes.c_uint64 * FP_UNIT)]


class Fp2(ctypes.Structure):
    _fields_ = [("d", Fp * 2)]


class Fr(ctypes.Structure):
    _fields_ = [("d", ctypes.c_uint64 * FR_UNIT)]


class G1(ctypes.Structure):
    _fields_ = [("x", Fp), ("y", Fp), ("z", Fp)]


class G2(ctypes.Structure):
    _fields_ = [("x", Fp2), ("y", Fp2), ("z", Fp2)]


class GT(ctypes.Structure):
    _fields_ = [("d", Fp * 12)]


if _lib.mclBn_init(MCL_BLS12_381, COMPILED_TIME_VAR) != 0:
    raise RuntimeError("mclBn_init failed")

P = ctypes.POINTER
_lib.mclBnG1_serialize.restype = ctypes.c_size_t
_lib.mclBnG2_serialize.restype = ctypes.c_size_t
_lib.mclBnGT_serialize.restype = ctypes.c_size_t
_lib.mclBnFr_serialize.restype = ctypes.c_size_t
for f in ("mclBnG1_mulVec", "mclBnG2_mulVec", "mclBn_millerLoopVec", "mclBnGT_powVec"):
    getattr(_lib, f).restype = None

# ---------- Fr ----------

def fr_rand():
    x = Fr(); _lib.mclBnFr_setByCSPRNG(ctypes.byref(x)); return x

def fr_int(i):
    x = Fr(); _lib.mclBnFr_setInt(ctypes.byref(x), ctypes.c_int64(i)); return x

def fr_hash(b: bytes):
    x = Fr(); _lib.mclBnFr_setHashOf(ctypes.byref(x), b, len(b)); return x

def fr_add(a, b):
    z = Fr(); _lib.mclBnFr_add(ctypes.byref(z), ctypes.byref(a), ctypes.byref(b)); return z

def fr_sub(a, b):
    z = Fr(); _lib.mclBnFr_sub(ctypes.byref(z), ctypes.byref(a), ctypes.byref(b)); return z

def fr_mul(a, b):
    z = Fr(); _lib.mclBnFr_mul(ctypes.byref(z), ctypes.byref(a), ctypes.byref(b)); return z

def fr_neg(a):
    z = Fr(); _lib.mclBnFr_neg(ctypes.byref(z), ctypes.byref(a)); return z

def fr_inv(a):
    z = Fr(); _lib.mclBnFr_inv(ctypes.byref(z), ctypes.byref(a)); return z

def fr_eq(a, b):
    return bool(_lib.mclBnFr_isEqual(ctypes.byref(a), ctypes.byref(b)))

def fr_bytes(a):
    buf = ctypes.create_string_buffer(64); n = _lib.mclBnFr_serialize(buf, 64, ctypes.byref(a)); return buf.raw[:n]

# ---------- G1 / G2 ----------

def g1_hash(b: bytes):
    x = G1(); _lib.mclBnG1_hashAndMapTo(ctypes.byref(x), b, len(b)); return x

def g2_hash(b: bytes):
    x = G2(); _lib.mclBnG2_hashAndMapTo(ctypes.byref(x), b, len(b)); return x

def g1_mul(p, s):
    z = G1(); _lib.mclBnG1_mul(ctypes.byref(z), ctypes.byref(p), ctypes.byref(s)); return z

def g2_mul(p, s):
    z = G2(); _lib.mclBnG2_mul(ctypes.byref(z), ctypes.byref(p), ctypes.byref(s)); return z

def g1_add(a, b):
    z = G1(); _lib.mclBnG1_add(ctypes.byref(z), ctypes.byref(a), ctypes.byref(b)); return z

def g2_add(a, b):
    z = G2(); _lib.mclBnG2_add(ctypes.byref(z), ctypes.byref(a), ctypes.byref(b)); return z

def g1_neg(a):
    z = G1(); _lib.mclBnG1_neg(ctypes.byref(z), ctypes.byref(a)); return z

def g2_neg(a):
    z = G2(); _lib.mclBnG2_neg(ctypes.byref(z), ctypes.byref(a)); return z

def g1_eq(a, b):
    return bool(_lib.mclBnG1_isEqual(ctypes.byref(a), ctypes.byref(b)))

def g1_mulvec(points, scalars):
    n = len(points)
    if n == 0:
        raise ValueError("empty mulVec")
    pa = (G1 * n)(*points); sa = (Fr * n)(*scalars); z = G1()
    _lib.mclBnG1_mulVec(ctypes.byref(z), pa, sa, ctypes.c_size_t(n)); return z

def g1_bytes(a):
    buf = ctypes.create_string_buffer(128); n = _lib.mclBnG1_serialize(buf, 128, ctypes.byref(a)); return buf.raw[:n]

def g2_bytes(a):
    buf = ctypes.create_string_buffer(256); n = _lib.mclBnG2_serialize(buf, 256, ctypes.byref(a)); return buf.raw[:n]

# ---------- GT ----------

def pairing(p, q):
    z = GT(); _lib.mclBn_pairing(ctypes.byref(z), ctypes.byref(p), ctypes.byref(q)); return z

def multi_pairing(g1s, g2s):
    """prod_i e(g1s[i], g2s[i]) with one shared final exponentiation."""
    n = len(g1s)
    a = (G1 * n)(*g1s); b = (G2 * n)(*g2s); ml = GT(); z = GT()
    _lib.mclBn_millerLoopVec(ctypes.byref(ml), a, b, ctypes.c_size_t(n))
    _lib.mclBn_finalExp(ctypes.byref(z), ctypes.byref(ml)); return z

def gt_mul(a, b):
    z = GT(); _lib.mclBnGT_mul(ctypes.byref(z), ctypes.byref(a), ctypes.byref(b)); return z

def gt_inv(a):
    z = GT(); _lib.mclBnGT_inv(ctypes.byref(z), ctypes.byref(a)); return z

def gt_pow(a, s):
    z = GT(); _lib.mclBnGT_pow(ctypes.byref(z), ctypes.byref(a), ctypes.byref(s)); return z

def gt_eq(a, b):
    return bool(_lib.mclBnGT_isEqual(ctypes.byref(a), ctypes.byref(b)))

def gt_one():
    z = GT(); _lib.mclBnGT_setInt(ctypes.byref(z), 1); return z

def gt_bytes(a):
    buf = ctypes.create_string_buffer(1024); n = _lib.mclBnGT_serialize(buf, 1024, ctypes.byref(a)); return buf.raw[:n]

def gt_kdf(a, label=b"PLEDGE-KEM"):
    return hashlib.sha256(label + gt_bytes(a)).digest()

# generators (hash-derived so they are fixed and nothing-up-my-sleeve for this prototype)
G1_GEN = g1_hash(b"PLEDGE generator G1")
G2_GEN = g2_hash(b"PLEDGE generator G2")
E_GG = pairing(G1_GEN, G2_GEN)

SIZES = {"G1": len(g1_bytes(G1_GEN)), "G2": len(g2_bytes(G2_GEN)),
         "GT": len(gt_bytes(E_GG)), "Fr": len(fr_bytes(fr_int(1)))}
