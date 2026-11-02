"""Rouselakis-Waters (FC 2015) decentralized, large-universe CP-ABE on a Type-3 pairing.

Asymmetric placement (keys in G1, ciphertext randomness in G2):

  AuthSetup : PK_theta = ( e(g1,g2)^alpha , g2^y ),  SK_theta = (alpha, y)
  KeyGen    : K = g1^alpha * H(GID)^y * F(u)^t  in G1,   K' = g2^t  in G2
  Encrypt   : C0   = M * e(g1,g2)^z
              C1,x = e(g1,g2)^{lambda_x} * e(g1,g2)^{alpha_d(x) t_x}
              C2,x = g2^{-t_x}
              C3,x = (g2^{y_d(x)})^{t_x} * g2^{omega_x}
              C4,x = F(rho(x))^{t_x}
  Decrypt   : D_x = C1,x e(K,C2,x) e(H(GID),C3,x) e(C4,x,K')
                  = e(g1,g2)^{lambda_x} e(H(GID),g2)^{omega_x}
              prod_x D_x^{c_x} = e(g1,g2)^z

Group operations in mcl are written additively (g1_add = group product,
g1_mul(P, s) = P^s); comments use the paper's multiplicative notation.
"""
from dataclasses import dataclass, field

from . import lsss as _lsss
from .pairing import (
    fr_rand, fr_zero, fr_neg, fr_inv, g1_mul, g1_add, g2_mul, g2_add, g2_pow, g1_pow,
    pairing, multi_pairing, gt_mul, gt_pow, gt_div, gt_prod, G2_GEN, E_GG,
    H_gid, F_attr, g1_bytes, g2_bytes, gt_bytes, SIZES,
)


# ---------------- keys ----------------

@dataclass
class AuthorityPK:
    name: str
    e_alpha: object      # e(g1,g2)^alpha  in GT
    g2_y: object         # g2^y            in G2


@dataclass
class Authority:
    name: str
    alpha: object
    y: object

    @classmethod
    def setup(cls, name: str) -> "Authority":
        return cls(name, fr_rand(), fr_rand())

    @property
    def pk(self) -> AuthorityPK:
        return AuthorityPK(self.name, gt_pow(E_GG, self.alpha), g2_pow(self.y))

    def keygen(self, gid: str, attr: str):
        """One key component for attribute `attr` owned by this authority."""
        t = fr_rand()
        K = g1_add(g1_add(g1_pow(self.alpha), g1_mul(H_gid(gid), self.y)), g1_mul(F_attr(attr), t))
        return K, g2_pow(t)


@dataclass
class UserKey:
    gid: str
    comps: dict = field(default_factory=dict)   # attr -> (K in G1, K' in G2)

    def add(self, attr, comp):
        self.comps[attr] = comp
        return self

    @property
    def attrs(self):
        return set(self.comps)


# ---------------- ciphertext ----------------

@dataclass
class Ciphertext:
    policy: str
    C0: object
    rows: list                     # [(C1, C2, C3, C4)] aligned with lsss rows
    _lsss: object = field(default=None, repr=False, compare=False)

    @property
    def matrix(self):
        if self._lsss is None:
            self._lsss = _lsss.build(self.policy)
        return self._lsss

    def size_bytes(self) -> int:
        n = len(self.rows)
        return SIZES["GT"] * (1 + n) + 2 * SIZES["G2"] * n + SIZES["G1"] * n

    def serialize(self) -> bytes:
        out = [self.policy.encode(), gt_bytes(self.C0)]
        for c1, c2, c3, c4 in self.rows:
            out += [gt_bytes(c1), g2_bytes(c2), g2_bytes(c3), g1_bytes(c4)]
        return b"|".join(out)


def encrypt(M, policy: str, pks: dict, owner) -> Ciphertext:
    """Encrypt GT element M under `policy`.

    pks   : authority name -> AuthorityPK
    owner : attribute -> authority name  (the map T in the paper)
    """
    A = _lsss.build(policy)
    z = fr_rand()
    v = [z] + [fr_rand() for _ in range(A.cols - 1)]
    w = [fr_zero()] + [fr_rand() for _ in range(A.cols - 1)]
    lam, omg = A.shares(v), A.shares(w)
    rows = []
    for x, attr in enumerate(A.rho):
        pk = pks[owner(attr)]
        t = fr_rand()
        C1 = gt_mul(gt_pow(E_GG, lam[x]), gt_pow(pk.e_alpha, t))
        C2 = g2_mul(G2_GEN, fr_neg(t))
        C3 = g2_add(g2_mul(pk.g2_y, t), g2_pow(omg[x]))
        C4 = g1_mul(F_attr(attr), t)
        rows.append((C1, C2, C3, C4))
    return Ciphertext(policy, gt_mul(M, gt_pow(E_GG, z)), rows, A)


class NotSatisfied(Exception):
    pass


def _selected(ct: Ciphertext, attrs):
    sel = ct.matrix.solve(attrs)
    if sel is None:
        raise NotSatisfied(f"attributes do not satisfy {ct.policy}")
    return sorted(sel)            # all coefficients are 1 (Lewko-Waters matrix)


def decrypt(ct: Ciphertext, key: UserKey):
    rows = _selected(ct, key.attrs)
    H = H_gid(key.gid)
    g1s, g2s, c1s = [], [], []
    C3_sum = None
    for x in rows:
        C1, C2, C3, C4 = ct.rows[x]
        K, Kp = key.comps[ct.matrix.rho[x]]
        g1s += [K, C4]
        g2s += [C2, Kp]
        C3_sum = C3 if C3_sum is None else g2_add(C3_sum, C3)
        c1s.append(C1)
    g1s.append(H)
    g2s.append(C3_sum)                 # e(H, prod C3_x) = prod e(H, C3_x)
    egg_z = gt_mul(gt_prod(c1s), multi_pairing(g1s, g2s))
    return gt_div(ct.C0, egg_z)


# ---------------- outsourced decryption (Green-Hohenberger-Waters style) ----------------

@dataclass
class TransformKey:
    gid: str
    H_z: object                     # H(GID)^{1/z}
    comps: dict                     # attr -> (K^{1/z}, K'^{1/z})

    @property
    def attrs(self):
        return set(self.comps)


def make_transform_key(key: UserKey):
    """Returns (TK for the proxy, retrieval secret z kept by the user)."""
    z = fr_rand()
    zi = fr_inv(z)
    comps = {a: (g1_mul(K, zi), g2_mul(Kp, zi)) for a, (K, Kp) in key.comps.items()}
    return TransformKey(key.gid, g1_mul(H_gid(key.gid), zi), comps), z


def transform(ct: Ciphertext, tk: TransformKey):
    """Proxy side: returns (A, T) with A * T^z = e(g1,g2)^s. Learns nothing about M."""
    rows = _selected(ct, tk.attrs)
    g1s, g2s, c1s, C3_sum = [], [], [], None
    for x in rows:
        C1, C2, C3, C4 = ct.rows[x]
        K, Kp = tk.comps[ct.matrix.rho[x]]
        g1s += [K, C4]
        g2s += [C2, Kp]
        C3_sum = C3 if C3_sum is None else g2_add(C3_sum, C3)
        c1s.append(C1)
    g1s.append(tk.H_z)
    g2s.append(C3_sum)
    return gt_prod(c1s), multi_pairing(g1s, g2s)


def finish(ct: Ciphertext, partial, z):
    """User side: one GT exponentiation."""
    A, T = partial
    return gt_div(ct.C0, gt_mul(A, gt_pow(T, z)))


# ---------------- serialization (for the FHIR store) ----------------

def ct_to_dict(ct: Ciphertext) -> dict:
    return {"policy": ct.policy, "C0": gt_bytes(ct.C0).hex(),
            "rows": [[gt_bytes(c1).hex(), g2_bytes(c2).hex(), g2_bytes(c3).hex(), g1_bytes(c4).hex()]
                     for c1, c2, c3, c4 in ct.rows]}


def ct_from_dict(d: dict) -> Ciphertext:
    from .pairing import gt_load, g2_load, g1_load
    rows = [(gt_load(bytes.fromhex(a)), g2_load(bytes.fromhex(b)), g2_load(bytes.fromhex(c)),
             g1_load(bytes.fromhex(e))) for a, b, c, e in d["rows"]]
    return Ciphertext(d["policy"], gt_load(bytes.fromhex(d["C0"])), rows)
