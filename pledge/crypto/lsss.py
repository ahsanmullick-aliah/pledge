"""Monotone Boolean policies -> LSSS matrices (Lewko-Waters conversion).

Policy syntax:  attr  |  ( expr )  |  expr AND expr  |  expr OR expr
AND binds tighter than OR. Attributes are tokens like ``role:physician``,
``spec:394579002``, ``acc:9f2c...``. Keywords are case-insensitive.

The conversion yields a matrix with entries in {0, 1, -1} for which the
reconstruction coefficients of a minimal satisfying leaf set are all 1.
"""
import re
from dataclasses import dataclass, field

from .pairing import fr_int, fr_mul, fr_add, fr_zero

_TOKEN = re.compile(r"\s*(\(|\)|[^\s()]+)")


class PolicyError(ValueError):
    pass


# ---------------- parsing ----------------

def parse(policy: str):
    toks = [m.group(1) for m in _TOKEN.finditer(policy)]
    pos = 0

    def peek():
        return toks[pos] if pos < len(toks) else None

    def take():
        nonlocal pos
        t = toks[pos]
        pos += 1
        return t

    def expr():
        kids = [term()]
        while peek() is not None and peek().upper() == "OR":
            take()
            kids.append(term())
        return kids[0] if len(kids) == 1 else ("or", kids)

    def term():
        kids = [factor()]
        while peek() is not None and peek().upper() == "AND":
            take()
            kids.append(factor())
        return kids[0] if len(kids) == 1 else ("and", kids)

    def factor():
        t = peek()
        if t is None:
            raise PolicyError("unexpected end of policy")
        if t == "(":
            take()
            e = expr()
            if peek() != ")":
                raise PolicyError("missing ')'")
            take()
            return e
        if t == ")" or t.upper() in ("AND", "OR"):
            raise PolicyError(f"unexpected token {t!r}")
        return ("attr", take())

    tree = expr()
    if pos != len(toks):
        raise PolicyError(f"trailing tokens: {toks[pos:]}")
    return tree


def to_string(tree) -> str:
    kind = tree[0]
    if kind == "attr":
        return tree[1]
    sep = " AND " if kind == "and" else " OR "
    return "(" + sep.join(to_string(k) for k in tree[1]) + ")"


def attributes(tree):
    if tree[0] == "attr":
        return {tree[1]}
    out = set()
    for k in tree[1]:
        out |= attributes(k)
    return out


# ---------------- LSSS ----------------

@dataclass
class LSSS:
    rows: list            # list of int vectors (all length `cols`)
    rho: list             # row index -> attribute string
    tree: tuple = field(repr=False)
    leaf_rows: dict = field(default_factory=dict, repr=False)  # id(leaf) -> row

    @property
    def cols(self):
        return len(self.rows[0]) if self.rows else 0

    def shares(self, vec):
        """lambda_x = <A_x, vec> for each row, computed in Z_p."""
        out = []
        for row in self.rows:
            acc = fr_zero()
            for a, v in zip(row, vec):
                if a == 1:
                    acc = fr_add(acc, v)
                elif a == -1:
                    acc = fr_add(acc, fr_mul(fr_int(-1), v))
                elif a != 0:
                    acc = fr_add(acc, fr_mul(fr_int(a), v))
            out.append(acc)
        return out

    def solve(self, attrs):
        """Return {row: coeff} with sum coeff*A_x = (1,0,...,0), or None.

        Picks a minimal satisfying leaf set by walking the tree; with the
        Lewko-Waters matrix every coefficient is 1.
        """
        attrs = set(attrs)

        def sat(node):
            if node[0] == "attr":
                return [self.leaf_rows[id(node)]] if node[1] in attrs else None
            if node[0] == "or":
                best = None
                for k in node[1]:
                    s = sat(k)
                    if s is not None and (best is None or len(s) < len(best)):
                        best = s
                return best
            picked = []
            for k in node[1]:
                s = sat(k)
                if s is None:
                    return None
                picked += s
            return picked

        rows = sat(self.tree)
        return None if rows is None else {r: 1 for r in rows}


def _binarize(tree):
    kind = tree[0]
    if kind == "attr":
        return tree
    kids = [_binarize(k) for k in tree[1]]
    if kind == "or":
        return ("or", kids)
    while len(kids) > 2:              # AND(a,b,c) -> AND(a, AND(b,c))
        kids = kids[:-2] + [("and", kids[-2:])]
    return ("and", kids)


def build(policy) -> LSSS:
    tree = _binarize(parse(policy) if isinstance(policy, str) else policy)
    labelled = []                      # (leaf node, vector)
    counter = [1]

    def walk(node, vec):
        if node[0] == "attr":
            labelled.append((node, vec))
        elif node[0] == "or":
            for k in node[1]:
                walk(k, vec)
        else:
            left, right = node[1]
            c = counter[0]
            counter[0] = c + 1          # reserve column c before recursing
            v = vec + [0] * (c - len(vec))
            walk(left, v + [1])
            walk(right, [0] * c + [-1])

    walk(tree, [1])
    width = counter[0]
    rows, rho, leaf_rows = [], [], {}
    for i, (leaf, vec) in enumerate(labelled):
        rows.append(vec + [0] * (width - len(vec)))
        rho.append(leaf[1])
        leaf_rows[id(leaf)] = i
    return LSSS(rows=rows, rho=rho, tree=tree, leaf_rows=leaf_rows)
