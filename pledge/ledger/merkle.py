"""Binary Merkle tree over access entries (RFC 6962-style domain separation)."""
import hashlib


def _leaf(d: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + d).digest()


def _node(a: bytes, b: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + a + b).digest()


def root(leaves) -> bytes:
    level = [_leaf(x) for x in leaves]
    if not level:
        return hashlib.sha256(b"").digest()
    while len(level) > 1:
        nxt = [_node(level[i], level[i + 1]) for i in range(0, len(level) - 1, 2)]
        if len(level) % 2:
            nxt.append(level[-1])
        level = nxt
    return level[0]


def prove(leaves, index: int):
    """Audit path for leaves[index]: list of (sibling hash, sibling_is_left)."""
    level = [_leaf(x) for x in leaves]
    path, i = [], index
    while len(level) > 1:
        if i % 2 == 1:
            path.append((level[i - 1], True))
        elif i + 1 < len(level):
            path.append((level[i + 1], False))
        nxt = [_node(level[j], level[j + 1]) for j in range(0, len(level) - 1, 2)]
        if len(level) % 2:
            nxt.append(level[-1])
        level, i = nxt, i // 2
    return path


def verify(leaf: bytes, path, expected_root: bytes) -> bool:
    h = _leaf(leaf)
    for sib, sib_left in path:
        h = _node(sib, h) if sib_left else _node(h, sib)
    return h == expected_root
