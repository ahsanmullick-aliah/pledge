"""In-process simulation of the hospital ledger: n hospitals, each running a
BFT orderer, a committing peer and a key-share service (KSS).

Faithful to the protocol logic of Section V-E (execute-order-validate with a
PBFT-style ordering service and k = f + 1 endorsement), not to Fabric's
wire formats or timings. Byzantine behaviours can be switched on per node to
reproduce the attacks of Section VI-B. Real throughput and latency numbers
come from the Hyperledger Fabric deployment, not from this simulator.

Behaviour flags per hospital:
  silent        never votes, endorses or issues shares (crash / omission)
  equivocate    as leader, proposes different blocks to different nodes
  endorse_all   endorses every transaction without checking it
  bad_share     returns malformed partial keys
  rogue         will issue partial keys for any request, logged or not
"""
import hashlib
from dataclasses import dataclass, field

from ..crypto import lgabe, sig as bls
from ..crypto.pairing import fr_rand, g1_pow, g2_pow
from . import merkle
from .chaincode import (AccessTx, Reject, WorldState, apply, check, tx_digest, H)


@dataclass
class Endorsement:
    index: int
    sig: object


@dataclass
class Block:
    height: int
    prev_hash: bytes
    txs: list                    # [(tx, [Endorsement])]
    view: int
    cert: list = field(default_factory=list)      # [(index, sig)] over commit digest
    valid: list = field(default_factory=list)     # per-tx validity flags (identical at honest peers)
    reasons: list = field(default_factory=list)

    @property
    def entry_leaves(self):
        """Every ordered access entry (valid or not: attempts are logged too)."""
        return [bytes.fromhex(t.entry_id) for t, _ in self.txs if isinstance(t, AccessTx)]

    @property
    def merkle_root(self) -> bytes:
        return merkle.root(self.entry_leaves)

    @property
    def digest(self) -> bytes:
        """Signed by the ordering quorum; covers the Merkle root of the block's entries."""
        return H(b"block", self.height, self.prev_hash, self.view, self.merkle_root,
                 *[tx_digest(t) for t, _ in self.txs])

    @property
    def block_hash(self) -> bytes:
        return H(self.digest, self.merkle_root, bytes(self.valid))


@dataclass
class Hospital:
    index: int
    signer: bls.SigningKey
    kss_secret: lgabe.KSSSecret
    state: WorldState
    behaviours: set = field(default_factory=set)
    chain: list = field(default_factory=list)

    @property
    def honest(self):
        return not self.behaviours

    # ---- endorsement (execute phase) ----
    def endorse(self, tx, now):
        if "silent" in self.behaviours:
            return None, "silent"
        if "endorse_all" not in self.behaviours:
            try:
                check(self.state, tx, now)
            except Reject as e:
                return None, str(e)
        return Endorsement(self.index, self.signer.sign(H(b"endorse", tx_digest(tx)))), None

    # ---- key-share service ----
    def issue_for_block(self, block: Block, pub):
        """Partial keys for every valid access entry in a committed block that names this service."""
        if "silent" in self.behaviours:
            return []
        out = []
        for (tx, _), ok in zip(block.txs, block.valid):
            if not ok or not isinstance(tx, AccessTx) or self.index not in tx.S:
                continue
            for it in tx.items:
                attr = lgabe.emergency_attr(it.tau) if tx.breakglass else lgabe.access_attr(it.tau)
                out.append((tx.gid, tx.entry_id, self._share(tx.gid, attr, tx.S)))
        return out

    def _share(self, gid, attr, S):
        pk = lgabe.share_gen(self.kss_secret, gid, attr, S)
        if "bad_share" in self.behaviours:
            pk.K = g1_pow(fr_rand())
        return pk

    def rogue_issue(self, gid, attr, S):
        """A corrupted service releasing its share without any ledger entry."""
        if "rogue" not in self.behaviours:
            raise PermissionError("honest key-share services issue only for committed entries")
        return lgabe.share_gen(self.kss_secret, gid, attr, S)


class Rejected(Exception):
    pass


class Ledger:
    def __init__(self, n, aa_keys, regulator_purpose_pk, behaviours=None, batch_size=50,
                 anchor_every=10, now=0):
        self.n = n
        self.f = (n - 1) // 3
        self.k = self.f + 1
        self.q = 2 * self.f + 1
        self.pub, secrets, _ = lgabe.run_dkg(n, self.k)
        behaviours = behaviours or {}
        genesis = WorldState(dict(aa_keys), regulator_purpose_pk, n, self.k)
        self.nodes = [Hospital(i, bls.SigningKey.generate(), secrets[i - 1], genesis.snapshot(),
                               set(behaviours.get(i, ()))) for i in range(1, n + 1)]
        self.node_vk = {h.index: h.signer.vk for h in self.nodes}
        self.pending = []
        self.batch_size = batch_size
        self.anchor_every = anchor_every
        self.public_anchor = []           # (height, block_hash) posted to a public chain
        self.mailbox = {}                 # (gid, entry_id) -> [PartialKey]
        self.now = now
        self.view_changes = 0

    # ---------------- helpers ----------------
    @property
    def honest_node(self) -> Hospital:
        return next(h for h in self.nodes if h.honest)

    @property
    def state(self) -> WorldState:
        return self.honest_node.state

    @property
    def height(self):
        return len(self.honest_node.chain)

    # ---------------- client API ----------------
    def submit(self, tx):
        """Collect endorsements; enqueue for ordering if at least k hospitals endorse."""
        ends, reasons = [], []
        for h in self.nodes:
            e, why = h.endorse(tx, self.now)
            if e:
                ends.append(e)
            elif why != "silent":
                reasons.append(why)
        if len(ends) < self.k:
            raise Rejected(reasons[0] if reasons else "not enough endorsements")
        self.pending.append((tx, ends))
        return tx

    def submit_raw(self, tx, endorsements):
        """Bypasses endorsement collection (used to model forged or partial endorsements)."""
        self.pending.append((tx, list(endorsements)))

    def flush(self):
        """Order and commit every pending transaction; returns committed blocks."""
        blocks = []
        while self.pending:
            batch, self.pending = self.pending[:self.batch_size], self.pending[self.batch_size:]
            blocks.append(self._order(batch))
        return blocks

    # ---------------- ordering (PBFT-style) ----------------
    def _order(self, batch):
        height = self.height
        prev = self.honest_node.chain[-1].block_hash if self.honest_node.chain else b"\x00" * 32
        for view in range(self.n):
            leader = self.nodes[(height + view) % self.n]
            if "silent" in leader.behaviours:
                self.view_changes += 1
                continue
            if "equivocate" in leader.behaviours and len(batch) > 1:
                alt = list(reversed(batch))
                proposals = {h.index: (batch if h.index % 2 else alt) for h in self.nodes}
            else:
                proposals = {h.index: batch for h in self.nodes}
            blocks = {i: Block(height, prev, p, view) for i, p in proposals.items()}
            prepares = {}
            for h in self.nodes:
                if "silent" in h.behaviours:
                    continue
                d = blocks[h.index].digest
                prepares.setdefault(d, set()).add(h.index)
                if "equivocate" in h.behaviours:            # equivocator votes for everything
                    for b in blocks.values():
                        prepares.setdefault(b.digest, set()).add(h.index)
            winner = next((d for d, v in prepares.items() if len(v) >= self.q), None)
            if winner is None:
                self.view_changes += 1
                continue
            block = next(b for b in blocks.values() if b.digest == winner)
            commit_msg = H(b"commit", winner)
            block.cert = [(h.index, h.signer.sign(commit_msg)) for h in self.nodes
                          if "silent" not in h.behaviours and h.index in prepares[winner]][: self.q]
            if len(block.cert) < self.q:
                self.view_changes += 1
                continue
            return self._commit(block)
        raise RuntimeError("no quorum: more than f hospitals faulty")

    # ---------------- validation, commit, key issuance ----------------
    def _valid_endorsements(self, tx, ends):
        msg = H(b"endorse", tx_digest(tx))
        good = {e.index for e in ends if e.index in self.node_vk and bls.verify(self.node_vk[e.index], msg, e.sig)}
        return len(good) >= self.k

    def _commit(self, template: Block):
        committed = None
        for h in self.nodes:
            blk = Block(template.height, template.prev_hash, template.txs, template.view, template.cert)
            for tx, ends in blk.txs:
                ok, why = True, ""
                if not self._valid_endorsements(tx, ends):
                    ok, why = False, "endorsement policy not met"
                else:
                    try:
                        check(h.state, tx, self.now)
                    except Reject as e:
                        ok, why = False, str(e)
                blk.valid.append(ok)
                blk.reasons.append(why)
                if ok:
                    apply(h.state, tx, blk.height)
            h.chain.append(blk)
            if h.honest and committed is None:
                committed = blk
        if (committed.height + 1) % self.anchor_every == 0:
            self.public_anchor.append((committed.height, committed.block_hash))
        for h in self.nodes:                       # KSS act on their own peer's committed block
            for gid, eid, part in h.issue_for_block(h.chain[-1], self.pub):
                self.mailbox.setdefault((gid, eid), []).append(part)
        return committed

    def shares_for(self, gid, tx):
        """Partial keys the key-share services released for this entry."""
        return list(self.mailbox.get((gid, tx.entry_id), []))

    # ---------------- receipts ----------------
    def receipts_for(self, taus):
        """Merkle inclusion receipts for every valid entry naming one of `taus`
        (the root is covered by the quorum certificate)."""
        taus = set(taus)
        out = []
        for blk in self.honest_node.chain:
            for (tx, _), ok in zip(blk.txs, blk.valid):
                if ok and isinstance(tx, AccessTx) and taus & {it.tau for it in tx.items}:
                    leaf = bytes.fromhex(tx.entry_id)
                    idx = blk.entry_leaves.index(leaf)
                    out.append(Receipt(blk.height, tx, merkle.prove(blk.entry_leaves, idx),
                                       blk.merkle_root, blk.prev_hash, blk.view,
                                       [tx_digest(t) for t, _ in blk.txs], list(blk.cert)))
        return out

    def verify_receipt(self, r) -> bool:
        leaf = bytes.fromhex(r.tx.entry_id)
        if not merkle.verify(leaf, r.path, r.root):
            return False
        digest = H(b"block", r.height, r.prev_hash, r.view, r.root, *r.tx_digests)
        msg = H(b"commit", digest)
        signers = {i for i, s in r.cert if i in self.node_vk and bls.verify(self.node_vk[i], msg, s)}
        return len(signers) >= self.q


@dataclass
class Receipt:
    height: int
    tx: AccessTx
    path: list
    root: bytes
    prev_hash: bytes
    view: int
    tx_digests: list
    cert: list
