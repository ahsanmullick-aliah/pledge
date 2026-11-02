import unittest

from pledge.crypto import lsss, rw15
from pledge.crypto.pairing import gt_rand, gt_eq


def owner(attr):
    return attr.split(":", 1)[0] if attr.split(":", 1)[0] in ("acc", "org") else "council"


class LSSSTest(unittest.TestCase):
    def check(self, policy, attrs, ok):
        A = lsss.build(policy)
        sel = A.solve(attrs)
        self.assertEqual(sel is not None, ok, policy)
        if sel:
            acc = [0] * A.cols
            for r in sel:
                acc = [a + b for a, b in zip(acc, A.rows[r])]
            self.assertEqual(acc, [1] + [0] * (A.cols - 1))

    def test_shapes(self):
        P = "(role:physician AND spec:c) OR (org:H1 AND role:nurse AND dept:ICU)"
        self.check(P, {"role:physician", "spec:c"}, True)
        self.check(P, {"org:H1", "role:nurse", "dept:ICU"}, True)
        self.check(P, {"org:H1", "role:nurse"}, False)
        self.check(f"({P}) AND acc:t1", {"role:physician", "spec:c"}, False)
        self.check(f"({P}) AND acc:t1", {"role:physician", "spec:c", "acc:t1"}, True)
        self.check("a AND (b OR (c AND (d OR e)))", {"a", "c", "e"}, True)
        self.check("a AND (b OR (c AND (d OR e)))", {"a", "c"}, False)

    def test_parse_errors(self):
        for bad in ("a AND", "(a OR b", "a b", "AND a"):
            with self.assertRaises(lsss.PolicyError):
                lsss.build(bad)


class RW15Test(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.auth = {n: rw15.Authority.setup(n) for n in ("council", "org", "acc")}
        cls.pks = {n: a.pk for n, a in cls.auth.items()}

    def key(self, gid, attrs):
        k = rw15.UserKey(gid)
        for a in attrs:
            k.add(a, self.auth[owner(a)].keygen(gid, a))
        return k

    def test_roundtrip_and_reject(self):
        P = "((role:physician AND spec:c) OR (org:H1 AND role:nurse)) AND acc:t1"
        M = gt_rand()
        ct = rw15.encrypt(M, P, self.pks, owner)
        good = self.key("dr-a", ["role:physician", "spec:c", "acc:t1"])
        self.assertTrue(gt_eq(rw15.decrypt(ct, good), M))
        nurse = self.key("rn-b", ["org:H1", "role:nurse", "acc:t1"])
        self.assertTrue(gt_eq(rw15.decrypt(ct, nurse), M))
        with self.assertRaises(rw15.NotSatisfied):
            rw15.decrypt(ct, self.key("dr-c", ["role:physician", "spec:c"]))

    def test_collusion_fails(self):
        """Two users pooling components get a wrong plaintext (H(GID) mismatch)."""
        P = "role:physician AND acc:t9"
        M = gt_rand()
        ct = rw15.encrypt(M, P, self.pks, owner)
        a = self.key("alice", ["role:physician"])
        b = self.key("bob", ["acc:t9"])
        pooled = rw15.UserKey("alice", {**a.comps, **b.comps})
        self.assertFalse(gt_eq(rw15.decrypt(ct, pooled), M))
        pooled_b = rw15.UserKey("bob", {**a.comps, **b.comps})
        self.assertFalse(gt_eq(rw15.decrypt(ct, pooled_b), M))

    def test_outsourcing(self):
        P = "role:physician AND (spec:c OR spec:d) AND acc:t2"
        M = gt_rand()
        ct = rw15.encrypt(M, P, self.pks, owner)
        k = self.key("dr-x", ["role:physician", "spec:d", "acc:t2"])
        tk, z = rw15.make_transform_key(k)
        self.assertTrue(gt_eq(rw15.finish(ct, rw15.transform(ct, tk), z), M))


if __name__ == "__main__":
    unittest.main()
