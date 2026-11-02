import unittest

from pledge.crypto import lgabe, rw15, sym, sig, sigma
from pledge.crypto.pairing import gt_rand, gt_eq


class LedgerGatedTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.pub, cls.secrets, cls.qual = lgabe.run_dkg(n=4, k=2)
        cls.council = rw15.Authority.setup("council")
        cls.pks = {"council": cls.council.pk, lgabe.LEDGER_AUTHORITY: cls.pub.pk}

    @staticmethod
    def owner(attr):
        return lgabe.LEDGER_AUTHORITY if attr.startswith(lgabe.ACC_PREFIX) else "council"

    def issue(self, gid, tau, S):
        return [lgabe.share_gen(self.secrets[i - 1], gid, lgabe.access_attr(tau), S) for i in S]

    def test_threshold_key_decrypts(self):
        tau = "t-123"
        M = gt_rand()
        ct = rw15.encrypt(M, f"role:physician AND {lgabe.access_attr(tau)}", self.pks, self.owner)
        key = rw15.UserKey("dr-1").add("role:physician", self.council.keygen("dr-1", "role:physician"))
        for S in ((1, 2), (2, 4), (3, 4)):
            parts = self.issue("dr-1", tau, S)
            self.assertTrue(all(lgabe.share_verify(self.pub, p) for p in parts))
            k = rw15.UserKey("dr-1", dict(key.comps))
            k.add(lgabe.access_attr(tau), lgabe.combine(self.pub, parts))
            self.assertTrue(gt_eq(rw15.decrypt(ct, k), M))

    def test_wrong_tau_and_wrong_gid(self):
        M = gt_rand()
        ct = rw15.encrypt(M, f"role:physician AND {lgabe.access_attr('B')}", self.pks, self.owner)
        # record substitution: key for tag A used on record B
        k = rw15.UserKey("dr-1").add("role:physician", self.council.keygen("dr-1", "role:physician"))
        k.add(lgabe.access_attr("A"), lgabe.combine(self.pub, self.issue("dr-1", "A", (1, 2))))
        with self.assertRaises(rw15.NotSatisfied):
            rw15.decrypt(ct, k)
        # pass transfer: dr-2's pass for B used by dr-1
        k.add(lgabe.access_attr("B"), lgabe.combine(self.pub, self.issue("dr-2", "B", (1, 2))))
        self.assertFalse(gt_eq(rw15.decrypt(ct, k), M))

    def test_bad_partial_detected(self):
        parts = self.issue("dr-1", "t", (1, 3))
        forged = lgabe.share_gen(lgabe.KSSSecret(3, self.secrets[0].alpha, self.secrets[0].y), "dr-1", "acc:t", (1, 3))
        self.assertFalse(lgabe.share_verify(self.pub, forged))
        with self.assertRaises(lgabe.CombineError):
            lgabe.combine(self.pub, [parts[0], forged])
        with self.assertRaises(lgabe.CombineError):
            lgabe.combine(self.pub, parts[:1])

    def test_dkg_excludes_cheating_dealer(self):
        pub, secrets, qual = lgabe.run_dkg(n=4, k=2, cheaters={3})
        self.assertNotIn(3, qual)
        parts = [lgabe.share_gen(secrets[i - 1], "g", "acc:x", (2, 4)) for i in (2, 4)]
        self.assertTrue(all(lgabe.share_verify(pub, p) for p in parts))


class SupportTest(unittest.TestCase):
    def test_sym(self):
        dek = sym.new_dek()
        ct = sym.aead_encrypt(dek, b"hello", b"ad")
        self.assertEqual(sym.aead_decrypt(dek, ct, b"ad"), b"hello")
        kp = sym.BoxKeyPair.generate()
        self.assertEqual(sym.open_sealed(kp, sym.seal(kp.pk, b"x" * 40)), b"x" * 40)

    def test_bls(self):
        sk = sig.SigningKey.generate()
        s = sk.sign(b"msg")
        self.assertTrue(sig.verify(sk.vk, b"msg", s))
        self.assertFalse(sig.verify(sk.vk, b"msh", s))

    def test_purpose_proof(self):
        P, R = sigma.ElGamalKey.generate(), sigma.ElGamalKey.generate()
        allowed = [sigma.PURPOSES["TREAT"], sigma.PURPOSES["ETREAT"]]
        ct, pr = sigma.encrypt_purpose(sigma.PURPOSES["TREAT"], P.pk, R.pk, allowed, b"ctx")
        self.assertTrue(sigma.verify_purpose(ct, pr, P.pk, R.pk, allowed, b"ctx"))
        self.assertFalse(sigma.verify_purpose(ct, pr, P.pk, R.pk, allowed, b"other"))
        self.assertEqual(P.decrypt_small(ct[0], ct[1]), sigma.PURPOSES["TREAT"])
        self.assertEqual(R.decrypt_small(ct[2], ct[3]), sigma.PURPOSES["TREAT"])
        with self.assertRaises(ValueError):
            sigma.encrypt_purpose(sigma.PURPOSES["HRESCH"], P.pk, R.pk, allowed, b"ctx")
        # a proof for a disallowed purpose cannot be forged by reusing branches
        bad, _ = sigma.encrypt_purpose(sigma.PURPOSES["HRESCH"], P.pk, R.pk,
                                       allowed + [sigma.PURPOSES["HRESCH"]], b"ctx")
        self.assertFalse(sigma.verify_purpose(bad, pr, P.pk, R.pk, allowed, b"ctx"))


if __name__ == "__main__":
    unittest.main()
