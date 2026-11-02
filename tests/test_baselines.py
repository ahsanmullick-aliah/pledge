import unittest

from baselines.guo import GuoSystem
from baselines.romel import RomelSystem
from baselines.calypso import CalypsoSystem, committee_decrypts
from pledge.crypto import lgabe, rw15
from pledge.system.actors import Deployment, Patient
from pledge.crypto import sym
from pledge.fhir import samples
from pledge.system.actors import AccessDenied

CARD = samples.CARDIOLOGY


class GuoTest(unittest.TestCase):
    def setUp(self):
        self.g = GuoSystem()
        self.box = sym.BoxKeyPair.generate()
        for x in (samples.observation(), samples.restricted_condition()):
            self.g.upload(self.box, samples.paper_consent(), x)

    def test_access_and_log(self):
        dr = self.g.enroll("dr", "doctor", CARD)
        self.assertEqual(dr.open("Observation/bp-1")["id"], "bp-1")
        self.assertEqual(len(self.g.ledger.entries), 1)
        with self.assertRaises(AccessDenied):
            dr.open("Condition/cond-1")

    def test_revocation_reencrypts_and_others_keep_access(self):
        a = self.g.enroll("dr-a", "doctor", CARD)
        b = self.g.enroll("dr-b", "doctor", CARD)
        st = self.g.revoke("dr-a")
        self.assertGreater(st["reencrypted_headers"], 0)
        self.assertGreater(st["reissued_keys"], 0)
        with self.assertRaises(AccessDenied):
            a.open("Observation/bp-1")
        self.assertEqual(b.open("Observation/bp-1")["id"], "bp-1")


class RomelTest(unittest.TestCase):
    def test_grant_access_revoke(self):
        s = RomelSystem()
        p = s.new_patient("p1")
        p.upload(samples.observation())
        p.upload(samples.restricted_condition())
        dr = s.enroll("dr", "doctor", CARD)
        rn = s.enroll("rn", "nurse", hospital="H2", dept="ICU")
        st = p.share_by_consent(samples.paper_consent(), [dr, rn])
        self.assertEqual(st, {"grants": 1, "wraps": 1})          # cardiologist, unlabelled record only
        self.assertEqual(dr.open("p1", "Observation/bp-1", log=True)["id"], "bp-1")
        self.assertEqual(len(s.contracts["p1"].receipts), 1)
        with self.assertRaises(AccessDenied):
            rn.open("p1", "Observation/bp-1")
        p.revoke(dr, ["Observation/bp-1"])
        self.assertEqual(dr.open("p1", "Observation/bp-1")["id"], "bp-1")   # cached DEK: inherent
        dr.cache.clear()
        with self.assertRaises(AccessDenied):
            dr.open("p1", "Observation/bp-1")



class CalypsoTest(unittest.TestCase):
    def setUp(self):
        self.s = CalypsoSystem()
        self.p = self.s.new_patient("p1", samples.paper_consent())
        self.p.upload(samples.observation())
        self.p.upload(samples.restricted_condition())
        self.wid = self.p.wids["Observation/bp-1"]

    def test_read_requires_logged_read_and_policy(self):
        dr = self.s.enroll("dr", "doctor", CARD)
        n0 = len(self.s.chain.reads)
        self.assertEqual(dr.open("Observation/bp-1")["id"], "bp-1")
        self.assertEqual(len(self.s.chain.reads), n0 + 1)
        with self.assertRaisesRegex(AccessDenied, "not logged"):
            dr.collect(self.wid, "missing")
        with self.assertRaisesRegex(AccessDenied, "policy"):
            dr.open("Condition/cond-1")

    def test_wrong_secret_and_wrong_reader(self):
        a = self.s.enroll("a", "doctor", CARD)
        b = self.s.enroll("b", "doctor", CARD)
        other = self.p.upload(samples.medication())
        ra = a.log_read(self.p.wids[other])
        with self.assertRaisesRegex(AccessDenied, "different secret"):
            a.collect(self.wid, ra)
        rb = b.log_read(self.wid)
        with self.assertRaisesRegex(AccessDenied, "reader named"):
            a.collect(self.wid, rb)

    def test_revocation_is_one_tx_and_quorum_can_decrypt(self):
        z = self.s.enroll("z", "doctor", CARD)
        n0 = self.s.chain.txs
        self.s.revoke(z)
        self.assertEqual(self.s.chain.txs, n0 + 1)
        with self.assertRaisesRegex(AccessDenied, "revoked"):
            z.open("Observation/bp-1")
        t = self.s.committee.t
        self.assertEqual(committee_decrypts(self.s, self.wid, range(1, t + 1))["id"], "bp-1")


class LedgerQuorumTest(unittest.TestCase):
    def test_all_ledger_nodes_together_cannot_decrypt(self):
        dep = Deployment()
        pat = Patient("p1", dep, samples.paper_consent())
        rec = pat.upload(samples.observation())
        dep.ledger.flush()
        a = lgabe.access_attr(rec.tau)
        S = tuple(range(1, dep.ledger.k + 1))
        parts = [lgabe.share_gen(dep.ledger.nodes[i - 1].kss_secret, "validators", a, S) for i in S]
        key = rw15.UserKey("validators").add(a, lgabe.combine(dep.ledger.pub, parts))
        with self.assertRaises(rw15.NotSatisfied):
            rw15.decrypt(rec.ct_abe, key)


if __name__ == "__main__":
    unittest.main()
