"""End-to-end flows and the attack suite of paper Section VI-B / planned Table IV."""
import unittest

from pledge.crypto import lgabe, rw15
from pledge.fhir import samples
from pledge.ledger import chaincode as cc
from pledge.ledger.network import Rejected, Endorsement
from pledge.system.actors import Deployment, Patient, AccessDenied

CARD = samples.CARDIOLOGY


def world(behaviours=None, deny=()):
    dep = Deployment(behaviours=behaviours)
    pat = Patient("p1", dep, samples.paper_consent(deny_practitioners=deny))
    pat.upload(samples.observation())
    pat.upload(samples.restricted_condition())
    pat.upload(samples.medication())
    dep.ledger.flush()
    return dep, pat


class FlowTest(unittest.TestCase):
    def test_cardiologist_reads_and_is_logged(self):
        dep, pat = world()
        dr = dep.enroll("dr-card", "doctor", CARD, hospital="H2")
        obs = dr.access(["Observation/bp-1"])[0]
        self.assertEqual(obs["valueQuantity"]["value"], 128)
        trail = pat.audit_trail()
        self.assertEqual([(t["clinician"], t["resource"], t["purpose"]) for t in trail],
                         [("dr-card", "Observation/bp-1", "TREAT")])

    def test_subspecialist_and_icu_nurse(self):
        dep, pat = world()
        ic = dep.enroll("dr-ic", "doctor", "pledge:interventional-cardiology", hospital="H3")
        self.assertEqual(ic.access(["MedicationRequest/med-1"])[0]["id"], "med-1")
        rn = dep.enroll("rn-icu", "nurse", hospital="H1", dept="ICU")
        self.assertEqual(rn.access(["Observation/bp-1"])[0]["id"], "bp-1")
        rn2 = dep.enroll("rn-ward", "nurse", hospital="H1", dept="WARD")
        with self.assertRaises(AccessDenied):
            rn2.access(["Observation/bp-1"])

    def test_restricted_record_only_patient_or_breakglass(self):
        dep, pat = world()
        dr = dep.enroll("dr-card", "doctor", CARD)
        with self.assertRaises(AccessDenied):
            dr.access(["Condition/cond-1"])
        self.assertEqual(pat.read_own("Condition/cond-1")["id"], "cond-1")

    def test_bundle_one_transaction(self):
        dep, pat = world()
        dr = dep.enroll("dr-card", "doctor", CARD)
        h0 = dep.ledger.height
        out = dr.access(["Observation/bp-1", "MedicationRequest/med-1"])
        self.assertEqual({o["id"] for o in out}, {"bp-1", "med-1"})
        self.assertEqual(dep.ledger.height, h0 + 1)

    def test_outsourced_decryption(self):
        dep, pat = world()
        dr = dep.enroll("dr-card", "doctor", CARD)
        self.assertEqual(dr.access(["Observation/bp-1"], use_proxy=True)[0]["id"], "bp-1")

    def test_breakglass(self):
        dep, pat = world()
        em = dep.enroll("dr-em", "doctor", hospital="H4", emergency=True)
        co = dep.enroll("dr-co", "doctor", hospital="H4")
        with self.assertRaises(AccessDenied):            # emergency role alone, normal request
            em.access(["Condition/cond-1"])
        obs_tau = dep.store.get("Observation/bp-1").tau
        with self.assertRaises(AccessDenied):            # cannot use the emergency role to skip break-glass
            em.access(["Observation/bp-1"])
        rec = em.access(["Condition/cond-1"], purpose="ETREAT", cosigner=co)[0]
        self.assertEqual(rec["id"], "cond-1")
        trail = pat.audit_trail()
        self.assertTrue(trail[-1]["breakglass"])
        self.assertEqual(trail[-1]["purpose"], "ETREAT")

    def test_consent_change_invalidates_old_pass(self):
        dep, pat = world()
        dr = dep.enroll("dr-card", "doctor", CARD)
        dr.access(["Observation/bp-1"])
        old_tau = dep.store.get("Observation/bp-1").tau
        consent = samples.paper_consent()
        consent["provision"]["provision"] = consent["provision"]["provision"][1:]   # drop cardiology
        pat.update_consent(consent)
        dep.ledger.flush()
        self.assertNotEqual(dep.store.get("Observation/bp-1").tau, old_tau)
        with self.assertRaises(AccessDenied):
            dr.open("Observation/bp-1")                   # cached pass is for the old tag
        with self.assertRaises(AccessDenied):
            dr.access(["Observation/bp-1"])               # and the new policy excludes him

    def test_receipts_verify_and_anchor(self):
        dep, pat = world()
        dr = dep.enroll("dr-card", "doctor", CARD)
        for _ in range(12):
            dr.access(["Observation/bp-1"])
        self.assertTrue(dep.ledger.public_anchor)
        rs = dep.ledger.receipts_for({pat.taus["Observation/bp-1"]})
        self.assertEqual(len(rs), 12)
        self.assertTrue(all(dep.ledger.verify_receipt(r) for r in rs))
        rs[0].path = rs[1].path if len(rs[0].path) else [(b"\x00" * 32, False)]
        rs[0].tx = rs[1].tx if rs[0].tx is not rs[1].tx else rs[0].tx
        tampered = rs[0]
        tampered.root = b"\x11" * 32
        self.assertFalse(dep.ledger.verify_receipt(tampered))


class AttackTest(unittest.TestCase):
    """Each test is one row of the attack table (paper Section VI-B)."""

    def test_A1_skip_the_log(self):
        dep, pat = world()
        dr = dep.enroll("dr-card", "doctor", CARD)
        with self.assertRaises(AccessDenied):
            dr.open("Observation/bp-1")                   # standing keys alone are useless
        rec = dep.store.get("Observation/bp-1")
        with self.assertRaises(rw15.NotSatisfied):
            rw15.decrypt(rec.ct_abe, dr.key)

    def test_A2_record_substitution(self):
        dep, pat = world()
        dr = dep.enroll("dr-card", "doctor", CARD)
        dr.access(["MedicationRequest/med-1"])            # logs record A only
        tau_a = dep.store.get("MedicationRequest/med-1").tau
        rec_b = dep.store.get("Observation/bp-1")
        key = rw15.UserKey(dr.gid, dict(dr.key.comps))
        key.add(lgabe.access_attr(rec_b.tau), dr.access_keys[lgabe.access_attr(tau_a)])  # relabel the pass
        M = rw15.decrypt(rec_b.ct_abe, key)
        from pledge.crypto import sym
        with self.assertRaises(Exception):
            sym.aead_decrypt(sym.kwk_from_gt(M, rec_b.tau, rec_b.version), rec_b.wrap, rec_b.tau.encode())

    def test_A3_pass_transfer(self):
        dep, pat = world()
        y = dep.enroll("dr-y", "doctor", CARD)
        x = dep.enroll("dr-x", "doctor", CARD)
        y.access(["Observation/bp-1"])
        tau = dep.store.get("Observation/bp-1").tau
        a = lgabe.access_attr(tau)
        x.access_keys[a] = y.access_keys[a]               # Y hands the pass to X
        with self.assertRaises(AccessDenied):
            x.open("Observation/bp-1")
        self.assertFalse(any(t["clinician"] == "dr-x" for t in pat.audit_trail()))

    def test_A4_revoked_clinician(self):
        dep, pat = world()
        dr = dep.enroll("dr-card", "doctor", CARD)
        dep.revoke("dr-card")
        dep.ledger.flush()
        with self.assertRaises(AccessDenied):
            dr.access(["Observation/bp-1"])

    def test_A4b_revocation_race(self):
        """Endorsed before revocation, ordered after it: invalid at commit, no key shares."""
        dep, pat = world()
        dr = dep.enroll("dr-card", "doctor", CARD)
        tx = dr.build_request(["Observation/bp-1"])
        dep.revoke("dr-card")                             # queued first
        dep.ledger.submit(tx)                             # still endorsable (revocation not committed)
        blk = dep.ledger.flush()[-1]
        self.assertEqual(blk.valid, [True, False])
        self.assertIn("revoked", blk.reasons[1])
        self.assertEqual(dr.collect(tx), [tx.items[0].tau])

    def test_A5_minority_of_hospitals(self):
        """f = 1 of n = 4 hospitals is fully malicious: endorses anything, issues rogue keys,
        equivocates as leader. It still cannot produce a usable pass without logging."""
        dep, pat = world(behaviours={2: {"endorse_all", "rogue", "equivocate"}})
        dr = dep.enroll("dr-card", "doctor", CARD)
        tau = dep.store.get("Observation/bp-1").tau
        rogue = dep.ledger.nodes[1].rogue_issue(dr.gid, lgabe.access_attr(tau), (2, 3))
        with self.assertRaises(lgabe.CombineError):
            lgabe.combine(dep.ledger.pub, [rogue])        # k = 2 shares needed
        # a forged request with one (malicious) endorsement fails validation
        bad = dr.build_request(["Observation/bp-1"])
        bad.items[0].proof.branches.reverse()             # invalid purpose proof
        with self.assertRaises(Rejected):
            dep.ledger.submit(bad)
        evil = dep.ledger.nodes[1]
        dep.ledger.submit_raw(bad, [Endorsement(2, evil.signer.sign(cc.H(b"endorse", bad.body())))])
        blk = dep.ledger.flush()[-1]
        self.assertEqual(blk.valid, [False])
        self.assertEqual(dr.collect(bad), [bad.items[0].tau])
        # honest flow still works despite the equivocating leader
        self.assertEqual(dr.access(["Observation/bp-1"])[0]["id"], "bp-1")

    def test_A5b_more_than_f_breaks_assumption(self):
        """Documented limit: k = f + 1 colluding services can issue a pass off-ledger."""
        dep, pat = world(behaviours={2: {"rogue"}, 3: {"rogue"}})
        dr = dep.enroll("dr-card", "doctor", CARD)
        tau = dep.store.get("Observation/bp-1").tau
        parts = [dep.ledger.nodes[i - 1].rogue_issue(dr.gid, lgabe.access_attr(tau), (2, 3)) for i in (2, 3)]
        dr.access_keys[lgabe.access_attr(tau)] = lgabe.combine(dep.ledger.pub, parts)
        self.assertEqual(dr.open("Observation/bp-1")["id"], "bp-1")

    def test_A6_curious_validators_learn_only_leakage(self):
        dep, pat = world()
        dr = dep.enroll("dr-card", "doctor", CARD)
        dr.access(["Observation/bp-1"])
        blk = dep.ledger.honest_node.chain[-1]
        tx = blk.txs[0][0]
        blob = repr(tx.items[0].aud_patient) + repr(tx.items[0].aud_regulator)
        for secret in (b"p1", b"Observation", b"TREAT", b"bp-1"):
            self.assertNotIn(secret, tx.items[0].aud_patient + tx.items[0].aud_regulator)
        self.assertNotIn("p1", tx.items[0].tau)
        self.assertEqual(dep.regulator.open_entry(tx)[0]["resource"], "Observation/bp-1")

    def test_deny_list_and_purpose_and_period(self):
        dep, pat = world(deny=("rn-99",))
        rn = dep.enroll("rn-99", "nurse", hospital="H1", dept="ICU")
        with self.assertRaises(AccessDenied):
            rn.access(["Observation/bp-1"])
        dr = dep.enroll("dr-card", "doctor", CARD)
        with self.assertRaises(ValueError):               # purpose not in consent
            dr.access(["Observation/bp-1"], purpose="HRESCH")
        dep.ledger.now = 1_830_000_000                    # 2027-12-28 .. still inside? move past end
        dep.ledger.now = 1_860_000_000                    # 2028-12
        with self.assertRaises(AccessDenied):
            dr.access(["Observation/bp-1"])

    def test_replay_rejected(self):
        dep, pat = world()
        dr = dep.enroll("dr-card", "doctor", CARD)
        tx = dr.request(["Observation/bp-1"])
        with self.assertRaises(Rejected):
            dep.ledger.submit(tx)

    def test_bad_share_triggers_logged_retry(self):
        dep, pat = world(behaviours={1: {"bad_share"}})
        dr = dep.enroll("dr-card", "doctor", CARD)
        self.assertEqual(dr.access(["Observation/bp-1"])[0]["id"], "bp-1")
        trail = pat.audit_trail()
        self.assertEqual(len(trail), 2)                    # original + retry, both logged

    def test_silent_hospital_liveness(self):
        dep, pat = world(behaviours={1: {"silent"}})
        dr = dep.enroll("dr-card", "doctor", CARD)
        self.assertEqual(dr.access(["Observation/bp-1"])[0]["id"], "bp-1")
        self.assertGreaterEqual(dep.ledger.view_changes, 1)


if __name__ == "__main__":
    unittest.main()
