"""Identity registration (Section 5.2), per-record keys (5.2) and tag retirement (5.8)."""
import copy
import unittest

from pledge.crypto import lgabe, rw15, sig as bls, sym
from pledge.fhir import samples
from pledge.ledger import chaincode as cc
from pledge.ledger.network import Rejected
from pledge.system.actors import Deployment, Patient, AccessDenied

CARD = samples.CARDIOLOGY


def world():
    dep = Deployment()
    pat = Patient("p1", dep, samples.paper_consent())
    pat.upload(samples.observation())
    pat.upload(samples.medication())
    dep.ledger.flush()
    return dep, pat


class RegistrationTest(unittest.TestCase):
    def test_patient_bound_under_pseudonym(self):
        dep, pat = world()
        st = dep.ledger.state
        self.assertEqual(len(st.patients), 1)
        reg = next(iter(st.patients.values()))
        self.assertEqual(reg.psi, pat.cert["psi"])
        self.assertEqual(len(pat.abha), 14)
        self.assertNotIn(pat.abha, repr(cc.canon(reg.to_wire())))     # ABHA never on the ledger
        self.assertEqual(reg.box_pk, pat.box.pk)

    def test_double_registration_and_forged_cert_rejected(self):
        dep, pat = world()
        tx = copy.deepcopy(dep.ledger.state.patients[pat.cert["psi"]])
        tx.rotate = False
        tx.sig = dep.hospital_signer["H1"].sign(tx.body())
        with self.assertRaises(Rejected):
            dep.ledger.submit(tx)                                     # psi already bound
        forged = cc.PatientRegTx("ab" * 32, pat.box.pk, pat.signer.vk_bytes, "2031-12-31", "H1")
        forged.sig = bls.SigningKey.generate().sign(forged.body())
        with self.assertRaises(Rejected):
            dep.ledger.submit(forged)

    def test_otp_and_assertion_checks(self):
        dep, pat = world()
        txn, code = dep.abdm.idp.request_otp(pat.abha)
        with self.assertRaises(PermissionError):
            dep.abdm.idp.verify_otp(txn, "000000" if code != "000000" else "111111", "n")
        txn, code = dep.abdm.idp.request_otp(pat.abha)
        a = dep.abdm.idp.verify_otp(txn, code, "nonce-1")
        with self.assertRaises(PermissionError):                      # replay to another registration
            dep.certify_patient("H1", a, "nonce-2", pat.box.pk, pat.signer.vk_bytes, b"x" * 16, None)

    def test_device_recovery_rotates_binding(self):
        dep, pat = world()
        dr = dep.enroll("dr-card", "doctor", CARD, hospital="H2")
        dr.access(["Observation/bp-1"])
        psi, old_vk = pat.cert["psi"], pat.cert["vk"]
        pat.recover_device()
        dep.ledger.flush()
        reg = dep.ledger.state.patients[psi]
        self.assertTrue(reg.rotate)
        self.assertNotEqual(reg.vk.hex(), old_vk)
        self.assertEqual(len(pat.audit_trail()), 1)                  # old audit fields still readable

    def test_clinician_needs_verified_hpr(self):
        dep, _ = world()
        hpr = dep.abdm.hpr.register("Dr X", "NMC", "REG-1", verified=False)
        with self.assertRaises(PermissionError):
            dep.enroll("dr-x", "doctor", CARD, hpr=hpr)
        ok = dep.abdm.hpr.register("Dr Y", "NMC", "REG-2")
        dep.enroll("dr-y", "doctor", CARD, hpr=ok)

    def test_eaud_uses_certified_key(self):
        dep, pat = world()
        rec = dep.store.get("Observation/bp-1")
        rec.patient_cert = dict(rec.patient_cert, box_pk=sym.BoxKeyPair.generate().pk.hex())
        dr = dep.enroll("dr-card", "doctor", CARD, hospital="H2")
        with self.assertRaises(PermissionError):                      # tampered cert_P
            dr.access(["Observation/bp-1"])


class UnlinkabilityTest(unittest.TestCase):
    def test_side_records_share_no_public_value(self):
        dep, pat = world()
        recs = [dep.ledger.state.records[pat.taus[r]] for r in ("Observation/bp-1", "MedicationRequest/med-1")]
        a, b = (cc.canon(r.to_wire()) for r in recs)
        wa, wb = (r.wire_body() for r in recs)
        for k in ("owner_vk", "patient_purpose_pk", "salt", "tau"):
            self.assertNotEqual(wa[k], wb[k], k)
        reg = next(iter(dep.ledger.state.patients.values()))
        for w in (a, b):                                              # nothing links a tag to Reg_P
            self.assertNotIn(reg.vk.hex().encode(), w)
            self.assertNotIn(reg.box_pk.hex().encode(), w)
            self.assertNotIn(reg.psi.encode(), w)

    def test_entries_do_not_name_patient_keys(self):
        dep, pat = world()
        dr = dep.enroll("dr-card", "doctor", CARD, hospital="H2")
        tx = dr.request(["Observation/bp-1", "MedicationRequest/med-1"])
        w = cc.canon(tx.to_wire())
        reg = next(iter(dep.ledger.state.patients.values()))
        for v in (reg.vk.hex(), reg.box_pk.hex(), reg.psi, pat.abha):
            self.assertNotIn(v.encode(), w)
        self.assertEqual({t["purpose"] for t in pat.audit_trail()}, {"TREAT"})


class RetirementTest(unittest.TestCase):
    def narrowed(self):
        c = samples.paper_consent()
        c["provision"]["provision"] = c["provision"]["provision"][1:]          # drop cardiology
        return c

    def test_retired_tag_gets_no_new_key(self):
        dep, pat = world()
        old = copy.deepcopy(dep.store.get("Observation/bp-1"))
        dr = dep.enroll("dr-card", "doctor", CARD, hospital="H2")
        pat.update_consent(self.narrowed())
        dep.ledger.flush()
        self.assertIn(old.tau, dep.ledger.state.retired)
        dep.store.put(old)                                   # a cached copy of the old header
        with self.assertRaises(AccessDenied) as e:
            dr.access(["Observation/bp-1"])
        self.assertIn("retired", str(e.exception))

    def test_key_issued_before_rekey_stays_valid_until_strict_rekey(self):
        dep, pat = world()
        dr = dep.enroll("dr-card", "doctor", CARD, hospital="H2")
        dr.access(["Observation/bp-1"])                      # access key for the old tag
        old = copy.deepcopy(dep.store.get("Observation/bp-1"))
        pat.update_consent(self.narrowed())                  # header-only: same DEK
        dep.ledger.flush()
        cur = dep.store.get("Observation/bp-1")
        self.assertEqual(cur.ct_data, old.ct_data)
        mixed = copy.deepcopy(cur)
        mixed.tau, mixed.ct_abe, mixed.wrap = old.tau, old.ct_abe, old.wrap
        dep.store.put(mixed)                                 # old header + current data
        self.assertEqual(dr.open("Observation/bp-1")["id"], "bp-1")   # residual access (G7)
        dep.store.put(cur)
        pat.update_consent(self.narrowed(), strict=True)     # new DEK, new version
        dep.ledger.flush()
        cur = dep.store.get("Observation/bp-1")
        mixed = copy.deepcopy(cur)
        mixed.tau, mixed.ct_abe, mixed.wrap = old.tau, old.ct_abe, old.wrap
        dep.store.put(mixed)
        with self.assertRaises(Exception):
            dr.open("Observation/bp-1")
        self.assertEqual(pat.read_own("Observation/bp-1")["id"], "bp-1")

    def test_retirement_needs_old_owner(self):
        dep, pat = world()
        old_tau = pat.taus["Observation/bp-1"]
        rec, compiled = pat._encrypt(samples.observation(), 2)
        side = compiled.side
        mallory = bls.SigningKey.generate()
        tx = cc.RecordTx(rec.tau, rec.header_hash, side.purpose_codes(), [], b"\0" * 16, side.period,
                         side.emergency, mallory.vk_bytes, pat._purpose_key(rec.tau).pk, retires=old_tau)
        tx.sig = mallory.sign(tx.body())
        tx.retire_sig = mallory.sign(tx.body())
        with self.assertRaises(Rejected):
            dep.ledger.submit(tx)

    def test_retire_without_successor(self):
        dep, pat = world()
        c = samples.paper_consent()
        c["provision"]["provision"] = []
        c["extension"] = [{"url": "urn:pledge:consent:no-emergency-access", "valueBoolean": True}]
        old = pat.taus["Observation/bp-1"]
        pat.update_consent(c)
        dep.ledger.flush()
        self.assertIn(old, dep.ledger.state.retired)
        self.assertIsNone(dep.store.get("Observation/bp-1").tau)


if __name__ == "__main__":
    unittest.main()
