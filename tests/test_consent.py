import random
import unittest
from datetime import date

from pledge.crypto import lsss
from pledge.fhir import consent as C, specialty

ROLE, SN, DEPT = C.SYS_ROLE, C.SYS_SNOMED, C.SYS_DEPT


def actor(role=None, spec=None, org=None, dept=None, practitioner=None):
    a, codings = {}, []
    if role: codings.append({"system": ROLE, "code": role})
    if spec: codings.append({"system": SN, "code": spec})
    if dept: codings.append({"system": DEPT, "code": dept})
    if codings: a["role"] = {"coding": codings}
    if org: a["reference"] = {"reference": f"Organization/{org}"}
    if practitioner: a["reference"] = {"reference": f"Practitioner/{practitioner}"}
    return a


PAPER_EXAMPLE = {
    "resourceType": "Consent", "status": "active",
    "provision": {"type": "deny", "period": {"start": "2026-01-01", "end": "2027-12-31"}, "provision": [
        {"type": "permit", "actor": [actor(role="doctor", spec="394579002")],
         "purpose": [{"system": C.SYS_PURPOSE, "code": "TREAT"}],
         "provision": [{"type": "deny", "securityLabel": [{"code": "R"}]}]},
        {"type": "permit", "actor": [actor(role="nurse", org="H1", dept="ICU")],
         "provision": [{"type": "deny", "securityLabel": [{"code": "R"}]},
                       {"type": "deny", "actor": [actor(practitioner="rn-99")]}]},
    ]},
}


def satisfied(policy, attrs):
    return policy is not None and lsss.build(policy).solve(attrs) is not None


class CompilerTest(unittest.TestCase):
    def test_paper_example(self):
        obs = C.Resource("Observation")
        out = C.compile_consent(PAPER_EXAMPLE, obs)
        self.assertTrue(satisfied(out.policy, {"role:doctor", "spec:394579002"}))
        self.assertTrue(satisfied(out.policy, {"role:nurse", "org:H1", "dept:H1.ICU"}))
        self.assertFalse(satisfied(out.policy, {"role:nurse", "org:H2", "dept:H2.ICU"}))
        self.assertFalse(satisfied(out.policy, {C.EMERGENCY_ATTR}))   # break-glass is a separate branch
        self.assertTrue(out.side.emergency)
        self.assertEqual(out.side.deny, {"rn-99"})
        self.assertEqual(out.side.period, ("2026-01-01", "2027-12-31"))
        restricted = C.compile_consent(PAPER_EXAMPLE, C.Resource("Condition", security_labels={"R"}))
        self.assertIsNone(restricted.policy)                         # only patient / break-glass
        self.assertTrue(restricted.side.emergency)

    def test_specialty_closure(self):
        attrs = {"role:doctor"} | {f"spec:{s}" for s in specialty.closure("pledge:interventional-cardiology")}
        out = C.compile_consent(PAPER_EXAMPLE, C.Resource("Observation"))
        self.assertTrue(satisfied(out.policy, attrs))
        general = {"role:doctor"} | {f"spec:{s}" for s in specialty.closure("394579002")}
        self.assertNotIn("spec:pledge:interventional-cardiology", general)

    def test_no_emergency_opt_out(self):
        c = dict(PAPER_EXAMPLE, extension=[{"url": C.EXT_NO_EMERGENCY, "valueBoolean": True}])
        out = C.compile_consent(c, C.Resource("Condition", security_labels={"R"}))
        self.assertIsNone(out.policy)
        self.assertFalse(out.side.emergency)

    def test_unsupported(self):
        bad = {"resourceType": "Consent", "provision": {"type": "permit", "provision": [
            {"type": "deny", "actor": [actor(role="researcher")]}]}}
        with self.assertRaises(C.Unsupported):
            C.compile_consent(bad, C.Resource("Observation"))


    def test_rejects_provision_data(self):
        c = {"resourceType": "Consent", "provision": {"type": "deny", "provision": [
            {"type": "permit", "actor": [actor(role="doctor")],
             "data": [{"meaning": "instance", "reference": {"reference": "Observation/bp-1"}}]}]}}
        with self.assertRaises(C.Unsupported):
            C.compile_consent(c, C.Resource("Observation"))

    def test_rejects_differing_purposes(self):
        c = {"resourceType": "Consent", "provision": {"type": "deny", "provision": [
            {"type": "permit", "actor": [actor(role="doctor")], "purpose": [{"code": "TREAT"}]},
            {"type": "permit", "actor": [actor(role="researcher")], "purpose": [{"code": "HRESCH"}]}]}}
        with self.assertRaises(C.Unsupported):
            C.compile_consent(c, C.Resource("Observation"))
        # a resource to which only one of the permits applies is fine
        c["provision"]["provision"][1]["class"] = [{"code": "Condition"}]
        self.assertEqual(C.compile_consent(c, C.Resource("Observation")).side.purposes[:1], ["TREAT"])

    def test_deny_overrides(self):
        # two applying data denies under one permit: only requesters re-admitted by both get through
        c = {"resourceType": "Consent", "provision": {"type": "deny", "provision": [
            {"type": "permit", "actor": [actor(role="doctor")], "provision": [
                {"type": "deny", "securityLabel": [{"code": "R"}],
                 "provision": [{"type": "permit", "actor": [actor(spec="394579002")]}]},
                {"type": "deny", "class": [{"code": "Condition"}],
                 "provision": [{"type": "permit", "actor": [actor(org="H1")]}]}]}]}}
        res = C.Resource("Condition", security_labels={"R"})
        out = C.compile_consent(c, res)
        both = {"role:doctor", "spec:394579002", "org:H1"}
        self.assertTrue(satisfied(out.policy, both))
        self.assertFalse(satisfied(out.policy, {"role:doctor", "spec:394579002"}))
        self.assertFalse(satisfied(out.policy, {"role:doctor", "org:H1"}))
        for attrs, want in ((both, True), ({"role:doctor", "org:H1"}, False)):
            self.assertEqual(C.evaluate(c, res, attrs, "g", "TREAT", date(2026, 6, 1)), want)
        # a deny that re-admits nobody blocks the permit entirely
        del c["provision"]["provision"][0]["provision"][1]["provision"]
        self.assertIsNone(C.compile_consent(c, res).policy)

    def test_named_deny_beats_breakglass(self):
        c = dict(PAPER_EXAMPLE)
        res = C.Resource("Observation")
        attrs = {C.EMERGENCY_ATTR, "role:nurse"}
        self.assertFalse(C.evaluate(c, res, attrs, "rn-99", "ETREAT", date(2026, 6, 1)))
        self.assertTrue(C.evaluate(c, res, attrs, "rn-1", "ETREAT", date(2026, 6, 1)))
        self.assertTrue(C.evaluate(c, res, attrs, "rn-1", "ETREAT", date(2030, 6, 1)))  # ignores period


# ---------- differential test against the reference evaluator ----------

ROLES = ["doctor", "nurse", "pharmacist"]
SPECS = ["394579002", "394584008", "394591006"]
ORGS = ["H1", "H2"]
CLASSES = ["Observation", "Condition", "MedicationRequest"]
LABELS = ["R", "PSY"]
GIDS = ["g1", "g2", "g3"]


def rand_actor(rng):
    kind = rng.random()
    if kind < 0.15:
        return actor(practitioner=rng.choice(GIDS))
    return actor(role=rng.choice(ROLES + [None]), spec=rng.choice(SPECS + [None, None]),
                 org=rng.choice(ORGS + [None]))


def rand_data(rng, prov):
    if rng.random() < 0.4: prov["class"] = [{"code": c} for c in rng.sample(CLASSES, rng.randint(1, 2))]
    if rng.random() < 0.3: prov["securityLabel"] = [{"code": rng.choice(LABELS)}]
    return prov


def rand_permit(rng, depth, purp=None):
    p = rand_data(rng, {"type": "permit"})
    if rng.random() < 0.8: p["actor"] = [rand_actor(rng) for _ in range(rng.randint(1, 2))]
    # usually one purpose set per consent (F7); sometimes a different one, which F rejects
    choice = purp if rng.random() < 0.9 else rng.choice([None, "TREAT", "HRESCH"])
    if choice: p["purpose"] = [{"code": choice}]
    kids = []
    if depth > 0:
        for _ in range(rng.randint(0, 2)):
            kids.append(rand_deny(rng, depth - 1, purp))
    if rng.random() < 0.2:
        kids.append({"type": "deny", "actor": [actor(practitioner=rng.choice(GIDS))]})
    if kids: p["provision"] = kids
    return p


def rand_deny(rng, depth, purp=None):
    d = rand_data(rng, {"type": "deny"})
    if d.keys() == {"type"}: d["securityLabel"] = [{"code": rng.choice(LABELS)}]
    if depth > 0 and rng.random() < 0.6:
        d["provision"] = [rand_permit(rng, depth - 1, purp) for _ in range(rng.randint(1, 2))]
    return d


def rand_consent(rng):
    purp = rng.choice([None, None, "TREAT", "HRESCH"])
    root = {"type": "deny", "period": {"start": "2026-01-01", "end": "2026-12-31"},
            "provision": [rand_permit(rng, 2, purp) for _ in range(rng.randint(1, 3))]}
    if rng.random() < 0.2:
        root = rand_permit(rng, 2, purp)
        root["period"] = {"start": "2026-01-01", "end": "2026-12-31"}
    return {"resourceType": "Consent", "status": "active", "provision": root,
            "extension": [{"url": C.EXT_NO_EMERGENCY, "valueBoolean": True}]}


class DifferentialTest(unittest.TestCase):
    def test_compiler_matches_reference(self):
        rng = random.Random(7)
        checked = agree = rejected = 0
        while checked < 6000:
            consent = rand_consent(rng)
            res = C.Resource(rng.choice(CLASSES), security_labels=set(rng.sample(LABELS, rng.randint(0, 1))))
            try:
                out = C.compile_consent(consent, res)
            except C.Unsupported:
                rejected += 1                 # outside the fragment F: rejected, never compiled
                continue
            for _ in range(15):
                gid = rng.choice(GIDS)
                attrs = {C.CLINICIAN_ATTR, f"role:{rng.choice(ROLES)}", f"org:{rng.choice(ORGS)}"}
                attrs |= {f"spec:{s}" for s in rng.sample(SPECS, rng.randint(0, 2))}
                attrs |= {f"id:{gid}"}
                purpose = rng.choice(["TREAT", "HRESCH", "HPAYMT"])
                on = date(2026, rng.choice([3, 6]), 1) if rng.random() < 0.9 else date(2027, 2, 1)
                ref = C.evaluate(consent, res, attrs, gid, purpose, on)
                s, e = out.side.period
                in_period = (s is None or on >= date.fromisoformat(s)) and (e is None or on <= date.fromisoformat(e))
                compiled = (satisfied(out.policy, attrs) and gid not in out.side.deny
                            and purpose in out.side.purposes and in_period)
                checked += 1
                agree += ref == compiled
                if ref != compiled:
                    self.fail(f"mismatch ref={ref} compiled={compiled}\nconsent={consent}\nres={res}\n"
                              f"attrs={attrs} gid={gid} purpose={purpose} policy={out.policy} side={out.side}")
        self.assertEqual(checked, agree)
        self.assertGreater(rejected, 0)
        print(f"\ndifferential test: {checked} triples agree; {rejected} generated consents rejected as outside F")


if __name__ == "__main__":
    unittest.main()
