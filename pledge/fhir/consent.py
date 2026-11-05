"""FHIR R4 Consent -> ABE policy compiler (paper Section 5.3, Algorithm 1).

Every provision is split into
  * data-side conditions  (class, code, securityLabel, dataPeriod): evaluated
    now, because the resource being encrypted is known;
  * requester-side conditions (actor): become ABE attributes, except deny
    rules naming individual practitioners, which go to the deny list that
    chaincode checks;
  * purpose and the consent period: go to the side record checked by chaincode.

PLEDGE actor profile (documented in the paper):
  * actor.role codings are combined with AND across code systems:
      practitioner-role code  -> role:<code>
      SNOMED CT specialty     -> spec:<code>
      urn:pledge:department     -> dept:<org>.<code>   (org taken from actor.reference)
  * actor.reference Organization/<id>  -> org:<id>
  * actor.reference Practitioner/<gid> -> id:<gid> in permits, deny-list entry in denies
  * several actors in one provision are alternatives (OR).

Supported fragment F (paper Section 5.3; anything else raises Unsupported):
F1 status active (otherwise only the patient can read); F2 no provision.data;
F3 actors as above; F4 provision types alternate (named denies anywhere);
F5 denies are data denies or named-practitioner denies; F6 period only on the
root; F7 all permits that apply to one resource carry the same purpose set;
F8 no free-text policyRule.

Several applying data denies under one permit resolve by deny-overrides: a
requester must be re-admitted by every one of them.
"""
from dataclasses import dataclass, field
from datetime import date

from ..crypto.lsss import to_string
from ..crypto.sigma import PURPOSES

SYS_ROLE = "http://terminology.hl7.org/CodeSystem/practitioner-role"
SYS_SNOMED = "http://snomed.info/sct"
SYS_DEPT = "urn:pledge:department"
SYS_PURPOSE = "http://terminology.hl7.org/CodeSystem/v3-ActReason"
EXT_NO_EMERGENCY = "urn:pledge:consent:no-emergency-access"

CLINICIAN_ATTR = "pledge:clinician"          # held by every licensed clinician
EMERGENCY_ATTR = "role:emergency-clinician"
DEFAULT_PURPOSES = ("TREAT", "ETREAT")


class Unsupported(ValueError):
    pass


@dataclass
class Resource:
    """The data-side view of the FHIR resource being encrypted."""
    resource_type: str
    codes: set = field(default_factory=set)            # e.g. {"http://loinc.org|8480-6"}
    security_labels: set = field(default_factory=set)  # e.g. {"R", "PSY"}
    effective: date | None = None

    @classmethod
    def from_fhir(cls, res: dict):
        codes = {f"{c.get('system', '')}|{c.get('code')}" for c in res.get("code", {}).get("coding", [])}
        labels = {s.get("code") for s in res.get("meta", {}).get("security", [])}
        eff = res.get("effectiveDateTime") or res.get("recordedDate") or res.get("onsetDateTime")
        return cls(res["resourceType"], codes, labels, date.fromisoformat(eff[:10]) if eff else None)


@dataclass
class SideRecord:
    purposes: list
    deny: set
    period: tuple          # (start ISO date or None, end ISO date or None)
    emergency: bool

    def purpose_codes(self):
        return sorted(PURPOSES[p] for p in self.purposes)


@dataclass
class Compiled:
    policy: str | None     # P_consent (None: only the patient can read)
    side: SideRecord


# ---------------- helpers ----------------

def _codings(cc):
    return cc.get("coding", []) if cc else []


def _in_period(d, period):
    if not period or d is None:
        return True
    s, e = period.get("start"), period.get("end")
    if s and d < date.fromisoformat(s[:10]):
        return False
    if e and d > date.fromisoformat(e[:10]):
        return False
    return True


def _data_match(prov, r: Resource) -> bool:
    classes = {c.get("code") for c in prov.get("class", [])}
    if classes and r.resource_type not in classes:
        return False
    codes = {f"{c.get('system', '')}|{c.get('code')}" for cc in prov.get("code", []) for c in _codings(cc)}
    if codes and not (codes & r.codes):
        return False
    labels = {s.get("code") for s in prov.get("securityLabel", [])}
    if labels and not (labels & r.security_labels):
        return False
    return _in_period(r.effective, prov.get("dataPeriod"))


def _actor_tree(actor):
    """One actor -> (attribute conjunction tree or None, individual gid or None)."""
    ref = actor.get("reference", {}).get("reference", "")
    org = ref.split("/", 1)[1] if ref.startswith("Organization/") else None
    if ref.startswith("Practitioner/"):
        return None, ref.split("/", 1)[1]
    attrs = []
    for c in _codings(actor.get("role")):
        sysu, code = c.get("system"), c.get("code")
        if sysu == SYS_ROLE:
            attrs.append(f"role:{code}")
        elif sysu == SYS_SNOMED:
            attrs.append(f"spec:{code}")
        elif sysu == SYS_DEPT:
            if not org:
                raise Unsupported("department role needs an Organization reference")
            attrs.append(f"dept:{org}.{code}")
        else:
            raise Unsupported(f"unsupported actor role system {sysu}")
    if org:
        attrs.append(f"org:{org}")
    if not attrs:
        attrs = [CLINICIAN_ATTR]
    leaves = [("attr", a) for a in attrs]
    return (leaves[0] if len(leaves) == 1 else ("and", leaves)), None


def _requester(prov):
    """-> (OR-tree over attribute actors or None when unrestricted, set of individual gids)."""
    trees, gids = [], set()
    for a in prov.get("actor", []):
        t, gid = _actor_tree(a)
        if gid:
            gids.add(gid)
        else:
            trees.append(t)
    tree = None if not trees else (trees[0] if len(trees) == 1 else ("or", trees))
    return tree, gids


def _and(parts):
    parts = [p for p in parts if p is not None]
    if not parts:
        return ("attr", CLINICIAN_ATTR)
    return parts[0] if len(parts) == 1 else ("and", parts)


# ---------------- compiler ----------------

def _purpose_set(node):
    """The purposes a permit names, or TREAT when it names none (F7). ETREAT is
    reserved for break-glass and added to the side record when emergency access is on."""
    own = {p.get("code") for p in node.get("purpose", [])}
    unknown = own - set(PURPOSES)
    if unknown:
        raise Unsupported(f"unknown purpose code {sorted(unknown)[0]}")
    own.discard("ETREAT")
    return frozenset(own) if own else frozenset({"TREAT"})


def compile_consent(consent: dict, resource: Resource) -> Compiled:
    """Algorithm 1 (Section 5.3): check C against the fragment F, then apply the
    resolution rules to resource r. Raises Unsupported for consents outside F."""
    if consent.get("resourceType") != "Consent":
        raise Unsupported("not a Consent resource")
    if consent.get("status") not in (None, "active"):                       # F1
        return Compiled(None, SideRecord(list(DEFAULT_PURPOSES), set(), (None, None), False))
    if consent.get("policyRule", {}).get("text"):                           # F8
        raise Unsupported("free-text policyRule is outside the supported fragment")
    root = consent.get("provision", {"type": "deny"})
    deny_list: set = set()
    purpose_sets: set = set()

    def check_shape(node, is_root):
        if "data" in node:                                                   # F2
            raise Unsupported("provision.data (individual resource instances) is outside the fragment")
        if not is_root and node.get("period"):                               # F6
            raise Unsupported("period below the root provision is outside the supported fragment")
        for k in node.get("provision", []):
            kind, kkind = node.get("type", "permit"), k.get("type", "permit")
            kreq, kgids = _requester(k)
            if kkind == "deny" and kreq is not None:                         # F5
                raise Unsupported("deny rules on roles/attributes are non-monotone; "
                                  "only data denies and named practitioners are supported")
            if kkind == kind and not (kkind == "deny" and kgids):            # F4
                raise Unsupported(f"{kind} nested directly in {kind}: provisions must alternate")
            check_shape(k, False)

    check_shape(root, True)

    def walk(node, kind):
        """Grant tree for an applying provision (None: admits nobody), without inherited context."""
        kids = [k for k in node.get("provision", []) if _data_match(k, resource)]
        for k in kids:                           # applying named denies -> record deny list
            if k.get("type", "permit") == "deny" and _requester(k)[1]:
                deny_list.update(_requester(k)[1])
        if kind == "permit":
            req, gids = _requester(node)
            if gids:
                ids = [("attr", f"id:{g}") for g in sorted(gids)]
                parts = ([req] if req else []) + ids
                req = parts[0] if len(parts) == 1 else ("or", parts)
            purpose_sets.add(_purpose_set(node))
            data_denies = [k for k in kids if k.get("type", "permit") == "deny" and not _requester(k)[1]]
            reopened = [walk(d, "deny") for d in data_denies]   # walk all: collects named denies
            if any(g is None for g in reopened):  # deny-overrides: every applying deny must re-admit
                return None
            return _and(([req] if req else []) + reopened)
        trees = [t for k in kids if k.get("type", "permit") == "permit"
                 for t in [walk(k, "permit")] if t is not None]
        if not trees:
            return None
        return trees[0] if len(trees) == 1 else ("or", trees)

    tree = walk(root, root.get("type", "deny")) if _data_match(root, resource) else None
    if len(purpose_sets) > 1:                                                # F7
        raise Unsupported("permits that apply to the same resource carry different purpose sets")
    emergency = not any(e.get("url") == EXT_NO_EMERGENCY and e.get("valueBoolean")
                        for e in consent.get("extension", []))
    # The break-glass branch (role:emergency-clinician AND eacc:tau) is added by the
    # encryptor next to (P_consent AND acc:tau); see Section 5.9.
    policy = to_string(tree) if tree is not None else None
    period = root.get("period", {})
    plist = sorted(next(iter(purpose_sets))) if purpose_sets else ["TREAT"]
    if emergency and "ETREAT" not in plist:
        plist.append("ETREAT")
    return Compiled(policy, SideRecord(plist, deny_list, (period.get("start"), period.get("end")), emergency))


# ---------------- reference evaluator (for differential testing, Theorem 4) ----------------

def _actor_matches(actor, attrs, gid):
    ref = actor.get("reference", {}).get("reference", "")
    if ref.startswith("Practitioner/"):
        return gid == ref.split("/", 1)[1]
    tree, _ = _actor_tree(actor)
    needed = {tree[1]} if tree[0] == "attr" else {leaf[1] for leaf in tree[1]}
    return needed <= set(attrs)


def _req_matches(node, attrs, gid):
    actors = node.get("actor", [])
    return not actors or any(_actor_matches(a, attrs, gid) for a in actors)


def evaluate(consent: dict, resource: Resource, attrs, gid: str, purpose: str, on: date) -> bool:
    """Direct R4 evaluation under the PLEDGE profile, independent of the compiler."""
    if consent.get("status") not in (None, "active"):
        return False
    root = consent.get("provision", {"type": "deny"})

    def named_deny(node):
        if not _data_match(node, resource):
            return False
        for k in node.get("provision", []):
            if k.get("type", "permit") == "deny" and _requester(k)[1] and _data_match(k, resource):
                if gid in _requester(k)[1]:
                    return True
            if named_deny(k):
                return True
        return False

    if named_deny(root):
        return False                     # named denies override every grant, break-glass included
    if EMERGENCY_ATTR in attrs and not any(e.get("url") == EXT_NO_EMERGENCY and e.get("valueBoolean")
                                           for e in consent.get("extension", [])):
        return purpose == "ETREAT"       # break-glass override (Section 5.9); ignores the period
    if not _in_period(on, root.get("period")):
        return False

    def purposes_of(node, kind):
        """Union of purposes over the permit provisions that apply to this resource."""
        if not _data_match(node, resource):
            return set()
        out = set()
        if kind == "permit":
            out |= (({p.get("code") for p in node.get("purpose", [])} & set(PURPOSES)) - {"ETREAT"}) or {"TREAT"}
        want = "deny" if kind == "permit" else "permit"
        for k in node.get("provision", []):
            if k.get("type", "permit") == want and not (want == "deny" and _requester(k)[1]):
                out |= purposes_of(k, want)
        return out

    allowed = purposes_of(root, root.get("type", "deny")) or {"TREAT"}
    if not any(e.get("url") == EXT_NO_EMERGENCY and e.get("valueBoolean") for e in consent.get("extension", [])):
        allowed.add("ETREAT")
    if purpose not in allowed:
        return False

    def decide(node, kind):
        kids = [k for k in node.get("provision", [])
                if _data_match(k, resource) and not (k.get("type", "permit") == "deny" and _requester(k)[1])]
        if kind == "permit":
            denies = [k for k in kids if k.get("type", "permit") == "deny"]
            return all(decide(k, "deny") for k in denies) if denies else True   # deny-overrides
        permits = [k for k in kids if k.get("type", "permit") == "permit" and _req_matches(k, attrs, gid)]
        return any(decide(k, "permit") for k in permits)

    if not _data_match(root, resource) or not _req_matches(root, attrs, gid):
        return False
    return decide(root, root.get("type", "deny"))
