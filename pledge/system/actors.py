"""PLEDGE participants wired together (paper Sections IV-V).

    Deployment   - sets up authorities, the regulator and the hospital ledger
    Patient      - uploads FHIR resources, owns consent, reads own data, audits
    Clinician    - holds standing attribute keys; requests access; decrypts
    EncryptedStore (ES), DecryptionProxy, Regulator
"""
import json
import os
import secrets
from dataclasses import dataclass, field

import hashlib

from ..crypto import lgabe, rw15, sig as bls, sigma, sym
from ..crypto.pairing import gt_rand, gt_bytes, fr_from_bytes
from ..fhir import consent as consent_mod, specialty
from ..ledger import chaincode as cc
from ..ledger.network import Ledger, Rejected
from .registry import ABDM

COUNCIL = "council"


def owner_of(attr: str) -> str:
    """The attribute-to-authority map T (paper Section III-B)."""
    if lgabe.is_ledger_attr(attr):
        return lgabe.LEDGER_AUTHORITY
    if attr.startswith("org:"):
        return attr[4:]
    if attr.startswith("dept:"):
        return attr[5:].split(".", 1)[0]
    return COUNCIL


# ---------------- infrastructure ----------------

@dataclass
class Regulator:
    box: sym.BoxKeyPair = field(default_factory=sym.BoxKeyPair.generate)
    purpose_key: sigma.ElGamalKey = field(default_factory=sigma.ElGamalKey.generate)

    def open_entry(self, tx: cc.AccessTx):
        out = []
        for it in tx.items:
            info = json.loads(sym.open_sealed(self.box, it.aud_regulator, it.tau.encode()))
            info["purpose_code"] = self.purpose_key.decrypt_small(it.purpose_ct[2], it.purpose_ct[3])
            out.append(info)
        return out


@dataclass
class StoredRecord:
    resource_id: str
    tau: str | None
    version: int
    ct_abe: object | None          # rw15.Ciphertext
    wrap: bytes | None             # W
    ct_data: bytes
    patient_wrap: bytes            # W_p
    header_hash: bytes | None
    patient_cert: dict | None = None   # cert_P (wire form of the patient's registration)


class EncryptedStore:
    """The ES: an honest-but-curious FHIR server holding only ciphertexts."""

    def __init__(self):
        self.records = {}          # resource id -> StoredRecord

    def put(self, rec: StoredRecord):
        self.records[rec.resource_id] = rec

    def get(self, resource_id) -> StoredRecord:
        return self.records[resource_id]


class DecryptionProxy:
    def transform(self, ct, tk):
        return rw15.transform(ct, tk)


class Deployment:
    def __init__(self, hospitals=("H1", "H2", "H3", "H4"), behaviours=None, now=1_780_000_000,
                 batch_size=50):
        self.council = rw15.Authority.setup(COUNCIL)
        self.council_signer = bls.SigningKey.generate()
        self.hospital_aa = {h: rw15.Authority.setup(h) for h in hospitals}
        self.hospital_signer = {h: bls.SigningKey.generate() for h in hospitals}
        self.regulator = Regulator()
        self.aa_keys = {COUNCIL: self.council_signer.vk, **{h: s.vk for h, s in self.hospital_signer.items()}}
        self.ledger = self._make_ledger(len(hospitals), behaviours=behaviours, batch_size=batch_size, now=now)
        self.store = EncryptedStore()
        self.proxy = DecryptionProxy()
        self.patient_boxes = {}        # resource id -> patient's X25519 key (legacy directory)
        self.abdm = ABDM()             # national health-ID registries (simulated)
        self.hfr = {h: self.abdm.hfr.register(h) for h in hospitals}
        self.registrations = {}        # AA side: ABHA -> (aa, psi salt), for rotation

    # ---- patient registration (Section V-B): the registering hospital's AA certifies ----
    def certify_patient(self, hospital, assertion, nonce, box_pk, vk_bytes, psi_salt, pop,
                        expiry="2031-12-31"):
        if not self.abdm.idp.verify(assertion, nonce):
            raise PermissionError("health-ID assertion invalid")
        pop_body = cc.digest("patient-pop", {"vk": vk_bytes.hex(), "box_pk": box_pk.hex(), "nonce": nonce})
        if not bls.verify(cc.g2_load(vk_bytes), pop_body, pop):
            raise PermissionError("no proof of possession of the signing key")
        abha = assertion.subject
        prev = self.registrations.get(abha)
        rotate = prev is not None
        if rotate:
            hospital, psi_salt = prev           # same AA, same pseudonym
        psi = hashlib.sha256(b"PLEDGE|psi|" + abha.encode() + b"|" + psi_salt).hexdigest()
        tx = cc.PatientRegTx(psi, box_pk, vk_bytes, expiry, hospital, rotate=rotate)
        tx.sig = self.hospital_signer[hospital].sign(tx.body())
        self.registrations[abha] = (hospital, psi_salt)
        return tx

    def verify_patient_cert(self, cert: dict) -> bytes:
        """Clinician side: check cert_P from a header and return the patient's box key."""
        tx = cc.PatientRegTx(cert["psi"], bytes.fromhex(cert["box_pk"]), bytes.fromhex(cert["vk"]),
                             cert["expiry"], cert["aa"], cert["rotate"])
        vk = self.aa_keys.get(tx.aa)
        if vk is None or not bls.verify(vk, tx.body(), cc.g1_load(bytes.fromhex(cert["sig"]))):
            raise PermissionError("patient certificate not signed by a known authority")
        return tx.box_pk

    def _make_ledger(self, n, **kw):
        """In-process BFT simulator; FabricDeployment overrides this with the real network."""
        return Ledger(n, self.aa_keys, self.regulator.purpose_key.pk, **kw)

    @property
    def pks(self):
        pks = {COUNCIL: self.council.pk, lgabe.LEDGER_AUTHORITY: self.ledger.pub.pk}
        pks.update({h: a.pk for h, a in self.hospital_aa.items()})
        return pks

    # ---- enrolment of clinicians (standing keys + ledger credential) ----
    def enroll(self, gid, role, specialty_code=None, hospital=None, dept=None, emergency=False, hpr=None):
        """Clinician registration (Section V-B). The council AA checks the HPR record and
        the clinician's proof of possession before issuing keys and submitting Reg_C.
        Tests pass readable GIDs; a deployment uses GID = (HPR ID, key epoch)."""
        c = Clinician(gid, self)
        if hpr is None:
            hpr = self.abdm.hpr.register(gid, "NMC", f"REG-{gid}")
        nonce = secrets.token_hex(8)
        record = self.abdm.hpr.assert_record(hpr, nonce)
        if not self.abdm.hpr.verify(record, nonce) or record.claims.get("status") != "verified":
            raise PermissionError("HPR record not verified")
        pop_body = cc.digest("cred-pop", {"gid": gid, "vk": c.signer.vk_bytes.hex(), "nonce": nonce})
        if not bls.verify(c.signer.vk, pop_body, c.signer.sign(pop_body)):
            raise PermissionError("no proof of possession of the signing key")
        c.hpr = hpr
        attrs = [consent_mod.CLINICIAN_ATTR, f"role:{role}", f"id:{gid}"]
        if specialty_code:
            attrs += [f"spec:{s}" for s in specialty.closure(specialty_code)]
        if emergency:
            attrs.append(consent_mod.EMERGENCY_ATTR)
        for a in attrs:
            c.key.add(a, self.council.keygen(gid, a))
        if hospital:
            hattrs = [f"org:{hospital}"] + ([f"dept:{hospital}.{dept}"] if dept else [])
            for a in hattrs:
                c.key.add(a, self.hospital_aa[hospital].keygen(gid, a))
        tx = cc.CredentialTx(gid, c.signer.vk_bytes, COUNCIL)
        tx.sig = self.council_signer.sign(tx.body())
        self.ledger.submit(tx)
        self.ledger.flush()
        return c

    def revoke(self, gid):
        tx = cc.RevokeTx(gid, COUNCIL)
        tx.sig = self.council_signer.sign(tx.body())
        self.ledger.submit(tx)
        return tx


# ---------------- patient ----------------

class Patient:
    """The patient's application (Sections V-A to V-C, V-I).

    Keys: a box key (W_p, E_aud) and a BLS key vk_P, certified against the
    patient's ABHA number by a hospital AA under the pseudonym psi_P; a private
    seed s_P from which every per-record value on the ledger is derived (update
    key, purpose key, deny-list salt), so that validators cannot group a
    patient's records; and a separate salt r_P for psi_P, the only secret the AA
    sees (the AA must not learn s_P, or it could forge side-record updates).
    """

    def __init__(self, pid: str, dep: Deployment, consent: dict, hospital=None, register=True):
        self.pid, self.dep, self.consent = pid, dep, consent
        self.signer = bls.SigningKey.generate()        # vk_P: patient-level operations only
        self.box = sym.BoxKeyPair.generate()
        self.seed = os.urandom(32)                      # s_P: never leaves the device
        self.psi_salt = os.urandom(16)                  # r_P: shared with the registering AA
        self.taus = {}                 # resource id -> current tau
        self.all_taus = set()          # every tag this patient ever registered (audit)
        self.resources = {}            # resource id -> FHIR json (patient's own copy)
        self.abha = dep.abdm.idp.enrol(pid)
        self.cert = None
        if register:
            self.register(hospital or next(iter(dep.hospital_aa)))

    # ---- registration and recovery (Section V-B) ----
    def _registration_tx(self, hospital):
        idp = self.dep.abdm.idp
        txn, code = idp.request_otp(self.abha)          # code arrives on the patient's phone
        nonce = secrets.token_hex(8)
        assertion = idp.verify_otp(txn, code, nonce)
        pop_body = cc.digest("patient-pop", {"vk": self.signer.vk_bytes.hex(),
                                             "box_pk": self.box.pk.hex(), "nonce": nonce})
        return self.dep.certify_patient(hospital, assertion, nonce, self.box.pk, self.signer.vk_bytes,
                                        self.psi_salt, self.signer.sign(pop_body))

    def register(self, hospital):
        tx = self._registration_tx(hospital)
        self.dep.ledger.submit(tx)
        self.dep.ledger.flush()
        self.cert = tx.to_wire()
        return tx

    def recover_device(self):
        """Lost device: new keys, re-authentication, rotation of the binding. The seed s_P
        and the old box key come from the patient's recovery backup."""
        old_box = self.box
        self.signer, self.box = bls.SigningKey.generate(), sym.BoxKeyPair.generate()
        tx = self.register(None)
        self._old_boxes = getattr(self, "_old_boxes", []) + [old_box]
        return tx

    # ---- per-record keys derived from s_P ----
    def _owner_key(self, tau):
        return bls.SigningKey(fr_from_bytes(sym.kdf(self.seed, b"PLEDGE|owner|" + tau.encode(), 48)))

    def _purpose_key(self, tau):
        return sigma.ElGamalKey(fr_from_bytes(sym.kdf(self.seed, b"PLEDGE|purpose|" + tau.encode(), 48)))

    def _salt(self, tau):
        return sym.kdf(self.seed, b"PLEDGE|salt|" + tau.encode(), 16)

    # ---- encryption ----
    def _header(self, res_json: dict, version: int, dek: bytes):
        view = consent_mod.Resource.from_fhir(res_json)
        compiled = consent_mod.compile_consent(self.consent, view)
        tau, ct_abe, wrap, hh = None, None, None, None
        branches = []
        if compiled.policy is not None or compiled.side.emergency:
            tau = secrets.token_hex(16)
        if compiled.policy is not None:
            branches.append(f"(({compiled.policy}) AND {lgabe.access_attr(tau)})")
        if compiled.side.emergency:
            branches.append(f"({consent_mod.EMERGENCY_ATTR} AND {lgabe.emergency_attr(tau)})")
        if branches:
            policy = " OR ".join(branches)
            M = gt_rand()
            ct_abe = rw15.encrypt(M, policy, self.dep.pks, owner_of)
            wrap = sym.aead_encrypt(sym.kwk_from_gt(M, tau, version), dek, tau.encode())
            hh = cc.H(tau, version, ct_abe.serialize(), wrap)
        return tau, ct_abe, wrap, hh, compiled

    def _encrypt(self, res_json: dict, version: int):
        rid = f'{res_json["resourceType"]}/{res_json["id"]}'
        dek = sym.new_dek()
        tau, ct_abe, wrap, hh, compiled = self._header(res_json, version, dek)
        ad = f"{rid}|{version}".encode()
        ct_data = sym.aead_encrypt(dek, json.dumps(res_json).encode(), ad)
        wp = sym.seal(self.box.pk, dek, ad)
        rec = StoredRecord(rid, tau, version, ct_abe, wrap, ct_data, wp, hh, self.cert)
        return rec, compiled

    def _register(self, rec: StoredRecord, compiled, retires: str | None = None):
        side = compiled.side
        owner = self._owner_key(rec.tau)
        salt = self._salt(rec.tau)
        tx = cc.RecordTx(rec.tau, rec.header_hash, side.purpose_codes(),
                         [cc.deny_tag(salt, g, rec.tau) for g in sorted(side.deny)], salt,
                         side.period, side.emergency, owner.vk_bytes, self._purpose_key(rec.tau).pk,
                         retires=retires)
        tx.sig = owner.sign(tx.body())
        if retires is not None:
            tx.retire_sig = self._owner_key(retires).sign(tx.body())
        self.dep.ledger.submit(tx)
        self.all_taus.add(rec.tau)

    def _retire(self, tau):
        """Retire a tag without a successor (the new consent admits no clinician)."""
        prev = self.dep.ledger.state.records[tau]
        tx = cc.RecordTx(tau, prev.header_hash, prev.purposes, prev.deny, prev.salt, prev.period,
                         prev.emergency, prev.owner_vk, prev.patient_purpose_pk, retires=tau)
        tx.sig = self._owner_key(tau).sign(tx.body())
        tx.retire_sig = tx.sig
        self.dep.ledger.submit(tx)

    def upload(self, res_json: dict, version: int = 1):
        rec, compiled = self._encrypt(res_json, version)
        self.dep.store.put(rec)
        self.dep.patient_boxes[rec.resource_id] = self.box.pk
        self.resources[rec.resource_id] = res_json
        self.taus[rec.resource_id] = rec.tau
        if rec.tau:
            self._register(rec, compiled)
        return rec

    def update_consent(self, new_consent: dict, strict: bool = False):
        """Re-key every record under the new consent (Section V-I).

        Default: header-only re-key. A fresh M' and tag tau' under the new policy
        re-wrap the same DEK; CT_data and W_p are untouched; the registration of
        tau' retires tau in the same transaction.
        strict=True also draws a new DEK and re-encrypts CT_data (new version),
        which cuts off clinicians who already hold an access key for tau."""
        self.consent = new_consent
        for rid, res in list(self.resources.items()):
            old = self.dep.store.get(rid)
            if strict:
                rec, compiled = self._encrypt(res, old.version + 1)
            else:
                ad = f"{rid}|{old.version}".encode()
                dek = sym.open_sealed(self.box, old.patient_wrap, ad)
                tau, ct_abe, wrap, hh, compiled = self._header(res, old.version, dek)
                rec = StoredRecord(rid, tau, old.version, ct_abe, wrap, old.ct_data, old.patient_wrap,
                                   hh, self.cert)
            self.dep.store.put(rec)
            self.taus[rid] = rec.tau
            if rec.tau:
                self._register(rec, compiled, retires=old.tau)
            elif old.tau:
                self._retire(old.tau)

    def read_own(self, rid):
        rec = self.dep.store.get(rid)
        ad = f"{rid}|{rec.version}".encode()
        dek = sym.open_sealed(self.box, rec.patient_wrap, ad)
        return json.loads(sym.aead_decrypt(dek, rec.ct_data, ad))

    def audit_trail(self):
        """Every logged access to this patient's records, with verified receipts."""
        out = []
        boxes = [self.box] + list(getattr(self, "_old_boxes", []))
        for r in self.dep.ledger.receipts_for(self.all_taus):
            if not self.dep.ledger.verify_receipt(r):
                raise ValueError("invalid receipt")
            for it in r.tx.items:
                if it.tau in self.all_taus:
                    info = None
                    for b in boxes:
                        try:
                            info = json.loads(sym.open_sealed(b, it.aud_patient, it.tau.encode()))
                            break
                        except Exception:
                            continue
                    info = info or {}
                    info["clinician"] = r.tx.gid
                    info["breakglass"] = r.tx.breakglass
                    info["purpose"] = sigma.PURPOSE_NAMES.get(
                        self._purpose_key(it.tau).decrypt_small(it.purpose_ct[0], it.purpose_ct[1]))
                    info["block"] = r.height
                    out.append(info)
        return out


# ---------------- clinician ----------------

class AccessDenied(Exception):
    pass


class Clinician:
    def __init__(self, gid, dep: Deployment):
        self.gid, self.dep = gid, dep
        self.signer = bls.SigningKey.generate()
        self.key = rw15.UserKey(gid)
        self.access_keys = {}          # tau -> (K, K')

    # ---- step 1-2: fetch headers, build the access entry ----
    def build_request(self, rids, purpose="TREAT", S=None, breakglass=False, retry_of=None):
        ledger = self.dep.ledger
        S = tuple(sorted(S or range(1, ledger.k + 1)))
        nonce = secrets.token_hex(12)
        items = []
        for rid in rids:
            rec = self.dep.store.get(rid)
            if rec.ct_abe is None:
                raise AccessDenied("record is readable only by the patient")
            standing = self.key.attrs | {lgabe.emergency_attr(rec.tau) if breakglass
                                         else lgabe.access_attr(rec.tau)}
            if rec.ct_abe.matrix.solve(standing) is None:
                raise AccessDenied("attributes do not satisfy the consent policy (nothing logged)")
            side = ledger.state.records[rec.tau]
            allowed = [sigma.PURPOSES["ETREAT"]] if breakglass else side.purposes
            ctx = cc.purpose_ctx(self.gid, rec.tau, nonce)
            ct, proof = sigma.encrypt_purpose(sigma.PURPOSES[purpose], side.patient_purpose_pk,
                                              ledger.state.regulator_purpose_pk, allowed, ctx)
            payload = json.dumps({"resource": rid, "type": self._rtype(rec), "purpose": purpose}).encode()
            patient_box = self._patient_box(rid)
            items.append(cc.AccessItem(rec.tau, ct, proof,
                                       sym.seal(patient_box, payload, rec.tau.encode()),
                                       sym.seal(self.dep.regulator.box.pk, payload, rec.tau.encode())))
        tx = cc.AccessTx(self.gid, items, ledger.now, nonce, S, breakglass=breakglass, retry_of=retry_of)
        tx.sig = self.signer.sign(tx.body())
        return tx

    def _rtype(self, rec):
        return rec.resource_id.split("/", 1)[0]

    def _patient_box(self, rid):
        # E_aud is addressed to the key in cert_P, carried in the record's header and
        # checked against the certifying AA's public key (Section V-B)
        rec = self.dep.store.get(rid)
        if rec.patient_cert is not None:
            return self.dep.verify_patient_cert(rec.patient_cert)
        return self.dep.patient_boxes[rid]

    # ---- step 3-5: submit and wait for the block ----
    def request(self, rids, purpose="TREAT", S=None, cosigner=None, retry_of=None):
        tx = self.build_request(rids, purpose, S, breakglass=cosigner is not None, retry_of=retry_of)
        if cosigner is not None:
            tx.cosigner = cosigner.gid
            tx.sig = self.signer.sign(tx.body())
            tx.cosig = cosigner.signer.sign(tx.body())
        try:
            self.dep.ledger.submit(tx)
        except Rejected as e:
            raise AccessDenied(str(e)) from e
        self.dep.ledger.flush()
        return tx

    # ---- step 6: collect partial keys, combine, decrypt ----
    def collect(self, tx):
        got = {}
        for part in self.dep.ledger.shares_for(self.gid, tx):
            got.setdefault(part.attr, []).append(part)
        missing = []
        for it in tx.items:
            attr = lgabe.emergency_attr(it.tau) if tx.breakglass else lgabe.access_attr(it.tau)
            parts = [p for p in got.get(attr, []) if lgabe.share_verify(self.dep.ledger.pub, p)]
            if len(parts) < self.dep.ledger.k:
                missing.append(it.tau)
                continue
            self.access_keys[attr] = lgabe.combine(self.dep.ledger.pub, parts[: self.dep.ledger.k])
        return missing

    def open(self, rid, use_proxy=False):
        rec = self.dep.store.get(rid)
        if rec.ct_abe is None:
            raise AccessDenied("record is readable only by the patient")
        key = rw15.UserKey(self.gid, dict(self.key.comps))
        for attr in (lgabe.access_attr(rec.tau), lgabe.emergency_attr(rec.tau)):
            if attr in self.access_keys:
                key.add(attr, self.access_keys[attr])
        try:
            if use_proxy:
                tk, z = rw15.make_transform_key(key)
                M = rw15.finish(rec.ct_abe, self.dep.proxy.transform(rec.ct_abe, tk), z)
            else:
                M = rw15.decrypt(rec.ct_abe, key)
        except rw15.NotSatisfied as e:
            raise AccessDenied("no access key for this record: request access first") from e
        try:
            dek = sym.aead_decrypt(sym.kwk_from_gt(M, rec.tau, rec.version), rec.wrap, rec.tau.encode())
        except Exception as e:
            raise AccessDenied("decryption failed (key not valid for this clinician/record)") from e
        ad = f"{rid}|{rec.version}".encode()
        return json.loads(sym.aead_decrypt(dek, rec.ct_data, ad))

    def access(self, rids, purpose="TREAT", use_proxy=False, cosigner=None):
        """Full flow with automatic retry if a designated service misbehaves."""
        ledger = self.dep.ledger
        tx = self.request(rids, purpose, cosigner=cosigner)
        missing = self.collect(tx)
        tried = set(tx.S)
        while missing:
            spare = [i for i in range(1, ledger.n + 1) if i not in tried]
            if not spare:
                raise AccessDenied("not enough honest key-share services")
            good = self._good_services(tx)
            S = tuple(sorted((list(good) + spare)[: ledger.k]))
            tried |= set(S)
            tx = self.request(rids, purpose, S=S, retry_of=tx.entry_id, cosigner=cosigner)
            missing = self.collect(tx)
        return [self.open(r, use_proxy) for r in rids]

    def _good_services(self, tx):
        return {p.index for p in self.dep.ledger.shares_for(self.gid, tx)
                if lgabe.share_verify(self.dep.ledger.pub, p)}
