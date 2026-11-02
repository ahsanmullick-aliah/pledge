"""Run the PLEDGE actors against the real Hyperledger Fabric network (stage 2).

FabricLedger implements the interface the actors use (submit, flush, state,
shares_for, pub, n, k, now) on top of:
  * the Go gateway bridge  (fabric/cmd/gateway)  -> endorse / order / commit
  * the Go key-share services (fabric/cmd/kss)  -> partial keys for committed entries

FabricDeployment runs the DKG for the ledger authority, writes each key-share
service's secret file, and initialises the chaincode with the authorities'
verification keys.
"""
import json
import time
import urllib.error
import urllib.request
from pathlib import Path

from .crypto import lgabe
from .crypto.pairing import g1_bytes, g1_load, g2_bytes, g2_load, fr_bytes
from .ledger import chaincode as cc
from .ledger.network import Rejected
from .system.actors import Deployment

FN = {cc.CredentialTx: "RegisterCredential", cc.RevokeTx: "Revoke",
      cc.RecordTx: "RegisterRecord", cc.AccessTx: "Access", cc.PatientRegTx: "RegisterPatient"}


def _post(url, body, timeout=120):
    req = urllib.request.Request(url, data=json.dumps(body).encode(), method="POST",
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"{}")


def _get(url, timeout=10):
    try:
        with urllib.request.urlopen(url, timeout=timeout) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, None


class _RecordView:
    """Record side records read back from the chaincode state."""

    def __init__(self, ledger):
        self.ledger = ledger

    def get(self, tau, default=None):
        st, body = _post(self.ledger.gateway + "/evaluate", {"fn": "GetRecord", "args": [tau]})
        if st != 200 or not body.get("result"):
            return default
        w = json.loads(body["result"])
        r = cc.RecordTx(w["tau"], bytes.fromhex(w["header_hash"]), w["purposes"], w["deny"],
                        bytes.fromhex(w["salt"]), tuple(w["period"]), w["emergency"],
                        bytes.fromhex(w["owner_vk"]), g1_load(bytes.fromhex(w["patient_purpose_pk"])),
                        retires=w.get("retires"))
        r.retired = bool(w.get("retired"))
        return r

    def __getitem__(self, tau):
        r = self.get(tau)
        if r is None:
            raise KeyError(tau)
        return r

    def __contains__(self, tau):
        return self.get(tau) is not None


class _StateView:
    def __init__(self, ledger, regulator_pk):
        self.records = _RecordView(ledger)
        self.regulator_purpose_pk = regulator_pk


class FabricLedger:
    def __init__(self, profile, gateway, kss_urls, regulator_pk, pub):
        self.profile = profile
        self.n, self.k, self.f = profile["n"], profile["k"], profile["f"]
        self.gateway = gateway.rstrip("/")
        self.kss_urls = kss_urls                    # index -> base URL
        self.pub = pub
        self.state = _StateView(self, regulator_pk)
        self.timings = []                           # per submitted tx
        self.share_wait = 5.0

    @property
    def now(self):
        return int(time.time())

    def submit(self, tx):
        t0 = time.perf_counter()
        status, body = _post(self.gateway + "/submit", {"fn": FN[type(tx)],
                                                       "arg": cc.canon(tx.to_wire()).decode()})
        rec = {"fn": FN[type(tx)], "http": status, "wall_ms": (time.perf_counter() - t0) * 1000,
               "bytes": len(cc.canon(tx.to_wire()))}
        if status == 409:
            rec["rejected"] = body.get("error", "")
            self.timings.append(rec)
            raise Rejected(_reason(body.get("error", "endorsement refused")))
        if status != 200:
            raise RuntimeError(f"gateway error {status}: {body}")
        rec.update({k: body[k] for k in ("endorse_ms", "submit_ms", "commit_ms", "block", "valid", "code")})
        self.timings.append(rec)
        tx._fabric = rec
        return tx

    def flush(self):
        return []                                   # the bridge waits for commit already

    def shares_for(self, gid, tx):
        out, deadline = [], time.time() + self.share_wait
        pending = set(tx.S)
        t0 = time.perf_counter()
        while pending and time.time() < deadline:
            for i in sorted(pending):
                st, body = _get(f"{self.kss_urls[i]}/shares?entry={tx.entry_id}")
                if st == 200 and body:
                    for p in body["parts"] or []:
                        if p["gid"] != gid:
                            continue
                        try:
                            out.append(lgabe.PartialKey(p["index"], tuple(p["S"]), p["gid"], p["attr"],
                                                        g1_load(bytes.fromhex(p["K"])),
                                                        g2_load(bytes.fromhex(p["Kp"]))))
                        except ValueError:
                            pass        # malformed share from a faulty service: treated as missing
                    pending.discard(i)
            if pending:
                time.sleep(0.02)
        if getattr(tx, "_fabric", None) is not None:
            tx._fabric["shares_ms"] = (time.perf_counter() - t0) * 1000
        return out


def _reason(err: str) -> str:
    # gateway errors embed the chaincode message; keep the readable part
    for marker in ("chaincode response 500, ", "message="):
        if marker in err:
            return err.split(marker, 1)[1].split(",", 1)[0].strip()
    return err


class FabricDeployment(Deployment):
    """Same actors as the simulator, wired to the Fabric network."""

    def __init__(self, profile_path, gateway="http://127.0.0.1:8800", kss_base_port=8800,
                 secrets_dir=None, init_chaincode=True, **kw):
        self.profile = json.loads(Path(profile_path).read_text())
        n = self.profile["n"]
        self._gateway = gateway
        self._kss = {i: f"http://127.0.0.1:{kss_base_port + i}" for i in range(1, n + 1)}
        self._secrets_dir = Path(secrets_dir or Path(profile_path).parent / "kss")
        self._init_cc = init_chaincode
        hospitals = tuple(f"H{i}" for i in range(1, n + 1))
        super().__init__(hospitals=hospitals, **kw)

    def _make_ledger(self, n, **kw):
        k = self.profile["k"]
        pub, secrets, _ = lgabe.run_dkg(n, k)
        self._secrets_dir.mkdir(parents=True, exist_ok=True)
        for s in secrets:
            (self._secrets_dir / f"kss{s.index}.json").write_text(json.dumps(
                {"index": s.index, "alpha": fr_bytes(s.alpha).hex(), "y": fr_bytes(s.y).hex(), "n": n, "k": k}))
        ledger = FabricLedger(self.profile, self._gateway, self._kss, self.regulator.purpose_key.pk, pub)
        if self._init_cc:
            cfg = {"aa_keys": {a: g2_bytes(vk).hex() for a, vk in self.aa_keys.items()},
                   "regulator_purpose_pk": g1_bytes(self.regulator.purpose_key.pk).hex(), "n": n, "k": k}
            deadline = time.time() + 120          # gossip/discovery may still be converging
            while True:
                st, body = _post(ledger.gateway + "/submit", {"fn": "InitConfig", "arg": json.dumps(cfg)})
                if st == 200 and body.get("valid"):
                    break
                if "no combination of peers" in str(body) and time.time() < deadline:
                    time.sleep(2)
                    continue
                raise RuntimeError(f"InitConfig failed: {body}")
        return ledger
