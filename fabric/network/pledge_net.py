#!/usr/bin/env python3
"""PLEDGE hospital ledger on Hyperledger Fabric 3 with SmartBFT ordering, without Docker.

Each hospital i runs one BFT orderer (org OrdHi) and one peer (org Hi), as
native processes on 127.0.0.1. The PLEDGE chaincode runs as an external service
(chaincode-as-a-service); one service instance serves all peers in this
single-machine deployment.

    python3 pledge_net.py up   --n 4      # generate, start, create channel, deploy chaincode
    python3 pledge_net.py down --n 4      # stop processes (keeps data)
    python3 pledge_net.py clean --n 4     # stop and delete everything

Environment: FABRIC_BIN (default ~/fabric-bin) holding bin/, config/, builders/.
Ports for hospital i: orderer 7000+10i (+1 admin, +2 ops), peer 7003+10i
(+1 chaincode, +2 ops); chaincode service 9999.
"""
import argparse
import json
import os
import shutil
import signal
import subprocess
import sys
import tarfile
import time
from pathlib import Path

import yaml

HERE = Path(__file__).resolve().parent
FABRIC = Path(os.environ.get("FABRIC_BIN", Path.home() / "fabric-bin"))
BIN = FABRIC / "bin"
CHANNEL = "pledgechannel"
CC_NAME = "pledge"
CC_PORT = 9999
CC_BIN = HERE.parent / "bin" / "pledge-chaincode"


def ports(i):
    b = 7000 + 10 * i
    return dict(ord=b, ord_admin=b + 1, ord_ops=b + 2, peer=b + 3, peer_cc=b + 4, peer_ops=b + 5)


class Net:
    def __init__(self, n, batch_ms=50, batch_max=100, guo_threshold=0):
        self.guo_threshold = guo_threshold
        self.n = n
        self.f = (n - 1) // 3
        self.k = self.f + 1
        self.root = HERE / "run" / f"n{n}"
        self.crypto = self.root / "crypto"
        self.batch_ms, self.batch_max = batch_ms, batch_max

    # ------------- paths -------------
    def org(self, i):
        return f"h{i}.pledge.local"

    def ordorg(self, i):
        return f"ordh{i}.pledge.local"

    def peer_dir(self, i):
        return self.crypto / "peerOrganizations" / self.org(i) / "peers" / f"peer0.{self.org(i)}"

    def ord_dir(self, i):
        return self.crypto / "ordererOrganizations" / self.ordorg(i) / "orderers" / f"orderer.{self.ordorg(i)}"

    def admin_msp(self, i):
        return self.crypto / "peerOrganizations" / self.org(i) / "users" / f"Admin@{self.org(i)}" / "msp"

    def ord_admin_tls(self, i):
        return self.crypto / "ordererOrganizations" / self.ordorg(i) / "users" / f"Admin@{self.ordorg(i)}" / "tls"

    def peer_tls_ca(self, i):
        return self.peer_dir(i) / "tls" / "ca.crt"

    def ord_tls_ca(self, i):
        return self.ord_dir(i) / "tls" / "ca.crt"

    # ------------- generation -------------
    def generate(self):
        if self.root.exists():
            shutil.rmtree(self.root)
        self.root.mkdir(parents=True)
        spec = {"OrdererOrgs": [], "PeerOrgs": []}
        for i in range(1, self.n + 1):
            spec["OrdererOrgs"].append({"Name": f"OrdH{i}", "Domain": self.ordorg(i), "EnableNodeOUs": True,
                                        "Specs": [{"Hostname": "orderer", "SANS": ["localhost", "127.0.0.1"]}]})
            spec["PeerOrgs"].append({"Name": f"H{i}", "Domain": self.org(i), "EnableNodeOUs": True,
                                     "Specs": [{"Hostname": "peer0", "SANS": ["localhost", "127.0.0.1"]}],
                                     "Users": {"Count": 1}})
        (self.root / "crypto-config.yaml").write_text(yaml.safe_dump(spec))
        run([BIN / "cryptogen", "generate", "--config", self.root / "crypto-config.yaml", "--output", self.crypto])
        self._configtx()
        run([BIN / "configtxgen", "-profile", "PledgeBFT", "-outputBlock", self.root / "genesis.block",
             "-channelID", CHANNEL, "-configPath", self.root])
        self._core_yaml()

    def _configtx(self):
        orgs, ord_orgs, consenters = [], [], []
        for i in range(1, self.n + 1):
            p = ports(i)
            oid = f"OrdH{i}MSP"
            ord_orgs.append({"Name": oid, "ID": oid,
                             "MSPDir": str(self.crypto / "ordererOrganizations" / self.ordorg(i) / "msp"),
                             "Policies": pol(oid, orderer=True),
                             "OrdererEndpoints": [f"127.0.0.1:{p['ord']}"]})
            pid = f"H{i}MSP"
            orgs.append({"Name": pid, "ID": pid,
                         "MSPDir": str(self.crypto / "peerOrganizations" / self.org(i) / "msp"),
                         "Policies": pol(pid),
                         "AnchorPeers": [{"Host": "127.0.0.1", "Port": p["peer"]}]})
            od = self.ord_dir(i)
            consenters.append({"ID": i, "Host": "127.0.0.1", "Port": p["ord"], "MSPID": oid,
                               "Identity": str(od / "msp" / "signcerts" / f"orderer.{self.ordorg(i)}-cert.pem"),
                               "ClientTLSCert": str(od / "tls" / "server.crt"),
                               "ServerTLSCert": str(od / "tls" / "server.crt")})
        implicit = lambda r: {"Type": "ImplicitMeta", "Rule": r}
        cfg = {
            "Profiles": {"PledgeBFT": {
                "Policies": {"Readers": implicit("ANY Readers"), "Writers": implicit("ANY Writers"),
                             "Admins": implicit("MAJORITY Admins")},
                "Capabilities": {"V3_0": True},
                "Orderer": {
                    "OrdererType": "BFT", "BatchTimeout": "2s",
                    "BatchSize": {"MaxMessageCount": self.batch_max, "AbsoluteMaxBytes": "99 MB",
                                  "PreferredMaxBytes": "2 MB"},
                    "Organizations": ord_orgs,
                    "Policies": {"Readers": implicit("ANY Readers"), "Writers": implicit("ANY Writers"),
                                 "Admins": implicit("MAJORITY Admins"),
                                 "BlockValidation": implicit("ANY Writers")},
                    "Capabilities": {"V2_0": True},
                    "SmartBFT": {"RequestBatchMaxCount": self.batch_max,
                                 "RequestBatchMaxInterval": f"{self.batch_ms}ms",
                                 "RequestForwardTimeout": "2s", "RequestComplainTimeout": "20s",
                                 "RequestAutoRemoveTimeout": "3m0s", "ViewChangeResendInterval": "5s",
                                 "ViewChangeTimeout": "20s", "LeaderHeartbeatTimeout": "1m0s",
                                 "CollectTimeout": "1s", "RequestBatchMaxBytes": 10485760,
                                 "IncomingMessageBufferSize": 200, "RequestPoolSize": 100000,
                                 "LeaderHeartbeatCount": 10},
                    "ConsenterMapping": consenters},
                "Application": {
                    "Organizations": orgs,
                    "Policies": {"Readers": implicit("ANY Readers"), "Writers": implicit("ANY Writers"),
                                 "Admins": implicit("MAJORITY Admins"),
                                 "LifecycleEndorsement": implicit("MAJORITY Endorsement"),
                                 "Endorsement": implicit("MAJORITY Endorsement")},
                    "Capabilities": {"V2_5": True}},
            }}}
        (self.root / "configtx.yaml").write_text(yaml.safe_dump(cfg, sort_keys=False))

    def _core_yaml(self):
        core = yaml.safe_load((FABRIC / "config" / "core.yaml").read_text())
        core["chaincode"]["externalBuilders"] = [{"name": "ccaas_builder", "path": str(FABRIC / "builders" / "ccaas"),
                                                  "propagateEnvironment": ["CHAINCODE_AS_A_SERVICE_BUILDER_CONFIG"]}]
        core["vm"]["endpoint"] = ""
        cfgdir = self.root / "peercfg"
        cfgdir.mkdir(exist_ok=True)
        (cfgdir / "core.yaml").write_text(yaml.safe_dump(core, sort_keys=False))
        shutil.copy(FABRIC / "config" / "orderer.yaml", self.root / "orderer.yaml")

    # ------------- processes -------------
    def orderer_env(self, i):
        p, d = ports(i), self.ord_dir(i)
        return {
            "FABRIC_CFG_PATH": str(self.root),
            "ORDERER_GENERAL_LISTENADDRESS": "127.0.0.1", "ORDERER_GENERAL_LISTENPORT": str(p["ord"]),
            "ORDERER_GENERAL_LOCALMSPID": f"OrdH{i}MSP", "ORDERER_GENERAL_LOCALMSPDIR": str(d / "msp"),
            "ORDERER_GENERAL_TLS_ENABLED": "true",
            "ORDERER_GENERAL_TLS_PRIVATEKEY": str(d / "tls" / "server.key"),
            "ORDERER_GENERAL_TLS_CERTIFICATE": str(d / "tls" / "server.crt"),
            "ORDERER_GENERAL_TLS_ROOTCAS": f"[{d / 'tls' / 'ca.crt'}]",
            "ORDERER_GENERAL_CLUSTER_CLIENTCERTIFICATE": str(d / "tls" / "server.crt"),
            "ORDERER_GENERAL_CLUSTER_CLIENTPRIVATEKEY": str(d / "tls" / "server.key"),
            "ORDERER_GENERAL_CLUSTER_ROOTCAS": f"[{d / 'tls' / 'ca.crt'}]",
            "ORDERER_GENERAL_BOOTSTRAPMETHOD": "none",
            "ORDERER_CHANNELPARTICIPATION_ENABLED": "true",
            "ORDERER_ADMIN_LISTENADDRESS": f"127.0.0.1:{p['ord_admin']}",
            "ORDERER_ADMIN_TLS_ENABLED": "true",
            "ORDERER_ADMIN_TLS_PRIVATEKEY": str(d / "tls" / "server.key"),
            "ORDERER_ADMIN_TLS_CERTIFICATE": str(d / "tls" / "server.crt"),
            "ORDERER_ADMIN_TLS_CLIENTAUTHREQUIRED": "true",
            "ORDERER_ADMIN_TLS_CLIENTROOTCAS": f"[{d / 'tls' / 'ca.crt'}]",
            "ORDERER_OPERATIONS_LISTENADDRESS": f"127.0.0.1:{p['ord_ops']}",
            "ORDERER_FILELEDGER_LOCATION": str(self.root / "data" / f"orderer{i}"),
            "ORDERER_CONSENSUS_WALDIR": str(self.root / "data" / f"orderer{i}" / "wal"),
            "ORDERER_CONSENSUS_SNAPDIR": str(self.root / "data" / f"orderer{i}" / "snap"),
            "ORDERER_GENERAL_LOGLEVEL": "warning", "FABRIC_LOGGING_SPEC": "warning",
        }

    def peer_env(self, i):
        p, d = ports(i), self.peer_dir(i)
        addr = f"127.0.0.1:{p['peer']}"
        return {
            "FABRIC_CFG_PATH": str(self.root / "peercfg"),
            "CORE_PEER_ID": f"peer0.{self.org(i)}", "CORE_PEER_ADDRESS": addr,
            "CORE_PEER_LISTENADDRESS": addr,
            "CORE_PEER_CHAINCODEADDRESS": f"127.0.0.1:{p['peer_cc']}",
            "CORE_PEER_CHAINCODELISTENADDRESS": f"127.0.0.1:{p['peer_cc']}",
            "CORE_PEER_GOSSIP_BOOTSTRAP": addr, "CORE_PEER_GOSSIP_EXTERNALENDPOINT": addr,
            "CORE_PEER_GOSSIP_USELEADERELECTION": "false", "CORE_PEER_GOSSIP_ORGLEADER": "true",
            "CORE_PEER_LOCALMSPID": f"H{i}MSP", "CORE_PEER_MSPCONFIGPATH": str(d / "msp"),
            "CORE_PEER_TLS_ENABLED": "true",
            "CORE_PEER_TLS_CERT_FILE": str(d / "tls" / "server.crt"),
            "CORE_PEER_TLS_KEY_FILE": str(d / "tls" / "server.key"),
            "CORE_PEER_TLS_ROOTCERT_FILE": str(d / "tls" / "ca.crt"),
            "CORE_PEER_FILESYSTEMPATH": str(self.root / "data" / f"peer{i}"),
            "CORE_LEDGER_SNAPSHOTS_ROOTDIR": str(self.root / "data" / f"peer{i}" / "snapshots"),
            "CORE_OPERATIONS_LISTENADDRESS": f"127.0.0.1:{p['peer_ops']}",
            "CORE_LEDGER_STATE_STATEDATABASE": "goleveldb",
            "CORE_METRICS_PROVIDER": "disabled",
            "FABRIC_LOGGING_SPEC": "warning:gateway=info",
        }

    def admin_env(self, i):
        e = self.peer_env(i)
        e["CORE_PEER_MSPCONFIGPATH"] = str(self.admin_msp(i))
        return e

    def start(self, name, cmd, env):
        logs = self.root / "logs"
        logs.mkdir(exist_ok=True)
        out = open(logs / f"{name}.log", "ab")
        proc = subprocess.Popen([str(c) for c in cmd], env={**os.environ, **env}, stdout=out, stderr=out,
                                start_new_session=True)
        (self.root / "pids").mkdir(exist_ok=True)
        (self.root / "pids" / name).write_text(str(proc.pid))
        return proc

    def up(self):
        self.generate()
        for i in range(1, self.n + 1):
            self.start(f"orderer{i}", [BIN / "orderer"], self.orderer_env(i))
            self.start(f"peer{i}", [BIN / "peer", "node", "start"], self.peer_env(i))
        for i in range(1, self.n + 1):                       # wait until every node listens
            wait_port(ports(i)["ord_admin"])
            wait_port(ports(i)["peer"])
        for i in range(1, self.n + 1):
            p, t = ports(i), self.ord_admin_tls(i)
            run([BIN / "osnadmin", "channel", "join", "--channelID", CHANNEL, "--config-block",
                 self.root / "genesis.block", "-o", f"127.0.0.1:{p['ord_admin']}",
                 "--ca-file", self.ord_tls_ca(i), "--client-cert", t / "client.crt", "--client-key", t / "client.key"])
        time.sleep(2)
        for i in range(1, self.n + 1):
            run([BIN / "peer", "channel", "join", "-b", self.root / "genesis.block"], env=self.admin_env(i))
        self.deploy_chaincode()
        if self.guo_threshold:
            self.deploy_chaincode("guolog", CC_PORT - 1, self.guo_threshold)
        self.write_profile()
        print(f"PLEDGE ledger up: n={self.n}, f={self.f}, k={self.k}, channel {CHANNEL}")

    def _package(self, name, port):
        pk = self.root / f"cc-{name}"
        pk.mkdir(exist_ok=True)
        conn = pk / "connection.json"
        conn.write_text(json.dumps({"address": f"127.0.0.1:{port}", "dial_timeout": "10s", "tls_required": False}))
        (pk / "metadata.json").write_text(json.dumps({"type": "ccaas", "label": f"{name}_1.0"}))
        with tarfile.open(pk / "code.tar.gz", "w:gz") as t:
            t.add(conn, arcname="connection.json")
        with tarfile.open(pk / f"{name}.tar.gz", "w:gz") as t:
            t.add(pk / "metadata.json", arcname="metadata.json")
            t.add(pk / "code.tar.gz", arcname="code.tar.gz")
        return pk / f"{name}.tar.gz"

    def deploy_chaincode(self, name=CC_NAME, port=CC_PORT, threshold=None):
        """Deploy the PLEDGE chaincode binary under `name` with an OutOf(threshold, all peers)
        endorsement policy (default k). The baseline log uses name 'guolog'."""
        threshold = threshold or self.k
        pkg = self._package(name, port)
        for i in range(1, self.n + 1):
            run([BIN / "peer", "lifecycle", "chaincode", "install", pkg], env=self.admin_env(i))
        pkg_id = run([BIN / "peer", "lifecycle", "chaincode", "calculatepackageid", pkg],
                     env=self.admin_env(1)).strip()
        self.start(f"chaincode-{name}", [CC_BIN], {"CHAINCODE_ID": pkg_id,
                                                   "CHAINCODE_SERVER_ADDRESS": f"127.0.0.1:{port}"})
        policy = "OutOf(%d,%s)" % (threshold, ",".join(f"'H{i}MSP.peer'" for i in range(1, self.n + 1)))
        o = ports(1)
        common = ["-o", f"127.0.0.1:{o['ord']}", "--tls", "--cafile", self.ord_tls_ca(1),
                  "--channelID", CHANNEL, "--name", name, "--version", "1.0", "--sequence", "1",
                  "--signature-policy", policy]
        for i in range(1, self.n + 1):
            run([BIN / "peer", "lifecycle", "chaincode", "approveformyorg", *common, "--package-id", pkg_id,
                 "--waitForEvent"], env=self.admin_env(i))
        peers = []
        for i in range(1, self.n // 2 + 2):
            peers += ["--peerAddresses", f"127.0.0.1:{ports(i)['peer']}", "--tlsRootCertFiles", self.peer_tls_ca(i)]
        run([BIN / "peer", "lifecycle", "chaincode", "commit", *common, *peers], env=self.admin_env(1))
        (self.root / f"package_id_{name}").write_text(pkg_id)
        (self.root / f"endorsement_policy_{name}").write_text(policy)

    def write_profile(self):
        """Connection profile consumed by the gateway bridge and key-share services."""
        prof = {"channel": CHANNEL, "chaincode": CC_NAME, "n": self.n, "k": self.k, "f": self.f, "hospitals": []}
        for i in range(1, self.n + 1):
            u = self.crypto / "peerOrganizations" / self.org(i) / "users" / f"User1@{self.org(i)}" / "msp"
            prof["hospitals"].append({
                "index": i, "mspid": f"H{i}MSP", "peer": f"127.0.0.1:{ports(i)['peer']}",
                "peer_host": f"peer0.{self.org(i)}", "tls_ca": str(self.peer_tls_ca(i)),
                "cert": str(next((u / "signcerts").glob("*.pem"))), "key": str(next((u / "keystore").glob("*")))})
        (self.root / "profile.json").write_text(json.dumps(prof, indent=1))

    def down(self):
        pids = self.root / "pids"
        if not pids.exists():
            return
        for f in pids.iterdir():
            try:
                os.killpg(int(f.read_text()), signal.SIGTERM)
            except (ProcessLookupError, PermissionError, ValueError):
                pass
            f.unlink()
        print("stopped")


def wait_port(port, timeout=60):
    import socket
    end = time.time() + timeout
    while time.time() < end:
        try:
            socket.create_connection(("127.0.0.1", port), timeout=1).close()
            return
        except OSError:
            time.sleep(0.3)
    raise SystemExit(f"port {port} did not open")


def pol(mspid, orderer=False):
    sig = lambda r: {"Type": "Signature", "Rule": r}
    p = {"Readers": sig(f"OR('{mspid}.member')"), "Writers": sig(f"OR('{mspid}.member')"),
         "Admins": sig(f"OR('{mspid}.admin')")}
    if not orderer:
        p["Endorsement"] = sig(f"OR('{mspid}.peer')")
    return p


def run(cmd, env=None):
    r = subprocess.run([str(c) for c in cmd], env={**os.environ, **(env or {})}, capture_output=True, text=True)
    if r.returncode != 0:
        sys.stderr.write(r.stdout + r.stderr)
        raise SystemExit(f"command failed: {' '.join(map(str, cmd[:4]))} ...")
    return r.stdout + r.stderr


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("cmd", choices=["up", "down", "clean", "generate"])
    ap.add_argument("--n", type=int, default=4)
    ap.add_argument("--batch-ms", type=int, default=50)
    ap.add_argument("--batch-max", type=int, default=100)
    ap.add_argument("--guo", type=int, default=0,
                    help="also deploy the Guo et al. baseline log chaincode with an OutOf(GUO, ...) policy")
    a = ap.parse_args()
    net = Net(a.n, a.batch_ms, a.batch_max, a.guo)
    if a.cmd == "up":
        net.down()
        net.up()
    elif a.cmd == "down":
        net.down()
    elif a.cmd == "clean":
        net.down()
        shutil.rmtree(net.root, ignore_errors=True)
    else:
        net.generate()


if __name__ == "__main__":
    main()
