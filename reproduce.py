#!/usr/bin/env python3
"""Run the experiments of the PLEDGE paper and compare the results with the paper.

    python reproduce.py quick              # about 20-30 minutes: every experiment, smaller sizes
    python reproduce.py full               # the paper's parameters (several hours on a laptop)
    python reproduce.py full --only tests,attacks       # selected stages
    python reproduce.py full --skip fabric              # everything except the Fabric runs

Results go to results/<mode>-<date-time>/ together with REPORT.html, which puts
every number of Section VII of the paper next to the number measured here.

Stages (in order):
  tests          unit, integration and differential tests (Python); Go/Python test vectors when Go is present
  attacks        Table XVII: every attack executed against PLEDGE and the three baselines
  crypto         Fig. 7: per-record cryptographic cost, all four systems, interleaved repetitions
  micro          Section VII-D: share generation, ShareVerify, Combine, outsourced decryption
  lifecycle      Fig. 10: revocation, onboarding, consent narrowing for all four systems
  registration   Section VII-A: identity registration and re-keying cost
  fhir-synthea   Section VII-G: the paper's Synthea cohort encrypted into a real HAPI FHIR server
  fhir-mimic     the same workload on real de-identified data (MIMIC-IV on FHIR demo; not in the paper)
  fabric-smoke   Hyperledger Fabric network: flows and attacks end to end          (Linux / Docker)
  fabric-e2e     Fig. 11: first access and chart opening on Fabric + HAPI FHIR      (Linux / Docker)
  fabric-ledger  Fig. 8: PLEDGE vs Guo on Fabric, n = 4 (n = 7, 10 in full mode)   (Linux / Docker)
  fabric-bundle  Fig. 9: bundling m record tags into one entry                     (Linux / Docker)
  figures        Figs. 6-10 and numbers.json from the raw results
  report         REPORT.html / REPORT.md: your numbers next to the paper's
"""
import argparse
import json
import os
import platform
import shutil
import subprocess
import sys
import time
import urllib.request
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent
PY = sys.executable
TOOLS = ROOT / "tools"
DATA = ROOT / "data"
WIN = os.name == "nt"

PARAMS = {
    "quick": dict(crypto_reps=8, micro_reps=5, micro_quick=True, lifecycle_quick=True, reg_reps=5, reg_records=5,
                  fhir_patients=5, mimic_patients=5, max_resources=100, e2e_trials=5, e2e_charts="1,10",
                  n4_rates="10,20", n4_duration=10, bundles="1,10", bundle_duration=10, big_n=()),
    "full": dict(crypto_reps=40, micro_reps=30, micro_quick=False, lifecycle_quick=False, reg_reps=20, reg_records=20,
                 fhir_patients=50, mimic_patients=100, max_resources=300, e2e_trials=40, e2e_charts="1,10,25,50,100",
                 n4_rates="5,10,15,20,30,40,50,60,80,100,120", n4_duration=30, bundles="1,10,25,50", bundle_duration=20,
                 big_n=(7, 10)),
}
STAGES = ["tests", "attacks", "crypto", "micro", "lifecycle", "registration", "fhir-synthea", "fhir-mimic",
          "fabric-smoke", "fabric-e2e", "fabric-ledger", "fabric-bundle", "figures", "report"]
GROUPS = {"fabric": [s for s in STAGES if s.startswith("fabric-")], "fhir": ["fhir-synthea", "fhir-mimic"]}


def say(msg):
    print(f"[{datetime.now():%H:%M:%S}] {msg}", flush=True)


def java():
    exe = TOOLS / "jre11" / "bin" / ("java.exe" if WIN else "java")
    return exe if exe.exists() else None


def fabric_ready():
    why = []
    if platform.system() != "Linux":
        why.append("Hyperledger Fabric runs on Linux only (use the Docker option on Windows or macOS)")
    if not (TOOLS / "fabric" / "bin" / "peer").exists():
        why.append("Fabric binaries missing (run setup)")
    if not (ROOT / "fabric" / "bin" / "pledge-chaincode").exists():
        why.append("fabric/bin/pledge-chaincode missing")
    try:
        import yaml  # noqa: F401
    except ImportError:
        why.append("Python package pyyaml missing")
    return why


class Runner:
    def __init__(self, mode, out):
        self.mode, self.out, self.p = mode, out, PARAMS[mode]
        self.logs = out / "logs"
        self.logs.mkdir(parents=True, exist_ok=True)
        self.info = {"mode": mode, "started": datetime.now().isoformat(timespec="seconds"),
                     "host": host_info(), "stages": {}}
        self.hapi = None
        self.env = {**os.environ, "PYTHONPATH": str(ROOT), "PYTHONUNBUFFERED": "1",
                    "FABRIC_BIN": str(TOOLS / "fabric"), "MPLBACKEND": "Agg", "PYTHONIOENCODING": "utf-8"}

    # ---------- helpers ----------
    def run(self, name, cmd, timeout=None):
        log = self.logs / f"{name}.log"
        say(f"{name}: {' '.join(str(c) for c in cmd[1:])}")
        t0 = time.time()
        with open(log, "w", encoding="utf-8") as f:
            proc = subprocess.Popen([str(c) for c in cmd], cwd=ROOT, env=self.env, stdout=subprocess.PIPE,
                                    stderr=subprocess.STDOUT, text=True, encoding="utf-8", errors="replace")
            try:
                for line in proc.stdout:
                    f.write(line)
                    f.flush()
                    print("    " + line.rstrip(), flush=True)
                proc.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                proc.kill()
        ok = proc.returncode == 0
        return ok, time.time() - t0

    def record(self, stage, status, secs=0.0, note=""):
        self.info["stages"][stage] = {"status": status, "seconds": round(secs, 1), "note": note}
        say(f"{stage}: {status}{' - ' + note if note else ''} ({secs:.0f} s)")
        self.save()

    def save(self):
        (self.out / "run_info.json").write_text(json.dumps(self.info, indent=1))

    # ---------- HAPI FHIR ----------
    def hapi_up(self):
        if self.hapi is not None:
            return True, ""
        j, jar = java(), TOOLS / "hapi" / "hapi-fhir-cli.jar"
        if j is None or not jar.exists():
            return False, "Java 11 or the HAPI FHIR CLI is missing (run setup)"
        if http_ok("http://127.0.0.1:8080/baseR4/metadata"):
            self.hapi = "external"
            return True, "using the FHIR server already running on port 8080"
        say("starting HAPI FHIR 5.1.0 on port 8080 (first start takes 1-3 minutes)")
        env = {**os.environ}
        env.pop("JAVA_TOOL_OPTIONS", None)
        log = open(self.logs / "hapi-server.log", "w")
        self.hapi = subprocess.Popen([str(j), "-Xmx2g", "-jar", str(jar), "run-server", "-v", "r4", "-p", "8080"],
                                     cwd=TOOLS / "hapi", env=env, stdout=log, stderr=subprocess.STDOUT)
        for _ in range(240):
            if http_ok("http://127.0.0.1:8080/baseR4/metadata"):
                say("HAPI FHIR is up")
                return True, ""
            if self.hapi.poll() is not None:
                break
            time.sleep(5)
        self.hapi_down()
        return False, "HAPI FHIR did not start (see logs/hapi-server.log)"

    def hapi_down(self):
        if isinstance(self.hapi, subprocess.Popen):
            self.hapi.terminate()
            try:
                self.hapi.wait(30)
            except subprocess.TimeoutExpired:
                self.hapi.kill()
        self.hapi = None

    def net_down(self, n):
        subprocess.run([PY, "fabric/network/pledge_net.py", "down", "--n", str(n)], cwd=ROOT, env=self.env,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    # ---------- stages ----------
    def stage(self, s):
        p, R = self.p, self.out
        if s == "tests":
            ok, t = self.run("tests", [PY, "-m", "unittest", "discover", "-s", "tests", "-t", ".", "-v"])
            note = parse_tests(self.logs / "tests.log")
            if platform.system() == "Linux":
                gok, gt = self.run_go()
                if gok is not None:
                    note += "; Go/Python test vectors " + ("pass" if gok else "FAIL")
                    ok, t = ok and gok, t + gt
            return ok, t, note
        if s == "attacks":
            return (*self.run(s, [PY, "-m", "bench.compare", "attacks", "--out", R]), "")
        if s == "crypto":
            return (*self.run(s, [PY, "-m", "bench.compare", "crypto", "--reps", p["crypto_reps"], "--out", R]),
                    f"{p['crypto_reps']} interleaved repetitions")
        if s == "micro":
            cmd = [PY, "-m", "bench.micro", "--reps", p["micro_reps"], "--out", R / "micro.csv"]
            return (*self.run(s, cmd + (["--quick"] if p["micro_quick"] else [])), "")
        if s == "lifecycle":
            cmd = [PY, "-m", "bench.compare", "lifecycle", "--out", R] + (["--quick"] if p["lifecycle_quick"] else [])
            return (*self.run(s, cmd), "reduced grid" if p["lifecycle_quick"] else "full grid")
        if s == "registration":
            return (*self.run(s, [PY, "-m", "bench.registration", "--reps", p["reg_reps"], "--records",
                                  p["reg_records"], "--out", R / "registration.csv"]), "")
        if s in ("fhir-synthea", "fhir-mimic"):
            src = DATA / ("synthea-seed42" if s == "fhir-synthea" else "mimic-iv-fhir-demo")
            if not src.exists() or not any(src.iterdir()):
                return None, 0, f"dataset missing: {src.relative_to(ROOT)} (run setup)"
            up, why = self.hapi_up()
            if not up:
                return None, 0, why
            n = p["fhir_patients"] if s == "fhir-synthea" else p["mimic_patients"]
            out = R / ("fhir_workload.csv" if s == "fhir-synthea" else "fhir_workload_mimic.csv")
            return (*self.run(s, [PY, "-m", "bench.fhir_workload", "--data", src, "--patients", n,
                                  "--max-resources", p["max_resources"], "--out", out]),
                    f"{n} patients, at most {p['max_resources']} resources each")
        if s.startswith("fabric-"):
            why = fabric_ready()
            if why:
                return None, 0, "; ".join(why)
        if s == "fabric-smoke":
            ok, t = self.run(s, [PY, "fabric/run_stage2.py", "--n", "4", "--bad-kss", "1"], timeout=3600)
            src = ROOT / "results" / "stage2_smoke_n4.json"
            if src.exists():
                shutil.copy(src, R / "stage2_smoke_n4.json")
            self.net_down(4)
            return ok, t, parse_smoke(self.logs / "fabric-smoke.log")
        if s == "fabric-e2e":
            up, why = self.hapi_up()
            if not up:
                return None, 0, why
            ok, t = self.run(s, [PY, "fabric/bench_e2e.py", "--n", "4", "--data", DATA / "synthea-seed42",
                                 "--trials", p["e2e_trials"], "--charts", p["e2e_charts"],
                                 "--out", R / "e2e_fabric.json"], timeout=7200)
            self.net_down(4)
            return ok, t, f"{p['e2e_trials']} first accesses, charts {p['e2e_charts']}"
        if s == "fabric-ledger":
            self.hapi_down()                          # like the paper: ledger runs do not share the CPU with HAPI
            ok, t = self.run("fabric-ledger-n4", [PY, "fabric/bench_ledger.py", "--n", "4", "--systems", "pledge,guo",
                                                  "--rates", p["n4_rates"], "--duration", p["n4_duration"],
                                                  "--out", R / "n4fine"], timeout=7200)
            self.net_down(4)
            for n in p["big_n"]:
                ok2, t2 = self.run(f"fabric-ledger-n{n}", [PY, "fabric/bench_ledger.py", "--n", n, "--systems",
                                                           "pledge,guo", "--rates", "10,25,50", "--duration", "20",
                                                           "--out", R], timeout=7200)
                self.net_down(n)
                ok, t = ok and ok2, t + t2
            return ok, t, f"n=4 at {p['n4_rates']} entries/s" + (", n=7 and n=10" if p["big_n"] else "")
        if s == "fabric-bundle":
            self.hapi_down()
            ok, t = self.run(s, [PY, "fabric/bench_ledger.py", "--n", "4", "--systems", "pledge", "--rates", "10",
                                 "--bundles", p["bundles"], "--duration", p["bundle_duration"],
                                 "--out", R / "bundles"], timeout=7200)
            self.net_down(4)
            return ok, t, f"m = {p['bundles']}"
        if s == "figures":
            return (*self.run(s, [PY, "-m", "bench.figures", R]), "")
        if s == "report":
            self.info["finished"] = datetime.now().isoformat(timespec="seconds")
            self.save()
            return (*self.run(s, [PY, "-m", "bench.verify", R, "--paper", ROOT / "paper_results"]), "")
        raise ValueError(s)

    def run_go(self):
        """The Go chaincode checks against the Python-generated test vectors: the prebuilt test
        binary when present (no Go toolchain needed), otherwise `go test` when Go is installed."""
        pkg = ROOT / "fabric" / "pkg" / "pledgecc"
        prebuilt = ROOT / "fabric" / "bin" / "pledgecc.test"
        if prebuilt.exists():
            cmd = [str(prebuilt), "-test.count=1", "-test.v"]
        elif shutil.which("go") and (ROOT / "fabric" / "third_party" / "mcl").exists():
            cmd, pkg = [shutil.which("go"), "test", "-count=1", "-v", "./pkg/pledgecc/"], ROOT / "fabric"
        else:
            return None, 0
        t0 = time.time()
        r = subprocess.run(cmd, cwd=pkg, env=self.env, capture_output=True, text=True)
        (self.logs / "go-vectors.log").write_text(r.stdout + r.stderr)
        say("go-vectors: " + ("pass" if r.returncode == 0 else "FAIL (see logs/go-vectors.log)"))
        return r.returncode == 0, time.time() - t0


def http_ok(url):
    try:
        with urllib.request.urlopen(url, timeout=5) as r:
            return r.status == 200
    except Exception:
        return False


def parse_tests(log):
    txt = log.read_text(encoding="utf-8", errors="replace")
    import re
    ran = re.search(r"Ran (\d+) tests", txt)
    res = re.search(r"\n(OK.*|FAILED.*)\n", txt)
    diff = re.search(r"differential test: (\d+) triples agree; (\d+) generated consents rejected", txt)
    out = f"{ran.group(1) if ran else '?'} tests: {res.group(1) if res else 'no result'}"
    if diff:
        out += f"; differential test {diff.group(1)} triples agree, {diff.group(2)} consents outside F rejected"
    return out


def parse_smoke(log):
    txt = log.read_text(encoding="utf-8", errors="replace") if log.exists() else ""
    import re
    m = re.search(r"Attacks blocked: (\d+)/(\d+)", txt)
    return f"attacks blocked {m.group(1)}/{m.group(2)}" if m else ""


def host_info():
    info = {"system": platform.platform(), "machine": platform.machine(), "python": platform.python_version(),
            "cpus": os.cpu_count()}
    try:
        if platform.system() == "Linux":
            for line in open("/proc/cpuinfo"):
                if line.startswith("model name"):
                    info["cpu"] = line.split(":", 1)[1].strip()
                    break
            for line in open("/proc/meminfo"):
                if line.startswith("MemTotal"):
                    info["ram_gb"] = round(int(line.split()[1]) / 1024 ** 2, 1)
        elif WIN:
            info["cpu"] = platform.processor()
            import ctypes

            class MS(ctypes.Structure):
                _fields_ = [("dwLength", ctypes.c_ulong), ("dwMemoryLoad", ctypes.c_ulong),
                            ("ullTotalPhys", ctypes.c_ulonglong), ("ullAvailPhys", ctypes.c_ulonglong),
                            ("ullTotalPageFile", ctypes.c_ulonglong), ("ullAvailPageFile", ctypes.c_ulonglong),
                            ("ullTotalVirtual", ctypes.c_ulonglong), ("ullAvailVirtual", ctypes.c_ulonglong),
                            ("sullAvailExtendedVirtual", ctypes.c_ulonglong)]
            m = MS()
            m.dwLength = ctypes.sizeof(MS)
            ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(m))
            info["ram_gb"] = round(m.ullTotalPhys / 1024 ** 3, 1)
        else:
            info["cpu"] = platform.processor()
    except Exception:
        pass
    return info


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("mode", choices=["quick", "full"])
    ap.add_argument("--only", default="", help="comma list of stages or groups (fabric, fhir)")
    ap.add_argument("--skip", default="", help="comma list of stages or groups to skip")
    ap.add_argument("--out", default="", help="results folder (default results/<mode>-<date-time>)")
    a = ap.parse_args()

    def expand(spec):
        out = []
        for x in filter(None, (y.strip() for y in spec.split(","))):
            if x not in GROUPS and x not in STAGES:
                ap.error(f"unknown stage {x}; stages: {', '.join(STAGES)}; groups: {', '.join(GROUPS)}")
            out += GROUPS.get(x, [x])
        return out
    stages = expand(a.only) if a.only else list(STAGES)
    if a.only and "report" not in stages:
        stages += ["figures", "report"]
    stages = [s for s in STAGES if s in stages and s not in expand(a.skip)]
    out = Path(a.out) if a.out else ROOT / "results" / f"{a.mode}-{datetime.now():%Y%m%d-%H%M%S}"
    out = out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    (ROOT / "results" / "LATEST.txt").write_text(str(out))
    r = Runner(a.mode, out)
    say(f"PLEDGE reproduction, {a.mode} mode -> {out}")
    say(f"stages: {', '.join(stages)}")
    try:
        for s in stages:
            try:
                ok, secs, note = r.stage(s)
            except Exception as e:                       # one stage failing must not stop the others
                ok, secs, note = False, 0, f"{type(e).__name__}: {e}"
            r.record(s, "skipped" if ok is None else ("ok" if ok else "FAILED"), secs, note)
    except KeyboardInterrupt:
        say("interrupted")
    finally:
        r.hapi_down()
        r.save()
    report = out / "REPORT.html"
    say(f"done. Report: {report}" if report.exists() else f"done (no report). Results in {out}")
    failed = [s for s, v in r.info["stages"].items() if v["status"] == "FAILED"]
    if failed:
        say("stages that failed: " + ", ".join(failed) + f" (logs in {out / 'logs'})")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
