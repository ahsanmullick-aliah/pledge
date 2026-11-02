#!/usr/bin/env python3
"""Download and unpack the third-party tools and data the experiments need (standard library only).

    python scripts/fetch.py                 # everything this platform can use
    python scripts/fetch.py --only mimic    # one component (jre, hapi, mimic, synthea, fabric)

Components, each from its official release:
  jre      Eclipse Temurin 11 JRE (runs HAPI FHIR)           -> tools/jre11
  hapi     HAPI FHIR CLI 5.1.0 (the FHIR server of the paper)  -> tools/hapi
  synthea  the paper's Synthea cohort, shipped with the code   -> data/synthea-seed42
  mimic    MIMIC-IV Clinical Database Demo on FHIR 2.1.0       -> data/mimic-iv-fhir-demo
           (real de-identified data, PhysioNet, open access, ODbL 1.0; checked against its SHA-256 sums)
  fabric   Hyperledger Fabric 3.1.1 binaries (Linux only)      -> tools/fabric
Anything already in place is kept, so the script can be re-run after an interrupted download.
"""
import argparse
import hashlib
import os
import platform
import shutil
import sys
import tarfile
import time
import urllib.request
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
TOOLS, DATA = ROOT / "tools", ROOT / "data"

JRE = "https://github.com/adoptium/temurin11-binaries/releases/download/jdk-11.0.25%2B9/"
JRE_FILES = {("Windows", "AMD64"): "OpenJDK11U-jre_x64_windows_hotspot_11.0.25_9.zip",
             ("Linux", "x86_64"): "OpenJDK11U-jre_x64_linux_hotspot_11.0.25_9.tar.gz",
             ("Linux", "aarch64"): "OpenJDK11U-jre_aarch64_linux_hotspot_11.0.25_9.tar.gz",
             ("Darwin", "x86_64"): "OpenJDK11U-jre_x64_mac_hotspot_11.0.25_9.tar.gz",
             ("Darwin", "arm64"): "OpenJDK11U-jre_aarch64_mac_hotspot_11.0.25_9.tar.gz"}
HAPI = "https://github.com/hapifhir/hapi-fhir/releases/download/v5.1.0/hapi-fhir-5.1.0-cli.zip"
FABRIC = "https://github.com/hyperledger/fabric/releases/download/v3.1.1/hyperledger-fabric-linux-amd64-3.1.1.tar.gz"


def say(msg):
    print(msg, flush=True)


def download(url, dest: Path, sha256=None, tries=5):
    dest.parent.mkdir(parents=True, exist_ok=True)
    if dest.exists() and (sha256 is None or _sha(dest) == sha256):
        return dest
    part = dest.with_suffix(dest.suffix + ".part")
    for attempt in range(1, tries + 1):
        shown = False
        try:
            have = part.stat().st_size if part.exists() else 0
            req = urllib.request.Request(url, headers={"User-Agent": "pledge-artifact/1.0",
                                                       **({"Range": f"bytes={have}-"} if have else {})})
            with urllib.request.urlopen(req, timeout=60) as r:
                if have and r.status != 206:          # server ignored the range: start again
                    have = 0
                total = int(r.headers.get("Content-Length", 0)) + have
                mode = "ab" if have else "wb"
                with open(part, mode) as f:
                    got, last = have, 0.0
                    while True:
                        buf = r.read(1 << 20)
                        if not buf:
                            break
                        f.write(buf)
                        got += len(buf)
                        if time.time() - last > 1 or got == total:
                            last = time.time()
                            pct = f"{100 * got / total:5.1f}%" if total else ""
                            print(f"\r    {dest.name}: {got / 2**20:7.1f} MB {pct}", end="", flush=True)
                            shown = True
            if shown:
                print()
            if sha256 and _sha(part) != sha256:
                part.unlink()
                raise IOError("checksum mismatch")
            part.replace(dest)
            return dest
        except Exception as e:
            if shown:
                print()
            say(f"    attempt {attempt}/{tries} failed: {e}")
            if attempt == tries:
                raise
            time.sleep(3 * attempt)


def _sha(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def unpack(archive: Path, dest: Path, strip_top=True):
    tmp = dest.with_name(dest.name + ".tmp")
    shutil.rmtree(tmp, ignore_errors=True)
    tmp.mkdir(parents=True)
    if archive.name.endswith(".zip"):
        with zipfile.ZipFile(archive) as z:
            z.extractall(tmp)
    else:
        with tarfile.open(archive) as t:
            t.extractall(tmp, **({"filter": "fully_trusted"} if hasattr(tarfile, "data_filter") else {}))
    inner = list(tmp.iterdir())
    src = inner[0] if strip_top and len(inner) == 1 and inner[0].is_dir() else tmp
    shutil.rmtree(dest, ignore_errors=True)
    shutil.move(str(src), str(dest))
    shutil.rmtree(tmp, ignore_errors=True)
    if not os.name == "nt":                         # zip files do not keep the executable bit
        for p in dest.rglob("*"):
            if p.is_file() and (p.parent.name == "bin" or p.suffix in ("", ".sh")):
                p.chmod(p.stat().st_mode | 0o755)


def fetch_jre():
    exe = TOOLS / "jre11" / "bin" / ("java.exe" if os.name == "nt" else "java")
    if exe.exists():
        return say("  Java 11: present")
    key = (platform.system(), platform.machine())
    if key not in JRE_FILES:
        raise SystemExit(f"no Java build listed for {key}")
    say("  Java 11 (Eclipse Temurin JRE)")
    a = download(JRE + JRE_FILES[key], TOOLS / "downloads" / JRE_FILES[key])
    unpack(a, TOOLS / "jre11")
    if platform.system() == "Darwin" and (TOOLS / "jre11" / "Contents" / "Home").exists():
        home = TOOLS / "jre11" / "Contents" / "Home"
        tmp = TOOLS / "jre11-home"
        shutil.move(str(home), str(tmp))
        shutil.rmtree(TOOLS / "jre11")
        tmp.rename(TOOLS / "jre11")


def fetch_hapi():
    if (TOOLS / "hapi" / "hapi-fhir-cli.jar").exists():
        return say("  HAPI FHIR 5.1.0: present")
    say("  HAPI FHIR CLI 5.1.0")
    a = download(HAPI, TOOLS / "downloads" / "hapi-fhir-5.1.0-cli.zip")
    unpack(a, TOOLS / "hapi", strip_top=False)


def fetch_synthea():
    dest = DATA / "synthea-seed42"
    if dest.exists() and any(dest.glob("*.json")):
        return say(f"  Synthea cohort: present ({len(list(dest.glob('*.json')))} patients)")
    src = DATA / "synthea-seed42.tar.gz"
    if not src.exists():
        raise SystemExit(f"{src} is missing from the package")
    say("  Synthea cohort of the paper (50 patients, seed 42)")
    unpack(src, dest)


def fetch_mimic():
    from pledge.fhir.mimic import BASE_URL, FILES
    dest = DATA / "mimic-iv-fhir-demo"
    if all((dest / n).exists() for n, _ in FILES):
        return say("  MIMIC-IV on FHIR demo: present")
    say("  MIMIC-IV Clinical Database Demo on FHIR 2.1.0 (PhysioNet, open access, ODbL 1.0)")
    for name, sha in FILES:
        download(BASE_URL + name, dest / name, sha256=sha)
    (dest / "SOURCE.txt").write_text(
        "MIMIC-IV Clinical Database Demo on FHIR, version 2.1.0.\n"
        "Bennett A, Ulrich H, Wiedekopf J, Szul P, Grimes J, Johnson A. PhysioNet (2025).\n"
        "https://doi.org/10.13026/vphg-y548  Licence: Open Data Commons Open Database License v1.0\n"
        "Only the files PLEDGE uses were downloaded; each matches the dataset's SHA256SUMS.txt.\n")


def fetch_fabric():
    if platform.system() != "Linux" or platform.machine() != "x86_64":
        return say("  Hyperledger Fabric: skipped (needs Linux x86-64; use the Docker option)")
    if (TOOLS / "fabric" / "bin" / "peer").exists():
        return say("  Hyperledger Fabric 3.1.1: present")
    say("  Hyperledger Fabric 3.1.1 binaries")
    a = download(FABRIC, TOOLS / "downloads" / "hyperledger-fabric-linux-amd64-3.1.1.tar.gz")
    unpack(a, TOOLS / "fabric", strip_top=False)


STEPS = {"jre": fetch_jre, "hapi": fetch_hapi, "synthea": fetch_synthea, "mimic": fetch_mimic, "fabric": fetch_fabric}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--only", default=",".join(STEPS))
    ap.add_argument("--keep-downloads", action="store_true")
    a = ap.parse_args()
    failed = []
    for name in a.only.split(","):
        try:
            STEPS[name.strip()]()
        except (Exception, SystemExit) as e:
            say(f"  {name}: FAILED ({e})")
            failed.append(name)
    if not a.keep_downloads and not failed:        # keep partial files so a re-run resumes them
        shutil.rmtree(TOOLS / "downloads", ignore_errors=True)
    if failed:
        say("Some downloads failed: " + ", ".join(failed) + ". Check the internet connection and run setup again.")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
