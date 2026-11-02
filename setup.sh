#!/usr/bin/env bash
# One-step setup on Linux (x86-64). On macOS, or Linux on ARM, use Docker: ./run.sh detects it.
#   ./setup.sh
set -euo pipefail
cd "$(dirname "$0")"
PYURL="https://github.com/astral-sh/python-build-standalone/releases/download/20250529/cpython-3.12.10%2B20250529-x86_64-unknown-linux-gnu-install_only.tar.gz"
say() { printf '\n==> %s\n' "$*"; }

if [ "$(uname -s)" != "Linux" ] || [ "$(uname -m)" != "x86_64" ]; then
  say "This computer is $(uname -s) $(uname -m). The native setup needs Linux x86-64."
  echo "Install Docker Desktop and run ./run.sh quick  (it builds and uses the Docker image)."
  exit 1
fi
mkdir -p tools
if [ ! -x tools/python/bin/python3 ]; then
  say "[1/4] Downloading a private copy of Python 3.12 (about 30 MB)"
  curl -L --fail --retry 3 -o tools/python.tar.gz "$PYURL"
  tar -xzf tools/python.tar.gz -C tools
  rm tools/python.tar.gz
fi
PY=tools/python/bin/python3
say "[2/4] Installing Python packages"
"$PY" -m pip install --disable-pip-version-check -q -r requirements.txt
say "[3/4] Downloading Java 11, HAPI FHIR 5.1.0, Hyperledger Fabric 3.1.1 and the MIMIC-IV FHIR data"
"$PY" scripts/fetch.py
say "[4/4] Checking the installation (unit tests, about a minute)"
PYTHONPATH=. "$PY" -m unittest discover -s tests -t . 2>&1 | tail -4
say "Setup complete. Next:  ./run.sh quick   (about 30 minutes)   or   ./run.sh full   (several hours)"
