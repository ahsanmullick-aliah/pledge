#!/usr/bin/env bash
# Run the paper's experiments and write a report that compares your numbers with the paper's.
#   ./run.sh quick            every experiment at reduced size (about 30 minutes)
#   ./run.sh full             the paper's parameters (several hours)
#   ./run.sh full --only crypto,attacks     selected stages (see: ./run.sh quick --help)
#   ./run.sh docker quick     force the Docker image (needed on macOS and ARM)
set -euo pipefail
cd "$(dirname "$0")"
USE_DOCKER=0
if [ "${1:-}" = "docker" ]; then USE_DOCKER=1; shift; fi
MODE="${1:-quick}"; shift || true
if [ "$(uname -s)" != "Linux" ] || [ "$(uname -m)" != "x86_64" ]; then USE_DOCKER=1; fi

if [ "$USE_DOCKER" = 1 ]; then
  command -v docker >/dev/null && docker info >/dev/null 2>&1 || { echo "Docker is not running. Start Docker Desktop and try again."; exit 1; }
  docker image inspect pledge-artifact >/dev/null 2>&1 || docker build -t pledge-artifact .
  mkdir -p results
  exec docker run --rm -v "$PWD/results:/pledge/results" pledge-artifact "$MODE" "$@"
fi
[ -x tools/python/bin/python3 ] || { echo "Run ./setup.sh first."; exit 1; }
tools/python/bin/python3 reproduce.py "$MODE" "$@"
LATEST=$(cat results/LATEST.txt 2>/dev/null || true)
[ -n "$LATEST" ] && [ -f "$LATEST/REPORT.html" ] && echo "Open $LATEST/REPORT.html in a browser." || true
