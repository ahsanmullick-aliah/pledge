#!/bin/bash
# PLEDGE Part 3: unmodified DEDIS CALYPSO (cothority v3 @ e0c9afb) on ByzCoin, n=4 conodes,
# measured on the same VM as the capacity sweep; then PLEDGE's first access on the same VM.
exec > "$HOME/part3.log" 2>&1
set -x
date -u
export PATH=$HOME/go/bin:$PATH
lscpu | head -20; free -g
cd "$HOME/cothority/calypso"
mkdir -p "$HOME/calypso-out"
CAL_OUT=$HOME/calypso-out CAL_BI=50ms,100ms,250ms,500ms CAL_N=40 CAL_RATES=5,10,20,40,60,80,120 CAL_DUR=30s \
  ./calbench -test.run TestPledgeBench -test.timeout 3h -test.v > "$HOME/calypso-out/calbench.log" 2>&1 \
  || echo CALBENCH_FAILED
grep -E "first access|p50|wrote|FAIL|PASS" "$HOME/calypso-out/calbench.log" | tail -60
date -u
# PLEDGE first access on the same VM (40 trials, as in the paper's Fig. 11)
cd "$HOME/art"
timeout 5400 tools/python/bin/python3 reproduce.py full --only fabric-e2e --out "$HOME/pledge-e2e" || echo E2E_FAILED
tools/python/bin/python3 fabric/network/pledge_net.py clean --n 4 || true
date -u
cd "$HOME" && tar czf part3.tgz calypso-out pledge-e2e part3.log 2>/dev/null
echo PART3_DONE
sudo shutdown -h +3
