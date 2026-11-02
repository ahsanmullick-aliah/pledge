#!/usr/bin/env bash
# Symbolic verification of PLEDGE's ledger-gated access (paper, Appendix "Symbolic Verification in Tamarin").
# Needs tamarin-prover (tested 1.10.0) and maude (tested 3.5) on PATH. Takes about 1 minute in total.
set -euo pipefail
cd "$(dirname "$0")"
export LC_ALL=C.UTF-8 LANG=C.UTF-8
summary() { sed -n '/summary of summaries/,$p'; }
echo "== Base model: all 10 lemmas should be verified";          tamarin-prover --prove pledge.spthy 2>&1 | summary
echo "== Colluding key-share quorum: audit_soundness should be falsified, ledger_cannot_read verified"
tamarin-prover --prove -D=QUORUM pledge.spthy 2>&1 | summary
for m in mutants/*.spthy; do
  echo "== Mutant $(basename "$m" .spthy): exactly one lemma should be falsified"
  tamarin-prover --prove "$m" 2>&1 | summary | grep -E "falsified|incomplete" || echo "  (nothing falsified)"
done
