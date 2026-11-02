#!/usr/bin/env bash
# Symbolic verification of PLEDGE's ledger-gated access (paper, Appendix "Symbolic Verification in Tamarin").
# Needs tamarin-prover (tested 1.10.0) and maude (tested 3.5) on PATH.
# Trace properties take about 1 minute; the two privacy equivalences about 4 minutes each.
set -euo pipefail
cd "$(dirname "$0")"
export LC_ALL=C.UTF-8 LANG=C.UTF-8
summary() { sed -n '/summary of summaries/,$p'; }
echo "== Base model: all 10 lemmas should be verified";          tamarin-prover --prove pledge.spthy 2>&1 | summary
echo "== Colluding key-share quorum: audit_soundness should be falsified, ledger_cannot_read verified"
tamarin-prover --prove -D=QUORUM pledge.spthy 2>&1 | summary
for m in mutants/M[1-4]_*.spthy; do
  echo "== Mutant $(basename "$m" .spthy): exactly one lemma should be falsified"
  tamarin-prover --prove "$m" 2>&1 | summary | grep -E "falsified|incomplete" || echo "  (nothing falsified)"
done
echo "== Log privacy (observational equivalence): both should be verified"
for f in privacy_owner.spthy privacy_purpose.spthy; do
  echo "-- $f"; tamarin-prover --diff --prove "$f" 2>&1 | summary | grep -E "Observational|incomplete"
done
for m in mutants/M[5-8]_*.spthy; do
  echo "== Mutant $(basename "$m" .spthy): equivalence should be falsified"
  tamarin-prover --diff --prove "$m" 2>&1 | summary | grep -E "Observational|incomplete"
done
