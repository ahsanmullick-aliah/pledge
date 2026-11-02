# Tamarin model of PLEDGE

`pledge.spthy` is a symbolic model of PLEDGE's ledger-gated access: enrolment, record upload,
ordinary and break-glass access entries, the chaincode checks, key issuance, revocation, tag
retirement and clinician corruption. The abstractions are listed at the top of the file and in the
paper's appendix ("Symbolic Verification in Tamarin").

Run `./run.sh` (needs `tamarin-prover` 1.10 and `maude` 3.5 on `PATH`; about one minute).

| Run | Expected result |
|---|---|
| `pledge.spthy` | all 10 lemmas verified ([expected/base.txt](expected/base.txt)) |
| `-D=QUORUM` (adversary controls k key-share services) | `audit_soundness` falsified, all others verified ([expected/quorum.txt](expected/quorum.txt)) |
| `mutants/M1_no_signature_check` | only `attribution` falsified |
| `mutants/M2_no_distinct_cosigner` | only `breakglass_cosigned` falsified |
| `mutants/M3_no_revocation_check` | only `revocation_forward` falsified |
| `mutants/M4_client_side_logging` | only `audit_soundness` falsified (attack A1) |

Not covered: log privacy (needs observational equivalence) and consent compilation; the
threshold issuer is modelled as one ideal service (its security is Theorem 1).
