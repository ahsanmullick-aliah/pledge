# Tamarin model of PLEDGE

`pledge.spthy` is a symbolic model of PLEDGE's ledger-gated access: enrolment, record upload,
ordinary and break-glass access entries, the chaincode checks, key issuance, revocation, tag
retirement and clinician corruption. The abstractions are listed at the top of the file and in the
paper's appendix ("Symbolic Verification in Tamarin").

`privacy_owner.spthy` and `privacy_purpose.spthy` model log privacy (Theorem 3) as observational
equivalence: validators cannot tell which of two patients owns a record, nor the purpose of an
access even when the encrypted store reveals each tag's owner.

With `-D=QUORUM` the privacy models also give the adversary every record ciphertext, every
attribute key and access keys minted off the ledger by a colluding key-share quorum.

Run `./run.sh` (needs `tamarin-prover` 1.10 and `maude` 3.5 on `PATH`; about 30 minutes).

| Run | Expected result |
|---|---|
| `pledge.spthy` | all 10 lemmas verified ([expected/base.txt](expected/base.txt)) |
| `-D=QUORUM` (adversary controls k key-share services) | `audit_soundness` falsified, all others verified ([expected/quorum.txt](expected/quorum.txt)) |
| `mutants/M1_no_signature_check` | only `attribution` falsified |
| `mutants/M2_no_distinct_cosigner` | only `breakglass_cosigned` falsified |
| `mutants/M3_no_revocation_check` | only `revocation_forward` falsified |
| `mutants/M4_client_side_logging` | only `audit_soundness` falsified (attack A1) |
| `privacy_owner.spthy` (`--diff`) | observational equivalence verified ([expected/privacy_owner.txt](expected/privacy_owner.txt)) |
| `privacy_purpose.spthy` (`--diff`) | observational equivalence verified ([expected/privacy_purpose.txt](expected/privacy_purpose.txt)) |
| `mutants/M5_writer_named` | owner privacy falsified (record transaction names its writer) |
| `mutants/M6_long_term_record_key` | owner privacy falsified (patient's long-term key on the record) |
| `mutants/M7_purpose_in_clear` | purpose privacy falsified |
| `mutants/M8_deterministic_purpose_enc` | purpose privacy falsified |
| `privacy_owner.spthy` (`--diff -D=QUORUM`) | observational equivalence verified ([expected/privacy_owner_quorum.txt](expected/privacy_owner_quorum.txt)) |
| `privacy_purpose.spthy` (`--diff -D=QUORUM`) | observational equivalence verified ([expected/privacy_purpose_quorum.txt](expected/privacy_purpose_quorum.txt)) |
| `mutants/M9_owner_in_record` (`-D=QUORUM`) | owner privacy falsified (the record plaintext names its owner, and the quorum can open it) |
| `mutants/M10_purpose_to_committee` (`-D=QUORUM`) | purpose privacy falsified (E_aud encrypted to a key the committee holds) |

Not covered: consent compilation (a property of the compiler, Theorem 4); the threshold issuer is modelled as one ideal service (its security is Theorem 1).
