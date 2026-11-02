# PLEDGE reproduction report (full run, 2026-10-31T00:19:32)

## Exact results

| Where | Result | Paper | Yours | Status |
|---|---|---|---|---|
| VII-A | Unit and integration tests | all pass | — | not run |
| VII-A | Differential test: compiler = reference evaluator (triples agreeing) | 6000 | — | not run |
| VII-A | Differential test: generated Consents outside F rejected | 14 | — | not run |
| Table IV | A1 Read without a log entry — PLEDGE | blocked | blocked | match |
| Table IV | A1 Read without a log entry — Guo et al. 2022 | succeeds | succeeds | match |
| Table IV | A1 Read without a log entry — Romel et al. 2025 | succeeds | succeeds | match |
| Table IV | A1 Read without a log entry — CALYPSO 2021 | blocked | blocked | match |
| Table IV | A2 Log record A, read record B — PLEDGE | blocked | blocked | match |
| Table IV | A2 Log record A, read record B — Guo et al. 2022 | succeeds | succeeds | match |
| Table IV | A2 Log record A, read record B — Romel et al. 2025 | succeeds | succeeds | match |
| Table IV | A2 Log record A, read record B — CALYPSO 2021 | blocked | blocked | match |
| Table IV | A3 Use another clinician's access capability — PLEDGE | blocked | blocked | match |
| Table IV | A3 Use another clinician's access capability — Guo et al. 2022 | n/a | n/a | match |
| Table IV | A3 Use another clinician's access capability — Romel et al. 2025 | blocked | blocked | match |
| Table IV | A3 Use another clinician's access capability — CALYPSO 2021 | blocked | blocked | match |
| Table IV | A4 Revoked clinician opens a new record — PLEDGE | blocked | blocked | match |
| Table IV | A4 Revoked clinician opens a new record — Guo et al. 2022 | blocked | blocked | match |
| Table IV | A4 Revoked clinician opens a new record — Romel et al. 2025 | blocked | blocked | match |
| Table IV | A4 Revoked clinician opens a new record — CALYPSO 2021 | blocked | blocked | match |
| Table IV | A4b Revoked clinician re-reads a record opened before — PLEDGE | succeeds | succeeds | match |
| Table IV | A4b Revoked clinician re-reads a record opened before — Guo et al. 2022 | succeeds | succeeds | match |
| Table IV | A4b Revoked clinician re-reads a record opened before — Romel et al. 2025 | succeeds | succeeds | match |
| Table IV | A4b Revoked clinician re-reads a record opened before — CALYPSO 2021 | succeeds | succeeds | match |
| Table IV | A5 f < n/3 ledger nodes grant access off-ledger — PLEDGE | blocked | blocked | match |
| Table IV | A5 f < n/3 ledger nodes grant access off-ledger — Guo et al. 2022 | n/a | n/a | match |
| Table IV | A5 f < n/3 ledger nodes grant access off-ledger — Romel et al. 2025 | n/a | n/a | match |
| Table IV | A5 f < n/3 ledger nodes grant access off-ledger — CALYPSO 2021 | blocked | blocked | match |
| Table IV | A6 Validators learn which patient record was read — PLEDGE | blocked | blocked | match |
| Table IV | A6 Validators learn which patient record was read — Guo et al. 2022 | succeeds | succeeds | match |
| Table IV | A6 Validators learn which patient record was read — Romel et al. 2025 | succeeds | succeeds | match |
| Table IV | A6 Validators learn which patient record was read — CALYPSO 2021 | succeeds | succeeds | match |
| Table IV | A7 Validators learn the purpose of access — PLEDGE | blocked | blocked | match |
| Table IV | A7 Validators learn the purpose of access — Guo et al. 2022 | n/a | n/a | match |
| Table IV | A7 Validators learn the purpose of access — Romel et al. 2025 | n/a | n/a | match |
| Table IV | A7 Validators learn the purpose of access — CALYPSO 2021 | n/a | n/a | match |
| Table IV | A8 Emergency role used without co-signed break-glass — PLEDGE | blocked | blocked | match |
| Table IV | A8 Emergency role used without co-signed break-glass — Guo et al. 2022 | n/a | n/a | match |
| Table IV | A8 Emergency role used without co-signed break-glass — Romel et al. 2025 | n/a | n/a | match |
| Table IV | A8 Emergency role used without co-signed break-glass — CALYPSO 2021 | n/a | n/a | match |
| Table IV | A9 A ledger quorum decrypts records itself — PLEDGE | blocked | blocked | match |
| Table IV | A9 A ledger quorum decrypts records itself — Guo et al. 2022 | blocked | blocked | match |
| Table IV | A9 A ledger quorum decrypts records itself — Romel et al. 2025 | blocked | blocked | match |
| Table IV | A9 A ledger quorum decrypts records itself — CALYPSO 2021 | succeeds | succeeds | match |
| VII-A | Fabric network: flows and attacks end to end (blocked/total) | 8/8 | 8/8 | match |
| Fig. 9 / VII-F | Revoke, 250 records: PLEDGE | 1 tx, 0 crypto ops | 1 tx, 0 crypto ops | match |
| Fig. 9 / VII-F | Revoke, 250 records: Guo et al. | 0 tx, 326 crypto ops | 0 tx, 326 crypto ops | match |
| Fig. 9 / VII-F | Revoke, 250 records: Romel et al. | 1 tx, 0 crypto ops | 1 tx, 0 crypto ops | match |
| Fig. 9 / VII-F | Revoke, 250 records: CALYPSO | 1 tx, 0 crypto ops | 1 tx, 0 crypto ops | match |
| Fig. 9 / VII-F | Onboard, 250 records: PLEDGE | 1 tx, 0 crypto ops | 1 tx, 0 crypto ops | match |
| Fig. 9 / VII-F | Onboard, 250 records: Romel et al. | 1 tx, 250 crypto ops | 1 tx, 250 crypto ops | match |
| Fig. 9 / VII-F | Onboard, 250 records: CALYPSO | 1 tx, 0 crypto ops | 1 tx, 0 crypto ops | match |
| Fig. 9 / VII-F | Narrow consent, 250 records: PLEDGE | 250 tx, 250 crypto ops | 250 tx, 250 crypto ops | match |
| Fig. 9 / VII-F | Narrow consent, 250 records: Guo et al. | 0 tx, 250 crypto ops | 0 tx, 250 crypto ops | match |
| Fig. 9 / VII-F | Narrow consent, 250 records: Romel et al. | 19 tx, 0 crypto ops | 19 tx, 0 crypto ops | match |
| Fig. 9 / VII-F | Narrow consent, 250 records: CALYPSO | 1 tx, 0 crypto ops | 1 tx, 0 crypto ops | match |
| Fig. 9 / VII-F | Revoke, 500 records of 5 patients: Guo et al. | 0 tx, 576 crypto ops | 0 tx, 576 crypto ops | match |
| Fig. 9 / VII-F | Revoke, 500 records of 5 patients: Romel et al. | 5 tx, 0 crypto ops | 5 tx, 0 crypto ops | match |
| Fig. 9 / VII-F | Onboard, 500 records of 5 patients: Romel et al. | 5 tx, 500 crypto ops | 5 tx, 500 crypto ops | match |
| Fig. 9 / VII-F | Narrow consent, 500 records: PLEDGE | 500 tx, 500 crypto ops | 500 tx, 500 crypto ops | match |
| Fig. 9 / VII-F | Narrow consent, 500 records: Romel et al. | 95 tx, 0 crypto ops | 95 tx, 0 crypto ops | match |
| Fig. 9 / VII-F | Narrow consent, 500 records: CALYPSO | 5 tx, 0 crypto ops | 5 tx, 0 crypto ops | match |
| VII-G | Synthea cohort: resources encrypted | 13791 | 13791 | match |
| VII-G | Synthea cohort: resources labelled R | 9 | 9 | match |

## Statements of Section VII on your numbers

| Where | Statement | Evidence | Status |
|---|---|---|---|
| VII-D | PLEDGE's extra decryption cost over Guo et al. stays about constant from 5 to 50 policy attributes | overhead 4.31 ms at 5 attributes, 4.23 ms at 50 | holds |
| VII-D | PLEDGE's extra encryption cost over Guo et al. is small and does not grow with the policy | overhead 1.36 ms at 5 attributes, 1.61 ms at 50 | holds |
| VII-D | Romel et al. encryption grows per grantee and exceeds PLEDGE's above roughly 8 grantees | crossover at 7.5 grantees (paper 8.2) | holds |
| VII-D | CALYPSO is the cheapest of the four to encrypt and to decrypt | encrypt 0.62 ms vs 6.22 ms; decrypt 0.39 vs 3.82 | holds |
| VII-D | Outsourced decryption leaves the device a fraction of a millisecond-scale task | device finish 0.32 ms vs full decryption 8.13 ms | holds |
| VII-E | At 10 entries/s PLEDGE's commit latency is close to Guo's plain logging (within 25%) | PLEDGE 109.9 ms vs Guo 77.1 ms (+32.8 ms) | DOES NOT HOLD |
| VII-E | The extra cost is in endorsement (PLEDGE's chaincode checks) | endorsement 28.2 ms vs 11.4 ms | holds |
| VII-E | Key shares are available within tens of milliseconds after commit | 8.1 ms (median) | holds |
| VII-E | PLEDGE saturates no later than Guo's plain logging on a shared host | max committed 39.8 vs 39.9 entries/s | holds |
| VII-E | Bundling raises the records opened per second | 10 records/s at m = 1, 100 at m = 10 | holds |
| VII-F | Revoking a clinician in PLEDGE is one transaction whose cost does not grow with the records | 1 tx, 0 ops; 7.8–9.7 ms across all sizes | holds |
| VII-F | Revoking under Guo et al.'s re-keying grows with the records affected | 117 ms to 10834 ms | holds |
| VII-F | Narrowing a consent costs PLEDGE about as much time as Guo et al. (within 2x) | 4.54 s vs 3.87 s for 500 records | holds |
| VII-G | A first access completes within interactive limits (< 1 s) | 163 ms median | holds |
| VII-G | The ledger (endorse, order, key shares) is most of a first access | 96 of 163 ms (59%) | holds |
| VII-G | Opening a chart with one bundled entry grows roughly linearly with the records | 1 rec: 0.14 s, 10 rec: 0.68 s, 25 rec: 1.55 s, 50 rec: 2.93 s, 100 rec: 5.40 s | holds |
| VII-G | Storage expansion on Synthea records is about 20x as stored, 10x in binary | x19.8 as stored, x9.6 binary | holds |

## Measured values

| Where | Quantity | Paper | Yours | Ratio |
|---|---|---|---|---|
| VII-D | Encrypt header, PLEDGE, 5 attributes | 6.68 ms | 8.98 ms | 1.34x |
| VII-D | Encrypt header, Guo et al., 5 attributes | 5.80 ms | 7.62 ms | 1.31x |
| VII-D | Encrypt header, PLEDGE, 50 attributes | 56.96 ms | 74.02 ms | 1.30x |
| VII-D | Encrypt header, Guo et al., 50 attributes | 55.46 ms | 72.41 ms | 1.31x |
| VII-D | First decryption, PLEDGE, 5 attributes | 6.01 ms | 8.13 ms | 1.35x |
| VII-D | First decryption, Guo et al., 5 attributes | 2.89 ms | 3.82 ms | 1.32x |
| VII-D | First decryption, PLEDGE, 50 attributes | 24.87 ms | 32.95 ms | 1.32x |
| VII-D | First decryption, Guo et al., 50 attributes | 21.79 ms | 28.72 ms | 1.32x |
| VII-D | ShareVerify (one share) | 1.26 ms | 1.75 ms | 1.39x |
| VII-D | Combine incl. verification, k = 2 | 2.88 ms | 3.74 ms | 1.30x |
| VII-D | ShareGen (one partial key) | 0.58 ms | 0.78 ms | 1.35x |
| VII-D | Outsourced decryption: device work | 0.25 ms | 0.32 ms | 1.31x |
| VII-D | Romel et al.: decrypt (one ECDH) | 0.59 ms | 0.81 ms | 1.37x |
| VII-D | Romel et al.: encrypt for 5 grantees | 4.13 ms | 6.22 ms | 1.50x |
| VII-D | Romel et al.: encrypt for 50 grantees | 40.76 ms | 60.44 ms | 1.48x |
| VII-D | CALYPSO: encrypt | 0.48 ms | 0.62 ms | 1.30x |
| VII-D | CALYPSO: trustee share release | 0.23 ms | 0.29 ms | 1.29x |
| VII-D | CALYPSO: reader recovers the key | 0.28 ms | 0.39 ms | 1.42x |
| VII-E | Commit latency p50 at 10/s, PLEDGE | 82.48 ms | 110 ms | 1.33x |
| VII-E | Commit latency p50 at 10/s, Guo et al. | 79.72 ms | 77.07 ms | 0.97x |
| VII-E | Commit latency p95 at 10/s, PLEDGE | 117 ms | 151 ms | 1.30x |
| VII-E | Commit latency p95 at 10/s, Guo et al. | 116 ms | 101 ms | 0.87x |
| VII-E | Endorsement p50 at 10/s, PLEDGE | 18.00 ms | 28.17 ms | 1.57x |
| VII-E | Endorsement p50 at 10/s, Guo et al. | 11.69 ms | 11.36 ms | 0.97x |
| VII-E | Key shares after commit, p50 at 10/s | 7.85 ms | 8.08 ms | 1.03x |
| VII-E | Commit latency p50 at 20/s, PLEDGE | 144 ms | 133 ms | 0.92x |
| VII-E | Commit latency p50 at 20/s, Guo et al. | 108 ms | 91.07 ms | 0.84x |
| VII-E | Max committed throughput, PLEDGE, n = 4 | 34.80 entries/s | 39.80 entries/s | 1.14x |
| VII-E | Max committed throughput, Guo et al., n = 4 | 39.80 entries/s | 39.90 entries/s | 1.00x |
| VII-E | Commit latency p50 at 10/s, PLEDGE, n = 7 | 594 ms | 145 ms | 0.24x |
| VII-E | Commit latency p50 at 10/s, PLEDGE, n = 10 | 7,102 ms | 253 ms | 0.04x |
| VII-E | Records opened per second, m = 10 | 98.00 records/s | 100 records/s | 1.02x |
| VII-E | Records opened per second, m = 50 | 245 records/s | 430 records/s | 1.76x |
| VII-F | Narrow consent, 500 records: PLEDGE | 3.59 s | 4.54 s | 1.26x |
| VII-F | Narrow consent, 500 records: Guo et al. | 3.64 s | 3.87 s | 1.06x |
| VII-F | Revoke, 500 records: Guo et al. | 5.37 s | 5.36 s | 1.00x |
| VII-G | Encryption per resource (median) | 12.13 ms | 15.66 ms | 1.29x |
| VII-G | FHIR write per resource | 6.90 ms | 6.12 ms | 0.89x |
| VII-G | FHIR read per resource | 2.59 ms | 3.33 ms | 1.28x |
| VII-G | Storage expansion as stored | 19.78 x | 19.78 x | 1.00x |
| VII-G | Storage expansion in binary | 9.58 x | 9.58 x | 1.00x |
| VII-G | First access end to end (median) | 133 ms | 163 ms | 1.22x |
| VII-G | First access p95 | 169 ms | 191 ms | 1.13x |
| VII-G |   of which endorsement | 20.37 ms | 20.06 ms | 0.98x |
| VII-G |   of which ordering and commit | 58.27 ms | 73.59 ms | 1.26x |
| VII-G |   of which key shares | 23.72 ms | 2.63 ms | 0.11x |
| VII-G | Open a chart of 10 records | 428 ms | 675 ms | 1.58x |
| VII-G | Open a chart of 50 records | 1,975 ms | 2,935 ms | 1.49x |
| VII-G | Open a chart of 100 records | 3,827 ms | 5,400 ms | 1.41x |
| VII-A | Registration / re-key: reg/patient-client | 0.70 ms | 0.78 ms | 1.11x |
| VII-A | Registration / re-key: reg/patient-aa | 3.26 ms | 3.52 ms | 1.08x |
| VII-A | Registration / re-key: reg/patient-check | 1.31 ms | 1.27 ms | 0.97x |
| VII-A | Registration / re-key: reg/clinician-aa | 28.69 ms | 42.92 ms | 1.50x |
| VII-A | Registration / re-key: rec/key-derive | 0.18 ms | 0.31 ms | 1.72x |
| VII-A | Registration / re-key: rekey/header-only | 17.17 ms | 28.02 ms | 1.63x |
| VII-A | Registration / re-key: rekey/strict | 20.00 ms | 28.16 ms | 1.41x |
| VII-A | Registration / re-key: check/rekey | 1.63 ms | 2.96 ms | 1.82x |
