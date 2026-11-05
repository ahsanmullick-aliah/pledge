# PLEDGE reproduction report (full run, 2026-11-03T11:39:08)

## Exact results

| Where | Result | Paper | Yours | Status |
|---|---|---|---|---|
| 7.1 | Unit and integration tests | all pass | — | not run |
| 7.1 | Differential test: compiler = reference evaluator (triples agreeing) | 6000 | — | not run |
| 7.1 | Differential test: generated Consents outside F rejected | 14 | — | not run |
| Table 17 | A1 Read without a log entry — PLEDGE | blocked | — | not run |
| Table 17 | A1 Read without a log entry — Guo et al. 2022 | succeeds | — | not run |
| Table 17 | A1 Read without a log entry — Romel et al. 2025 | succeeds | — | not run |
| Table 17 | A1 Read without a log entry — CALYPSO 2021 | blocked | — | not run |
| Table 17 | A2 Log record A, read record B — PLEDGE | blocked | — | not run |
| Table 17 | A2 Log record A, read record B — Guo et al. 2022 | succeeds | — | not run |
| Table 17 | A2 Log record A, read record B — Romel et al. 2025 | succeeds | — | not run |
| Table 17 | A2 Log record A, read record B — CALYPSO 2021 | blocked | — | not run |
| Table 17 | A3 Use another clinician's access capability — PLEDGE | blocked | — | not run |
| Table 17 | A3 Use another clinician's access capability — Guo et al. 2022 | n/a | — | not run |
| Table 17 | A3 Use another clinician's access capability — Romel et al. 2025 | blocked | — | not run |
| Table 17 | A3 Use another clinician's access capability — CALYPSO 2021 | blocked | — | not run |
| Table 17 | A4 Revoked clinician opens a new record — PLEDGE | blocked | — | not run |
| Table 17 | A4 Revoked clinician opens a new record — Guo et al. 2022 | blocked | — | not run |
| Table 17 | A4 Revoked clinician opens a new record — Romel et al. 2025 | blocked | — | not run |
| Table 17 | A4 Revoked clinician opens a new record — CALYPSO 2021 | blocked | — | not run |
| Table 17 | A4b Revoked clinician re-reads a record opened before — PLEDGE | succeeds | — | not run |
| Table 17 | A4b Revoked clinician re-reads a record opened before — Guo et al. 2022 | succeeds | — | not run |
| Table 17 | A4b Revoked clinician re-reads a record opened before — Romel et al. 2025 | succeeds | — | not run |
| Table 17 | A4b Revoked clinician re-reads a record opened before — CALYPSO 2021 | succeeds | — | not run |
| Table 17 | A5 f < n/3 ledger nodes grant access off-ledger — PLEDGE | blocked | — | not run |
| Table 17 | A5 f < n/3 ledger nodes grant access off-ledger — Guo et al. 2022 | n/a | — | not run |
| Table 17 | A5 f < n/3 ledger nodes grant access off-ledger — Romel et al. 2025 | n/a | — | not run |
| Table 17 | A5 f < n/3 ledger nodes grant access off-ledger — CALYPSO 2021 | blocked | — | not run |
| Table 17 | A6 Validators learn which patient record was read — PLEDGE | blocked | — | not run |
| Table 17 | A6 Validators learn which patient record was read — Guo et al. 2022 | succeeds | — | not run |
| Table 17 | A6 Validators learn which patient record was read — Romel et al. 2025 | succeeds | — | not run |
| Table 17 | A6 Validators learn which patient record was read — CALYPSO 2021 | succeeds | — | not run |
| Table 17 | A7 Validators learn the purpose of access — PLEDGE | blocked | — | not run |
| Table 17 | A7 Validators learn the purpose of access — Guo et al. 2022 | n/a | — | not run |
| Table 17 | A7 Validators learn the purpose of access — Romel et al. 2025 | n/a | — | not run |
| Table 17 | A7 Validators learn the purpose of access — CALYPSO 2021 | n/a | — | not run |
| Table 17 | A8 Emergency role used without co-signed break-glass — PLEDGE | blocked | — | not run |
| Table 17 | A8 Emergency role used without co-signed break-glass — Guo et al. 2022 | n/a | — | not run |
| Table 17 | A8 Emergency role used without co-signed break-glass — Romel et al. 2025 | n/a | — | not run |
| Table 17 | A8 Emergency role used without co-signed break-glass — CALYPSO 2021 | n/a | — | not run |
| Table 17 | A9 A ledger quorum decrypts records itself — PLEDGE | blocked | — | not run |
| Table 17 | A9 A ledger quorum decrypts records itself — Guo et al. 2022 | blocked | — | not run |
| Table 17 | A9 A ledger quorum decrypts records itself — Romel et al. 2025 | blocked | — | not run |
| Table 17 | A9 A ledger quorum decrypts records itself — CALYPSO 2021 | succeeds | — | not run |
| 7.1 | Fabric network: flows and attacks end to end (blocked/total) | 8/8 | — | not run |
| Fig. 10 / 7.6 | Revoke, 250 records: PLEDGE | 1 tx, 0 crypto ops | — | not run |
| Fig. 10 / 7.6 | Revoke, 250 records: Guo et al. | 0 tx, 326 crypto ops | — | not run |
| Fig. 10 / 7.6 | Revoke, 250 records: Romel et al. | 1 tx, 0 crypto ops | — | not run |
| Fig. 10 / 7.6 | Revoke, 250 records: CALYPSO | 1 tx, 0 crypto ops | — | not run |
| Fig. 10 / 7.6 | Onboard, 250 records: PLEDGE | 1 tx, 0 crypto ops | — | not run |
| Fig. 10 / 7.6 | Onboard, 250 records: Romel et al. | 1 tx, 250 crypto ops | — | not run |
| Fig. 10 / 7.6 | Onboard, 250 records: CALYPSO | 1 tx, 0 crypto ops | — | not run |
| Fig. 10 / 7.6 | Narrow consent, 250 records: PLEDGE | 250 tx, 250 crypto ops | — | not run |
| Fig. 10 / 7.6 | Narrow consent, 250 records: Guo et al. | 0 tx, 250 crypto ops | — | not run |
| Fig. 10 / 7.6 | Narrow consent, 250 records: Romel et al. | 19 tx, 0 crypto ops | — | not run |
| Fig. 10 / 7.6 | Narrow consent, 250 records: CALYPSO | 1 tx, 0 crypto ops | — | not run |
| Fig. 10 / 7.6 | Revoke, 500 records of 5 patients: Guo et al. | 0 tx, 576 crypto ops | — | not run |
| Fig. 10 / 7.6 | Revoke, 500 records of 5 patients: Romel et al. | 5 tx, 0 crypto ops | — | not run |
| Fig. 10 / 7.6 | Onboard, 500 records of 5 patients: Romel et al. | 5 tx, 500 crypto ops | — | not run |
| Fig. 10 / 7.6 | Narrow consent, 500 records: PLEDGE | 500 tx, 500 crypto ops | — | not run |
| Fig. 10 / 7.6 | Narrow consent, 500 records: Romel et al. | 95 tx, 0 crypto ops | — | not run |
| Fig. 10 / 7.6 | Narrow consent, 500 records: CALYPSO | 5 tx, 0 crypto ops | — | not run |
| 7.7 | Synthea cohort (50 patients): resources / labelled R | 13791 / 9 | — | not run |

## Statements of Section 7 on your numbers

| Where | Statement | Evidence | Status |
|---|---|---|---|
| 7.4 | PLEDGE's extra decryption cost over Guo et al. stays about constant from 5 to 50 policy attributes | — | not run |
| 7.4 | PLEDGE's extra encryption cost over Guo et al. is small and does not grow with the policy | — | not run |
| 7.4 | Romel et al. encryption grows per grantee and exceeds PLEDGE's above roughly 8 grantees | — | not run |
| 7.4 | CALYPSO is the cheapest of the four to encrypt and to decrypt | — | not run |
| 7.4 | Outsourced decryption leaves the device a fraction of a millisecond-scale task | — | not run |
| 7.5 | At 10 entries/s PLEDGE's commit latency is close to Guo's plain logging (within 25%) | — | not run |
| 7.5 | The extra cost is in endorsement (PLEDGE's chaincode checks) | — | not run |
| 7.5 | Key shares are available within tens of milliseconds after commit | — | not run |
| 7.5 | PLEDGE saturates no later than Guo's plain logging on a shared host | — | not run |
| 7.5 | Bundling raises the records opened per second | — | not run |
| 7.6 | Revoking a clinician in PLEDGE is one transaction whose cost does not grow with the records | — | not run |
| 7.6 | Revoking under Guo et al.'s re-keying grows with the records affected | — | not run |
| 7.6 | Narrowing a consent costs PLEDGE about as much time as Guo et al. (within 2x) | — | not run |
| 7.7 | A first access completes within interactive limits (< 1 s) | 118 ms median | holds |
| 7.7 | The ledger (endorse, order, key shares) is most of a first access | 72 of 118 ms (61%) | holds |
| 7.7 | Opening a chart with one bundled entry grows roughly linearly with the records | 1 rec: 0.14 s, 10 rec: 0.62 s, 25 rec: 1.31 s, 50 rec: 2.40 s, 100 rec: 4.43 s | holds |
| 7.7 | Storage expansion on Synthea records is about 20x as stored, 10x in binary | — | not run |

## Measured values

| Where | Quantity | Paper | Yours | Ratio |
|---|---|---|---|---|
| 7.4 | Encrypt header, PLEDGE, 5 attributes | 8.98 ms | — | — |
| 7.4 | Encrypt header, Guo et al., 5 attributes | 7.62 ms | — | — |
| 7.4 | Encrypt header, PLEDGE, 50 attributes | 74.02 ms | — | — |
| 7.4 | Encrypt header, Guo et al., 50 attributes | 72.41 ms | — | — |
| 7.4 | First decryption, PLEDGE, 5 attributes | 8.13 ms | — | — |
| 7.4 | First decryption, Guo et al., 5 attributes | 3.82 ms | — | — |
| 7.4 | First decryption, PLEDGE, 50 attributes | 32.95 ms | — | — |
| 7.4 | First decryption, Guo et al., 50 attributes | 28.72 ms | — | — |
| 7.4 | ShareVerify (one share) | 1.75 ms | — | — |
| 7.4 | Combine incl. verification, k = 2 | 3.74 ms | — | — |
| 7.4 | ShareGen (one partial key) | 0.78 ms | — | — |
| 7.4 | Outsourced decryption: device work | 0.32 ms | — | — |
| 7.4 | Romel et al.: decrypt (one ECDH) | 0.81 ms | — | — |
| 7.4 | Romel et al.: encrypt for 5 grantees | 6.22 ms | — | — |
| 7.4 | Romel et al.: encrypt for 50 grantees | 60.44 ms | — | — |
| 7.4 | CALYPSO: encrypt | 0.62 ms | — | — |
| 7.4 | CALYPSO: trustee share release | 0.29 ms | — | — |
| 7.4 | CALYPSO: reader recovers the key | 0.39 ms | — | — |
| 7.5 | Commit latency p50 at 10/s, PLEDGE | 110 ms | — | — |
| 7.5 | Commit latency p50 at 10/s, Guo et al. | 77.07 ms | — | — |
| 7.5 | Commit latency p95 at 10/s, PLEDGE | 151 ms | — | — |
| 7.5 | Commit latency p95 at 10/s, Guo et al. | 101 ms | — | — |
| 7.5 | Endorsement p50 at 10/s, PLEDGE | 28.17 ms | — | — |
| 7.5 | Endorsement p50 at 10/s, Guo et al. | 11.36 ms | — | — |
| 7.5 | Key shares after commit, p50 at 10/s | 8.08 ms | — | — |
| 7.5 | Commit latency p50 at 20/s, PLEDGE | 133 ms | — | — |
| 7.5 | Commit latency p50 at 20/s, Guo et al. | 91.07 ms | — | — |
| 7.5 | Max committed throughput, PLEDGE, n = 4 | 39.80 entries/s | — | — |
| 7.5 | Max committed throughput, Guo et al., n = 4 | 39.90 entries/s | — | — |
| 7.5 | Commit latency p50 at 10/s, PLEDGE, n = 7 | 145 ms | — | — |
| 7.5 | Commit latency p50 at 10/s, PLEDGE, n = 10 | 253 ms | — | — |
| 7.5 | Records opened per second, m = 10 | 100 records/s | — | — |
| 7.5 | Records opened per second, m = 50 | 430 records/s | — | — |
| 7.6 | Narrow consent, 500 records: PLEDGE | 4.54 s | — | — |
| 7.6 | Narrow consent, 500 records: Guo et al. | 3.87 s | — | — |
| 7.6 | Revoke, 500 records: Guo et al. | 5.36 s | — | — |
| 7.7 | Encryption per resource (median) | 15.66 ms | — | — |
| 7.7 | FHIR write per resource | 6.12 ms | — | — |
| 7.7 | FHIR read per resource | 3.33 ms | — | — |
| 7.7 | Storage expansion as stored | 19.78 x | — | — |
| 7.7 | Storage expansion in binary | 9.58 x | — | — |
| 7.7 | First access end to end (median) | 163 ms | 118 ms | 0.73x |
| 7.7 | First access p95 | 191 ms | 170 ms | 0.89x |
| 7.7 |   of which endorsement | 20.06 ms | 18.95 ms | 0.94x |
| 7.7 |   of which ordering and commit | 73.59 ms | 50.65 ms | 0.69x |
| 7.7 |   of which key shares | 2.63 ms | 2.52 ms | 0.96x |
| 7.7 | Open a chart of 10 records | 675 ms | 624 ms | 0.92x |
| 7.7 | Open a chart of 50 records | 2,935 ms | 2,403 ms | 0.82x |
| 7.7 | Open a chart of 100 records | 5,400 ms | 4,427 ms | 0.82x |
| 7.6 | Registration / re-key: reg/patient-client | 0.78 ms | — | — |
| 7.6 | Registration / re-key: reg/patient-aa | 3.52 ms | — | — |
| 7.6 | Registration / re-key: reg/patient-check | 1.27 ms | — | — |
| 7.6 | Registration / re-key: reg/clinician-aa | 42.92 ms | — | — |
| 7.6 | Registration / re-key: rec/key-derive | 0.31 ms | — | — |
| 7.6 | Registration / re-key: rekey/header-only | 28.02 ms | — | — |
| 7.6 | Registration / re-key: rekey/strict | 28.16 ms | — | — |
| 7.6 | Registration / re-key: check/rekey | 2.96 ms | — | — |
