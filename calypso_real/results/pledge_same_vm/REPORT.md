# PLEDGE reproduction report (full run, 2026-11-03T11:39:08)

## Exact results

| Where | Result | Paper | Yours | Status |
|---|---|---|---|---|
| VII-A | Unit and integration tests | all pass | — | not run |
| VII-A | Differential test: compiler = reference evaluator (triples agreeing) | 6000 | — | not run |
| VII-A | Differential test: generated Consents outside F rejected | 14 | — | not run |
| Table XVII | A1 Read without a log entry — PLEDGE | blocked | — | not run |
| Table XVII | A1 Read without a log entry — Guo et al. 2022 | succeeds | — | not run |
| Table XVII | A1 Read without a log entry — Romel et al. 2025 | succeeds | — | not run |
| Table XVII | A1 Read without a log entry — CALYPSO 2021 | blocked | — | not run |
| Table XVII | A2 Log record A, read record B — PLEDGE | blocked | — | not run |
| Table XVII | A2 Log record A, read record B — Guo et al. 2022 | succeeds | — | not run |
| Table XVII | A2 Log record A, read record B — Romel et al. 2025 | succeeds | — | not run |
| Table XVII | A2 Log record A, read record B — CALYPSO 2021 | blocked | — | not run |
| Table XVII | A3 Use another clinician's access capability — PLEDGE | blocked | — | not run |
| Table XVII | A3 Use another clinician's access capability — Guo et al. 2022 | n/a | — | not run |
| Table XVII | A3 Use another clinician's access capability — Romel et al. 2025 | blocked | — | not run |
| Table XVII | A3 Use another clinician's access capability — CALYPSO 2021 | blocked | — | not run |
| Table XVII | A4 Revoked clinician opens a new record — PLEDGE | blocked | — | not run |
| Table XVII | A4 Revoked clinician opens a new record — Guo et al. 2022 | blocked | — | not run |
| Table XVII | A4 Revoked clinician opens a new record — Romel et al. 2025 | blocked | — | not run |
| Table XVII | A4 Revoked clinician opens a new record — CALYPSO 2021 | blocked | — | not run |
| Table XVII | A4b Revoked clinician re-reads a record opened before — PLEDGE | succeeds | — | not run |
| Table XVII | A4b Revoked clinician re-reads a record opened before — Guo et al. 2022 | succeeds | — | not run |
| Table XVII | A4b Revoked clinician re-reads a record opened before — Romel et al. 2025 | succeeds | — | not run |
| Table XVII | A4b Revoked clinician re-reads a record opened before — CALYPSO 2021 | succeeds | — | not run |
| Table XVII | A5 f < n/3 ledger nodes grant access off-ledger — PLEDGE | blocked | — | not run |
| Table XVII | A5 f < n/3 ledger nodes grant access off-ledger — Guo et al. 2022 | n/a | — | not run |
| Table XVII | A5 f < n/3 ledger nodes grant access off-ledger — Romel et al. 2025 | n/a | — | not run |
| Table XVII | A5 f < n/3 ledger nodes grant access off-ledger — CALYPSO 2021 | blocked | — | not run |
| Table XVII | A6 Validators learn which patient record was read — PLEDGE | blocked | — | not run |
| Table XVII | A6 Validators learn which patient record was read — Guo et al. 2022 | succeeds | — | not run |
| Table XVII | A6 Validators learn which patient record was read — Romel et al. 2025 | succeeds | — | not run |
| Table XVII | A6 Validators learn which patient record was read — CALYPSO 2021 | succeeds | — | not run |
| Table XVII | A7 Validators learn the purpose of access — PLEDGE | blocked | — | not run |
| Table XVII | A7 Validators learn the purpose of access — Guo et al. 2022 | n/a | — | not run |
| Table XVII | A7 Validators learn the purpose of access — Romel et al. 2025 | n/a | — | not run |
| Table XVII | A7 Validators learn the purpose of access — CALYPSO 2021 | n/a | — | not run |
| Table XVII | A8 Emergency role used without co-signed break-glass — PLEDGE | blocked | — | not run |
| Table XVII | A8 Emergency role used without co-signed break-glass — Guo et al. 2022 | n/a | — | not run |
| Table XVII | A8 Emergency role used without co-signed break-glass — Romel et al. 2025 | n/a | — | not run |
| Table XVII | A8 Emergency role used without co-signed break-glass — CALYPSO 2021 | n/a | — | not run |
| Table XVII | A9 A ledger quorum decrypts records itself — PLEDGE | blocked | — | not run |
| Table XVII | A9 A ledger quorum decrypts records itself — Guo et al. 2022 | blocked | — | not run |
| Table XVII | A9 A ledger quorum decrypts records itself — Romel et al. 2025 | blocked | — | not run |
| Table XVII | A9 A ledger quorum decrypts records itself — CALYPSO 2021 | succeeds | — | not run |
| VII-A | Fabric network: flows and attacks end to end (blocked/total) | 8/8 | — | not run |
| Fig. 10 / VII-F | Revoke, 250 records: PLEDGE | 1 tx, 0 crypto ops | — | not run |
| Fig. 10 / VII-F | Revoke, 250 records: Guo et al. | 0 tx, 326 crypto ops | — | not run |
| Fig. 10 / VII-F | Revoke, 250 records: Romel et al. | 1 tx, 0 crypto ops | — | not run |
| Fig. 10 / VII-F | Revoke, 250 records: CALYPSO | 1 tx, 0 crypto ops | — | not run |
| Fig. 10 / VII-F | Onboard, 250 records: PLEDGE | 1 tx, 0 crypto ops | — | not run |
| Fig. 10 / VII-F | Onboard, 250 records: Romel et al. | 1 tx, 250 crypto ops | — | not run |
| Fig. 10 / VII-F | Onboard, 250 records: CALYPSO | 1 tx, 0 crypto ops | — | not run |
| Fig. 10 / VII-F | Narrow consent, 250 records: PLEDGE | 250 tx, 250 crypto ops | — | not run |
| Fig. 10 / VII-F | Narrow consent, 250 records: Guo et al. | 0 tx, 250 crypto ops | — | not run |
| Fig. 10 / VII-F | Narrow consent, 250 records: Romel et al. | 19 tx, 0 crypto ops | — | not run |
| Fig. 10 / VII-F | Narrow consent, 250 records: CALYPSO | 1 tx, 0 crypto ops | — | not run |
| Fig. 10 / VII-F | Revoke, 500 records of 5 patients: Guo et al. | 0 tx, 576 crypto ops | — | not run |
| Fig. 10 / VII-F | Revoke, 500 records of 5 patients: Romel et al. | 5 tx, 0 crypto ops | — | not run |
| Fig. 10 / VII-F | Onboard, 500 records of 5 patients: Romel et al. | 5 tx, 500 crypto ops | — | not run |
| Fig. 10 / VII-F | Narrow consent, 500 records: PLEDGE | 500 tx, 500 crypto ops | — | not run |
| Fig. 10 / VII-F | Narrow consent, 500 records: Romel et al. | 95 tx, 0 crypto ops | — | not run |
| Fig. 10 / VII-F | Narrow consent, 500 records: CALYPSO | 5 tx, 0 crypto ops | — | not run |
| VII-G | Synthea cohort (50 patients): resources / labelled R | 13791 / 9 | — | not run |

## Statements of Section VII on your numbers

| Where | Statement | Evidence | Status |
|---|---|---|---|
| VII-D | PLEDGE's extra decryption cost over Guo et al. stays about constant from 5 to 50 policy attributes | — | not run |
| VII-D | PLEDGE's extra encryption cost over Guo et al. is small and does not grow with the policy | — | not run |
| VII-D | Romel et al. encryption grows per grantee and exceeds PLEDGE's above roughly 8 grantees | — | not run |
| VII-D | CALYPSO is the cheapest of the four to encrypt and to decrypt | — | not run |
| VII-D | Outsourced decryption leaves the device a fraction of a millisecond-scale task | — | not run |
| VII-E | At 10 entries/s PLEDGE's commit latency is close to Guo's plain logging (within 25%) | — | not run |
| VII-E | The extra cost is in endorsement (PLEDGE's chaincode checks) | — | not run |
| VII-E | Key shares are available within tens of milliseconds after commit | — | not run |
| VII-E | PLEDGE saturates no later than Guo's plain logging on a shared host | — | not run |
| VII-E | Bundling raises the records opened per second | — | not run |
| VII-F | Revoking a clinician in PLEDGE is one transaction whose cost does not grow with the records | — | not run |
| VII-F | Revoking under Guo et al.'s re-keying grows with the records affected | — | not run |
| VII-F | Narrowing a consent costs PLEDGE about as much time as Guo et al. (within 2x) | — | not run |
| VII-G | A first access completes within interactive limits (< 1 s) | 118 ms median | holds |
| VII-G | The ledger (endorse, order, key shares) is most of a first access | 72 of 118 ms (61%) | holds |
| VII-G | Opening a chart with one bundled entry grows roughly linearly with the records | 1 rec: 0.14 s, 10 rec: 0.62 s, 25 rec: 1.31 s, 50 rec: 2.40 s, 100 rec: 4.43 s | holds |
| VII-G | Storage expansion on Synthea records is about 20x as stored, 10x in binary | — | not run |

## Measured values

| Where | Quantity | Paper | Yours | Ratio |
|---|---|---|---|---|
| VII-D | Encrypt header, PLEDGE, 5 attributes | 8.98 ms | — | — |
| VII-D | Encrypt header, Guo et al., 5 attributes | 7.62 ms | — | — |
| VII-D | Encrypt header, PLEDGE, 50 attributes | 74.02 ms | — | — |
| VII-D | Encrypt header, Guo et al., 50 attributes | 72.41 ms | — | — |
| VII-D | First decryption, PLEDGE, 5 attributes | 8.13 ms | — | — |
| VII-D | First decryption, Guo et al., 5 attributes | 3.82 ms | — | — |
| VII-D | First decryption, PLEDGE, 50 attributes | 32.95 ms | — | — |
| VII-D | First decryption, Guo et al., 50 attributes | 28.72 ms | — | — |
| VII-D | ShareVerify (one share) | 1.75 ms | — | — |
| VII-D | Combine incl. verification, k = 2 | 3.74 ms | — | — |
| VII-D | ShareGen (one partial key) | 0.78 ms | — | — |
| VII-D | Outsourced decryption: device work | 0.32 ms | — | — |
| VII-D | Romel et al.: decrypt (one ECDH) | 0.81 ms | — | — |
| VII-D | Romel et al.: encrypt for 5 grantees | 6.22 ms | — | — |
| VII-D | Romel et al.: encrypt for 50 grantees | 60.44 ms | — | — |
| VII-D | CALYPSO: encrypt | 0.62 ms | — | — |
| VII-D | CALYPSO: trustee share release | 0.29 ms | — | — |
| VII-D | CALYPSO: reader recovers the key | 0.39 ms | — | — |
| VII-E | Commit latency p50 at 10/s, PLEDGE | 110 ms | — | — |
| VII-E | Commit latency p50 at 10/s, Guo et al. | 77.07 ms | — | — |
| VII-E | Commit latency p95 at 10/s, PLEDGE | 151 ms | — | — |
| VII-E | Commit latency p95 at 10/s, Guo et al. | 101 ms | — | — |
| VII-E | Endorsement p50 at 10/s, PLEDGE | 28.17 ms | — | — |
| VII-E | Endorsement p50 at 10/s, Guo et al. | 11.36 ms | — | — |
| VII-E | Key shares after commit, p50 at 10/s | 8.08 ms | — | — |
| VII-E | Commit latency p50 at 20/s, PLEDGE | 133 ms | — | — |
| VII-E | Commit latency p50 at 20/s, Guo et al. | 91.07 ms | — | — |
| VII-E | Max committed throughput, PLEDGE, n = 4 | 39.80 entries/s | — | — |
| VII-E | Max committed throughput, Guo et al., n = 4 | 39.90 entries/s | — | — |
| VII-E | Commit latency p50 at 10/s, PLEDGE, n = 7 | 145 ms | — | — |
| VII-E | Commit latency p50 at 10/s, PLEDGE, n = 10 | 253 ms | — | — |
| VII-E | Records opened per second, m = 10 | 100 records/s | — | — |
| VII-E | Records opened per second, m = 50 | 430 records/s | — | — |
| VII-F | Narrow consent, 500 records: PLEDGE | 4.54 s | — | — |
| VII-F | Narrow consent, 500 records: Guo et al. | 3.87 s | — | — |
| VII-F | Revoke, 500 records: Guo et al. | 5.36 s | — | — |
| VII-G | Encryption per resource (median) | 15.66 ms | — | — |
| VII-G | FHIR write per resource | 6.12 ms | — | — |
| VII-G | FHIR read per resource | 3.33 ms | — | — |
| VII-G | Storage expansion as stored | 19.78 x | — | — |
| VII-G | Storage expansion in binary | 9.58 x | — | — |
| VII-G | First access end to end (median) | 163 ms | 118 ms | 0.73x |
| VII-G | First access p95 | 191 ms | 170 ms | 0.89x |
| VII-G |   of which endorsement | 20.06 ms | 18.95 ms | 0.94x |
| VII-G |   of which ordering and commit | 73.59 ms | 50.65 ms | 0.69x |
| VII-G |   of which key shares | 2.63 ms | 2.52 ms | 0.96x |
| VII-G | Open a chart of 10 records | 675 ms | 624 ms | 0.92x |
| VII-G | Open a chart of 50 records | 2,935 ms | 2,403 ms | 0.82x |
| VII-G | Open a chart of 100 records | 5,400 ms | 4,427 ms | 0.82x |
| VII-A | Registration / re-key: reg/patient-client | 0.78 ms | — | — |
| VII-A | Registration / re-key: reg/patient-aa | 3.52 ms | — | — |
| VII-A | Registration / re-key: reg/patient-check | 1.27 ms | — | — |
| VII-A | Registration / re-key: reg/clinician-aa | 42.92 ms | — | — |
| VII-A | Registration / re-key: rec/key-derive | 0.31 ms | — | — |
| VII-A | Registration / re-key: rekey/header-only | 28.02 ms | — | — |
| VII-A | Registration / re-key: rekey/strict | 28.16 ms | — | — |
| VII-A | Registration / re-key: check/rekey | 2.96 ms | — | — |
