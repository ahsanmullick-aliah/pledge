# Baselines re-implemented for the comparison

Both baselines run on the same machine, curve and code base as PLEDGE, so only
the protocol differs. State every assumption below in the paper's
experimental setup; items marked **[VERIFY]** should be checked against the
original paper's full text before submission.

## Guo et al., IEEE TNSM 2022 — `baselines/guo.py`

| Aspect | Original | Re-implementation |
| --- | --- | --- |
| Record encryption | MA-ABE (OpenABE) | Rouselakis–Waters MA-CP-ABE, same as PLEDGE (no access row) |
| Policy | attribute policies, e.g. (Doctor or Nurse) | the same compiled consent policies PLEDGE uses |
| Access logging | EHR activities recorded on Hyperledger Fabric | client submits a signed log entry after decrypting; chaincode `GuoLog` checks the signature only |
| Endorsement | 1/2/3-of-any | configurable; default matched to PLEDGE's k for a like-for-like ledger comparison |
| Revocation | not specified **[VERIFY]** | **assumed** standard ABE re-keying: re-version attributes, re-issue to remaining holders, re-encrypt affected headers |
| Log contents | access/authentication events **[VERIFY field list]** | clinician id and record id in clear |
| Not reproduced | ABSA signatures, Paillier homomorphic computation, edge nodes | orthogonal to the measured operations |

## Romel et al., arXiv 2025 — `baselines/romel.py`

| Aspect | Original | Re-implementation |
| --- | --- | --- |
| Record encryption | AES-256-GCM off-chain | same |
| Key distribution | ECIES on secp256k1 per grantee | same (HKDF-SHA256 + AES-GCM) |
| Permissions | patient-signed, time-bounded EIP-712 permissions in a per-patient contract | same structure; EIP-712 hashing with SHA3-256 instead of Keccak-256 |
| Read receipts | optional `logAccess` | optional `log=True` |
| Role-based consent | not supported | **assumed** realised by granting each eligible clinician individually |
| Storage service | releases wraps per on-chain permission **[VERIFY]** | honest gatekeeper |
| Chain | public Ethereum (gas) | in-process contract; ledger costs reported as transaction counts, not timed on Fabric |

## What each comparison shows

* `python3 -m bench.compare attacks` — the attack table for PLEDGE and the three baselines (each cell executed).
* `python3 -m bench.compare lifecycle` — share / revoke / onboard / narrow-consent cost vs records, clinicians, patients.
* `python3 -m bench.compare crypto` — per-record encryption and first-decryption cost.
* `python3 fabric/bench_ledger.py --systems pledge,guo` — PLEDGE access entries vs Guo log entries on the same Fabric network.

## CALYPSO, Kokoris-Kogias et al., PVLDB 14(4), 2021 — `baselines/calypso.py`

| Aspect | Original | Re-implementation |
| --- | --- | --- |
| Secret storage | on-chain secrets, long-term secrets (LTS): symmetric key under the committee's threshold ElGamal key, NIZK of correct encryption | same, on BLS12-381 G1; NIZK = Schnorr proof of knowledge of r bound to (U, V, policy) |
| Committee | n trustees, threshold t = f+1, DKG | same n and t as PLEDGE's federation (n = 3f+1); Shamir-dealt key in place of the DKG (setup cost not measured) |
| Read | logged read transaction txr; trustees release shares re-encrypted to the reader's key only for a logged txr | same; trustees check txr is committed, names the same secret and the same reader |
| Access control | SIAM: decentralised RBAC with identity, federated (group/role) and policy skipchains | **assumed** generously: groups carry the same attribute sets PLEDGE clinicians hold; one resource policy per patient = the patient's FHIR Consent, evaluated by the chain |
| Revocation | remove from a federated group / set policy to ∅ (atomic w.r.t. logged reads) | one membership transaction; no re-encryption |
| Reader blinding | optional | off (it hides the reader, not the writer, so it does not change A6) |
| Not reproduced | one-time secrets (PVSS), skipchain mechanics, key rotation via translation certificates | orthogonal to the measured operations |

Attack A9 (a ledger quorum decrypts records itself) is the main structural
difference: in CALYPSO any t trustees can combine their shares and open every
secret with no read transaction; in PLEDGE even all ledger nodes together hold
only the access attribute, not the consent attributes, so they cannot decrypt.
