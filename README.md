# PLEDGE — source code and reproduction package

This package contains the complete source code of **PLEDGE** (ledger-gated
attribute-based encryption for accountable, consent-driven sharing of FHIR health
records), the three systems the paper compares it with, and every experiment of
the paper's evaluation (Section 7). One script reruns the experiments on your
computer and writes a report that puts each of your numbers next to the
paper's.

| Included | What it is |
| --- | --- |
| `pledge/` | PLEDGE: LG-ABE on BLS12-381 (mcl), threshold key-share services, FHIR Consent compiler, patient / clinician / authority applications, health-ID registration, audit log |
| `baselines/` | Re-implementations of **Guo et al. 2022**, **Romel et al. 2025** and **CALYPSO 2021** on the same curve and code base (assumptions in `baselines/README.md`) |
| `fabric/` | The Hyperledger Fabric 3.1.1 deployment: Go chaincode, key-share services, gateway, load generator (source + prebuilt Linux binaries) |
| `bench/`, `reproduce.py` | The experiments, the figures, and the comparison report |
| `tests/` | 66 unit, integration, attack and differential tests |
| `data/synthea-seed42.tar.gz` | The paper's Synthea cohort (50 synthetic patients, seed 42, 13,791 resources) |
| `paper_results/` | The raw results, figures and numbers behind the paper, for comparison |

The data sets:

* **Synthea** (synthetic, used in the paper): realistic FHIR records of 50 generated patients. The exact cohort of the paper is included, so record counts and sizes match the paper exactly.
* **MIMIC-IV Clinical Database Demo on FHIR v2.1.0** (real, Table 23 of the paper): 100 real, de-identified ICU patients from Beth Israel Deaconess Medical Center, published open access on PhysioNet under the ODbL 1.0 licence. Setup downloads it and checks every file against the publisher's SHA-256 sums. The FHIR workload runs on it exactly as on Synthea, with the same consent and the same HAPI FHIR server.

## Windows: one-click

1. Unzip the package to a folder whose path has no special characters (for example `C:\PLEDGE`).
2. Double-click **`1 - Setup.bat`**. It downloads a private copy of Python 3.12, Java 11, HAPI FHIR 5.1.0 and the MIMIC-IV data into this folder (about 2 GB, nothing is installed system-wide) and runs the unit tests.
3. Double-click **`2 - Quick check - about 30 minutes.bat`**: every experiment at reduced size.
   Or **`3 - Full paper experiments - several hours.bat`**: the paper's parameters.
4. The report opens in your browser when the run ends. **`4 - Open the latest report.bat`** opens it again.

**Hyperledger Fabric needs Linux.** If [Docker Desktop](https://www.docker.com/products/docker-desktop/) is installed and running, setup builds a Linux image and the run files use it for *all* experiments, including the Fabric ones (Figs. 7, 8 and 10), exactly as in the paper. Without Docker, everything else runs directly on Windows and the report marks the Fabric experiments as not run. In Docker Desktop, give the engine at least 6 GB of memory (Settings → Resources) for the full run.

## Linux (x86-64)

```bash
./setup.sh            # private Python 3.12, Java 11, HAPI FHIR, Fabric 3.1.1, MIMIC-IV data, unit tests
./run.sh quick        # about 30 minutes
./run.sh full         # the paper's parameters, several hours
```

## macOS, or any machine with Docker

```bash
./run.sh docker quick     # builds the image on first use, then runs everything inside it
./run.sh docker full
```

or by hand: `docker build -t pledge-artifact .` and
`docker run --rm -v "$PWD/results:/pledge/results" pledge-artifact quick`.

## What a run does

| Stage | Paper | Quick | Full |
| --- | --- | --- | --- |
| `tests` | 7.1 | 66 tests incl. the compiler-vs-reference differential test (6,000 triples) and, on Linux, the Go/Python test vectors | same |
| `attacks` | Table 17 | all 10 attacks against all 4 systems, each cell executed | same |
| `crypto` | Fig. 7 | 8 interleaved repetitions | 40 |
| `micro` | 7.4 | 5 repetitions | 30 |
| `lifecycle` | Fig. 10 | reduced grid | 10–250 records, 5–50 clinicians, 1–10 patients |
| `registration` | 7.6 | 5 repetitions | 20 |
| `fhir-synthea` | 7.7 | 5 patients into HAPI FHIR | the 50-patient cohort, 13,791 resources |
| `fhir-mimic` | — (real data) | 5 patients | all 100 patients |
| `fabric-smoke` | 7.1 | n = 4: flows, attacks, a faulty key-share service, registration, re-keying | same |
| `fabric-e2e` | Fig. 11 | 5 first accesses, charts of 1 and 10 records | 40 first accesses, charts of 1–100 records |
| `fabric-ledger` | Fig. 8 | PLEDGE vs Guo, n = 4, 10 and 20 entries/s for 10 s | 5–40 entries/s for 30 s; n = 7 and 10 |
| `fabric-bundle` | Fig. 9 | m = 1, 10 | m = 1, 10, 25, 50 |
| `figures`, `report` | Figs. 6–10 | | |

Run single stages with `--only` (and leave out stages with `--skip`), for example
`tools\python\python.exe reproduce.py full --only attacks,crypto` on Windows or
`./run.sh full --only lifecycle` on Linux. The groups `fabric` and `fhir` name several stages at once.

Every run writes to `results/<mode>-<date-time>/`:
`REPORT.html` (open it in a browser), `REPORT.md`, `numbers.json`, the figures `fig6`–`fig10`, every raw CSV/JSON file, and a log per stage in `logs/`.

## Symbolic verification (Tamarin)

The `tamarin/` folder holds the Tamarin model of the access protocol from the paper's appendix,
the log-privacy equivalence models, eight mutants that each remove one check, and the expected prover output. Run `tamarin/run.sh`
(needs `tamarin-prover` 1.10 and `maude` 3.5; about 10 minutes). See [tamarin/README.md](tamarin/README.md).

## Reading the report

* **Exact results** do not depend on the machine and must equal the paper's: the outcome of every attack against every system (Table 17), the test results, the differential test, the transaction and cryptographic-operation counts of revocation, onboarding and consent narrowing (Fig. 10), and the record counts of the Synthea cohort.
* **Statements of Section 7** — for example *PLEDGE's extra decryption cost over Guo et al. stays about constant*, or *revocation is one transaction whose cost does not grow with the records* — are evaluated on your own numbers, so they can be checked on any hardware.
* **Measured values** (milliseconds, entries per second) depend on the hardware. The paper used one Google Cloud e2-standard-8 VM (8 vCPU, 31 GiB) with every hospital on that host; the report shows the paper's value, yours, and their ratio. Faster machines give smaller times; the comparisons between systems should hold.
* **Figures**: yours next to the paper's.

## Notes

* The baselines are our re-implementations, not the authors' code; `baselines/README.md` lists what was kept, changed or assumed, as the paper does.
* CALYPSO runs its own skipchain ledger, which is not re-implemented; its ledger costs are counted as transactions, as in the paper.
* Client code is Python (with the C pairing library), so absolute times are upper bounds for an optimized implementation.
* Ports used during a run: 8080 (HAPI FHIR); for Fabric, 7010–7105, 8800–8810 and 9999. Close other programs using them.
* The Go programs in `fabric/bin/` and `pledge/crypto/libmcl.so` were built from `fabric/cmd`, `fabric/pkg` and mcl at the pinned commit with Go 1.24 on Ubuntu 22.04, so they run on Ubuntu 22.04 or newer (glibc 2.34+). To rebuild them: install Go 1.22+, `g++` and `make`, then run `fabric/setup_deps.sh` (it fetches the Go modules, builds mcl at the pinned commit, builds the four programs and runs the cross-language test).
* A map from each section of the paper to the code is in `docs/CODE_MAP.md`.

## Licences of third-party components

mcl (BSD-3-Clause, bundled as `pledge/crypto/libmcl.so` and `mcl.dll`); downloaded at setup: Hyperledger Fabric (Apache-2.0), HAPI FHIR (Apache-2.0), Eclipse Temurin JRE (GPLv2 with Classpath Exception), Python (PSF). Data: Synthea output (generated with Synthea, Apache-2.0); MIMIC-IV Clinical Database Demo on FHIR (ODbL 1.0) — cite Bennett et al., *MIMIC-IV Clinical Database Demo on FHIR* (version 2.1.0), PhysioNet, 2025, https://doi.org/10.13026/vphg-y548, and Johnson et al., *MIMIC-IV*, PhysioNet.
