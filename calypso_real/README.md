# CALYPSO on its original code

This harness measures the unmodified DEDIS CALYPSO implementation
(`go.dedis.ch/cothority/v3/calypso`, commit `e0c9afbb847b070e1bda6f54561a4082b803db80`)
on ByzCoin with n = 4 conodes over localhost TCP. CALYPSO's DKG threshold there is
n-(n-1)/3 = 3.

    git clone https://github.com/dedis/cothority.git && cd cothority
    git checkout e0c9afbb847b070e1bda6f54561a4082b803db80
    cp /path/to/calypso_real/pledge_bench_test.go calypso/
    cd calypso && go test -c -o calbench .
    CAL_OUT=out CAL_BI=50ms,100ms,250ms,500ms CAL_N=40 \
      CAL_RATES=5,10,20,40,60,80,120 CAL_DUR=30s \
      ./calbench -test.run TestPledgeBench -test.timeout 3h -test.v

It needs Go 1.18 or newer and network access to the Go module proxy.

For each block interval it writes `out/calypso_bi<interval>.json` with:
- sequential per-record latencies over 40 records: encrypt, write commit,
  read commit, read proof, DecryptKey (trustee re-encryption) and key recovery
  plus AES-GCM decryption of a 2 KB record;
- ten darc-evolve transactions, which CALYPSO uses to revoke, onboard and narrow consent;
- an open-loop load test of first accesses at fixed rates;
- three security checks: DecryptKey with another record's read proof is refused;
  what a read transaction reveals to validators; and whether a threshold of
  trustees can pool their DKG shares and open records that nobody has read.

`run_vm.sh` is the unattended job used on the testbed VM. After the CALYPSO run
it also measures PLEDGE's first access on the same machine.

## Results in `results/`

`results/calypso/` holds the run reported in the paper (Section 7.3, "CALYPSO on its original
code"): one JSON per block interval plus the full log, on a GCP e2-standard-8 VM (8 vCPU, AMD EPYC).
`results/SUMMARY.txt` is produced by `python3 summarize.py results/calypso`. `results/pledge_same_vm/` is PLEDGE's
first-access run (40 accesses) on the same VM, for the latency comparison.

| Block interval | 50 ms | 100 ms | 250 ms | 500 ms |
|---|---|---|---|---|
| First access, median (ms) | 174.9 | 173.2 | 167.2 | 191.1 |
| Read committed / key re-encrypted, median (ms) | 70.5 / 50.3 | 87.9 / 50.6 | 74.0 / 50.3 | 83.8 / 57.1 |
| 5 first accesses/s | all done | all done | all done | all done |
| 10 first accesses/s | all done | 32 of 300 unfinished after 60 s | 58 of 300 | 51 of 300 |
| Darc evolve (revoke / onboard), median (ms) | 104.4 | 73.8 | 87.1 | 114.9 |

At every interval: DecryptKey with another record's read proof is refused; the read transaction
names the record and the reader's key, and the write is governed by the owner's darc; 3 of 4
trustees pooled their DKG shares and opened 5 of 5 records that had no read transaction, while 2
could not. PLEDGE's first access on the same VM: median 118.1 ms (40 accesses, HAPI fetch included).
The load test stops at the first rate CALYPSO cannot sustain, so higher rates were not offered.
