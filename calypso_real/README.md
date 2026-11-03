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
