# PLEDGE on Hyperledger Fabric 3.1.1

The same protocol as the Python reference, on Hyperledger Fabric 3.1.1 with
SmartBFT ordering: every hospital runs a BFT orderer, a peer and a key-share
service; the access chaincode (Go) re-implements every check of
`pledge/ledger/chaincode.py` and is cross-tested against it.

```
fabric/
  cmd/chaincode   PLEDGE chaincode (chaincode-as-a-service, Go + mcl): registry, records, access entries
  cmd/kss         key-share service: partial keys from its own peer's committed events
  cmd/gateway     HTTP bridge used by the Python actors (pledge/fabric_client.py)
  cmd/loadgen     open-loop load generator (throughput / latency / key-share delay)
  pkg/pledgecc    shared checks, canonical wire format, BLS + purpose-proof verification, ShareGen
  bin/            the programs above, prebuilt for Linux x86-64, and pledgecc.test (the test-vector check)
  network/pledge_net.py   creates the crypto material and BFT channel for n hospitals and starts everything
  run_stage2.py   end-to-end flows and attacks on the live network
  bench_ledger.py send-rate and bundle-size sweeps (Figs. 7 and 8)
  bench_e2e.py    first access and chart opening with HAPI FHIR (Fig. 11)
```

`reproduce.py` at the top of the package runs all of these with the paper's
parameters. By hand (Linux, after `./setup.sh`):

```bash
export FABRIC_BIN=$PWD/tools/fabric
tools/python/bin/python3 fabric/run_stage2.py --n 4 --bad-kss 1
tools/python/bin/python3 fabric/bench_ledger.py --n 4 --systems pledge,guo --rates 5,10,15,20,30,40,50,60,80,100,120 --duration 30 --out results/manual/n4fine
tools/python/bin/python3 fabric/network/pledge_net.py clean --n 4
```

`n` hospitals tolerate `f = (n-1)//3` Byzantine ones; the key threshold is
`k = f + 1` and the endorsement policy is `OutOf(k, H1MSP.peer, ..., HnMSP.peer)`.
Everything binds to 127.0.0.1; for a multi-host deployment replace the host in
`ports()`, `ConsenterMapping` and `AnchorPeers` of `network/pledge_net.py`.

## Rebuilding the Go programs

Needs Go 1.22+, `g++`, `make` and `git`. `./setup_deps.sh` fetches the Go
modules, builds herumi/mcl at the commit the Python side uses, builds the four
programs into `bin/` and runs the cross-language test. Regenerate the test
vectors after changing a check: `python3 scripts/gen_vectors.py fabric/pkg/pledgecc/testdata/vectors.json`.
