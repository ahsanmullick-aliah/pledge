#!/usr/bin/env bash
# Build the Go side of PLEDGE stage 2.
#   ./setup_deps.sh            # normal machine: Go modules download from the proxy
#   OFFLINE_SRC=/path ./setup_deps.sh   # sandbox: every module cloned under $OFFLINE_SRC
set -euo pipefail
cd "$(dirname "$0")"
MCL_COMMIT=9f49ba06593e2d426ab6fb9b0e17bc125a6f720c
if [ ! -f third_party/mcl/lib/libmcl.a ]; then
  mkdir -p third_party
  [ -d third_party/mcl ] || git clone -q https://github.com/herumi/mcl third_party/mcl
  git -C third_party/mcl checkout -q "$MCL_COMMIT"
  make -C third_party/mcl -j"$(nproc)" lib/libmcl.a
fi
if [ -n "${OFFLINE_SRC:-}" ]; then
  export GOFLAGS=-mod=mod GOPROXY=off GOSUMDB=off
  for pair in \
    github.com/hyperledger/fabric-chaincode-go/v2=fabric-chaincode-go \
    github.com/hyperledger/fabric-gateway=fabric-gateway \
    github.com/hyperledger/fabric-protos-go-apiv2=fabric-protos-go-apiv2 \
    google.golang.org/grpc=grpc google.golang.org/protobuf=protobuf \
    google.golang.org/genproto/googleapis/rpc=genproto/googleapis/rpc \
    golang.org/x/net=x-net golang.org/x/sys=x-sys golang.org/x/text=x-text golang.org/x/crypto=x-crypto; do
    go mod edit -replace "${pair%%=*}=$OFFLINE_SRC/${pair#*=}"
  done
else
  go mod tidy
fi
mkdir -p bin
for c in chaincode gateway kss loadgen; do go build -o "bin/pledge-$c" "./cmd/$c"; done
go test -c -o bin/pledgecc.test ./pkg/pledgecc/
go test ./pkg/pledgecc/
echo "built: $(ls bin | tr '\n' ' ')"
