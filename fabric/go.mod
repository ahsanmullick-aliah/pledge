module pledge.local/fabric

go 1.22.0

require (
	github.com/herumi/mcl v0.0.0
	github.com/hyperledger/fabric-chaincode-go/v2 v2.1.0
	github.com/hyperledger/fabric-gateway v1.7.0
	github.com/hyperledger/fabric-protos-go-apiv2 v0.3.5
	google.golang.org/grpc v1.69.4
	google.golang.org/protobuf v1.36.3
)

// herumi/mcl is built from source (cgo) by setup_deps.sh at the commit the
// Python side uses, so both languages share one pairing implementation.
replace github.com/herumi/mcl => ./third_party/mcl
