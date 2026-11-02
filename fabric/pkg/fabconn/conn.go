// Package fabconn opens Fabric Gateway connections from the profile written by pledge_net.py.
package fabconn

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"time"

	"github.com/hyperledger/fabric-gateway/pkg/client"
	"github.com/hyperledger/fabric-gateway/pkg/identity"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

type Hospital struct {
	Index    int    `json:"index"`
	MSPID    string `json:"mspid"`
	Peer     string `json:"peer"`
	PeerHost string `json:"peer_host"`
	TLSCA    string `json:"tls_ca"`
	Cert     string `json:"cert"`
	Key      string `json:"key"`
}

type Profile struct {
	Channel   string     `json:"channel"`
	Chaincode string     `json:"chaincode"`
	N         int        `json:"n"`
	K         int        `json:"k"`
	F         int        `json:"f"`
	Hospitals []Hospital `json:"hospitals"`
}

func LoadProfile(path string) (*Profile, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var p Profile
	return &p, json.Unmarshal(b, &p)
}

func readPEM(path string) ([]byte, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	blk, _ := pem.Decode(b)
	if blk == nil {
		return nil, fmt.Errorf("no PEM block in %s", path)
	}
	return blk.Bytes, nil
}

// Connect opens a gateway session as hospital h's client identity, through h's own peer.
func Connect(h Hospital) (*client.Gateway, *grpc.ClientConn, error) {
	caPEM, err := os.ReadFile(h.TLSCA)
	if err != nil {
		return nil, nil, err
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(caPEM)
	conn, err := grpc.NewClient(h.Peer, grpc.WithTransportCredentials(credentials.NewClientTLSFromCert(pool, h.PeerHost)))
	if err != nil {
		return nil, nil, err
	}
	certDER, err := readPEM(h.Cert)
	if err != nil {
		return nil, nil, err
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, nil, err
	}
	id, err := identity.NewX509Identity(h.MSPID, cert)
	if err != nil {
		return nil, nil, err
	}
	keyDER, err := readPEM(h.Key)
	if err != nil {
		return nil, nil, err
	}
	key, err := x509.ParsePKCS8PrivateKey(keyDER)
	if err != nil {
		return nil, nil, err
	}
	sign, err := identity.NewPrivateKeySign(key)
	if err != nil {
		return nil, nil, err
	}
	gw, err := client.Connect(id, client.WithSign(sign), client.WithClientConnection(conn),
		client.WithEvaluateTimeout(30*time.Second), client.WithEndorseTimeout(60*time.Second),
		client.WithSubmitTimeout(60*time.Second), client.WithCommitStatusTimeout(2*time.Minute))
	if err != nil {
		conn.Close()
		return nil, nil, err
	}
	return gw, conn, nil
}
