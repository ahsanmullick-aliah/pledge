// PLEDGE access chaincode, run as an external service (chaincode-as-a-service).
//
//	CHAINCODE_ID=<package id> CHAINCODE_SERVER_ADDRESS=0.0.0.0:9999 pledge-chaincode
//
// Functions (all arguments are canonical-JSON transactions from the Python client):
//
//	InitConfig(cfg)           one-time: authority keys, regulator purpose key, n, k
//	RegisterCredential(tx)    authority-signed clinician credential
//	Revoke(tx)                authority-signed revocation
//	RegisterPatient(tx)       AA-certified patient registration Reg_P (or rotation)
//	RegisterRecord(tx)        owner-signed record tag, header hash and side record;
//	                          with "retires", a re-key that retires the old tag
//	Access(tx)                clinician access entry; emits chaincode event "access"
//	GetConfig / GetRecord(tau) / GetEntry(id) / IsRevoked(gid)
//
// The ledger time used for consent periods and clock-skew checks is the
// transaction timestamp, identical at every endorser.
package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"

	"github.com/hyperledger/fabric-chaincode-go/v2/shim"
	"github.com/hyperledger/fabric-protos-go-apiv2/peer"
	"pledge.local/fabric/pkg/pledgecc"
)

type stubState struct {
	stub shim.ChaincodeStubInterface
	cfg  *pledgecc.Config
}

func (s *stubState) Config() (*pledgecc.Config, error) {
	if s.cfg != nil {
		return s.cfg, nil
	}
	b, err := s.stub.GetState("cfg")
	if err != nil {
		return nil, err
	}
	if b == nil {
		return nil, fmt.Errorf("ledger not initialised")
	}
	var c pledgecc.Config
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, err
	}
	s.cfg = &c
	return s.cfg, nil
}

func (s *stubState) Credential(gid string) (*pledgecc.Cred, error) {
	b, err := s.stub.GetState("cred~" + gid)
	if err != nil || b == nil {
		return nil, err
	}
	var c pledgecc.Cred
	return &c, json.Unmarshal(b, &c)
}

// Revoked always reads the key, so a revocation committed earlier in the same
// block invalidates this transaction through Fabric's MVCC check.
func (s *stubState) Revoked(gid string) (bool, error) {
	b, err := s.stub.GetState("rev~" + gid)
	return b != nil, err
}

func (s *stubState) Record(tau string) (map[string]interface{}, error) {
	b, err := s.stub.GetState("rec~" + tau)
	if err != nil || b == nil {
		return nil, err
	}
	return pledgecc.Decode(b)
}

func (s *stubState) NonceSeen(gid, nonce string) (bool, error) {
	b, err := s.stub.GetState("nonce~" + gid + "~" + nonce)
	return b != nil, err
}

// PatientBound reads the binding key, so a concurrent registration of the same
// pseudonym is caught by MVCC.
func (s *stubState) PatientBound(psi string) (bool, error) {
	b, err := s.stub.GetState("pat~" + psi)
	return b != nil, err
}

func (s *stubState) EntryGID(id string) (string, error) {
	b, err := s.stub.GetState("entry~" + id)
	return string(b), err
}

type PledgeCC struct{}

func (PledgeCC) Init(stub shim.ChaincodeStubInterface) *peer.Response { return shim.Success(nil) }

func (PledgeCC) Invoke(stub shim.ChaincodeStubInterface) *peer.Response {
	fn, args := stub.GetFunctionAndParameters()
	st := &stubState{stub: stub}
	arg := func() ([]byte, map[string]interface{}, error) {
		if len(args) != 1 {
			return nil, nil, fmt.Errorf("expected one JSON argument")
		}
		m, err := pledgecc.Decode([]byte(args[0]))
		return []byte(args[0]), m, err
	}
	switch fn {
	case "InitConfig":
		if b, _ := stub.GetState("cfg"); b != nil {
			return shim.Error("already initialised")
		}
		var c pledgecc.Config
		if len(args) != 1 || json.Unmarshal([]byte(args[0]), &c) != nil || c.K < 1 || c.N < c.K {
			return shim.Error("bad config")
		}
		return put(stub, "cfg", []byte(args[0]), nil)
	case "RegisterCredential":
		_, m, err := arg()
		if err == nil {
			err = pledgecc.CheckCredential(st, m)
		}
		if err != nil {
			return shim.Error(err.Error())
		}
		c, _ := json.Marshal(pledgecc.Cred{VK: m["vk"].(string), AA: m["aa"].(string)})
		return put(stub, "cred~"+m["gid"].(string), c, nil)
	case "Revoke":
		_, m, err := arg()
		if err == nil {
			err = pledgecc.CheckRevoke(st, m)
		}
		if err != nil {
			return shim.Error(err.Error())
		}
		return put(stub, "rev~"+m["gid"].(string), []byte("1"), nil)
	case "RegisterRecord":
		_, m, err := arg()
		var owner string
		if err == nil {
			owner, err = pledgecc.CheckRecord(st, m)
		}
		if err != nil {
			return shim.Error(err.Error())
		}
		m["owner_vk"] = owner
		tau := m["tau"].(string)
		if old, ok := m["retires"].(string); ok {
			if old == tau {
				m["retired"] = true
			} else {
				prev, err := st.Record(old)
				if err != nil || prev == nil {
					return shim.Error("retired record vanished")
				}
				prev["retired"] = true
				pb, _ := pledgecc.Canon(prev)
				if err := stub.PutState("rec~"+old, pb); err != nil {
					return shim.Error(err.Error())
				}
			}
		}
		b, _ := pledgecc.Canon(m)
		return put(stub, "rec~"+tau, b, nil)
	case "RegisterPatient":
		_, m, err := arg()
		if err == nil {
			err = pledgecc.CheckPatient(st, m)
		}
		if err != nil {
			return shim.Error(err.Error())
		}
		b, _ := pledgecc.Canon(m)
		return put(stub, "pat~"+m["psi"].(string), b, nil)
	case "Access":
		_, m, err := arg()
		if err != nil {
			return shim.Error(err.Error())
		}
		ts, err := stub.GetTxTimestamp()
		if err != nil {
			return shim.Error(err.Error())
		}
		ev, err := pledgecc.CheckAccess(st, m, ts.GetSeconds())
		if err != nil {
			return shim.Error(err.Error())
		}
		if err := stub.PutState("nonce~"+ev.GID+"~"+m["nonce"].(string), []byte("1")); err != nil {
			return shim.Error(err.Error())
		}
		evb, _ := json.Marshal(ev)
		if err := stub.SetEvent("access", evb); err != nil {
			return shim.Error(err.Error())
		}
		return put(stub, "entry~"+ev.EntryID, []byte(ev.GID), evb)
	case "GuoLog":
		// Baseline (Guo et al. 2022): the client reports an access after decrypting.
		// The chaincode checks only the reporter's signature and stores the event in clear.
		_, m, err := arg()
		if err != nil {
			return shim.Error(err.Error())
		}
		gid, _ := m["gid"].(string)
		cred, err := st.Credential(gid)
		if err != nil || cred == nil {
			return shim.Error("unregistered clinician")
		}
		d, err := pledgecc.Digest("guolog", pledgecc.Body(m))
		if err != nil {
			return shim.Error(err.Error())
		}
		sig, _ := m["sig"].(string)
		if !pledgecc.BLSVerify(cred.VK, sig, d) {
			return shim.Error("bad log signature")
		}
		b, _ := pledgecc.Canon(pledgecc.Body(m))
		return put(stub, "glog~"+stub.GetTxID(), b, nil)
	case "GetConfig":
		return get(stub, "cfg")
	case "GetRecord":
		return get(stub, "rec~"+first(args))
	case "GetEntry":
		return get(stub, "entry~"+first(args))
	case "IsRevoked":
		b, err := stub.GetState("rev~" + first(args))
		if err != nil {
			return shim.Error(err.Error())
		}
		return shim.Success([]byte(fmt.Sprint(b != nil)))
	}
	return shim.Error("unknown function " + fn)
}

func first(a []string) string {
	if len(a) == 0 {
		return ""
	}
	return a[0]
}

func put(stub shim.ChaincodeStubInterface, k string, v, resp []byte) *peer.Response {
	if err := stub.PutState(k, v); err != nil {
		return shim.Error(err.Error())
	}
	return shim.Success(resp)
}

func get(stub shim.ChaincodeStubInterface, k string) *peer.Response {
	b, err := stub.GetState(k)
	if err != nil {
		return shim.Error(err.Error())
	}
	return shim.Success(b)
}

func main() {
	pledgecc.Init()
	server := &shim.ChaincodeServer{
		CCID:     os.Getenv("CHAINCODE_ID"),
		Address:  os.Getenv("CHAINCODE_SERVER_ADDRESS"),
		CC:       PledgeCC{},
		TLSProps: shim.TLSProperties{Disabled: true},
	}
	log.Printf("PLEDGE chaincode listening on %s (ccid %s)", server.Address, server.CCID)
	if err := server.Start(); err != nil {
		log.Fatal(err)
	}
}
