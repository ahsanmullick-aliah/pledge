// HTTP bridge from the Python PLEDGE actors to the Fabric Gateway.
//
//	pledge-gateway --profile run/n4/profile.json --hospital 1 --listen 127.0.0.1:8800
//
//	POST /submit   {"fn": "Access", "arg": "<canonical tx JSON>"}
//	     -> {"tx_id","block","valid","code","result","endorse_ms","submit_ms","commit_ms"}
//	        HTTP 409 with {"error": ...} when endorsement is refused (chaincode check failed)
//	POST /evaluate {"fn": "GetRecord", "args": ["<tau>"]} -> {"result": "<payload>"}
package main

import (
	"encoding/json"
	"strings"
	"flag"
	"log"
	"net/http"
	"time"

	"github.com/hyperledger/fabric-gateway/pkg/client"
	"github.com/hyperledger/fabric-protos-go-apiv2/gateway"
	"google.golang.org/grpc/status"
	"pledge.local/fabric/pkg/fabconn"
)

type submitReq struct {
	Fn  string `json:"fn"`
	Arg string `json:"arg"`
	CC  string `json:"cc"`
}

type evalReq struct {
	Fn   string   `json:"fn"`
	Args []string `json:"args"`
	CC   string   `json:"cc"`
}

func main() {
	profile := flag.String("profile", "", "connection profile from pledge_net.py")
	hosp := flag.Int("hospital", 1, "which hospital's peer and client identity to use")
	listen := flag.String("listen", "127.0.0.1:8800", "HTTP listen address")
	flag.Parse()
	prof, err := fabconn.LoadProfile(*profile)
	if err != nil {
		log.Fatal(err)
	}
	gw, conn, err := fabconn.Connect(prof.Hospitals[*hosp-1])
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()
	defer gw.Close()
	network := gw.GetNetwork(prof.Channel)
	contractFor := func(name string) *client.Contract {
		if name == "" {
			name = prof.Chaincode
		}
		return network.GetContract(name)
	}

	reply := func(w http.ResponseWriter, code int, v interface{}) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		json.NewEncoder(w).Encode(v)
	}

	http.HandleFunc("/submit", func(w http.ResponseWriter, r *http.Request) {
		var req submitReq
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			reply(w, 400, map[string]string{"error": err.Error()})
			return
		}
		t0 := time.Now()
		prop, err := contractFor(req.CC).NewProposal(req.Fn, client.WithArguments(req.Arg))
		if err != nil {
			reply(w, 400, map[string]string{"error": err.Error()})
			return
		}
		tx, err := prop.Endorse()
		t1 := time.Now()
		if err != nil {
			reply(w, 409, map[string]interface{}{"error": detail(err), "endorse_ms": ms(t1.Sub(t0))})
			return
		}
		commit, err := tx.Submit()
		t2 := time.Now()
		if err != nil {
			reply(w, 502, map[string]string{"error": err.Error()})
			return
		}
		st, err := commit.Status()
		t3 := time.Now()
		if err != nil {
			reply(w, 502, map[string]string{"error": err.Error()})
			return
		}
		reply(w, 200, map[string]interface{}{
			"tx_id": st.TransactionID, "block": st.BlockNumber, "valid": st.Successful,
			"code": st.Code.String(), "result": string(tx.Result()),
			"endorse_ms": ms(t1.Sub(t0)), "submit_ms": ms(t2.Sub(t1)), "commit_ms": ms(t3.Sub(t2)),
		})
	})

	http.HandleFunc("/evaluate", func(w http.ResponseWriter, r *http.Request) {
		var req evalReq
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			reply(w, 400, map[string]string{"error": err.Error()})
			return
		}
		res, err := contractFor(req.CC).EvaluateTransaction(req.Fn, req.Args...)
		if err != nil {
			reply(w, 409, map[string]string{"error": detail(err)})
			return
		}
		reply(w, 200, map[string]string{"result": string(res)})
	})

	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		reply(w, 200, map[string]interface{}{"ok": true, "n": prof.N, "k": prof.K})
	})
	log.Printf("PLEDGE gateway bridge on %s via %s", *listen, prof.Hospitals[*hosp-1].Peer)
	log.Fatal(http.ListenAndServe(*listen, nil))
}

// detail extracts the chaincode's own rejection message from a gateway error.
func detail(err error) string {
	st, ok := status.FromError(err)
	if !ok {
		return err.Error()
	}
	for _, d := range st.Details() {
		if ed, ok := d.(*gateway.ErrorDetail); ok && ed.GetMessage() != "" {
			msg := ed.GetMessage()
			if i := strings.Index(msg, "message="); i >= 0 {
				msg = msg[i+len("message="):]
			}
			return msg
		}
	}
	return st.Message()
}

func ms(d time.Duration) float64 { return float64(d.Microseconds()) / 1000 }
