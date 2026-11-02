// Key-share service of one hospital.
//
//	pledge-kss --profile run/n4/profile.json --index 2 --secret secrets/kss2.json --listen 127.0.0.1:8802
//
// It follows chaincode events from its OWN hospital's peer. Fabric delivers
// chaincode events only for transactions that were ordered, committed and
// marked valid, so a partial key is produced only for a committed access
// entry (paper Section V-E, step 5). Clinicians fetch partial keys with
//
//	GET /shares?entry=<entry id>  ->  [PartialKey]
package main

import (
	"context"
	"encoding/json"
	"flag"
	"log"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/hyperledger/fabric-gateway/pkg/client"
	"pledge.local/fabric/pkg/fabconn"
	"pledge.local/fabric/pkg/pledgecc"
)

type issued struct {
	Parts     []*pledgecc.PartialKey `json:"parts"`
	Block     uint64               `json:"block"`
	IssuedAt  float64              `json:"issued_at"`
	ShareGenMs float64             `json:"sharegen_ms"`
}

func main() {
	profile := flag.String("profile", "", "connection profile")
	index := flag.Int("index", 1, "hospital / service index (1..n)")
	secretPath := flag.String("secret", "", "DKG share file")
	listen := flag.String("listen", "", "HTTP listen address")
	mode := flag.String("mode", "honest", "honest | silent | bad_share (fault injection)")
	flag.Parse()
	pledgecc.Init()
	prof, err := fabconn.LoadProfile(*profile)
	if err != nil {
		log.Fatal(err)
	}
	raw, err := os.ReadFile(*secretPath)
	if err != nil {
		log.Fatal(err)
	}
	var sec pledgecc.KSSSecret
	if err := json.Unmarshal(raw, &sec); err != nil {
		log.Fatal(err)
	}
	if sec.Index != *index {
		log.Fatalf("secret file is for service %d, not %d", sec.Index, *index)
	}
	gw, conn, err := fabconn.Connect(prof.Hospitals[*index-1])
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()
	defer gw.Close()
	network := gw.GetNetwork(prof.Channel)

	var mu sync.Mutex
	store := map[string]*issued{}

	go func() {
		for {
			events, err := network.ChaincodeEvents(context.Background(), prof.Chaincode, client.WithStartBlock(0))
			if err != nil {
				log.Printf("event stream: %v (retrying)", err)
				time.Sleep(time.Second)
				continue
			}
			for ev := range events {
				if ev.EventName != "access" || *mode == "silent" {
					continue
				}
				var ae pledgecc.AccessEvent
				if json.Unmarshal(ev.Payload, &ae) != nil {
					continue
				}
				named := false
				for _, i := range ae.S {
					if int(i) == *index {
						named = true
					}
				}
				if !named {
					continue
				}
				t0 := time.Now()
				rec := &issued{Block: ev.BlockNumber}
				for _, tau := range ae.Taus {
					attr := "acc:" + tau
					if ae.Breakglass {
						attr = "eacc:" + tau
					}
					pk, err := pledgecc.ShareGen(&sec, ae.GID, attr, ae.S)
					if err != nil {
						log.Printf("sharegen: %v", err)
						continue
					}
					if *mode == "bad_share" {
						pk.K = pk.K[:len(pk.K)-2] + "00"
					}
					rec.Parts = append(rec.Parts, pk)
				}
				rec.ShareGenMs = float64(time.Since(t0).Microseconds()) / 1000
				rec.IssuedAt = float64(time.Now().UnixNano()) / 1e9
				mu.Lock()
				store[ae.EntryID] = rec
				mu.Unlock()
			}
			time.Sleep(time.Second)
		}
	}()

	http.HandleFunc("/shares", func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Query().Get("entry")
		mu.Lock()
		rec := store[id]
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		if rec == nil {
			w.WriteHeader(404)
			w.Write([]byte(`{"error":"no committed entry with this id names this service"}`))
			return
		}
		json.NewEncoder(w).Encode(rec)
	})
	log.Printf("KSS %d (%s) listening on %s", *index, *mode, *listen)
	log.Fatal(http.ListenAndServe(*listen, nil))
}
