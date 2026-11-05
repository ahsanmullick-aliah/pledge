// Open-loop load generator for the PLEDGE ledger (paper Figs. 8 and 9).
//
//	pledge-loadgen --profile run/n4/profile.json --input load.jsonl --rate 50 --out res.csv [--kss-base 8800]
//
// Each input line is {"fn": "Access", "arg": "<signed canonical tx>"} produced
// by fabric/bench_ledger.py. Transactions are released at a fixed send rate
// (open loop, so queueing shows up as latency), spread round-robin over every
// hospital's gateway. For each Access transaction it records endorsement,
// ordering/submit and commit times, and the time until all k key-share
// services named in S have released their partial keys.
package main

import (
	"bufio"
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/hyperledger/fabric-gateway/pkg/client"
	"pledge.local/fabric/pkg/fabconn"
	"pledge.local/fabric/pkg/pledgecc"
)

type job struct {
	Fn  string `json:"fn"`
	Arg string `json:"arg"`
}

type result struct {
	seq                                      int
	start                                    time.Time
	endorseMs, submitMs, commitMs, sharesMs  float64
	ok                                       bool
	code, err                                string
	block                                    uint64
	gw                                       int
}

func main() {
	profile := flag.String("profile", "", "connection profile")
	input := flag.String("input", "", "JSONL of signed transactions")
	rate := flag.Float64("rate", 10, "send rate (tx/s)")
	out := flag.String("out", "loadgen.csv", "per-transaction CSV")
	ccName := flag.String("chaincode", "", "chaincode name (default: profile's)")
	kssBase := flag.Int("kss-base", 8800, "key-share service i listens on 127.0.0.1:<kss-base+i>; 0 disables")
	flag.Parse()
	prof, err := fabconn.LoadProfile(*profile)
	if err != nil {
		log.Fatal(err)
	}
	var contracts []*client.Contract
	for _, h := range prof.Hospitals {
		gw, conn, err := fabconn.Connect(h)
		if err != nil {
			log.Fatal(err)
		}
		defer conn.Close()
		defer gw.Close()
		name := prof.Chaincode
		if *ccName != "" {
			name = *ccName
		}
		contracts = append(contracts, gw.GetNetwork(prof.Channel).GetContract(name))
	}
	f, err := os.Open(*input)
	if err != nil {
		log.Fatal(err)
	}
	var jobs []job
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<24)
	for sc.Scan() {
		var j job
		if err := json.Unmarshal(sc.Bytes(), &j); err != nil {
			log.Fatal(err)
		}
		jobs = append(jobs, j)
	}
	results := make([]result, len(jobs))
	var wg sync.WaitGroup
	interval := time.Duration(float64(time.Second) / *rate)
	t0 := time.Now()
	httpc := &http.Client{Timeout: 5 * time.Second}
	for i, j := range jobs {
		next := t0.Add(time.Duration(i) * interval)
		if d := time.Until(next); d > 0 {
			time.Sleep(d)
		}
		wg.Add(1)
		go func(i int, j job) {
			defer wg.Done()
			c := contracts[i%len(contracts)]
			r := result{seq: i, start: time.Now(), gw: i%len(contracts) + 1}
			prop, err := c.NewProposal(j.Fn, client.WithArguments(j.Arg))
			if err != nil {
				r.err = err.Error()
				results[i] = r
				return
			}
			a := time.Now()
			tx, err := prop.Endorse()
			b := time.Now()
			r.endorseMs = ms(b.Sub(a))
			if err != nil {
				r.err = "endorse: " + err.Error()
				results[i] = r
				return
			}
			commit, err := tx.Submit()
			cT := time.Now()
			r.submitMs = ms(cT.Sub(b))
			if err != nil {
				r.err = "submit: " + err.Error()
				results[i] = r
				return
			}
			st, err := commit.Status()
			d := time.Now()
			r.commitMs = ms(d.Sub(cT))
			if err != nil {
				r.err = "status: " + err.Error()
				results[i] = r
				return
			}
			r.ok, r.code, r.block = st.Successful, st.Code.String(), st.BlockNumber
			if r.ok && j.Fn == "Access" && *kssBase > 0 {
				var ev pledgecc.AccessEvent
				if json.Unmarshal(tx.Result(), &ev) == nil {
					r.sharesMs = waitShares(httpc, *kssBase, ev, d)
				}
			}
			results[i] = r
		}(i, j)
	}
	wg.Wait()
	elapsed := time.Since(t0)
	write(*out, results)
	summarize(results, elapsed, *rate)
}

// waitShares polls the k designated key-share services until each has released its share.
func waitShares(c *http.Client, base int, ev pledgecc.AccessEvent, since time.Time) float64 {
	deadline := time.Now().Add(10 * time.Second)
	pending := map[int64]bool{}
	for _, i := range ev.S {
		pending[i] = true
	}
	for len(pending) > 0 && time.Now().Before(deadline) {
		for i := range pending {
			resp, err := c.Get(fmt.Sprintf("http://127.0.0.1:%d/shares?entry=%s", base+int(i), ev.EntryID))
			if err == nil {
				resp.Body.Close()
				if resp.StatusCode == 200 {
					delete(pending, i)
				}
			}
		}
		if len(pending) > 0 {
			time.Sleep(5 * time.Millisecond)
		}
	}
	if len(pending) > 0 {
		return -1
	}
	return ms(time.Since(since))
}

func ms(d time.Duration) float64 { return float64(d.Microseconds()) / 1000 }

func write(path string, rs []result) {
	f, err := os.Create(path)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()
	w := csv.NewWriter(f)
	w.Write([]string{"seq", "gateway", "ok", "code", "block", "endorse_ms", "submit_ms", "commit_ms", "shares_ms", "error"})
	for _, r := range rs {
		w.Write([]string{strconv.Itoa(r.seq), strconv.Itoa(r.gw), strconv.FormatBool(r.ok), r.code,
			strconv.FormatUint(r.block, 10), f3(r.endorseMs), f3(r.submitMs), f3(r.commitMs), f3(r.sharesMs), r.err})
	}
	w.Flush()
}

func f3(x float64) string { return strconv.FormatFloat(x, 'f', 3, 64) }

func pct(xs []float64, p float64) float64 {
	if len(xs) == 0 {
		return 0
	}
	sort.Float64s(xs)
	return xs[int(p*float64(len(xs)-1))]
}

func summarize(rs []result, elapsed time.Duration, rate float64) {
	var ok int
	var lat, shares []float64
	var first, last time.Time
	for _, r := range rs {
		if !r.ok {
			continue
		}
		ok++
		lat = append(lat, r.endorseMs+r.submitMs+r.commitMs)
		if r.sharesMs > 0 {
			shares = append(shares, r.sharesMs)
		}
		end := r.start.Add(time.Duration((r.endorseMs + r.submitMs + r.commitMs) * float64(time.Millisecond)))
		if first.IsZero() || r.start.Before(first) {
			first = r.start
		}
		if end.After(last) {
			last = end
		}
	}
	tput := 0.0
	if ok > 0 {
		tput = float64(ok) / last.Sub(first).Seconds()
	}
	fmt.Printf("send_rate=%.1f sent=%d committed_valid=%d throughput=%.1f tx/s latency_ms p50=%.1f p95=%.1f "+
		"key_shares_after_commit_ms p50=%.1f p95=%.1f wall=%.1fs\n",
		rate, len(rs), ok, tput, pct(lat, 0.5), pct(lat, 0.95), pct(shares, 0.5), pct(shares, 0.95), elapsed.Seconds())
}
