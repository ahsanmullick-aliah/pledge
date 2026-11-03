package calypso

// PLEDGE comparison harness for the unmodified DEDIS CALYPSO code
// (go.dedis.ch/cothority/v3/calypso on ByzCoin).
//
//   CAL_OUT=/path/to/out CAL_BI=50ms,100ms,250ms,500ms CAL_N=40 \
//   CAL_RATES=5,10,20,40 CAL_DUR=30s \
//   go test -run TestPledgeBench -timeout 4h -v .
//
// For each ByzCoin block interval it starts n=4 conodes on localhost TCP
// (onet.NewTCPTest), creates the long-term secret (DKG, threshold
// n-(n-1)/3 as in the CALYPSO service), and measures:
//   seq.*    sequential per-record latencies (write, read, re-encryption, recovery)
//   evolve   one darc-evolve transaction (revoke / onboard / narrow consent)
//   load.*   open-loop first accesses (read tx + DecryptKey + recovery) at fixed rates
// and executes three security checks on the real code:
//   no_read      DecryptKey with a read proof for another record is refused
//   leak         what a validator reads off the ledger for one access
//   quorum_open  t trustees pool their DKG shares and open records with no read tx

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.dedis.ch/cothority/v3"
	"go.dedis.ch/cothority/v3/byzcoin"
	"go.dedis.ch/cothority/v3/darc"
	"go.dedis.ch/cothority/v3/darc/expression"
	"go.dedis.ch/kyber/v3/share"
	"go.dedis.ch/onet/v3"
)

const nNodes = 4
const payloadSize = 2048
const nReaders = 64
const maxBacklog = 200
const drainTimeout = 60 * time.Second

func envOr(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

func ms(d time.Duration) float64 { return float64(d.Microseconds()) / 1000 }

type pool struct {
	signer darc.Signer
	ctr    uint64
}

type rec struct {
	Key   []byte
	Nonce []byte
	CT    []byte
	Proof *byzcoin.Proof
	Plain []byte
}

func sealRecord(t *testing.T) (key, nonce, ct, plain []byte) {
	key = make([]byte, 16)
	nonce = make([]byte, 12)
	plain = make([]byte, payloadSize)
	rand.Read(key)
	rand.Read(nonce)
	rand.Read(plain)
	b, err := aes.NewCipher(key)
	require.NoError(t, err)
	g, err := cipher.NewGCM(b)
	require.NoError(t, err)
	ct = g.Seal(nil, nonce, plain, nil)
	return
}

func openRecord(key, nonce, ct []byte) ([]byte, error) {
	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	g, err := cipher.NewGCM(b)
	if err != nil {
		return nil, err
	}
	return g.Open(nil, nonce, ct, nil)
}

type result struct {
	BlockInterval string                   `json:"block_interval"`
	Nodes         int                      `json:"nodes"`
	Threshold     int                      `json:"threshold"`
	PayloadBytes  int                      `json:"payload_bytes"`
	Seq           map[string][]float64     `json:"seq_ms"`
	Evolve        []float64                `json:"evolve_ms"`
	Load          []map[string]interface{} `json:"load"`
	Security      map[string]interface{}   `json:"security"`
	Errors        []string                 `json:"errors"`
	Started       string                   `json:"started"`
	Finished      string                   `json:"finished"`
}

func TestPledgeBench(t *testing.T) {
	if os.Getenv("CAL_OUT") == "" {
		t.Skip("set CAL_OUT to run the PLEDGE comparison harness")
	}
	out := os.Getenv("CAL_OUT")
	require.NoError(t, os.MkdirAll(out, 0755))
	n, _ := strconv.Atoi(envOr("CAL_N", "40"))
	dur, err := time.ParseDuration(envOr("CAL_DUR", "30s"))
	require.NoError(t, err)
	var rates []float64
	for _, s := range strings.Split(envOr("CAL_RATES", "5,10,20,40"), ",") {
		r, err := strconv.ParseFloat(s, 64)
		require.NoError(t, err)
		rates = append(rates, r)
	}
	for _, bis := range strings.Split(envOr("CAL_BI", "50ms,100ms,250ms,500ms"), ",") {
		bi, err := time.ParseDuration(bis)
		require.NoError(t, err)
		runOne(t, bi, n, rates, dur, filepath.Join(out, "calypso_bi"+bis+".json"))
	}
}

func runOne(t *testing.T, bi time.Duration, n int, rates []float64, dur time.Duration, fn string) {
	res := &result{BlockInterval: bi.String(), Nodes: nNodes, PayloadBytes: payloadSize,
		Seq: map[string][]float64{}, Security: map[string]interface{}{},
		Started: time.Now().UTC().Format(time.RFC3339)}
	errf := func(f string, a ...interface{}) {
		s := fmt.Sprintf(f, a...)
		res.Errors = append(res.Errors, s)
		t.Log(s)
	}
	wait := int(10*time.Second/bi) + 2

	l := onet.NewTCPTest(cothority.Suite)
	// a saturated load level leaves requests in flight; do not fail on them at shutdown
	l.Check = onet.CheckNone
	servers, roster, _ := l.GenTree(nNodes, true)
	defer l.CloseAll()

	admin := darc.NewSignerEd25519(nil, nil)
	adminCt := uint64(1)
	msg, err := byzcoin.DefaultGenesisMsg(byzcoin.CurrentVersion, roster,
		[]string{"spawn:" + ContractLongTermSecretID}, admin.Identity())
	require.NoError(t, err)
	msg.BlockInterval = bi
	gDarc := msg.GenesisDarc
	bc, _, err := byzcoin.NewLedger(msg, false)
	require.NoError(t, err)
	cl := NewClient(bc)
	for _, who := range roster.List {
		require.NoError(t, cl.Authorize(who, bc.ID))
	}
	lts, err := cl.CreateLTS(roster, gDarc.GetBaseID(), []darc.Signer{admin}, []uint64{adminCt})
	require.NoError(t, err)
	adminCt++
	cl.ltsReply = lts

	// One patient (data provider) and a pool of clinicians (readers)
	patient := darc.NewSignerEd25519(nil, nil)
	patientCt := uint64(1)
	readers := make([]*pool, nReaders)
	ids := make([]string, nReaders)
	for i := range readers {
		readers[i] = &pool{signer: darc.NewSignerEd25519(nil, nil), ctr: 1}
		ids[i] = readers[i].signer.Identity().String()
	}
	pd := darc.NewDarc(darc.InitRulesWith([]darc.Identity{patient.Identity()},
		[]darc.Identity{patient.Identity()}, "invoke:darc.evolve"), []byte("Patient-P1"))
	require.NoError(t, pd.Rules.AddRule(darc.Action("spawn:"+ContractWriteID),
		expression.InitOrExpr(patient.Identity().String())))
	require.NoError(t, pd.Rules.AddRule(darc.Action("spawn:"+ContractReadID),
		expression.InitOrExpr(ids...)))
	_, err = cl.SpawnDarc(admin, adminCt, gDarc, *pd, wait)
	require.NoError(t, err)
	adminCt++

	writeRecord := func() (*rec, time.Duration, time.Duration, error) {
		key, nonce, ct, plain := sealRecord(t)
		t0 := time.Now()
		w := NewWrite(cothority.Suite, lts.InstanceID, pd.GetBaseID(), lts.X, key)
		tEnc := time.Since(t0)
		t1 := time.Now()
		wr, err := cl.AddWrite(w, patient, patientCt, *pd, wait)
		if err != nil {
			return nil, 0, 0, err
		}
		patientCt++
		pr, err := cl.WaitProof(wr.InstanceID, 20*time.Millisecond, nil)
		if err != nil {
			return nil, 0, 0, err
		}
		return &rec{Key: key, Nonce: nonce, CT: ct, Proof: pr, Plain: plain}, tEnc, time.Since(t1), nil
	}

	// firstAccess = read transaction committed + proof + DecryptKey + recovery
	type acc struct{ commit, proof, dk, recov time.Duration }
	access := func(r *rec, rd *pool) (*acc, *byzcoin.Proof, error) {
		a := &acc{}
		t0 := time.Now()
		re, err := cl.AddRead(r.Proof, rd.signer, rd.ctr, wait)
		if err != nil {
			return nil, nil, err
		}
		rd.ctr++
		a.commit = time.Since(t0)
		t1 := time.Now()
		prRe, err := cl.WaitProof(re.InstanceID, 20*time.Millisecond, nil)
		if err != nil {
			return nil, nil, err
		}
		a.proof = time.Since(t1)
		t2 := time.Now()
		dk, err := cl.DecryptKey(&DecryptKey{Read: *prRe, Write: *r.Proof})
		if err != nil {
			return nil, nil, err
		}
		a.dk = time.Since(t2)
		t3 := time.Now()
		k, err := dk.RecoverKey(rd.signer.Ed25519.Secret)
		if err != nil {
			return nil, nil, err
		}
		pt, err := openRecord(k, r.Nonce, r.CT)
		if err != nil {
			return nil, nil, err
		}
		a.recov = time.Since(t3)
		if string(pt) != string(r.Plain) {
			return nil, nil, fmt.Errorf("wrong plaintext")
		}
		return a, prRe, nil
	}

	// ---------------- sequential per-record latencies ----------------
	var recs []*rec
	var lastRead *byzcoin.Proof
	for i := 0; i < n; i++ {
		r, tEnc, tW, err := writeRecord()
		if err != nil {
			errf("write %d: %v", i, err)
			continue
		}
		recs = append(recs, r)
		res.Seq["encrypt"] = append(res.Seq["encrypt"], ms(tEnc))
		res.Seq["write_commit"] = append(res.Seq["write_commit"], ms(tW))
		a, prRe, err := access(r, readers[i%nReaders])
		if err != nil {
			errf("access %d: %v", i, err)
			continue
		}
		lastRead = prRe
		res.Seq["read_commit"] = append(res.Seq["read_commit"], ms(a.commit))
		res.Seq["read_proof"] = append(res.Seq["read_proof"], ms(a.proof))
		res.Seq["decrypt_key"] = append(res.Seq["decrypt_key"], ms(a.dk))
		res.Seq["recover"] = append(res.Seq["recover"], ms(a.recov))
		res.Seq["first_access"] = append(res.Seq["first_access"], ms(a.commit+a.proof+a.dk+a.recov))
	}
	require.True(t, len(recs) >= 2 && lastRead != nil, "too few successful records")

	// ---------------- security checks on the real code ----------------
	// (a) re-encryption without a committed read for THIS record is refused
	_, err = cl.DecryptKey(&DecryptKey{Read: *lastRead, Write: *recs[0].Proof})
	res.Security["decrypt_without_matching_read_refused"] = err != nil

	// (b) what a validator reads off the ledger for one access
	var rd Read
	require.NoError(t, lastRead.VerifyAndDecode(cothority.Suite, ContractReadID, &rd))
	wp, err := bc.GetProof(rd.Write.Slice())
	require.NoError(t, err)
	_, _, _, wDarcID, err := wp.Proof.KeyValue()
	require.NoError(t, err)
	dp, err := bc.GetProof(wDarcID)
	require.NoError(t, err)
	_, dv, _, _, err := dp.Proof.KeyValue()
	require.NoError(t, err)
	od, err := darc.NewFromProtobuf(dv)
	require.NoError(t, err)
	res.Security["read_tx_names_write_instance"] = rd.Write.String()
	res.Security["read_tx_names_reader_key"] = rd.Xc.String()
	res.Security["write_instance_darc_description"] = string(od.Description)

	// (c) a threshold of trustees pools DKG shares and opens records that
	// were never read, with no transaction at all
	svcs := l.GetServices(servers, calypsoID)
	var shares []*share.PriShare
	for _, s := range svcs {
		ss := s.(*Service).storage.Shared[lts.InstanceID]
		if ss != nil {
			shares = append(shares, &share.PriShare{I: ss.Index, V: ss.V.Clone()})
		}
	}
	thr := nNodes - (nNodes-1)/3
	res.Threshold = thr
	res.Security["trustees_with_shares"] = len(shares)
	tryOpen := func(k int) (bool, int, int) {
		x, err := share.RecoverSecret(cothority.Suite, shares[:k], k, nNodes)
		if err != nil {
			return false, 0, 0
		}
		okX := cothority.Suite.Point().Mul(x, nil).Equal(lts.X)
		opened, tried := 0, 0
		for i := 0; i < 5; i++ {
			r, _, _, err := writeRecord() // fresh records, never read
			if err != nil {
				errf("quorum write: %v", err)
				continue
			}
			tried++
			var w Write
			if err := r.Proof.VerifyAndDecode(cothority.Suite, ContractWriteID, &w); err != nil {
				continue
			}
			kp := cothority.Suite.Point().Sub(w.C, cothority.Suite.Point().Mul(x, w.U))
			key, err := kp.Data()
			if err != nil {
				continue
			}
			if pt, err := openRecord(key, r.Nonce, r.CT); err == nil && string(pt) == string(r.Plain) {
				opened++
			}
		}
		return okX, opened, tried
	}
	if len(shares) >= thr {
		ok, o, tr := tryOpen(thr)
		res.Security["quorum_t"] = thr
		res.Security["quorum_recovers_lts_key"] = ok
		res.Security["quorum_opened_unread_records"] = fmt.Sprintf("%d/%d", o, tr)
		ok2, o2, tr2 := tryOpen(thr - 1)
		res.Security["below_quorum_recovers_lts_key"] = ok2
		res.Security["below_quorum_opened_unread_records"] = fmt.Sprintf("%d/%d", o2, tr2)
	}

	// ---------------- darc evolve: revoke / onboard / narrow consent ----------------
	cur := pd
	revoked := readers[nReaders-1]
	for i := 0; i < 10; i++ {
		nd := cur.Copy()
		var keep []string
		if i%2 == 0 { // revoke the last reader
			keep = ids[:nReaders-1]
		} else { // onboard it again
			keep = ids
		}
		require.NoError(t, nd.Rules.UpdateRule(darc.Action("spawn:"+ContractReadID), expression.InitOrExpr(keep...)))
		require.NoError(t, nd.EvolveFrom(cur))
		buf, err := nd.ToProto()
		require.NoError(t, err)
		ctx := byzcoin.NewClientTransaction(byzcoin.CurrentVersion, byzcoin.Instruction{
			InstanceID: byzcoin.NewInstanceID(pd.GetBaseID()),
			Invoke: &byzcoin.Invoke{ContractID: byzcoin.ContractDarcID, Command: "evolve",
				Args: byzcoin.Arguments{{Name: "darc", Value: buf}}},
			SignerCounter: []uint64{patientCt},
		})
		require.NoError(t, ctx.FillSignersAndSignWith(patient))
		t0 := time.Now()
		_, err = bc.AddTransactionAndWait(ctx, wait)
		if err != nil {
			errf("evolve %d: %v", i, err)
			break
		}
		res.Evolve = append(res.Evolve, ms(time.Since(t0)))
		patientCt++
		cur = nd
		if i == 0 {
			_, err := cl.AddRead(recs[0].Proof, revoked.signer, revoked.ctr, wait)
			res.Security["revoked_reader_read_refused"] = err != nil
			if err == nil {
				revoked.ctr++
			}
		}
	}

	// ---------------- open-loop load: first accesses at fixed rates ----------------
	free := make(chan *pool, nReaders)
	for _, r := range readers {
		free <- r
	}
	for _, rate := range rates {
		total := int(rate * dur.Seconds())
		var mu sync.Mutex
		var commit, firstAcc []float64
		fails, inflight, offered := 0, 0, 0
		saturated := false
		var wg sync.WaitGroup
		start := time.Now()
		for i := 0; i < total; i++ {
			mu.Lock()
			backlog := inflight
			mu.Unlock()
			if backlog > maxBacklog { // the system no longer keeps up: stop offering
				saturated = true
				break
			}
			sched := start.Add(time.Duration(float64(i) / rate * float64(time.Second)))
			time.Sleep(time.Until(sched))
			offered++
			wg.Add(1)
			mu.Lock()
			inflight++
			mu.Unlock()
			go func(i int, sched time.Time) {
				defer wg.Done()
				rd := <-free
				defer func() { free <- rd }()
				r := recs[i%len(recs)]
				a, _, err := access(r, rd)
				mu.Lock()
				defer mu.Unlock()
				inflight--
				if err != nil {
					fails++
					if fails <= 3 {
						errf("load %.0f/s: %v", rate, err)
					}
					return
				}
				// latency from the scheduled send time (open loop)
				commit = append(commit, ms(a.commit))
				firstAcc = append(firstAcc, ms(time.Since(sched)))
			}(i, sched)
		}
		done := make(chan struct{})
		go func() { wg.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(drainTimeout):
			saturated = true
		}
		el := time.Since(start)
		mu.Lock()
		c := append([]float64(nil), commit...)
		f := append([]float64(nil), firstAcc...)
		nf, left := fails, inflight
		mu.Unlock()
		if len(f) < int(0.9*float64(total)) || pct(f, 50) > 2000 {
			saturated = true
		}
		res.Load = append(res.Load, map[string]interface{}{
			"rate_offered": rate, "scheduled": total, "offered": offered, "completed": len(f),
			"failed": nf, "unfinished": left, "saturated": saturated,
			"elapsed_s": el.Seconds(), "throughput": float64(len(f)) / el.Seconds(),
			"read_commit_ms": c, "first_access_ms": f,
			"read_commit_p50": pct(c, 50), "first_access_p50": pct(f, 50),
			"first_access_p95": pct(f, 95),
		})
		t.Logf("BI %v rate %.0f: %d/%d ok (offered %d, unfinished %d, saturated %v), first access p50 %.1f ms",
			bi, rate, len(f), total, offered, left, saturated, pct(f, 50))
		if saturated {
			break // higher rates would only queue further
		}
	}

	for k, v := range res.Seq {
		t.Logf("BI %v %s p50 %.1f ms (n=%d)", bi, k, pct(v, 50), len(v))
	}
	res.Finished = time.Now().UTC().Format(time.RFC3339)
	// write before the network is closed
	buf, _ := json.MarshalIndent(res, "", " ")
	require.NoError(t, os.WriteFile(fn, buf, 0644))
	t.Logf("wrote %s", fn)
}

func pct(v []float64, p float64) float64 {
	if len(v) == 0 {
		return -1
	}
	s := append([]float64(nil), v...)
	sort.Float64s(s)
	i := int(p / 100 * float64(len(s)-1))
	return s[i]
}
