// Package pledgecc holds the PLEDGE access-chaincode logic shared by the Fabric
// chaincode, the key-share services and the tests. Every byte format here
// matches the Python reference implementation (pledge/ledger/chaincode.py,
// pledge/crypto/{sig,sigma}.py) exactly.
package pledgecc

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/herumi/mcl/ffi/go/mcl"
)

var (
	initOnce sync.Once
	G1Gen    mcl.G1
	G2Gen    mcl.G2
)

// Init initialises mcl on BLS12-381 and the hash-derived generators used by PLEDGE.
func Init() {
	initOnce.Do(func() {
		if err := mcl.Init(mcl.BLS12_381); err != nil {
			panic(err)
		}
		G1Gen.HashAndMapTo([]byte("PLEDGE generator G1"))
		G2Gen.HashAndMapTo([]byte("PLEDGE generator G2"))
	})
}

func G1FromHex(s string) (*mcl.G1, error) {
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, err
	}
	var p mcl.G1
	if err := p.Deserialize(b); err != nil {
		return nil, fmt.Errorf("bad G1 encoding: %w", err)
	}
	return &p, nil
}

func G2FromHex(s string) (*mcl.G2, error) {
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, err
	}
	var p mcl.G2
	if err := p.Deserialize(b); err != nil {
		return nil, fmt.Errorf("bad G2 encoding: %w", err)
	}
	return &p, nil
}

func FrFromHex(s string) (*mcl.Fr, error) {
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, err
	}
	var x mcl.Fr
	if err := x.Deserialize(b); err != nil {
		return nil, fmt.Errorf("bad Fr encoding: %w", err)
	}
	return &x, nil
}

// BLSVerify checks e(sig, g2) == e(H("PLEDGE|SIG|"||msg), vk).
func BLSVerify(vkHex, sigHex string, msg []byte) bool {
	vk, err := G2FromHex(vkHex)
	if err != nil {
		return false
	}
	sig, err := G1FromHex(sigHex)
	if err != nil {
		return false
	}
	var hm, nhm mcl.G1
	hm.HashAndMapTo(append([]byte("PLEDGE|SIG|"), msg...))
	mcl.G1Neg(&nhm, &hm)
	var ml, out mcl.GT
	mcl.MillerLoopVec(&ml, []mcl.G1{*sig, nhm}, []mcl.G2{G2Gen, *vk})
	mcl.FinalExp(&out, &ml)
	return out.IsOne()
}

func frInt(v int64) *mcl.Fr {
	var x mcl.Fr
	x.SetInt64(v)
	return &x
}

func g1Pow(s *mcl.Fr) *mcl.G1 {
	var p mcl.G1
	mcl.G1Mul(&p, &G1Gen, s)
	return &p
}

func mul(p *mcl.G1, s *mcl.Fr) *mcl.G1 {
	var r mcl.G1
	mcl.G1Mul(&r, p, s)
	return &r
}

func add(a, b *mcl.G1) *mcl.G1 {
	var r mcl.G1
	mcl.G1Add(&r, a, b)
	return &r
}

func neg(a *mcl.G1) *mcl.G1 {
	var r mcl.G1
	mcl.G1Neg(&r, a)
	return &r
}

// VerifyPurpose checks the CDS OR-proof that the two ElGamal ciphertexts in ct
// (to the patient key P and the regulator key R) encrypt the same purpose code,
// and that the code is in `allowed` (order as stored in the record).
func VerifyPurpose(ctHex []string, proofHex [][]string, Phex, Rhex string, allowed []int64, ctx []byte) error {
	if len(ctHex) != 4 {
		return errors.New("purpose ciphertext must have 4 elements")
	}
	if len(proofHex) != len(allowed) {
		return errors.New("one proof branch per allowed purpose required")
	}
	ct := make([]*mcl.G1, 4)
	for i, h := range ctHex {
		p, err := G1FromHex(h)
		if err != nil {
			return err
		}
		ct[i] = p
	}
	P, err := G1FromHex(Phex)
	if err != nil {
		return err
	}
	R, err := G1FromHex(Rhex)
	if err != nil {
		return err
	}
	a1, b1, a2, b2 := ct[0], ct[1], ct[2], ct[3]
	var csum mcl.Fr
	csum.SetInt64(0)
	var Ts [][4]*mcl.G1
	for j, m := range allowed {
		if len(proofHex[j]) != 3 {
			return errors.New("malformed proof branch")
		}
		c, err1 := FrFromHex(proofHex[j][0])
		s1, err2 := FrFromHex(proofHex[j][1])
		s2, err3 := FrFromHex(proofHex[j][2])
		if err1 != nil || err2 != nil || err3 != nil {
			return errors.New("malformed proof scalar")
		}
		mg := g1Pow(frInt(m))
		b1m := add(b1, neg(mg))
		b2m := add(b2, neg(mg))
		T := [4]*mcl.G1{
			add(g1Pow(s1), neg(mul(a1, c))),
			add(mul(P, s1), neg(mul(b1m, c))),
			add(g1Pow(s2), neg(mul(a2, c))),
			add(mul(R, s2), neg(mul(b2m, c))),
		}
		Ts = append(Ts, T)
		mcl.FrAdd(&csum, &csum, c)
	}
	buf := []byte("PLEDGE|purpose|")
	buf = append(buf, ctx...)
	buf = append(buf, P.Serialize()...)
	buf = append(buf, R.Serialize()...)
	for _, e := range ct {
		buf = append(buf, e.Serialize()...)
	}
	sorted := append([]int64(nil), allowed...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	parts := make([]string, len(sorted))
	for i, m := range sorted {
		parts[i] = strconv.FormatInt(m, 10)
	}
	buf = append(buf, []byte(strings.Join(parts, ","))...)
	for _, T := range Ts {
		for _, e := range T {
			buf = append(buf, e.Serialize()...)
		}
	}
	var chal mcl.Fr
	chal.SetHashOf(buf)
	if !csum.IsEqual(&chal) {
		return errors.New("purpose proof invalid or purpose not allowed")
	}
	return nil
}

func sha(b []byte) []byte {
	h := sha256.Sum256(b)
	return h[:]
}
