package pledgecc

import (
	"encoding/hex"

	"github.com/herumi/mcl/ffi/go/mcl"
)

// KSSSecret is key-share service i's DKG output (shares of alpha* and y*).
type KSSSecret struct {
	Index int    `json:"index"`
	Alpha string `json:"alpha"` // Fr hex
	Y     string `json:"y"`     // Fr hex
	N     int    `json:"n"`
	K     int    `json:"k"`
}

type PartialKey struct {
	Index int     `json:"index"`
	S     []int64 `json:"S"`
	GID   string  `json:"gid"`
	Attr  string  `json:"attr"`
	K     string  `json:"K"`  // G1 hex
	Kp    string  `json:"Kp"` // G2 hex
}

func lagrangeAtZero(i int64, S []int64) mcl.Fr {
	var num, den, tmp mcl.Fr
	num.SetInt64(1)
	den.SetInt64(1)
	for _, j := range S {
		if j == i {
			continue
		}
		var fj, fi mcl.Fr
		fj.SetInt64(j)
		fi.SetInt64(i)
		mcl.FrMul(&num, &num, &fj)
		mcl.FrSub(&tmp, &fj, &fi)
		mcl.FrMul(&den, &den, &tmp)
	}
	var inv, out mcl.Fr
	mcl.FrInv(&inv, &den)
	mcl.FrMul(&out, &num, &inv)
	return out
}

// ShareGen: K_i = g1^{L alpha_i} H(GID)^{L y_i} F(attr)^{t_i},  K'_i = g2^{t_i}
// (identical to pledge/crypto/lgabe.py:share_gen).
func ShareGen(sec *KSSSecret, gid, attr string, S []int64) (*PartialKey, error) {
	alpha, err := FrFromHex(sec.Alpha)
	if err != nil {
		return nil, err
	}
	y, err := FrFromHex(sec.Y)
	if err != nil {
		return nil, err
	}
	L := lagrangeAtZero(int64(sec.Index), S)
	var la, ly, t mcl.Fr
	mcl.FrMul(&la, &L, alpha)
	mcl.FrMul(&ly, &L, y)
	t.SetByCSPRNG()
	var Hg, Fa, a, b, c, K1, K mcl.G1
	Hg.HashAndMapTo([]byte("PLEDGE|H|" + gid))
	Fa.HashAndMapTo([]byte("PLEDGE|F|" + attr))
	mcl.G1Mul(&a, &G1Gen, &la)
	mcl.G1Mul(&b, &Hg, &ly)
	mcl.G1Mul(&c, &Fa, &t)
	mcl.G1Add(&K1, &a, &b)
	mcl.G1Add(&K, &K1, &c)
	var Kp mcl.G2
	mcl.G2Mul(&Kp, &G2Gen, &t)
	return &PartialKey{Index: sec.Index, S: S, GID: gid, Attr: attr,
		K: hex.EncodeToString(K.Serialize()), Kp: hex.EncodeToString(Kp.Serialize())}, nil
}
