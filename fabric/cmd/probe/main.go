package main

import (
	"encoding/hex"
	"fmt"

	"github.com/herumi/mcl/ffi/go/mcl"
)

func main() {
	if err := mcl.Init(mcl.BLS12_381); err != nil {
		panic(err)
	}
	var p mcl.G1
	p.HashAndMapTo([]byte("PLEDGE generator G1"))
	var q mcl.G2
	q.HashAndMapTo([]byte("PLEDGE generator G2"))
	var f mcl.Fr
	f.SetHashOf([]byte("abc"))
	fmt.Println(hex.EncodeToString(p.Serialize()))
	fmt.Println(hex.EncodeToString(q.Serialize())[:64])
	fmt.Println(hex.EncodeToString(f.Serialize()))
}
