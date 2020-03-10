package cryptopals

import (
	"fmt"
	"math/big"
	"testing"
)

func TestDsaSignature(t *testing.T) {
	m := []byte("some test message")

	l, n := 1024, 160
	priv, pub := generateDsaKeys(l, n)

	k := randomBigIntLessThan(priv.params.q)
	sign := signDsa(m, priv, k)

	if !verifyDsaSign(m, sign, pub) {
		t.Fatal("a signature that is supposed to be valid not accepted as such")
	} else {
		t.Logf("successfull signature verification")
	}
}

func TestRecoverDsaKeyByKBruteforceTest(t *testing.T) {
	p := toInt("800000000000000089e1855218a0e7dac38136ffafa72eda7"+
		"859f2171e25e65eac698c1702578b07dc2a1076da241c76c6"+
		"2d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebe"+
		"ac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2"+
		"b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc87"+
		"1a584471bb1", 16)
	q := toInt("f4f47f05794b256174bba6e9b396a7707e563c5b", 16)
	g := toInt("5958c9d3898b224b12672c0b98e06c60df923cb8bc999d119"+
		"458fef538b8fa4046c8db53039db620c094c9fa077ef389b5"+
		"322a559946a71903f990f1f7e0e025e2d7f7cf494aff1a047"+
		"0f5b64c36b625a097f1651fe775323556fe00b3608c887892"+
		"878480e99041be601a62166ca6894bdd41a7054ec89f756ba"+
		"9fc95302291", 16)
	y := toInt("84ad4719d044495496a3201c8ff484feb45b962e7302e56a392aee4"+
		"abab3e4bdebf2955b4736012f21a08084056b19bcd7fee56048e004"+
		"e44984e2f411788efdc837a0d2e5abb7b555039fd243ac01f0fb2ed"+
		"1dec568280ce678e931868d23eb095fde9d3779191b8c0299d6e07b"+
		"bb283e6633451e535c45513b2d33c99ea17", 16)

	m := []byte("For those that envy a MC it can be hazardous to your health\nSo be friendly, a matter of life and death, just like a etch-a-sketch\n")
	r := toInt("548099063082341131477253921760299949438196259240", 10)
	s := toInt("857042759984254168557880549501802188789837994940", 10)

	maxK := 1 << 16

	params := dsaParams{p: p, q: q, g: g}
	pub := dsaPublicKey{y: y, params: &params}
	sign := dsaSignature{r: r, s: s}

	x, k, err := recoverDsaKeyByKBruteforce(m, &sign, &pub, maxK)
	if err != nil {
		t.Fatal(err)
	}

	if validDsaKey(x, &params, m, &sign, k) {
		t.Log("recovered the private key successfully")
	} else {
		t.Fatalf("the recovered key is doesn't generate a valid signature")
	}
}

func toInt(s string, base int) *big.Int {
	n, ok := new(big.Int).SetString(s, base)
	if !ok {
		panic(fmt.Errorf("not a valid number: %s", s))
	}

	return n
}

func validDsaKey(x *big.Int, params *dsaParams, m []byte, sign *dsaSignature, k *big.Int) bool {
	priv := dsaPrivateKey{x: x, params: params}
	sign2 := signDsa(m, &priv, k)
	return sign.eq(sign2)
}
