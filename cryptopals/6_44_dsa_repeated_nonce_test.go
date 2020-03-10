package cryptopals

import (
	"errors"
	"math/big"
	"strings"
	"testing"
)

func TestRecoverKeyFromRepeatedNonce(t *testing.T) {
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
	y := toInt("2d026f4bf30195ede3a088da85e398ef869611d0f68f07"+
		"13d51c9c1a3a26c95105d915e2d8cdf26d056b86b8a7b8"+
		"5519b1c23cc3ecdc6062650462e3063bd179c2a6581519"+
		"f674a61f1d89a1fff27171ebc1b93d4dc57bceb7ae2430"+
		"f98a6a4d83d8279ee65d71c1203d2c96d65ebbf7cce9d3"+
		"2971c3de5084cce04a2e147821", 16)

	params := dsaParams{p: p, q: q, g: g}
	pub := dsaPublicKey{y: y, params: &params}

	signatures, err := readSignatures644("../data/44.txt")
	if err != nil {
		t.Fatal(err)
	}

	x, k, err := recoverKeyFromRepeatedNonce(signatures, &pub)
	if err != nil {
		t.Fatal(err)
	} else {
		t.Logf("recovered k=%x, x=%x", k, x)
	}

	y2 := new(big.Int)
	y2.Exp(g, x, p)

	if eq(y, y2) {
		t.Log("recovered the private key successfully")
	} else {
		t.Fatalf("the recovered key doesn't generate a valid public key: \n%x \n!= \n%x", y2, y)
	}
}

func readSignatures644(path string) ([]*dsaMessageSignature, error) {
	data, err := readLines("../data/44.txt")
	if err != nil {
		return nil, err
	}
	if len(data)%4 != 0 {
		return nil, errors.New("unexpected data file format")
	}
	signatures := make([]*dsaMessageSignature, len(data)/4)
	for i := 0; i+4 < len(data); i += 4 {
		// msg := data[i]
		s := strings.TrimPrefix(string(data[i+1]), "s: ")
		r := strings.TrimPrefix(string(data[i+2]), "r: ")
		m := strings.TrimPrefix(string(data[i+3]), "m: ")
		signatures[i/4] = &dsaMessageSignature{
			sign: &dsaSignature{
				s: toInt(s, 10),
				r: toInt(r, 10),
			},
			m: toInt(m, 16),
		}
	}

	return signatures, nil
}
