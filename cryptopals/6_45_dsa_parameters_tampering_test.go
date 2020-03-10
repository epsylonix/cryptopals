package cryptopals

import (
	"math/big"
	"testing"
)

func TestDsaEncryptionWithZeroGenerator(t *testing.T) {
	x := toInt("f1b733db159c66bce071d21e044a48b0e4c1665a", 16)
	y := toInt("2d026f4bf30195ede3a088da85e398ef869611d0f68f07"+
		"13d51c9c1a3a26c95105d915e2d8cdf26d056b86b8a7b8"+
		"5519b1c23cc3ecdc6062650462e3063bd179c2a6581519"+
		"f674a61f1d89a1fff27171ebc1b93d4dc57bceb7ae2430"+
		"f98a6a4d83d8279ee65d71c1203d2c96d65ebbf7cce9d3"+
		"2971c3de5084cce04a2e147821", 16)

	g := big.NewInt(0)
	params := defaultDsaParams()
	params.g = g
	priv := dsaPrivateKey{x: x, params: params}
	pub := dsaPublicKey{y: y, params: params}

	m := []byte("some test message")
	m2 := []byte("completely different message")

	k := randomBigIntLessThan(priv.params.q)
	sign := signDsaNoChecks(m, &priv, k)
	t.Logf("signed message using g=0: s=%x r=%x", sign.s, sign.r)

	if !verifyDsaSign(m, sign, &pub) {
		t.Fatal("a signature that is supposed to be valid not accepted as such")
	} else {
		t.Logf("successfull signature verification")
	}

	// r=g^... and v=g^...*.. so both are zero when g=0 for any message
	if !verifyDsaSign(m2, sign, &pub) {
		t.Fatal("signature for a different message should be verified successfully when g=0")
	} else {
		t.Logf("successfull signature verification for a forged message")
	}
}

func TestDsaEncryptionWithEGenerator(t *testing.T) {
	/*
		if g eq 1 mod p
		then v = g^u1 * y^u2 (mod p) (mod q) = g^u2 (mod p) (mod q)
		where u2 = r * s^{-1} mod q

		if r = y^z mod p mod q
			 s = r * z^{-1} mod q
		then  u2 = r * s^{-1} = r * r^{-1} * z = z
					v = y^u2 = y^z mod p mod q == r for any y

		What is not clear is how is it possible to provide a g after the keys were generated?
		If we generated keys with this g = 1 mod p,
		   y = g^x mod p = 1 mod p
		and this would be similar to having g = 0 mod p except
		r would be 1 and v would be 1 for any message and for any s (that has a mod inverse)
	*/

	y := toInt("2d026f4bf30195ede3a088da85e398ef869611d0f68f07"+
		"13d51c9c1a3a26c95105d915e2d8cdf26d056b86b8a7b8"+
		"5519b1c23cc3ecdc6062650462e3063bd179c2a6581519"+
		"f674a61f1d89a1fff27171ebc1b93d4dc57bceb7ae2430"+
		"f98a6a4d83d8279ee65d71c1203d2c96d65ebbf7cce9d3"+
		"2971c3de5084cce04a2e147821", 16)

	params := defaultDsaParams()
	g := new(big.Int).Add(params.p, one)
	params.g = g
	pub := dsaPublicKey{y: y, params: params}

	// we don't need a the actual message hash
	// we just need to use the same (random) number in r and s construction
	z, _ := new(big.Int).SetString("1234567890", 10)

	r := new(big.Int).Exp(pub.y, z, pub.params.p)
	r.Mod(r, pub.params.q)

	s := new(big.Int).ModInverse(z, pub.params.q)
	s.Mul(s, r)
	s.Mod(s, pub.params.q)

	magicSign := dsaSignature{s: s, r: r}

	if !verifyDsaSign([]byte("some test message"), &magicSign, &pub) {
		t.Fatal("a signature that is supposed to be valid not accepted as such")
	} else {
		t.Logf("successfull signature verification")
	}
}

func defaultDsaParams() *dsaParams {
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

	return &dsaParams{p: p, q: q, g: g}
}
