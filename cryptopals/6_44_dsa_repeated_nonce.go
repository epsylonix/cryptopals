package cryptopals

import (
	"errors"
	"math/big"
)

type dsaMessageSignature struct {
	sign *dsaSignature
	m    *big.Int
}

func recoverKeyFromRepeatedNonce(signatures []*dsaMessageSignature, pub *dsaPublicKey) (*big.Int, *big.Int, error) {
	/*
		s = k^{-1} * (z + x*r) mod q, r = (g^k mod p) mod q
		between 2 signatures x (private key) is the obviously the same
		if k1 == k2 => r1 == r2 => k(s2 - s1) = z2 - z1 =>
		k = (z2 - z1) * (s2 - s1)^{-1} mod q
	*/

	var k = new(big.Int)
	var deltaSInv = new(big.Int)

	for i := 0; i < len(signatures)-1; i++ {
		for j := i + 1; j < len(signatures); j++ {
			sign1 := signatures[i]
			sign2 := signatures[j]
			deltaSInv.Sub(sign2.sign.s, sign1.sign.s)
			if deltaSInv.ModInverse(deltaSInv, pub.params.q) == nil {
				continue // no modular inverse exists => k1 != k2
			}

			k.Sub(sign2.m, sign1.m)
			k.Mul(k, deltaSInv)
			k.Mod(k, pub.params.q)

			if !isValidK(k, sign1.sign, pub) {
				continue
			}

			x, err := xFromK(k, sign1.m, sign1.sign, pub)
			if err != nil {
				return nil, nil, err
			}
			return x, k, nil
		}
	}

	return nil, nil, errors.New("no repeated k found")
}
