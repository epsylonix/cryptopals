package cryptopals

import (
	"errors"
	"math/big"
)

func crt(a, n []int) (int, error) {
	if len(a) != len(n) {
		return -1, errors.New("a and n len should be equal")
	}

	if len(a) == 1 {
		return a[0], nil
	}

	var a2, n2 int
	var a1 = a[0]
	var n1 = n[0]

	for i := 1; i < len(a); i++ {
		a2 = a[i]
		n2 = n[i]

		m1, m2, gcd := extGcd(n1, n2)
		if gcd != 1 {
			return -1, errors.New("to apply CRT all n'a should be coprime")
		}

		a1 = a1*m2*n2 + a2*m1*n1
		n1 *= n2
	}

	return a1 % n1, nil
}

func crtBig(a, n []*big.Int) (*big.Int, error) {
	if len(a) != len(n) {
		return nil, errors.New("a and n len should be equal")
	}

	if len(a) == 1 {
		return new(big.Int).Set(a[0]), nil
	}

	var a2, n2 *big.Int
	var tmp = new(big.Int)
	var a1 = new(big.Int).Set(a[0])
	var n1 = new(big.Int).Set(n[0])

	for i := 1; i < len(a); i++ {
		a2 = a[i]
		n2 = n[i]

		m1, m2, gcd := extGcdBig(n1, n2)
		if !eq(gcd, one) {
			return nil, errors.New("to apply CRT all n'a should be coprime")
		}

		// a1 = a1*m2*n2 + a2*m1*n1
		a1.Mul(a1, m2)
		a1.Mul(a1, n2)
		tmp.Mul(a2, m1)
		tmp.Mul(tmp, n1)
		a1.Add(a1, tmp)

		n1.Mul(n1, n2)
	}

	return a1.Mod(a1, n1), nil
}

// e from public key, n from public keys, for attack to succeed e <= len(n)
// c -the same message encrypted using the corresponding public keys from n
func decryptUsingBroadcastAttack(e int, c, n []*big.Int) []byte {
	if len(n) != len(c) {
		panic(errors.New("for every n a corresponding encrypted message should be provided"))
	}

	if int64(e) > int64(len(c)) {
		panic(errors.New("e cant be less that the number of available ecryptions of the same message"))
	}

	mExpE, err := crtBig(c, n)
	if err != nil {
		panic(err)
	}

	return root(mExpE, e).Bytes()
}
