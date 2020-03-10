package cryptopals

import (
	"crypto/rand"
	"errors"
	"io"
	"math/big"
)

type dsaParams struct {
	p, q, g *big.Int
}

type dsaPrivateKey struct {
	params *dsaParams
	x      *big.Int
}

type dsaPublicKey struct {
	params *dsaParams
	y      *big.Int
}

type dsaSignature struct {
	r, s *big.Int
}

func (p1 *dsaParams) eq(p2 *dsaParams) bool {
	return eq(p1.g, p2.g) && eq(p1.p, p2.p) && eq(p1.q, p2.q)
}

func (s1 *dsaSignature) eq(s2 *dsaSignature) bool {
	return eq(s1.r, s2.r) && eq(s1.s, s2.s)
}

func signDsa(m []byte, priv *dsaPrivateKey, k *big.Int) *dsaSignature {
	// by the way there is a NIST document that describes
	// a determenistic algorithm for k generation

	if k.Cmp(one) != 1 || priv.params.q.Cmp(k) < 0 {
		panic("k should in 2..q-1 range")
	}

	var tmp = sha1(m)
	var z = new(big.Int).SetBytes(tmp[:])
	kInv, err := mulInv(k, priv.params.q)
	if err != nil {
		panic(err)
	}
	var r = new(big.Int)
	var s *big.Int
	for {
		r.Exp(priv.params.g, k, priv.params.p)
		r.Mod(r, priv.params.q)
		if isZero(r) {
			continue
		}

		s = mulMod(priv.x, r, priv.params.q)
		s.Add(s, z)
		s = mulMod(s, kInv, priv.params.q)
		if !isZero(s) {
			break
		}
	}

	return &dsaSignature{r: r, s: s}
}

func verifyDsaSign(m []byte, sign *dsaSignature, pub *dsaPublicKey) bool {
	var w, error = mulInv(sign.s, pub.params.q)
	if error != nil {
		panic(error)
	}

	var tmp = sha1(m)
	var z = new(big.Int).SetBytes(tmp[:])

	var gu1 = mulMod(z, w, pub.params.q) // we can do mod q right away because g^q mod p= 1
	gu1.Exp(pub.params.g, gu1, pub.params.p)

	var yu2 = mulMod(sign.r, w, pub.params.q) // y = g^x so (g^x)^(rw + tq) = g^xrw+(g^q)^tx = g ^xrw, so again we can do mod q now
	yu2.Exp(pub.y, yu2, pub.params.p)

	var v = mulMod(gu1, yu2, pub.params.p)
	v.Mod(v, pub.params.q)

	return eq(v, sign.r)
}

func generateDsaKeys(l, n int) (*dsaPrivateKey, *dsaPublicKey) {
	var params = generateDsaParams(l, n)

	var x *big.Int
	for {
		x = randomBigIntLessThan(params.q)
		if !eq(x, one) {
			break
		}
	}

	var y = new(big.Int).Exp(params.g, x, params.p)

	return &dsaPrivateKey{params: params, x: x}, &dsaPublicKey{params: params, y: y}
}

func generateDsaParams(l, n int) *dsaParams {
	if n >= l || l < 64 || l%8 != 0 {
		panic("invalid l or/and n")
	}

	var q *big.Int
	var p = new(big.Int)
	var pModQ = new(big.Int)

	var pInit = make([]byte, l/8)

	/*
		NIST describes an algorithm for p generation but I didn't immediately grasped how it works
		so I decided to take the easier to understand route here:
		q must divide p-1 => (p - 1) mod q = 0 => p equivalent 1 (mod q)
		So here is the plan:
		1. generate prime q of n bits len
		2. generate any odd p of l bitlen
		3. calculate p mod q
		4. calculate p = p - p mod q - that number is divisable by q
		5. calculate p = p + 1 - now that q is a divisor of p - 1
		6. check if p is prime and repeat from 1 if it is not
	*/
	i := 0
	for {
		i++
		q = generatePrime(n)

		_, err := io.ReadFull(rand.Reader, pInit)
		if err != nil {
			panic(err)
		}
		pInit[0] |= 0x80
		pInit[len(pInit)-1] |= 0x01
		p.SetBytes(pInit)

		pModQ.Mod(p, q)
		p.Sub(p, pModQ)
		p.Add(p, one)

		if p.BitLen() < l {
			continue
		}
		if isProbablePrime(p) {
			break
		}
	}

	/*
		now find g - element of U(p) of order q
		let b = h^{(p-1)/q}, then b^q = h^(p-1) equivalent 1 mod p
		Then the order of b divides q, but q is a prime => b is an element of order q unless b = 1
	*/

	// e = (p - 1) / q
	var e = new(big.Int)
	e.Sub(p, one)
	e.Div(e, q)

	var h = big.NewInt(2)
	var g = new(big.Int)

	for {
		// g = h^{(p-1)/q}
		g.Set(h)
		g.Exp(g, e, p)
		if !eq(g, one) { // unlikely to happen
			break
		}

		h.Add(h, one)
	}

	return &dsaParams{
		p: p,
		q: q,
		g: g,
	}
}

func recoverDsaKeyByKBruteforce(message []byte, sign *dsaSignature, pub *dsaPublicKey, maxK int) (*big.Int, *big.Int, error) {
	k, err := bruteforceK(sign, pub, maxK)
	if err != nil {
		return nil, nil, err
	}

	var tmp = sha1(message)
	var z = new(big.Int).SetBytes(tmp[:])

	x, err := xFromK(k, z, sign, pub)
	if err != nil {
		return nil, nil, err
	}
	return x, k, nil
}

func bruteforceK(sign *dsaSignature, pub *dsaPublicKey, maxK int) (*big.Int, error) {
	var kGuess = big.NewInt(0)

	for i := 0; i <= maxK; i++ {
		if isValidK(kGuess, sign, pub) {
			return kGuess, nil
		}
		kGuess.Add(kGuess, one)
	}

	return nil, errors.New("k bruteforce failed")
}

func xFromK(k, z *big.Int, sign *dsaSignature, pub *dsaPublicKey) (*big.Int, error) {
	rInv, err := mulInv(sign.r, pub.params.q)
	if err != nil {
		return nil, err
	}

	var x = new(big.Int)
	x.Mul(sign.s, k)
	x.Sub(x, z)
	x.Mul(x, rInv)
	x.Mod(x, pub.params.q)
	return x, nil
}

func isValidK(k *big.Int, sign *dsaSignature, pub *dsaPublicKey) bool {
	var rGuess = new(big.Int)

	rGuess.Exp(pub.params.g, k, pub.params.p)
	rGuess.Mod(rGuess, pub.params.q)
	if eq(rGuess, sign.r) {
		return true
	}
	return false
}
