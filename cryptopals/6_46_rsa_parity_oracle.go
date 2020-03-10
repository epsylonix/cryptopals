package cryptopals

import (
	"math/big"
)

type rsaParityOracle struct {
	key *privateKey
}

func (o rsaParityOracle) isRsaMessageOdd(encrypted []byte) bool {
	decrypted := decryptRsa(encrypted, o.key)
	if len(decrypted) == 0 {
		return false
	}

	return decrypted[len(decrypted)-1]%2 == 1
}

func decryptRsaUsingParityOracle(encrypted []byte, oracle *rsaParityOracle, public *publicKey) []byte {
	/*
		The suggested solution is to the half the interval in each iteration
		but if we do it using integers, rounding errors will accumulate
		and the last byte or two will get corrupted.

		So the approach below is generally the same but adapted to use integer arithmetic:
		1. whe start with the interval: 0 <= x <= n
		2. double x and interval: 2 * 0 <= 2 * x <= 2 * n
			 So the new interval is 2 * n width,
			 but the parity oracle tells us which half of it contains x
			 and we can move left or right margin accordingly.
			 The middle of this new interval is (2 * l + 2 * r) / 2 = l + r (always an integer).
			 This means that on each iteration the interval moves but the width stays the same (n)
			 but x doubles: for example we stated with x in [0..n],
			 then in the next iteration it will become 2x in [0..n] (or 2x in [n..2n]
			 i.e. x in [0..n/2] - margins get tighter every round, eventually they will contain
			 only one integer number, x.

		We could print x on every turn but to do this well have to do the division on every turn.
	*/

	l := big.NewInt(0)
	h := new(big.Int).Set(public.N)
	mid := new(big.Int)
	twoExp := new(big.Int).Exp(two, public.E, public.N)
	x := new(big.Int).SetBytes(encrypted)
	for i := 0; i < public.N.BitLen(); i++ {
		mid.Add(l, h)
		l.Lsh(l, 1)
		h.Lsh(h, 1)

		x.Mul(x, twoExp)
		x.Mod(x, public.N)
		if oracle.isRsaMessageOdd(x.Bytes()) {
			l.Set(mid)
		} else {
			h.Set(mid)
		}
	}

	mul := big.NewInt(1) // this is the coefficient of x
	mul.Lsh(mul, uint(public.N.BitLen()))
	decrypted := h.Div(h, mul).Bytes()
	return decrypted
}
