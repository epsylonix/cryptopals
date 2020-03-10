package cryptopals

import (
	"crypto/rand"
	"errors"
	"io"
	"math"
	"math/big"
)

/*
	not everything here is required for the challenges,
	some thing I just implemented to understand the problem better
	but left here so they not get lost
*/

var one = big.NewInt(int64(1))
var two = big.NewInt(int64(2))

var smallPrimes = []int64{
	2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53,
	59, 61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131,
	137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223,
	227, 229, 233, 239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293, 307, 311,
	313, 317, 331, 337, 347, 349, 353, 359, 367, 373, 379, 383, 389, 397, 401, 409,
	419, 421, 431, 433, 439, 443, 449, 457, 461, 463, 467, 479, 487, 491, 499, 503,
	509, 521, 523, 541, 547, 557, 563, 569, 571, 577, 587, 593, 599, 601, 607, 613,
	617, 619, 631, 641, 643, 647, 653, 659, 661, 673, 677, 683, 691, 701, 709, 719,
	727, 733, 739, 743, 751, 757, 761, 769, 773, 787, 797, 809, 811, 821, 823, 827,
	829, 839, 853, 857, 859, 863, 877, 881, 883, 887, 907, 911, 919, 929, 937, 941,
	947, 953, 967, 971, 977, 983, 991, 997,
}

type privateKey struct {
	N *big.Int
	D *big.Int
}

type publicKey struct {
	N *big.Int
	E *big.Int
}

func (key *publicKey) BitLen() int {
	return key.N.BitLen()
}

func (key *publicKey) Size() int {
	return key.BitLen() >> 3
}

func (key *privateKey) BitLen() int {
	return key.N.BitLen()
}

func (key *privateKey) Size() int {
	return key.BitLen() >> 3
}

func gcd(a, b int) int {
	if b == 0 {
		return a
	}
	return gcd(b, a%b)
}

// Euclidian algorithm, see big.GCD for an optimized version
func gcdBig(a, b *big.Int) *big.Int {
	if b.Sign() == 0 {
		return a
	}
	return gcdBig(b, new(big.Int).Mod(a, b))
}

// returns: a coeff, b coeff, GCD(a,b)
func extGcd(a, b int) (int, int, int) {
	if b == 0 {
		return a, 1, 0
	}

	var x0 = 1
	var y0 = 0
	var x = 0
	var y = 1
	var r int
	for {
		r = a % b
		if r == 0 {
			return x, y, b
		}
		var q = a / b
		y, y0 = y0-q*y, y
		x, x0 = x0-q*x, x
		a, b = b, r
	}
}

func extGcdBig(a, b *big.Int) (*big.Int, *big.Int, *big.Int) {
	if isZero(b) {
		return big.NewInt(1), big.NewInt(0), new(big.Int).Set(a)
	}

	var r0 = new(big.Int).Set(a)
	var r1 = new(big.Int).Set(b)
	var r2 = new(big.Int)
	var x0 = big.NewInt(1)
	var y0 = big.NewInt(0)
	var x = big.NewInt(0)
	var y = big.NewInt(1)
	var q = new(big.Int)
	var tmp = new(big.Int)
	for {
		r2.Mod(r0, r1)
		if isZero(r2) {
			return x, y, r1
		}

		q.Div(r0, r1)

		// y, y0 = y0-q*y, y
		tmp.Mul(q, y)
		tmp.Neg(tmp)
		tmp.Add(tmp, y0)
		y0.Set(y)
		y.Set(tmp)

		// x, x0 = x0-q*x, x
		tmp.Mul(q, x)
		tmp.Neg(tmp)
		tmp.Add(tmp, x0)
		x0.Set(x)
		x.Set(tmp)

		r0.Set(r1)
		r1.Set(r2)
	}
}

func mulInv(a, n *big.Int) (*big.Int, error) {
	if isZero(n) {
		return nil, errors.New("n can't be zero")
	}

	var r0 = new(big.Int).Set(a)
	var r1 = new(big.Int).Set(n)
	var r2 = new(big.Int)
	var x0 = big.NewInt(1)
	var x = big.NewInt(0)
	var q = new(big.Int)
	var tmp = new(big.Int)
	for {
		r2.Mod(r0, r1)
		if isZero(r2) {
			if eq(r1, one) {
				if x.Sign() < 0 {
					return x.Add(x, n), nil
				}
				return x, nil
			}

			return nil, errors.New("no multiplicative inverse exists: numbers are not coprime")
		}

		q.Div(r0, r1)

		// x, x0 = x0-q*x, x
		tmp.Mul(q, x)
		tmp.Neg(tmp)
		tmp.Add(tmp, x0)
		x0.Set(x)
		x.Set(tmp)

		r0.Set(r1)
		r1.Set(r2)
	}
}

func factorizeFermat(n int) (int, int) {
	if n%2 == 0 {
		return 2, n / 2
	}

	var tmp = math.Sqrt(float64(n))
	if tmp == math.Floor(tmp) {
		return int(tmp), int(tmp)
	}

	var x = int(math.Ceil(tmp))
	var y float64
	var topLimit = (n + 1) / 2
	for {
		x = x + 1
		if x > topLimit {
			return 1, n
		}

		y = math.Sqrt(float64(x*x - n)) // overflow handling?
		if y == float64(int(y)) {
			return x - int(y), x + int(y)
		}
	}
}

// false - the number is composite
// true - probable prime
func fermatPrimalityTest(n, base *big.Int) bool {
	var gcd = gcdBig(n, base)
	if gcd.Cmp(one) == 1 {
		return false
	}

	// base^(n-1) == 1?
	if expMod(base, new(big.Int).Sub(n, one), n).Cmp(one) == 0 {
		return true
	}

	return false
}

func millerPrimalityTest(n, base *big.Int) bool {
	var nm1 = new(big.Int).Sub(n, one) // n - 1

	if !(base.Cmp(one) > 0) {
		panic("base should be > 1")
	}
	if !(base.Cmp(nm1) < 0) {
		panic("base should be < n - 1")
	}

	var mod = new(big.Int)
	if isZero(mod.Mod(n, two)) {
		return false
	}

	// now n is odd, 1 < base < n - 1

	var k = uint(0)
	var q = new(big.Int).Sub(n, one)
	for !isZero(q) {
		if isZero(mod.Mod(q, two)) {
			k++
			q.Rsh(q, 1)
		} else {
			break
		}
	}

	var x = expMod(base, q, n) // x = b^(2^0 * q)
	if eq(x, one) || eq(x, nm1) {
		return true
	}

	for j := uint(1); j < k; j++ {
		// x = b^{2^(j-1) * q} =
		//  b^{2^j * q} = (b ^ {2^(j-1) * q}) ^ 2
		x = expMod(x, two, n)

		if eq(x, nm1) {
			return true
		}

		if eq(x, one) {
			return false
		}
	}

	return false
}

// false - the number is composite
// true - probable prime
func millerRabinPrimalityTest(n *big.Int, iterations int) bool {
	nm1 := new(big.Int).Sub(n, one)

	var b *big.Int
	for i := 0; i < iterations; i++ {
		b = randomBigIntLessThan(nm1)
		for b.Cmp(one) != 1 {
			b = randomBigIntLessThan(nm1)
		}

		if !millerPrimalityTest(n, b) {
			return false // composite
		}
	}
	return true // probable prime
}

// false - the number is composite
// true - probable prime
func trialDivisionsTest(n *big.Int) bool {
	low := n.Int64()
	mod := new(big.Int)
	pBig := new(big.Int)
	for _, p := range smallPrimes {
		if p*p > low { // only try up to sqrt of n
			return true
		}

		pBig.SetInt64(p)
		if eq(n, pBig) {
			return true // n is actually a small prime
		}
		if isZero(mod.Mod(n, pBig)) {
			return false // n is divisable by p, so it is composite
		}
	}
	return true // n is not divisable by a small prime
}

func isZero(x *big.Int) bool {
	return x.Sign() == 0
}

func eq(x, y *big.Int) bool {
	return x.Cmp(y) == 0
}

func generateRsaKeys(bitLen int, e *big.Int) (*privateKey, *publicKey) {
	if bitLen < 8 {
		panic("Key size is too small")
	}

	for {
		var p = generatePrime(bitLen >> 1)
		var q = generatePrime(bitLen - bitLen>>1)
		var n = new(big.Int).Mul(p, q)

		p.Sub(p, one)
		q.Sub(q, one)
		var phi = new(big.Int).Mul(p, q)
		var d, error = mulInv(e, phi)
		if error != nil {
			continue
		}

		var private = privateKey{N: n, D: d}
		var public = publicKey{N: n, E: e}

		return &private, &public
	}
}

func encryptRsa(message []byte, key *publicKey) []byte {
	var m = new(big.Int).SetBytes(message)
	if m.Cmp(key.N) >= 0 {
		panic("message is to large to be encrypted with the specified key")
	}

	var e = expMod(m, key.E, key.N)
	return e.Bytes()
}

func decryptRsa(encrypted []byte, key *privateKey) []byte {
	var e = new(big.Int).SetBytes(encrypted)
	if e.Cmp(key.N) == 1 {
		panic("data is too large to be decrypted with the specified key")
	}

	var m = expMod(e, key.D, key.N)
	// fmt.Printf("%x\n", m)
	return m.Bytes()
}

func generatePrime(bitLen int) *big.Int {
	// find a prime using incremental search, see http://cacr.uwaterloo.ca/hac/about/chap4.pdf section 4.51
	if bitLen < 2 {
		panic("Can't generate a prime less than 2")
	}

	for {
		x := randomOdd(bitLen)
		if isProbablePrime(x) {
			return x // probable prime
		}
		// try next odd number
		x.Add(x, two)
	}
}

func isProbablePrime(x *big.Int) bool {
	if trialDivisionsTest(x) && millerRabinPrimalityTest(x, 16) {
		return true
	}

	return false
}

func randomOdd(bitLen int) *big.Int {
	if bitLen == 1 {
		return new(big.Int).SetInt64(1)
	}

	bytes := make([]byte, (bitLen+7)/8)
	_, err := io.ReadFull(rand.Reader, bytes)
	if err != nil {
		panic(err)
	}

	b := bitLen % 8
	if b == 0 {
		b = 8
	}

	bytes[0] &= 0xFF >> uint8(8-b)     // clear bits that overflow bitLen
	bytes[0] |= (3 << 6) >> uint8(8-b) // set top 2 bits to make sure we have exatly bitLen bits
	// and also that multiplication of 2 such numbers will have twice the numer of digits

	bytes[len(bytes)-1] |= 1 // make sure the number is odd

	n := new(big.Int)
	n.SetBytes(bytes)

	return n
}
