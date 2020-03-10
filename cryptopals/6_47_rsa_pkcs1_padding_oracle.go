package cryptopals

import (
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
)

var minPkscs15Len = 11
var errInvalidPadding = errors.New("invalid padding")

type rsaPkcs15PaddingOracle struct {
	key *privateKey
}

func gt(x, y *big.Int) bool {
	return x.Cmp(y) == 1
}

func gte(x, y *big.Int) bool {
	return x.Cmp(y) >= 0
}

func lt(x, y *big.Int) bool {
	return x.Cmp(y) == -1
}

func pkcs15Pad(m []byte, size int) []byte {
	var paddingLen = size - len(m)
	if paddingLen < minPkscs15Len {
		panic(fmt.Errorf("pkcs 1.5 requres at least %v bytes", minPkscs15Len))
	}

	var padded = make([]byte, size)
	padded[1] = 2
	_, err := rand.Reader.Read(padded[2 : paddingLen-2])
	if err != nil {
		panic(err)
	}

	for i := 2; i < paddingLen-1; {
		if padded[i] == 0 {
			_, err = rand.Reader.Read(padded[i : i+1])
			if err != nil {
				panic(err)
			}
		} else {
			i++
		}
	}

	copy(padded[paddingLen:], m)
	return padded
}

func pkcs15Unpad(padded []byte) ([]byte, error) {
	if len(padded) <= minPkscs15Len {
		return nil, errInvalidPadding
	}
	if padded[0] != 0 || padded[1] != 2 {
		return nil, errInvalidPadding
	}

	var i = 2
	for ; i < minPkscs15Len; i++ {
		if padded[i] == 0 {
			return nil, errInvalidPadding
		}
	}
	for ; i < len(padded); i++ {
		if padded[i] == 0 {
			var unpadded = make([]byte, len(padded)-i-1)
			copy(unpadded, padded[i+1:])
			return unpadded, nil
		}
	}

	return nil, errInvalidPadding
}

func (o rsaPkcs15PaddingOracle) isValidPadding(encrypted []byte) bool {
	var decrypted = pad(decryptRsa(encrypted, o.key), o.key.Size())

	/*
		the probability that the message would be completly pkcs 1.5-conforming
		i.e. 00 02 [at least 11 not null bytes] 00 ..
		seems to be pretty low
		so we only check the pkcs 1.5 signature bytes here
	*/
	if decrypted[0] == 0 && decrypted[1] == 2 {
		return true
	}

	return false
}

type interval struct {
	a, b *big.Int
}

func (i1 *interval) eq(i2 *interval) bool {
	return eq(i1.a, i2.a) && eq(i1.b, i2.b)
}

type intervals []*interval

func (itrvls intervals) contains(x *interval) bool {
	/*
		the Set data structure is a good fit here
		but it would be hard to use it here since we opereate with pointers.
		Anyway this is not done often and there would not be a lot of intervals
		so this O(n) could actually be faster then map's O(1)
	*/
	for _, y := range itrvls {
		if x.eq(y) {
			return true
		}
	}
	return false
}

func pad(b []byte, width int) []byte {
	var diff = width - len(b)
	if diff == 0 {
		return b
	}

	var j = make([]byte, width)
	copy(j[diff:], b)
	return j
}

func pkcs15PaddingOracleAttack(encrypted []byte, p *publicKey, o *rsaPkcs15PaddingOracle) []byte {
	var B = big.NewInt(1)
	B.Lsh(B, uint(8*(p.Size()-2)))

	var B2 = new(big.Int).Mul(B, big.NewInt(2))
	var B3 = new(big.Int).Mul(B, big.NewInt(3))

	var c = new(big.Int).SetBytes(encrypted)
	var cc = new(big.Int)
	var isValidS = func(s *big.Int) bool {
		// cc = c * s^e mod N
		cc.Exp(s, p.E, p.N)
		cc.Mul(cc, c)
		cc.Mod(cc, p.N)

		return o.isValidPadding(cc.Bytes())
	}

	var s, sMax = new(big.Int), new(big.Int)
	var r = new(big.Int)

	var M = intervals([]*interval{&interval{
		a: new(big.Int).Set(B2),
		b: new(big.Int).Set(B3),
	}})
	M[0].b.Sub(M[0].b, one)

	/*
		step 2. a
		---------
		We know s0 = 1 because m is already PKCS 1.5 conforming,  but we can't use that value for s
		to get a new message approximation the same way we use s1, s2, ...
		because whth s = 1, r_max = (B-1)/n < 1 => r_max=0 and the only s that is possible with that r
		is again s = 1

		For that reason we have to use a bruteforce approach to fine s1.
		But we can start from s = n / 3B:
		since 2B <= m < 3B, multiplying m with a smallest possible s=2
		will make m * s > 3B, so the next time it can become PKCS 1.5-conforming is
		after it will "wrap" n.
		m * s >= n => s >= n/m, s is min when m is max, which is 3B-1,
		so s >= n / 3B

	*/

	for s.Div(p.N, B3); ; s.Add(s, one) {
		if isValidS(s) {
			break
		}
	}
	M = calculateNewIntervals(s, M, p)

	for {
		if len(M) == 0 {
			panic("no intervals to search m in left")
		}

		if len(M) == 1 {
			fmt.Printf("max(m)=%v\n", M[0].b)

			// check if we zeroed in on m
			if eq(M[0].a, M[0].b) {
				return pad(M[0].a.Bytes(), p.Size())
			}

			/*
					step 2.c
					________

					mi = m0 * si - rn => si = (mi + rn) / m0
					a <= m0 <= b; 2B <= mi <= 3B-1 =>
						(2B + rn) / b <= si <= ((3B - 1) + rn) / a

					We want to half the interval we're searching s in each iteration.
					The width of the interval is approximately (3B - 2b) / s = B / s
					So doubling s would half the interval.
					this means that every iteration s is doubled

				From the whitepaper:
					  r >= 2 * (s_{i-1} b - 2 B) / n

					Sticking it into s >= (2B + rn) / m0
					results in si that is roughly 2 * s{i-1}

					we choose r, calculate si boundaries fot that r using
						(2B + rn) / b <= si <= ((3B - 1) + rn) / a
					and then search for si. After it is found
					we can calculate a new set of boundaries for m0:

					(2B + ri * n) / si <= m0 <= ((3B-1) + ri * n) / si

					for explanation what is ri see the note below
			*/

			// r >= 2 * (s_{i-1} b - 2 B) / n
			r.Mul(s, M[0].b)
			r.Sub(r, B2)
			r.Mul(r, two)
			r.Div(r, p.N)

			var sFound = false
			for ; ; r.Add(r, one) {
				// (2B + rn) / b <= si <= ((3B - 1) + rn) / a
				sMax.Mul(r, p.N)
				sMax.Add(sMax, B3)
				sMax.Sub(sMax, one)
				sMax.Div(sMax, M[0].a)

				s.Mul(r, p.N)
				s.Add(s, B2)
				s.Div(s, M[0].b)

				for ; gte(sMax, s); s.Add(s, one) {
					if isValidS(s) {
						sFound = true
						break
					}
				}

				if sFound {
					break
				}
			}

			/*
				no we found s but we we don't know can't know the exact r exactly (otherwise we could calculate m0 directly).
				The r we used before is of no use anymore - we used it to narrow the interval we search si for.
				Now that we know si, we can fund all r that could give as a valida padding knowing the boundaries for m0:

				so that r we used in the loop above is not the exact r that gives us 2B <= m*s - r*m < 3B:
					(m si - (3B - 1)) / n <= r <= (m si - 2B)/n
					m is in [a, b] => (a si - (3B - 1)) / n <= r <= (b si - 2B) / n

				for every we get a new possible interval, m0 would be in one of them.
				calculateNewIntervals(...) is basically step 3.
			*/

			M = calculateNewIntervals(s, M, p)
			continue
		}

		/*
			len(M) > 1

			step 2.b
			________
			mi = m0 * si mod n = m0 * si - r * n

			we don't know r but can estimate it's boundaries:
			r = (m0 * si - mi) / n
			a <= m0 <= b, 2B <= mi <= 3B-1
			r_min = (a * si - 2B) / n
			r_max = (b * si - (3B - 1)) / n

			now we can estimate new boundaries for m0 for each r in [r_min..r_max]:
			m0 = (mi + r * n)/si, 2B <= mi <= 3B-1
			(2B + r * n) / si <= m0 <= ((3B-1) + r * n) / si
			because we're don't know actual r, just guessing,
			not all of these boundaries will contain m0,
			but since we try all possible r, one of them will.

			But we don't know which one so have to use a bruteforce again
			which will give us a new s and with that s some intervals would be filtered out
		*/

		// search for s_i beginning with s_{i-1} + 1
		for s.Add(s, one); ; s.Add(s, one) {
			if isValidS(s) {
				break
			}
		}

		M = calculateNewIntervals(s, M, p)
		continue
	}
}

func calculateNewIntervals(s *big.Int, M intervals, p *publicKey) intervals {
	var B = big.NewInt(1)
	B.Lsh(B, uint(8*(p.Size()-2)))

	var B2 = new(big.Int).Mul(B, big.NewInt(2))
	var B3 = new(big.Int).Mul(B, big.NewInt(3))

	// step 3
	var Mi = intervals([]*interval{})
	var r, rMax = new(big.Int), new(big.Int)
	var a, b = new(big.Int), new(big.Int)
	var tmp = new(big.Int)

	for _, itrvl := range M {
		r.Mul(itrvl.a, s)
		r.Sub(r, B3)
		r.Add(r, one)
		r.Div(r, p.N)

		rMax.Mul(itrvl.b, s)
		rMax.Sub(rMax, B2)
		rMax.Div(rMax, p.N)

		for ; gte(rMax, r); r.Add(r, one) {
			// (2B + r * n) / si <= m0 <= ((3B-1) + r * n) / si
			a.Mul(r, p.N)
			a.Add(a, B2)
			a.QuoRem(a, s, tmp)
			if !isZero(tmp) {
				a.Add(a, one)
			}

			b.Mul(r, p.N)
			b.Add(b, B3)
			b.Sub(b, one)
			b.Div(b, s)

			if gt(itrvl.a, a) {
				a.Set(itrvl.a)
			}
			if lt(itrvl.b, b) {
				b.Set(itrvl.b)
			}

			if gte(b, a) {
				var newInterval = &interval{
					new(big.Int).Set(a),
					new(big.Int).Set(b),
				}
				if Mi.contains(newInterval) {
					continue
				}

				Mi = append(Mi, newInterval)
			}
		}
	}
	return Mi
}
