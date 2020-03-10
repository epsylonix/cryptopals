package cryptopals

import (
	"crypto/rand"
	"math/big"
)

type diffieHellman struct {
	private *big.Int
	public  *big.Int
	session *big.Int
	g       *big.Int
	p       *big.Int
}

func (dh *diffieHellman) keySize() int {
	return 1024 / 8
}

func (dh *diffieHellman) init() *diffieHellman {
	p, _ := new(big.Int).SetString("ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff", 16)
	g := big.NewInt(int64(2))
	return dh.initCustom(g, p)
}

func (dh *diffieHellman) initCustom(g, p *big.Int) *diffieHellman {
	dh.p = p
	dh.g = g

	dh.private = randomBigInt(dh.keySize())
	dh.public = expMod(dh.g, dh.private, dh.p)

	return dh
}

func (dh *diffieHellman) genSessionKey(otherPublic *big.Int) {
	dh.session = expMod(otherPublic, dh.private, dh.p)
}

func randomBigInt(sizeBytes int) *big.Int {
	one := big.NewInt(int64(1))
	max := new(big.Int)
	max.Lsh(one, uint(sizeBytes)*8)
	max.Sub(max, one)

	i, err := rand.Int(rand.Reader, max)
	if err != nil {
		panic(err)
	}

	return i
}

func randomBigIntLessThan(max *big.Int) *big.Int {
	i, err := rand.Int(rand.Reader, max)
	if err != nil {
		panic(err)
	}

	return i
}

// exponentiation by squaring
func expMod(x *big.Int, e *big.Int, m *big.Int) *big.Int {
	if e.Sign() == 0 {
		return big.NewInt(int64(1))
	} else if e.Sign() < 0 {
		panic("e should be >= 0")
	}

	two := big.NewInt(int64(2))
	bit := new(big.Int)

	tmp := new(big.Int).Set(x)
	z := big.NewInt(int64(1))

	for i := new(big.Int).Set(e); i.Sign() > 0; {
		if bit.Mod(i, two); bit.Sign() > 0 {
			z.Mul(z, tmp)
			z.Mod(z, m)
		}

		tmp.Mul(tmp, tmp)
		tmp.Mod(tmp, m)

		i.Rsh(i, uint(1))
	}

	return z
}

func subMod(x *big.Int, y *big.Int, m *big.Int) *big.Int {
	z := new(big.Int).Sub(x, y)
	z = z.Mod(z, m)
	return z
}

func addMod(x *big.Int, y *big.Int, m *big.Int) *big.Int {
	z := new(big.Int).Add(x, y)
	z = z.Mod(z, m)
	return z
}

func mulMod(x *big.Int, y *big.Int, m *big.Int) *big.Int {
	z := new(big.Int).Mul(x, y)
	z = z.Mod(z, m)
	return z
}
