package cryptopals

import (
	"math/big"
)

// this is a vulnarable version that doesn't check params values
// and skips intermediate checks
func signDsaNoChecks(m []byte, priv *dsaPrivateKey, k *big.Int) *dsaSignature {
	var tmp = sha1(m)
	var z = new(big.Int).SetBytes(tmp[:])
	kInv, err := mulInv(k, priv.params.q)
	if err != nil {
		panic(err)
	}
	var r = new(big.Int)
	var s *big.Int

	r.Exp(priv.params.g, k, priv.params.p)
	r.Mod(r, priv.params.q)

	s = mulMod(priv.x, r, priv.params.q)
	s.Add(s, z)
	s = mulMod(s, kInv, priv.params.q)

	return &dsaSignature{r: r, s: s}
}
