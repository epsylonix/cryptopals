package cryptopals

import (
	"bytes"
	"math/big"
	"testing"
)

func TestMillerRabinPrimalityTest(t *testing.T) {
	var primes = toBigArray("37", "135344567777", "1098767743", "98767751", "21429125819")
	for _, p := range primes {
		if !millerRabinPrimalityTest(p, 64) {
			t.Errorf("prime %s is detected as a composite", p)
		}
	}

	var notPrimes = toBigArray("135344567775", "1098767741", "98767753", "21429125817")
	for _, p := range notPrimes {
		if millerRabinPrimalityTest(p, 64) {
			t.Errorf("composite %s is detected as a prime", p)
		}
	}
}

func TestRsaEncryption(t *testing.T) {
	var e = big.NewInt(65537)
	private, public := generateRsaKeys(1024, e)
	message := []byte("some test message")
	enc := encryptRsa(message, public)
	dec := decryptRsa(enc, private)

	if !bytes.Equal(message, dec) {
		t.Errorf("error decrypting message, expected '%s', got '%s'", message, dec)
	}
}

func toBigArray(values ...string) []*big.Int {
	var res = make([]*big.Int, len(values))
	for i, v := range values {
		var x, _ = new(big.Int).SetString(v, 10)
		if x == nil {
			panic("unable to covert string to number")
		}
		res[i] = x
	}
	return res
}
