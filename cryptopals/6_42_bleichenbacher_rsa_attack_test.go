package cryptopals

import (
	"math/big"
	"testing"
)

func TestForgeRsaSignature(t *testing.T) {
	message := []byte("some test message")
	forgedMessage := []byte("this should not be accepted!")

	e := big.NewInt(3)
	private, public := generateRsaKeys(1024, e)

	validSignature := signRsa(message, private)

	if !checkRsaSignature642(message, validSignature, public) {
		t.Fatal("a signature that is supposed to be valid not accepted as such")
	}

	if checkRsaSignature642(forgedMessage, validSignature, public) {
		t.Fatal("a signature that is supposed to be invalid is accepted")
	}

	forgedSignature := forgeRsaSignature(forgedMessage, public)
	if !checkRsaSignature642(forgedMessage, forgedSignature, public) {
		t.Fatal("the forged signature not accepted")
	} else {
		t.Logf("successfully forged a signature!")
	}
}
