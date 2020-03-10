package cryptopals

import (
	"testing"
)

func TestDetectSingleByteXor(t *testing.T) {
	cyphertexts, err := readLines("../data/4.txt")
	if err != nil {
		t.Fatal(err)
	}

	guessedCythertext, decryptionResult, err := detectSingleByteXor(cyphertexts)
	if err != nil {
		t.Fatal(err)
	}

	t.Logf("detected single byte xor for [%s] \nscore=%v(key=%v) \ndecrypted: %s\n", guessedCythertext, decryptionResult.score, decryptionResult.value.(messageWithKey).key, decryptionResult.value.(messageWithKey).v)
}
