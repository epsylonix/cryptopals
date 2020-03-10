package cryptopals

import (
	"testing"
)

func TestFixedNonceCtrDecryption2(t *testing.T) {
	key := randomBytes(16)
	var nonce, ctr = uint64(0), uint64(0)

	plaintextStrings := readBase64FileLines("../data/20.txt")
	encryptedStrings := make([][]byte, len(plaintextStrings))
	for i, s := range plaintextStrings {
		e, _ := ctrEncrypt(s, key, nonce, ctr)
		encryptedStrings[i] = e
	}

	decryptedStrings := decryptFixedNonceCtrAsMultibyteXor(encryptedStrings)
	for _, decrypted := range decryptedStrings {
		t.Logf("%s\n", decrypted)
	}
}
