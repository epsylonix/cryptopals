package cryptopals

import (
	"bytes"
	"testing"
)

func TestCbcKeyEqIvRecovery(t *testing.T) {
	key := randomBytes(16)
	ed := set427EncryptorDecryptor{key}

	plaintext := []byte("012345678912345601234567891234560123456789123456")
	cyphertext := ed.encrypt(plaintext)

	recoveredKey, err := recoverKeyForCbcWithKeyEqIV(cyphertext, &ed)

	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(key, recoveredKey) {
		t.Fatalf("Recovered key is invalid: %v (valid: %v)", recoveredKey, key)
	}

	t.Logf("successfully recovered the key: %x", key)
}
