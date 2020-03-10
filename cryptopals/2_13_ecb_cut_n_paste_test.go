package cryptopals

import (
	"testing"
)

func TestEcbCutAndPaste(t *testing.T) {
	const blockSize int = 16

	key := randomBytes(blockSize)
	encryptionOracle := func(email string) []byte {
		data := profileFor(email)
		return ecbEncrypt([]byte(data), key)
	}

	encryptedWithRoleAdmin := ecbCutAndPasteAttack(encryptionOracle, blockSize)

	decrypted, err := ecbDecrypt(encryptedWithRoleAdmin, key)
	if err != nil {
		t.Fatal(err)
	}

	decoded := kvDecode(string(decrypted), "&")
	if decoded["role"] != "admin" {
		t.Fatalf("expected the 'role' param to be admin, got: %v", decoded)
	}
	t.Logf("Result: %v", decoded)
}
