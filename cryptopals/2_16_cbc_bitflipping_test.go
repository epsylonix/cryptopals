package cryptopals

import (
	"testing"
)

func TestCbcBitflipping(t *testing.T) {
	const blockSize int = 16

	ed := set216EncryptorDecryptor{
		key:              randomBytes(16),
		iv:               randomBytes(16),
		encryptionPrefix: []byte("comment1=cooking%20MCs;userdata="),
		encryptionSuffix: []byte(";comment2=%20like%20a%20pound%20of%20bacon"),
	}

	encryptedData := makeAdminWithCbcBitflip(ed, blockSize)
	decryptedData := ed.decrypt(encryptedData)

	decoded := kvDecode(string(decryptedData), ";")
	if decoded["admin"] != "true" {
		t.Fatalf("expected the 'admin' param to be true, got: %v", decoded)
	}
	t.Logf("Result: %v", decoded)
}
