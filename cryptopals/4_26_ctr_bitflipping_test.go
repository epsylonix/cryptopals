package cryptopals

import (
	"testing"
)

func TestCtrBitflippingAttack(t *testing.T) {
	key := randomBytes(16)
	nonce := uint64(1)
	initialCtr := uint64(0)

	var prefix = []byte("comment1=cooking%20MCs;userdata=")
	var suffix = []byte(";comment2=%20like%20a%20pound%20of%20bacon")
	var dataToInsert = []byte(";admin=true")

	ed := set426EncryptorDecryptor{
		key:              key,
		nonce:            nonce,
		initialCtr:       initialCtr,
		encryptionPrefix: prefix,
		encryptionSuffix: suffix,
	}

	newCyphertext := makeAdminWithCtrBitflip(prefix, dataToInsert, &ed)
	decrypted := ed.decrypt(newCyphertext)
	decoded := kvDecode(string(decrypted), ";")

	if decoded["admin"] != "true" {
		t.Fatalf("expected the 'admin' param to be true, got: %v", decoded)
	}
	t.Logf("Result: %v", decoded)
}
