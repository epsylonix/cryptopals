package cryptopals

import (
	"bytes"
	"math/big"
	"testing"
)

func TestDecryptUsingUnpadedAttack(t *testing.T) {
	message := []byte("some test message")
	e := big.NewInt(1<<16 + 1)
	private, public := generateRsaKeys(1024, e)

	encryptor := rsaEncryptor541{public}
	decryptor := rsaDecryptor541{
		seenEncryptedMessages: []*big.Int{},
		privateKey:            private,
	}

	encrypted := encryptor.encrypt(message)
	decrypted, err := decryptor.decrypt(encrypted)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(message, decrypted.Bytes()) {
		t.Fatalf("encryption/decryption doesn't work: expected '%s', got '%s'", message, decrypted.Bytes())
	}

	decrypted2, err := decryptor.decrypt(encrypted)
	if err == nil {
		t.Fatalf("expected a repeated decryption to fail but it didn't: decrypted '%s'", decrypted2.Bytes())
	}

	recovered := unpaddedMessageAttack(decryptor, public, encrypted)
	if !bytes.Equal(message, recovered) {
		t.Fatalf("original message wan't recovered: expected '%s', got '%s'", message, recovered)
	} else {
		t.Logf("message recovered: '%s'", recovered)
	}
}
