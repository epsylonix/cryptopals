package cryptopals

import (
	"bytes"
	"testing"
)

func TestByteAtATimeEcbDecryption(t *testing.T) {
	message := readBase64File("../data/12.txt")
	key := randomBytes(16)
	encryptionOracle := buildEcbEncryptorWithSuffix(message, key)

	decrypted := decryptAesEcbUsingEncryptionOracle(encryptionOracle)
	if !bytes.Equal(decrypted, message) {
		t.Fatalf("decrypted messages differs from the orignal: \ndecrypted: \n%s \n\n \noriginal: \n%s", decrypted, message)
	}
	t.Logf("Decrypted: \n%s\n", decrypted)
}
