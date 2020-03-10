package cryptopals

import (
	"bytes"
	"testing"
)

func TestCbcPaddingOracle(t *testing.T) {
	data := readBase64FileLines("../data/17.txt")
	message := randomElement(data)

	ed := set317EncryptorDecryptor{
		key: randomBytes(blockSize),
		iv:  randomBytes(blockSize),
	}

	encryptedMessage := ed.encrypt(message)
	decrypted := paddingOracleAttack(encryptedMessage, ed)
	if !bytes.Equal(message, decrypted) {
		t.Fatalf("expected: \n%s\n got:\n%s", message, decrypted)
	}
	t.Logf("decrypted: \n%s", decrypted)
}
