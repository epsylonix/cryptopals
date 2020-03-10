package cryptopals

import (
	"bytes"
	"testing"
)

func TestRandomAccessCtrMessageRecovery(t *testing.T) {
	key := randomBytes(16)
	plaintext, err := ecbDecrypt(readBase64File("../data/25.txt"), []byte("YELLOW SUBMARINE"))
	if err != nil {
		panic(err)
	}

	nonce := uint64(1)
	initCtr := uint64(1)
	editor := ctrEditor{
		key:     key,
		nonce:   nonce,
		initCtr: initCtr,
	}

	cyphertext, _ := ctrEncrypt(plaintext, key, nonce, initCtr)

	decrypted, err := recoverCtrEncryptedMessage(cyphertext, &editor)
	if err != nil {
		panic(err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Fatalf("the decrypted message differs from the original: \n%v", decrypted)
	}

	t.Logf("decrypted: \n%s\n", decrypted)
}
