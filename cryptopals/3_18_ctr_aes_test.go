package cryptopals

import (
	"testing"
)

func TestAesCtr(t *testing.T) {
	src := []byte("L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==")
	key := []byte("YELLOW SUBMARINE")
	var nonce, ctr = uint64(0), uint64(0)

	encrypted, err := base64decode(src)
	if err != nil {
		panic(err)
	}

	decrypted, _ := ctrDecrypt(encrypted, key, nonce, ctr)
	t.Logf("Decrypted: %s", decrypted)
}
