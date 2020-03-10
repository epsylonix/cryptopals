package cryptopals

import (
	"bytes"
	"math/big"
	"testing"
)

func TestDecryptUsingBroadcastAttack(t *testing.T) {
	message := []byte("some test message")
	e := 3

	ns := make([]*big.Int, e)
	enc := make([]*big.Int, e)

	for i := 0; i < e; i++ {
		_, public := generateRsaKeys(1024, big.NewInt(int64(e)))
		ns[i] = public.N
		tmp := new(big.Int).SetBytes(encryptRsa(message, public))
		enc[i] = tmp
	}

	dec := decryptUsingBroadcastAttack(e, enc, ns)

	if !bytes.Equal(message, dec) {
		t.Errorf("error decrypting message, expected '%s', got '%s'", message, dec)
	} else {
		t.Logf("successfully decrypted message: '%s'", dec)
	}
}
