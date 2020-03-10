package cryptopals

import (
	"bytes"
	"math/big"
	"testing"
)

func TestPkcs15PaddingOracleLargeKeyAttack(t *testing.T) {
	// this is exactly the same as 6.47 except the key is larger
	e := big.NewInt(3)
	keyBitlen := 768
	private, public := generateRsaKeys(keyBitlen, e)
	if public.BitLen() != keyBitlen {
		panic("key of invalid size generated")
	}

	oracle := rsaPkcs15PaddingOracle{key: private}
	message := []byte("kick it, CC")
	padded := pkcs15Pad(message, keyBitlen/8)
	encrypted := encryptRsa(padded, public)
	decryptedPadded := pkcs15PaddingOracleAttack(encrypted, public, &oracle)
	decrypted, err := pkcs15Unpad(decryptedPadded)
	if err != nil {
		t.Fatal(err)
	}

	if bytes.Equal(message, decrypted) {
		t.Logf("\n\ndecrypted successfully: %s\n\n", decrypted)
	} else {
		t.Fatalf("\n\ndecrypted message differs from original: %s\n\n", decrypted)
	}
}
