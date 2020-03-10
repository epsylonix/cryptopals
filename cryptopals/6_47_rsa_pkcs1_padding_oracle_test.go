package cryptopals

import (
	"bytes"
	"math/big"
	"testing"
)

func TestPkcs15Pad(t *testing.T) {
	x := []byte{1, 2, 3}
	paddedLen := 20

	padded := pkcs15Pad(x, paddedLen)

	if len(padded) != paddedLen {
		t.Fatalf("invalid padding length: %v", padded)
	}

	if padded[0] != 0 || padded[1] != 2 {
		t.Fatalf("invalid padding signature: %v", padded)
	}

	for i := 2; i < paddedLen-len(x)-1; i++ {
		if padded[i] == 0 {
			t.Fatalf("invalid padding byte %v: %v", i, padded)
		}
	}

	if padded[paddedLen-len(x)-1] != 0 {
		t.Fatalf("invalid padding ending byte: %v", padded)
	}

	if !bytes.Equal(x, padded[paddedLen-len(x):]) {
		t.Fatalf("padded array is not the same as the orignal: %v", padded)
	}
}

func TestPkcs15Unpad(t *testing.T) {
	x := []byte{1, 2, 3}
	paddedLen := 25

	padded := pkcs15Pad(x, paddedLen)
	unpadded, err := pkcs15Unpad(padded)
	if err != nil {
		t.Fatalf("unpadding failed with error: %v", err)
	}
	if !bytes.Equal(x, unpadded) {
		t.Fatalf("unpadded array is not the same as the orignal: %v", unpadded)
	}

	padded[1] = 3
	_, err = pkcs15Unpad(padded)
	if err == nil {
		t.Fatal("unpadding should fail when padding is incorrect")
	}
}

func TestPkcs15PaddingOracleAttack(t *testing.T) {
	e := big.NewInt(3)
	keyBitlen := 256
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
