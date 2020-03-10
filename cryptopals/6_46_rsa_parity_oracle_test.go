package cryptopals

import (
	"bytes"
	"fmt"
	"math/big"
	"testing"
)

func TestRsaParityOracle(t *testing.T) {
	var e = big.NewInt(65537)
	private, public := generateRsaKeys(1024, e)
	oracle := rsaParityOracle{key: private}
	message, err := base64decode([]byte("VGhhdCdzIHdoeSBJIGZvdW5kIHlvdSBkb24ndCBwbGF5IGFyb3VuZCB3aXRoIHRoZSBGdW5reSBDb2xkIE1lZGluYQ=="))
	if err != nil {
		panic(err)
	}
	encrypted := encryptRsa(message, public)
	decrypted := decryptRsaUsingParityOracle(encrypted, &oracle, public)

	if bytes.Equal(decrypted, message) {
		fmt.Printf("\n\ndecrypted successfully: %s\n\n", decrypted)
	} else {
		fmt.Printf("\n\ndecrypted message differs from original: %s\n\n", decrypted)
	}
}
