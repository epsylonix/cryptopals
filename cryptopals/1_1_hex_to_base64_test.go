package cryptopals

import (
	"bytes"
	"testing"
)

func TestHexToBase64(t *testing.T) {
	hex := "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
	base64 := []byte("SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t")

	b, err := hexDecode([]byte(hex))
	if err != nil {
		t.Fatal(err)
	}

	base64Encoded := base64encode(b)

	if !bytes.Equal(base64Encoded, base64) {
		t.Logf("Hex to Base 64 failed: \ngot: [%s] \nnot: [%s]", base64Encoded, base64)
	}
}
