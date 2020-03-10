package cryptopals

import (
	"bytes"
	"testing"
)

func TestSha1MacLengthExtention(t *testing.T) {
	key := []byte("secret_key_stuff")
	originalData := []byte("comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon")
	signature := sha1mac(originalData, key)
	dataToAppend := []byte(";admin=true")

	extendedData, extendedDataSignature := extendSha1Mac(originalData, signature, dataToAppend, len(key))
	expectedSignature := sha1mac(extendedData, key)

	decoded := kvDecode(string(extendedData), ";")
	if decoded["admin"] != "true" {
		t.Fatalf("failed to extend the data, got: %s", decoded)
	}

	if !bytes.Equal(extendedDataSignature, expectedSignature) {
		t.Fatalf("failed to generate a valid signature for extended data: %v != %v (%s)\n", extendedDataSignature, expectedSignature, extendedData)
	}

	t.Logf("succesfully extended data: %s\n", decoded)
}
