package cryptopals

import (
	"bytes"
	"testing"
)

func TestMD4MacLengthExtention(t *testing.T) {
	/*
	  Basically the same routine as for the previous challange.
	  if I knew about md4 exercise I would have made the code for sha1 mac length extension more generic
	  but now it would be too boring to refactor and apparently copy-paste style os sort of idiomatic for go,
	  so here we go :)
	*/

	key := []byte("secret_key_stuff")
	originalData := []byte("comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon")
	signature := md4mac(originalData, key)
	dataToAppend := []byte(";admin=true")

	extendedData, extendedDataSignature := extendMd4Mac(originalData, signature, dataToAppend, len(key))
	expectedSignature := md4mac(extendedData, key)

	decoded := kvDecode(string(extendedData), ";")
	if decoded["admin"] != "true" {
		t.Fatalf("failed to extend the data, got: %s", decoded)
	}

	if !bytes.Equal(extendedDataSignature, expectedSignature) {
		t.Fatalf("failed to generate a valid signature for extended data: %v != %v (%s)\n", extendedDataSignature, expectedSignature, extendedData)
	}

	t.Logf("succesfully extended data: %s\n", decoded)
}
