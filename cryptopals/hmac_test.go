package cryptopals

import "testing"

func TestSha1Hmac(t *testing.T) {
	key, _ := hexDecode([]byte("707172737475767778797a7b7c7d7e7f80818283"))
	data := []byte("Hello World")
	digest := "2e492768aa339e32a9280569c5d026262b912431"
	assertValidSha1Hmac(t, data, key, digest)
}

func assertValidSha1Hmac(t *testing.T, data, key []byte, hexEncodedHash string) {
	hash := sha1Hmac(data, key)
	hex := hexEncode(hash[:])
	assertEqualArrays(t, hex, []byte(hexEncodedHash))
}
