package cryptopals

import "testing"

func TestPkcs7Padding(t *testing.T) {
	src := []byte("YELLOW SUBMARINE")
	expected := append(src, []byte{4, 4, 4, 4}...)

	assertEqualArrays(t, pkcs7(src, 20), expected)
}
