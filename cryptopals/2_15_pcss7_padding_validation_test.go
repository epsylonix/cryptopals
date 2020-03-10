package cryptopals

import (
	"testing"
)

func TestPkcs7PaddingValidation(t *testing.T) {
	const blockSize byte = 16

	data := []byte("ICE ICE BABY\x04\x04\x04\x04")
	if !isPkcs7padded(data, blockSize) {
		t.Logf("Expected this string to be detected as having a valid pcks7 padding: \n %v\n", data)
	}

	data = []byte("ICE ICE BABY\x05\x05\x05\x05")
	if isPkcs7padded(data, blockSize) {
		t.Logf("Expected this string to be detected as not having a invalid pcks7 padding: \n %v\n", data)
	}

	data = []byte("ICE ICE BABY\x01\x02\x03\x04")
	if isPkcs7padded(data, blockSize) {
		t.Logf("Expected this string to be detected as not having a invalid pcks7 padding: \n %v\n", data)
	}
}
