package cryptopals

import "testing"

func TestMd4(t *testing.T) {
	assertValidMd41Hash(t, "The quick brown fox jumps over the lazy dog", "1bee69a46ba811185c194762abaeae90")
	assertValidMd41Hash(t, "The quick brown fox jumps over the lazy cog", "b86e130ce7028da59e672d56ad0113df")
	assertValidMd41Hash(t, "", "31d6cfe0d16ae931b73c59d7e0c089c0")
}

func assertValidMd41Hash(t *testing.T, data, hexEncodedHash string) {
	hash := md4([]byte(data))
	hex := hexEncode(hash[:])
	assertEqualArrays(t, hex, []byte(hexEncodedHash))
}
