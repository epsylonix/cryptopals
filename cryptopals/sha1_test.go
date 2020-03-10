package cryptopals

import "testing"

func TestSha1(t *testing.T) {
	assertValidSha1Hash(t, "The quick brown fox jumps over the lazy dog", "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12")
	assertValidSha1Hash(t, "The quick brown fox jumps over the lazy cog", "de9f2c7fd25e1b3afad3e85a0bd17d9b100db4b3")
	assertValidSha1Hash(t, "", "da39a3ee5e6b4b0d3255bfef95601890afd80709")
}

func assertValidSha1Hash(t *testing.T, data, hexEncodedHash string) {
	hash := sha1([]byte(data))
	hex := hexEncode(hash[:])
	assertEqualArrays(t, hex, []byte(hexEncodedHash))
}
