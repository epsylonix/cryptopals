package cryptopals

import (
	"bytes"
	"testing"
)

func TestSha1Mac(t *testing.T) {
	data := []byte("The quick brown fox jumps over the lazy dog")

	data2 := make([]byte, len(data))
	copy(data2, data)
	data2[5] = data2[5] + 1

	key := []byte("some key")
	s := sha1mac(data, key)
	s2 := sha1mac(data2, key)

	if bytes.Equal(s, s2) {
		t.Fatalf("signing doesn't work: signature for the modified text is equal to the original signature")
	}
}
