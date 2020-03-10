package cryptopals

import (
	"testing"
)

func TestBreakRepeatingKeyXor(t *testing.T) {
	src, err := readFile("../data/6.txt")
	if err != nil {
		t.Fatal(err)
	}

	src, err = base64decode(src)
	if err != nil {
		t.Fatal(err)
	}

	m := breakRepeatingKeyXor(src)
	t.Logf("decrypted with key: %x \n%s", m.key, m.v)
}
