package cryptopals

import (
	"testing"
)

func TestAesEcbDecrypt(t *testing.T) {
	key := []byte("YELLOW SUBMARINE")

	src, err := readFile("../data/7.txt")
	if err != nil {
		t.Fatal(err)
	}

	src, err = base64decode(src)
	if err != nil {
		t.Fatal(err)
	}

	res, err := ecbDecrypt(src, key)
	if err != nil {
		t.Fatal(err)
	}

	t.Logf("decrypted: %s", res)
}
