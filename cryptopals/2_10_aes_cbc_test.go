package cryptopals

import "testing"

func TestCbcDecrypt(t *testing.T) {
	src, err := readFile("../data/10.txt")
	if err != nil {
		t.Fatal(err)
	}

	src, err = base64decode(src)
	if err != nil {
		t.Fatal(err)
	}

	key := []byte("YELLOW SUBMARINE")
	iv := []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	dec, err := cbcDecrypt(src, key, iv)
	if err != nil {
		t.Fatal(err)
	}

	t.Logf("Decrypted: %s\n", dec)
}
