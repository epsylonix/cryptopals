package cryptopals

import (
	"testing"
)

func TestDetectAesEcb(t *testing.T) {
	cyphertexts := [][]byte{}

	source, err := readLines("../data/8.txt")
	if err != nil {
		t.Fatal(err)
	}

	for _, b64encoded := range source {
		decoded, err := hexDecode(b64encoded)
		if err != nil {
			t.Fatal(err)
		}

		cyphertexts = append(cyphertexts, decoded)
	}

	ecbEncrypted, err := detectAesEcb(cyphertexts)
	if err != nil {
		t.Fatal(err)
	}

	t.Logf("found data that is likely to be encrypted in ECB mode: \n %x\n", ecbEncrypted)
}
