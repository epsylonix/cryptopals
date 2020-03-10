package cryptopals

import "testing"

func TestBruteforceSingleByteXor(t *testing.T) {
	hex := []byte("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
	data, err := hexDecode(hex)
	if err != nil {
		t.Fatal(err)
	}

	decrypted := bruteforceSingleByteXor(data).value.(messageWithKey)
	if decrypted.key.(byte) != 88 {
		t.Fatalf("invalid key found: %v, decrypted message is: %s", decrypted.key, decrypted.v)
	}
	t.Logf("decrypted the message: %s (key: %v)", decrypted.v, decrypted.key)
}
