package cryptopals

import (
	"bytes"
	"math/rand"
	"testing"
	"time"
)

func TestByteAtATimeDecryption2(t *testing.T) {
	rand.Seed(time.Now().UTC().UnixNano())

	message := readBase64File("../data/12.txt")
	key := randomBytes(16)
	prefix := randomBytes(rand.Intn(50))
	t.Logf("real prefix len: %v, real suffix len: %v\n", len(prefix), len(message))
	encryptionOracle := buildEcbEncryptorWithPrefixAndSuffix(prefix, message, key)

	// not the shortest function name - naming functions for these challenges is hard!
	decrypted := decryptAesEcbWitnEnryptionOracleIgnoringPrefix(encryptionOracle)
	if !bytes.Equal(decrypted, message) {
		t.Fatalf("decrypted messages differs from the orignal: \ndecrypted: \n%s \n\n \noriginal: \n%s", decrypted, message)
	}
	t.Logf("Decrypted: \n%s\n", decrypted)
}
