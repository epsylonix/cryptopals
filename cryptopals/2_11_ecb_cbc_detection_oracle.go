package cryptopals

import (
	"crypto/rand"
	rnd "math/rand"
)

func isEcbEncrypted(data []byte) bool {
	if hasDuplicateBlocks(data) {
		return true
	}
	return false
}

func encryptWithEcbOrCbc(data []byte) ([]byte, string) {
	key := randomBytes(16)

	if rnd.Intn(2) == 0 {
		return ecbEncrypt(data, key), "ecb"
	}

	iv := randomBytes(16)
	return cbcEncrypt(data, key, iv), "cbc"
}

func randomBytes(length int) []byte {
	k := make([]byte, length)
	_, err := rand.Read(k)
	if err != nil {
		panic(err)
	}

	return k
}
