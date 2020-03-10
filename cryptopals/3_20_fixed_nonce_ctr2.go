package cryptopals

func decryptFixedNonceCtrAsMultibyteXor(encryptedStrings [][]byte) [][]byte {
	// every string is basically xorred with the same key
	// so join it to one string and decrypt statistically like a repeating key cypher
	keyLen := minLen(encryptedStrings)
	encryptedString := make([]byte, len(encryptedStrings)*keyLen)
	for i, s := range encryptedStrings {
		copy(encryptedString[i*keyLen:], s[:keyLen])
	}

	decryptedWithMetadata := bruteforceMultibyteByteXor(encryptedString, keyLen)
	decryptedString := decryptedWithMetadata.value.(*messageWithKey).v
	decryptedStrings := make([][]byte, len(encryptedStrings))
	for i := 0; i < len(encryptedStrings); i++ {
		decryptedStrings[i] = decryptedString[i*keyLen : i*keyLen+keyLen]
	}

	return decryptedStrings
}

func minLen(data [][]byte) int {
	if len(data) == 0 {
		return 0
	}

	minLen := len(data[0])
	for _, s := range data {
		if l := len(s); l < minLen {
			minLen = l
		}
	}
	return minLen
}
