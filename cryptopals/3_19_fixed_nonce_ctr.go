package cryptopals

func decryptFixedNonceCtr(encryptedStrings [][]byte) [][]byte {
	maxLen := maxLen(encryptedStrings)
	guessedKeystream := make([]byte, maxLen)

	for i, col := range toByteColumns(encryptedStrings) {
		// Original strings have different lengths.
		// Because of that the right most columns have less chars
		// and less data to guess the correct key byte,
		// so expect the end of each long string to be decrypted incorrectly
		guess := bruteforceSingleByteXor(col)
		guessedKeystream[i] = guess.value.(messageWithKey).key.(byte)
	}

	decryptedStrings := make([][]byte, len(encryptedStrings))
	for i, s := range encryptedStrings {
		decrypted := make([]byte, len(s))
		for j := 0; j < len(s); j++ {
			decrypted[j] = s[j] ^ guessedKeystream[j]
		}
		decryptedStrings[i] = decrypted
	}

	return decryptedStrings
}

func toByteColumns(data [][]byte) [][]byte {
	maxLen := maxLen(data)

	res := make([][]byte, maxLen)

	for c := 0; c < maxLen; c++ {
		column := make([]byte, len(data))
		i := 0
		for _, s := range data {
			if len(s) <= c {
				continue
			}
			column[i] = s[c]
			i++
		}
		res[c] = column[:i]
	}

	return res
}

func maxLen(data [][]byte) int {
	maxLen := 0
	for _, s := range data {
		if l := len(s); l > maxLen {
			maxLen = l
		}
	}
	return maxLen
}
