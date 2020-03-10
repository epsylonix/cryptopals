package cryptopals

import (
	"bytes"
	"fmt"
)

func decryptAesEcbWitnEnryptionOracleIgnoringPrefix(encryptionOracle func([]byte) []byte) []byte {
	blockSize := detectBlockSize(encryptionOracle)

	ignoredPrefixLen, suffixLen := calculatePrefixAndSuffixLength(encryptionOracle, blockSize)
	fmt.Printf("detected prefix len: %v, detected suffix len: %v\n", ignoredPrefixLen, suffixLen)
	// pad ignored prefix to a full block
	var padLen int
	if partialBlock := ignoredPrefixLen % blockSize; partialBlock != 0 {
		padLen = blockSize - partialBlock
	}
	prefixAndPadLen := ignoredPrefixLen + padLen

	encryptionOracleWithPrefixTruncated := func(data []byte) []byte {
		paddedData := make([]byte, padLen+len(data))
		copy(paddedData[padLen:], data)
		encrypted := encryptionOracle(paddedData)
		return encrypted[prefixAndPadLen:]
	}

	return decryptAesEcbUsingEncryptionOracle(encryptionOracleWithPrefixTruncated)
}

func calculatePrefixAndSuffixLength(encryptor func([]byte) []byte, blockSize int) (int, int) {
	// start with 2 blocks, and increase zond's length untill duplicate blocks appear
	// At this point the part of the zond besides 2 blocks got merged with the prefix into one block

	for i := 0; i < blockSize; i++ {
		zond := make([]byte, blockSize*2+i)
		encrypted := encryptor(zond)
		start, end := findConseqEqualBlocks(encrypted, blockSize)
		if start != -1 {
			prefixLen := start - i
			suffixLen := len(encrypted) - end + 1
			return prefixLen, suffixLen
		}
	}

	panic("can't determine prefix and suffix len, not encrypted with ecb?")
}

func findConseqEqualBlocks(data []byte, blockSize int) (int, int) {
	var i int
	for i = blockSize; i <= len(data)-blockSize; i += blockSize {
		if bytes.Equal(data[i-blockSize:i], data[i:i+blockSize]) {
			start := i - blockSize
			end := i + blockSize
			for ; end <= len(data)-blockSize; end += blockSize {
				if !bytes.Equal(data[end-blockSize:end], data[end:end+blockSize]) {
					break
				}
			}
			return start, end
		}
	}

	return -1, -1
}

func buildEcbEncryptorWithPrefixAndSuffix(prefix, suffix, key []byte) func([]byte) []byte {
	return func(data []byte) []byte {
		toEncrypt := append(append(prefix, data...), suffix...)
		return ecbEncrypt(toEncrypt, key)
	}
}
