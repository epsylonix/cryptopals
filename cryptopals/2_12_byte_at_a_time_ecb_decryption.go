package cryptopals

import (
	"fmt"
)

func decryptAesEcbUsingEncryptionOracle(encryptionOracle func([]byte) []byte) []byte {
	const blockSize int = 16

	detectedBlockSize := detectBlockSize(encryptionOracle)
	fmt.Printf("Detected blocksize: %v\n", blockSize)
	if detectedBlockSize != blockSize {
		panic("Don't know how to decrypt data with a blocksize of " + string(detectedBlockSize))
	}

	repeatingData := make([]byte, blockSize*4)
	if !isEcbEncrypted(encryptionOracle(repeatingData)) {
		panic("Data is not encrypted using ECB method")
	}

	// length of a suffix that we are decrypting
	// Actually it might be shorter if padded to fill the last block
	maxSuffixLength := len(encryptionOracle([]byte{})) // actual string can be shorter because of the padding
	decrypted := make([]byte, maxSuffixLength)
	decryptedBytes := 0
	for b := 0; ; b++ {
		// decrypt each block
		for prefixLength := blockSize - 1; prefixLength >= 0; prefixLength-- {
			// in the current window of [blockSize] bytes
			// we shifted [prefixLength] bytes of prev (already decrypted) block (or 0s from the prefix)
			// and [blockSize - prefixLength - 1] bytes of the currently decrypted block
			// Now we're guessing the last byte of the plaintext in this window that we don't know yet

			// encrypt all blocks with all possible values for the last byte
			// and map encrypted data to the plaintext
			encToDec := map[string][]byte{}
			for lastByte := 0; lastByte <= 255; lastByte++ {
				// the block consists of 15 previosly decrypted chars + 1 unknown char
				block := make([]byte, blockSize)
				if b > 0 {
					// take last prefixLength bytes of the previosly (bth-1) decrypted block
					copy(block, decrypted[b*blockSize-prefixLength:b*blockSize])
				}
				// we're already decrypted [blockSize-prefixLength-1] bytes of the current (bth) block
				// copy them to the end of the guessed block
				copy(block[prefixLength:], decrypted[b*blockSize:decryptedBytes])
				// guess the last byte
				block[blockSize-1] = byte(lastByte)

				// encrypt this block and map encrypted block to the plaintext block
				encryptedBlock := encryptionOracle(block)[:blockSize]
				encToDec[string(encryptedBlock)] = block
			}

			// decrypt (blockSize-prefixLength)th byte of block b
			prefix := make([]byte, prefixLength)
			encrypted := encryptionOracle(prefix)
			encryptedBlock := encrypted[b*blockSize : b*blockSize+blockSize]
			decryptedBlock, ok := encToDec[string(encryptedBlock)]
			if !ok {
				fmt.Printf("Failed to decrypt a byte #%v/%v\n", b, prefixLength)
				fmt.Printf("Have decrypted so far: \n%s\n", decrypted)
				panic("Failed to decrypt a byte")
			}
			decryptedByte := decryptedBlock[blockSize-1]
			decrypted[decryptedBytes] = decryptedByte
			decryptedBytes++

			if prefixLength+decryptedBytes == len(encrypted) {
				// All bytes are decrypted.
				// At previous step we encountered a condition
				// when we decrypted the whole message but
				// a since padding + messageLen were multiple of blockSize
				// and didn't require padding, a new all-padding block was appended
				// and prefixLength+decryptedBytes == len(encrypted) was false because
				// 'encrypted' contained a padding block.
				// At this point we decreased the padding by one so
				// padding + messageLen became 1 byte short of blockSize multiple
				// and that last byte of padding was added and decrypted
				// by actual message size without padding is decryptedBytes-1
				return decrypted[:decryptedBytes-1]
			}
		}
	}
}

func detectBlockSize(encryptor func([]byte) []byte) int {
	maxExpectedBlockSize := 256
	x := make([]byte, maxExpectedBlockSize)

	initSize := len(encryptor([]byte{}))
	for i := 1; i <= maxExpectedBlockSize; i++ {
		newSize := len(encryptor(x[:i]))
		// size should grow in increments of a whole block
		if change := newSize - initSize; change > 0 {
			return change
		}
	}

	panic("Couldn't detect blocksize")
}

func buildEcbEncryptorWithSuffix(suffix, key []byte) func([]byte) []byte {
	return func(data []byte) []byte {
		toEncrypt := append(data, suffix...)
		return ecbEncrypt(toEncrypt, key)
	}
}

func readBase64File(path string) []byte {
	src, err := readFile(path)
	if err != nil {
		panic(err)
	}

	src, err = base64decode(src)
	if err != nil {
		panic(err)
	}

	return src
}
