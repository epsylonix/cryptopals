package cryptopals

import (
	"errors"
	"fmt"
	"log"
	"math/rand"
	"time"
)

const blockSize = 16

type set317EncryptorDecryptor struct {
	key []byte
	iv  []byte
}

func (ed set317EncryptorDecryptor) encrypt(message []byte) []byte {
	return cbcEncrypt(message, ed.key, ed.iv)
}

func (ed set317EncryptorDecryptor) decrypts(encryptedData, iv []byte) bool {
	_, err := cbcDecrypt(encryptedData, ed.key, iv)
	if err != nil {
		if _, ok := err.(*paddingError); ok {
			return false
		}
		// not expecting an error of a different kind
		panic(err)
	}
	return true
}

func paddingOracleAttack(encryptedMessage []byte, ed set317EncryptorDecryptor) []byte {
	decryptedMessage := make([]byte, len(encryptedMessage))

	var prevBlock, encryptedBlock, decryptedBlock []byte
	prevBlock = ed.iv
	for i := 0; i < len(encryptedMessage)/blockSize; i++ {
		encryptedBlock = encryptedMessage[blockSize*i : blockSize*(i+1)]
		decryptedBlock = paddingOracleAttackBlock(encryptedBlock, prevBlock, ed)

		copy(decryptedMessage[blockSize*i:], decryptedBlock)

		prevBlock = encryptedBlock
	}

	unpadded, err := unpkcs7(decryptedMessage, blockSize)
	if err != nil {
		fmt.Printf("can't unpad! decrypted: %s (%v)", decryptedMessage, decryptedMessage)
		panic(errors.New("Invalid padding"))
	}

	return unpadded
}

func paddingOracleAttackBlock(encryptedBlock, originalPrevBlock []byte, ed set317EncryptorDecryptor) []byte {
	prevBlock := make([]byte, blockSize)
	copy(prevBlock, originalPrevBlock)

	decryptedBlock := make([]byte, blockSize)

	var paddingByte byte = 1
	for i := blockSize - 1; i >= 0; i-- {
		var validPaddingMaker byte
		successful := false
		// obviosly originalByte makes the padding correct
		// but it might not be a padding we're manufacturing (of len = paddingByte bytes)
		// it is what we need if we won't find any other byte that makes the padding valid

		for b := 0; b <= 255; b++ {
			// try all the possible byte values

			prevBlock[i] = byte(b)
			if ed.decrypts(encryptedBlock, prevBlock) {
				// found byte in prev block that makes next block ith byte a valid padding byte
				if i != blockSize-1 {
					validPaddingMaker = byte(b)
					successful = true
					break
				}

				// if it's the last block of the message
				// then we need to make sure it is a padding of 0x1
				// i.e if message is {... 0x2 [padding: 0x1]} then changing last byte to 0x2 still makes this a valid padding
				// so we need to make sure that message bytes dont interfere with our manufactured padding

				// modify the prev byte
				// if padding is still valid - we manufactured a correct padding of paddingByte bytes
				prevBlock[i-1]++
				isCorrect := ed.decrypts(encryptedBlock, prevBlock)
				prevBlock[i-1]--

				if isCorrect {
					validPaddingMaker = byte(b)
					successful = true
					break
				}
				// otherwise it means that part of te original message became part of the padding
				// so we need to try other values
			}
		}
		if !successful {
			fmt.Printf("Failed to decrypt, have so far: %v", decryptedBlock)
			panic(errors.New("Failed to decrypt"))
		}
		// validPaddingMaker ^ unxoredPlaintextBlock[i] == paddingByte
		// unxoredPlaintextBlock[i] = validPaddingMaker ^ paddingByte
		// plaintextBlock[i] = unxoredPlaintextBlock[i] ^ originalByte Of prev block
		// so:
		decryptedBlock[i] = validPaddingMaker ^ paddingByte ^ originalPrevBlock[i]
		// now we gonna make the prev byte a valid padding
		// that means the padding length is incremented
		// and paddingByte is incremented
		paddingByte++

		// now we need to make sure all [i:] bytes of encryptedBlock after decryption
		// are equal to the new paddingByte
		for j := i; j < blockSize; j++ {
			// we know the jth byte = decryptedBlock[j]
			// after decryption it we'll be xored with prevBlock[j]
			// so we modify it to make
			// unxorredBlock[j] ^ originalPrevBlock[j] == decryptedBlock[j]
			// we need
			// unxorredBlock[j] ^ x == paddingByte
			// x = unxorredBlock[j] ^ paddingByte == (originalPrevBlock[j] ^ decryptedBlock[j]) ^ paddingByte
			//   decryptedBlock[j] ^ prevBlock[j] == paddingByte
			prevBlock[j] = originalPrevBlock[j] ^ decryptedBlock[j] ^ paddingByte
		}
	}

	return decryptedBlock
}

func readBase64FileLines(path string) [][]byte {
	data, err := readLines(path)
	if err != nil {
		log.Fatal(err)
		panic(err)
	}

	res := [][]byte{}

	for _, encoded := range data {
		decoded, err := base64decode(encoded)

		if err != nil {
			log.Fatal(err)
			panic(err)
		}
		res = append(res, decoded)
	}

	return res
}

func randomElement(elements [][]byte) []byte {
	if len(elements) == 0 {
		panic(errors.New("elements can't be empty"))
	}

	rand.Seed(time.Now().UTC().UnixNano())
	return elements[rand.Intn(len(elements))]
}
