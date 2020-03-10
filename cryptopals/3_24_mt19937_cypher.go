package cryptopals

import (
	"errors"
	"time"
)

type set324EncryptorDecryptor struct {
	seed int
	mt   *mtRand
}

func newSet324ED(key uint16) set324EncryptorDecryptor {
	return set324EncryptorDecryptor{
		seed: int(key),
	}
}

func newSet324CurTimestampED() set324EncryptorDecryptor {
	return set324EncryptorDecryptor{
		seed: int(time.Now().UnixNano()),
	}
}

func (ed *set324EncryptorDecryptor) encrypt(data []byte) []byte {
	encrypted := make([]byte, len(data))
	mt := newRng(ed.seed)

	for i := 0; i < len(data); i++ {
		encrypted[i] = data[i] ^ byte(mt.nextInt())
	}

	return encrypted
}

func (ed *set324EncryptorDecryptor) decrypt(data []byte) []byte {
	return ed.encrypt(data)
}

func recoverMt19937Seed(data []byte, knownPlaintextTail []byte, maxKey int, minKey int) (int, error) {
	rngOutputs := make([]byte, len(knownPlaintextTail))
	tailStart := len(data) - len(knownPlaintextTail)
	for i := tailStart; i < len(data); i++ {
		rngOutputs[i-tailStart] = data[i] ^ knownPlaintextTail[i-tailStart]
	}

	for key := maxKey; key >= minKey; key-- {
		mt := newRng(key)
		// skip unknown part of cyphertext
		for i := 0; i < tailStart; i++ {
			mt.nextInt()
		}

		// compare mt outputs with known mt outputs
		for i := tailStart; i < len(data); i++ {
			if byte(mt.nextInt()) != rngOutputs[i-tailStart] {
				break
			}

			if i == len(data)-1 {
				return key, nil
			}
		}
	}

	return 0, errors.New("Couldn't recover the key")
}
