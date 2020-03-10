package cryptopals

import (
	"errors"
	"log"
)

func detectAesEcb(cyphertexts [][]byte) ([]byte, error) {
	for _, cyphertext := range cyphertexts {
		if hasDuplicateBlocks(cyphertext) {
			return cyphertext, nil
		}
	}

	return nil, errors.New("No cyphertext encrypted in ECB mode found")
}

func hasDuplicateBlocks(data []byte) bool {
	const blockSize int = 16

	counters := map[[blockSize]byte]int{}
	if len(data)%blockSize != 0 {
		log.Fatal(errors.New("data can't be split into blocks"))
		return false
	}

	var b [blockSize]byte
	for i := 0; i < len(data)-blockSize+1; i += blockSize {
		copy(b[:], data[i:i+blockSize])
		val, ok := counters[b]
		if !ok {
			val = 0
		}
		counters[b] = val + 1
	}

	for _, counter := range counters {
		if counter > 1 {
			return true
		}
	}

	return false
}
