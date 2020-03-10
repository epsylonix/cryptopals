package cryptopals

import (
	"errors"
	"log"
	"sort"
)

func breakRepeatingKeyXor(encrypted []byte) messageWithKey {
	possibleKeyLengths := guessKeyLength([]byte(encrypted), 2, 42)
	keysToTry := minInt(3, len(possibleKeyLengths))
	decrypted := make([]*scoredValue, keysToTry)

	for k := 0; k < keysToTry; k++ {
		decrypted[k] = bruteforceMultibyteByteXor(encrypted, possibleKeyLengths[k].size)
	}

	sort.Slice(decrypted, func(i, j int) bool {
		return (*decrypted[i]).score > (*decrypted[j]).score
	})

	key := decrypted[0].value.(*messageWithKey).key.([]byte)
	mes := decrypted[0].value.(*messageWithKey).v

	return messageWithKey{
		key: key,
		v:   mes,
	}
}

type keysizeWithDist struct {
	size int
	dist float64
}

func bruteforceMultibyteByteXor(src []byte, keySize int) *scoredValue {
	if keySize <= 0 {
		panic(errors.New("Invalid key size"))
	}

	if len(src)/keySize < 2 {
		panic(errors.New("Source data is too small to break encryption with this method"))
	}

	key := make([]byte, keySize)
	for i := 0; i < keySize; i++ {
		nths := takeNth(src, keySize, i)
		v := bruteforceSingleByteXor(nths)
		key[i] = v.value.(messageWithKey).key.(byte)
	}

	mes := repeatingKeyXorEncrypt(src, key)
	return &scoredValue{
		value: &messageWithKey{
			key: key,
			v:   mes,
		},
		score: scoreByCharFreq(mes),
	}
}

func guessKeyLength(cythertext []byte, startLen, stopLen int) []*keysizeWithDist {
	distances := make([]*keysizeWithDist, stopLen-startLen+1)

	for l := startLen; l <= stopLen; l++ {
		// impossible to guess key length using this method
		if l*4 > len(cythertext) {
			continue
		}

		p1 := cythertext[0 : 4*l]
		p2 := cythertext[4*l : 8*l]

		d, err := HammingDistance(p1, p2)
		if err != nil {
			log.Fatal(err)
			return []*keysizeWithDist{}
		}
		distances[l-startLen] = &keysizeWithDist{
			dist: float64(d) / float64(l),
			size: l,
		}
	}

	sort.Slice(distances, func(i, j int) bool {
		return (*distances[i]).dist < (*distances[j]).dist
	})

	return distances
}
