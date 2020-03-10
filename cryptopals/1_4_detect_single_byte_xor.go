package cryptopals

import (
	"fmt"
	"sync"
)

func detectSingleByteXor(cyphertexts [][]byte) ([]byte, *scoredValue, error) {
	type result struct {
		cyphertext []byte
		value      *scoredValue
	}

	bestGuess := &scoredValue{}
	var guessedCythertext []byte

	var waitGroup sync.WaitGroup

	c := make(chan *result)
	waitGroup.Add(len(cyphertexts))

	for _, cyphertext := range cyphertexts {
		h, err := hexDecode(cyphertext)
		if err != nil {
			fmt.Println(err)
			return nil, nil, err
		}

		go func(ctext []byte) {
			c <- &result{
				cyphertext: ctext,
				value:      bruteforceSingleByteXor(h),
			}
			waitGroup.Done()
		}(cyphertext)
	}

	go func() {
		waitGroup.Wait()
		close(c)
	}()

	for r := range c {
		if r.value.score > bestGuess.score {
			bestGuess = r.value
			guessedCythertext = r.cyphertext
		}
	}

	return guessedCythertext, bestGuess, nil
}
