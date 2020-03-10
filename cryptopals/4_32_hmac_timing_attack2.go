package cryptopals

import (
	"fmt"
	"time"
)

type durationPerChar struct {
	c byte
	d time.Duration
}

func recoverHmacViaTimingLeak2(file string) ([sha1Size * 2]byte, error) {
	signatureGuess := [sha1Size * 2]byte{} // 20 bytes sha1 * 2 hex chars per byte
	var avrTimes = 3

	/*
	  Trying to detect a duration of a request duration change
	  averaging avrTimes requests duration.
	  Considering the char as valid when the request is longer with this char vs with any other
	  If we can't detect a valid char reliably
	  then double the avrTimes (make double the number of requests with the same char and average the result)
	  The longer the sequence we're processing, the more is noise interference
	  so avrTimes will grow as more chars are recovered
	*/
	for i := 0; i < len(signatureGuess); i++ {
		foundValidChar := false

		for !foundValidChar && avrTimes < 50 {
			fmt.Printf("averaging times : %v\n", avrTimes)

			var charGuess byte
			var cnt = 0
			var tries = 10
			for ; tries > 0; tries-- {
				c := recoverSignatureChar(file, signatureGuess, i, avrTimes)
				fmt.Printf("%vth char is probably: %s, prev guess: %s\n", i, string(c), string(charGuess))
				if c == charGuess {
					cnt++
					if cnt == 3 {
						foundValidChar = true
						signatureGuess[i] = charGuess
						fmt.Printf("Found %vth char, have so far: %s\n", i, signatureGuess)
						break
					}
				} else {
					cnt = 1
					charGuess = c
				}
			}
			if !foundValidChar {
				avrTimes *= 2
			}
		}
	}

	if _, res := timeHmacValidationRequest(file, string(signatureGuess[:]), 1); res {
		return signatureGuess, nil
	}
	return [sha1Size * 2]byte{}, fmt.Errorf("Couldn't find a valid signature, have so far: %s", signatureGuess)
}

func recoverSignatureChar(file string, signatureGuess [sha1Size * 2]byte, guessedIndex int, avrTimes int) byte {
	chars := [...]byte{'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'}

	var d durationPerChar
	var duration int
	var res bool

	for j := 0; j < len(chars); j++ {
		signatureGuess[guessedIndex] = chars[j]

		duration, res = timeHmacValidationRequest(file, string(signatureGuess[:]), avrTimes)
		if res {
			// found valid signature
			break
		}

		if t := time.Duration(duration); d.d < t {
			d.d = t
			d.c = chars[j]
		}

		// fmt.Printf("Tried %vth char: %s, d=%v\n", guessedIndex, string(chars[j]), duration)
	}

	// fmt.Printf("%v", durations)
	return d.c
}
