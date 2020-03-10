package cryptopals

import (
	"errors"
	"fmt"
	"math/rand"
	"time"
)

func guessUnixTimestampSeed(firstRandom int, lookBackSeconds int) (int, error) {
	now := int(time.Now().Unix())

	for i := now; i >= now-lookBackSeconds; i-- {
		mt := newRng(i)
		if firstRandom == mt.nextInt() {
			return i, nil
		}
	}

	return -1, errors.New("Can't find seed within specified time interval")
}

func seedAndSleep(maxSleepSec int) (int, int) {
	rand.Seed(time.Now().UnixNano())
	maxSleep := maxSleepSec / 2 // ther are 2 sleeps

	s := rand.Intn(maxSleep)
	fmt.Printf("Sleeping %v sec\n", s)
	time.Sleep(time.Duration(s) * time.Second)

	seed := int(time.Now().Unix())
	fmt.Printf("seeded with: %v\n", seed)

	mt := newRng(seed)

	s = rand.Intn(maxSleep)
	fmt.Printf("Sleeping %v sec\n", s)
	time.Sleep(time.Duration(s) * time.Second)

	return seed, mt.nextInt()
}
