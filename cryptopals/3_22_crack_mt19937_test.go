package cryptopals

import (
	"testing"
)

func TestMt19937TimestampSeedGuessing(t *testing.T) {
	const maxSleepSec = 20

	seed, rnd := seedAndSleep(maxSleepSec)
	guessedSeed, err := guessUnixTimestampSeed(rnd, maxSleepSec)
	if err != nil {
		t.Fatal(err)
	}

	if seed != guessedSeed {
		t.Fatalf("Seed guessed incorrectly: %v != %v\n", seed, guessedSeed)
	}

	t.Logf("Seed guessed correctly: %v", guessedSeed)
}
