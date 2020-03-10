package cryptopals

import (
	"testing"
)

func TestMersenneTwister(t *testing.T) {
	// Not much of a test obviously.
	// Considered implementing chi-squared or Kolmogorov-Smirnov test here
	// but it turned out to be rather time-consuming,
	// Don't want to include an external dependency either,
	// so no test here for the time being (unlikely to add one later though :)
	mt := newRng(4357)
	m := 100
	for i := 0; i < 10; i++ {
		t.Logf("[0..%v]: %v", m, mt.nextInt()%m)
	}
}
