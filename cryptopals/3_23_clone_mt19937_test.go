package cryptopals

import (
	"testing"
	"time"
)

func TestCloneMt19937(t *testing.T) {
	originalMt := newRng(int(time.Now().UnixNano()))
	clonedMt := cloneMt199377(originalMt)

	for i := 0; i < mtStateSize; i++ {
		if originalMt.nextInt() != clonedMt.nextInt() {
			t.Fatalf("failed to clone random number generator at i=%v", i)
		}
	}

	t.Logf("the random number generator successfully cloned")
}
