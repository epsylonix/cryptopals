package cryptopals

import (
	"container/heap"
)

type messageWithKey struct {
	v   []byte
	key interface{}
}

func decryptWithKeygen(keyGenerator func() chan interface{}, decryptor func(interface{}) []byte, scorrer func([]byte) float64) []*scoredValue {
	bestScoresToKeep := 3
	guesses := &scoredHeap{}

	for k := range keyGenerator() {
		m := messageWithKey{
			v:   decryptor(k),
			key: k,
		}

		scored := &scoredValue{
			value: m,
			score: scorrer(m.v),
		}

		pushCapped(guesses, scored, bestScoresToKeep)
	}

	bestGuesses := guesses.toA()
	return reverse(bestGuesses)
}

func pushCapped(h *scoredHeap, v *scoredValue, n int) {
	if h.Len() < n {
		heap.Push(h, v)
		return
	}

	if h.min().score > v.score {
		return
	}

	heap.Pop(h)
	heap.Push(h, v)
}

func reverse(a []*scoredValue) []*scoredValue {
	n := len(a)
	for i := n - 1; i > n/2; i-- {
		a[i], a[n-1-i] = a[n-1-i], a[i]
	}

	return a
}
