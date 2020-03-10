package cryptopals

import "container/heap"

type scoredValue struct {
	value interface{}
	score float64
}

type scoredHeap []*scoredValue

func (h scoredHeap) Len() int { return len(h) }

func (h scoredHeap) Less(i, j int) bool {
	return h[i].score < h[j].score
}

func (h scoredHeap) Swap(i, j int) {
	h[i], h[j] = h[j], h[i]
}

func (h *scoredHeap) Push(x interface{}) {
	*h = append(*h, x.(*scoredValue))
}

func (h *scoredHeap) Pop() interface{} {
	old := *h
	n := len(old)
	x := old[n-1]
	*h = old[0 : n-1]
	return x
}

func (h scoredHeap) min() *scoredValue {
	return h[0]
}

func (h *scoredHeap) toA() []*scoredValue {
	sorted := make([]*scoredValue, h.Len())

	for i := 0; h.Len() > 0; i++ {
		sorted[i] = heap.Pop(h).(*scoredValue)
	}

	return sorted
}
