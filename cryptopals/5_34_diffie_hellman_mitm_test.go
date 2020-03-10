package cryptopals

import (
	"bytes"
	"testing"
)

func TestDiffieHellmanMitm(t *testing.T) {
	aliceToMallory := make(chan []byte, 10)
	bobToMallory := make(chan []byte, 10)
	malloryToAlice := make(chan []byte, 10)
	malloryToBob := make(chan []byte, 10)

	toAlice := make(chan []byte, 10)
	fromAlice := make(chan []byte, 10)
	toBob := make(chan []byte, 10)
	fromBob := make(chan []byte, 10)
	fromMallory := make(chan []byte, 10)

	go mitmSet534(aliceToMallory, malloryToAlice, bobToMallory, malloryToBob, fromMallory)
	go targetSet534("Alice", true, malloryToAlice, aliceToMallory, toAlice, fromAlice)
	go targetSet534("Bob", false, malloryToBob, bobToMallory, toBob, fromBob)

	var m1, m2 []byte

	m1 = []byte("alice's secret message")
	toAlice <- m1
	m2 = <-fromMallory
	if !bytes.Equal(m1, m2) {
		t.Fatalf("Expected Mallory to intercept '%s', got: '%s'", m1, m2)
	}
	m2 = <-fromBob
	if !bytes.Equal(m1, m2) {
		t.Fatalf("Expected Bob to receive '%s', got: '%s'", m1, m2)
	}

	m1 = []byte("bob's data")
	toBob <- m1
	m2 = <-fromMallory
	if !bytes.Equal(m1, m2) {
		t.Fatalf("Expected Mallory to intercept '%s', got: '%s'", m1, m2)
	}
	m2 = <-fromAlice
	if !bytes.Equal(m1, m2) {
		t.Fatalf("Expected Alice to receive '%s', got: '%s'", m1, m2)
	}
}
