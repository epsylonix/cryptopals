package cryptopals

import (
	"bytes"
	"fmt"
	"math/big"
	"testing"
)

func TestDiffieHellmanMaliciosG(t *testing.T) {
	// Alice uses this value for p
	// Not injecting it for simplicity
	p := new(diffieHellman).init().p

	zero := big.NewInt(int64(0))
	one := big.NewInt(int64(1))
	pMinusOne := new(big.Int).Sub(p, one)

	// all g's
	gs := [](*big.Int){one, p, pMinusOne}
	// shared secrets
	ss := [](*big.Int){one, zero, pMinusOne}

	/*
		X = a * b
		1) g=1 => s = (1^X) mod p = 1
		2) g=p => s = (p^X) mod p = 0
		3) g = p -1 =>
		s = (p-1)^X mod p = p^X - 1^p mod p = -1 mod p = p - 1 mod p (when p is prime)
	*/

	for i, g := range gs {
		fmt.Printf("\n\nusing g: %x\n\n", g)

		aliceToMallory := make(chan []byte, 10)
		bobToMallory := make(chan []byte, 10)
		malloryToAlice := make(chan []byte, 10)
		malloryToBob := make(chan []byte, 10)

		toAlice := make(chan []byte, 10)
		fromAlice := make(chan []byte, 10)
		toBob := make(chan []byte, 10)
		fromBob := make(chan []byte, 10)
		fromMallory := make(chan []byte, 10)

		go mitmSet535(g.Bytes(), ss[i], aliceToMallory, malloryToAlice, bobToMallory, malloryToBob, fromMallory)
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

		close(toAlice)
		close(toBob)
	}
}
