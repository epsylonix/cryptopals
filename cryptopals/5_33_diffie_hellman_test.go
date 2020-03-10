package cryptopals

import (
	"math/big"
	"testing"
)

func TestExpMod(t *testing.T) {
	x := big.NewInt(int64(123456789012345))
	e := big.NewInt(int64(987654321097654321))
	m := big.NewInt(int64(1))
	m.Lsh(m, uint(1025))

	actual := expMod(x, e, m)

	expected := new(big.Int)
	expected.Exp(x, e, m)

	if !eq(actual, expected) {
		t.Fatalf("expected: \n%x \n\ngot: \n%x", expected, actual)
	}
}

func TestDiffieHellmanSession(t *testing.T) {
	dh1 := new(diffieHellman)
	dh1.init()

	dh2 := new(diffieHellman)
	dh2.init()

	dh1.genSessionKey(dh2.public)
	dh2.genSessionKey(dh1.public)

	if dh1.session.Cmp(dh2.session) != 0 {
		t.Fatalf("different session keys!: %x != %x", dh1.session, dh2.session)
	}

	t.Logf("session key: %x", dh1.session)
}
