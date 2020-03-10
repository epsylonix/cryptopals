package cryptopals

import "testing"

func TestXor(t *testing.T) {
	a, _ := hexDecode([]byte("1c0111001f010100061a024b53535009181c"))
	b, _ := hexDecode([]byte("686974207468652062756c6c277320657965"))

	xorred, _ := xor(a, b)
	expected, _ := hexDecode([]byte("746865206b696420646f6e277420706c6179"))

	assertEqualArrays(t, xorred, expected)
}
