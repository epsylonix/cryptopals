package cryptopals

import (
	"errors"
	"fmt"
)

func main12() {
	first, err := ReadHex("Enter first hex: ")
	if err != nil {
		fmt.Println(err)
		return
	}

	second, err := ReadHex("Enter second hex: ")
	if err != nil {
		fmt.Println(err)
		return
	}

	result, err := xor(first, second)
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Printf("Xored: %s\n", result)
}

// xor xors bytes of the first array with bytes of the second
func xor(a, b []byte) ([]byte, error) {
	if len(a) != len(b) {
		return nil, errors.New("lengths should be equal")
	}

	c := make([]byte, len(a))
	for i := 0; i < len(a); i++ {
		c[i] = a[i] ^ b[i]
	}

	return c, nil
}
