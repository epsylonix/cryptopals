package cryptopals

import (
	"fmt"
	"log"
)

func main210() {
	src, err := readFile("../data/10.txt")
	if err != nil {
		log.Fatal(err)
		return
	}

	src, err = base64decode(src)
	if err != nil {
		log.Fatal(err)
		return
	}

	key := []byte("YELLOW SUBMARINE")
	iv := []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	dec, err := cbcDecrypt(src, key, iv)
	if err != nil {
		panic(err)
	}

	fmt.Printf("%s\n", dec)
}
