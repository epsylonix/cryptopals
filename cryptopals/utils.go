package cryptopals

import (
	"bufio"
	"errors"
	"fmt"
	"log"
	"math/big"
	"os"
)

const b64alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
const hexAlphabet = "0123456789abcdef"

var base64ToNum = [...]byte{
	64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
	64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
	64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 62, 64, 64, 64, 63,
	52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 64, 64, 64, 64, 64, 64,
	64, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14,
	15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 64, 64, 64, 64, 64,
	64, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
	41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 64, 64, 64, 64, 64,
	64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
	64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
	64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
	64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
	64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
	64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
	64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
	64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
}

// base64encode - base64 encode without padding
func base64encode(input []byte) []byte {
	inpLen := len(input)
	// every 6 bits of input to one byte (3 bytes inp -> 4 bytes outp)
	outLen := inpLen / 3 * 4
	if r := inpLen % 3; r != 0 {
		outLen += r + 1 // 2 out bytes for 1 source byte, 3 for 2
	}
	out := make([]byte, outLen)

	o, i := 0, 0
	// encode first 3*x bytes
	for ; i < inpLen-2; i += 3 {
		out[o] = b64alphabet[input[i]>>2]
		out[o+1] = b64alphabet[((input[i]&0x03)<<4)|(input[i+1]>>4)]
		out[o+2] = b64alphabet[((input[i+1]&0xF)<<2)|(input[i+2]>>6)]
		out[o+3] = b64alphabet[input[i+2]&0x3F]
		o += 4
	}

	// encode last 1 or 2 bytes if inpLen is not multiple of 3
	// 1 byte encodes into 2 bytes (top 6 bits + last 2 bits), 2 bytes into 3
	if i < inpLen {
		out[o] = b64alphabet[input[i]>>2]
		o++
		if i == (inpLen - 1) { // one byte not encoded
			out[o] = b64alphabet[(input[i]&0x03)<<4] // encode last 2 bits
			o++
		} else { // 2 bytes not encoded
			out[o] = b64alphabet[((input[i]&0x03)<<4)|(input[i+1]>>4)]
			out[o+1] = b64alphabet[(input[i+1]&0xF)<<2]
			o += 2
		}
	}

	return out
}

// base64decode - base64 decode without padding
func base64decode(input []byte) ([]byte, error) {
	inpLen := len(input)
	if inpLen == 0 {
		return []byte{}, nil
	}

	// unpad
	padLen := 0
	for i := inpLen - 1; i >= 0; i-- {
		if input[i] != '=' {
			break
		}
		padLen++
	}
	if padLen > 0 {
		inpLen -= padLen
		input = input[:inpLen]
	}

	outLen := inpLen / 4 * 3
	switch inpLen % 4 {
	case 1:
		return []byte{}, errors.New("Error decoding data: input length is invalid")
	case 2:
		outLen++
	case 3:
		outLen += 2
	}
	out := make([]byte, outLen)

	o, i := 0, 0
	// encode first 4*x bytes
	for ; i < inpLen-3; i += 4 {
		out[o] = base64ToNum[input[i]]<<2 | base64ToNum[input[i+1]]>>4
		out[o+1] = base64ToNum[input[i+1]]<<4 | base64ToNum[input[i+2]]>>2
		out[o+2] = base64ToNum[input[i+2]]<<6 | base64ToNum[input[i+3]]
		o += 3
	}

	// decode last 2 bytes
	if i == inpLen-2 {
		out[o] = base64ToNum[input[i]]<<2 | base64ToNum[input[i+1]]>>4
	}

	// decode last 3 bytes
	if i == inpLen-3 {
		out[o] = base64ToNum[input[i]]<<2 | base64ToNum[input[i+1]]>>4
		out[o+1] = base64ToNum[input[i+1]]<<4 | base64ToNum[input[i+2]]>>2
	}

	return out, nil
}

// hexDecode decodes string like "ab12b7" to bytes
func hexDecode(h []byte) ([]byte, error) {
	outLen := (len(h) + 1) / 2
	o := outLen - 1
	out := make([]byte, outLen)

	i := len(h) - 1
	for ; i >= 1; i -= 2 {
		r, err := decodeHexDigit(h[i])
		if err != nil {
			return nil, err
		}

		l, err := decodeHexDigit(h[i-1])
		if err != nil {
			return nil, err
		}

		out[o] = (l << 4) | r
		o--
	}

	if i == 0 {
		r, err := decodeHexDigit(h[i])
		if err != nil {
			return nil, err
		}
		out[0] = r
	}

	return out, nil
}

func decodeHexDigit(d byte) (byte, error) {
	var b byte
	var err error
	switch {
	case d >= '0' && d <= '9':
		b = d - '0'
	case d >= 'a' && d <= 'f':
		b = d + 10 - 'a'
	case d >= 'A' && d <= 'F':
		b = d + 10 - 'A'
	default:
		b = 0
		err = errors.New(string(d) + " is not a valid hex char")
	}
	return b, err
}

// ReadHex reads hex string from STDIN and decodes it
func ReadHex(message string) ([]byte, error) {
	reader := bufio.NewReader(os.Stdin)
	fmt.Print(message)

	inp, _ := reader.ReadBytes('\r')
	if (len(inp)-1)%2 != 0 { // last char is \r
		copy(inp[1:], inp[:len(inp)-1])
		inp[0] = '0'
	} else {
		inp = inp[:len(inp)-1]
	}

	// fmt.Printf("source: %v", inp)
	res, err := hexDecode(inp)
	if err != nil {
		fmt.Printf("Error: %s\n", err)
		return nil, err
	}
	return res, nil
}

func hexEncode(data []byte) []byte {
	encodedLen := len(data) * 2
	encoded := make([]byte, encodedLen)

	for i, b := range data {
		encoded[2*i] = hexAlphabet[b>>4]
		encoded[2*i+1] = hexAlphabet[b&0xF]
	}

	return encoded
}

func HammingDistance(a, b []byte) (int, error) {
	if len(a) != len(b) {
		return -1, errors.New("inputs length shuld be the same")
	}

	d := 0
	for i := range a {
		d += int(bitsCount(a[i] ^ b[i]))
	}

	return d, nil
}

func bitsCount(b byte) byte {
	var count byte

	for b > 0 {
		count += b & 1
		b = b >> 1
	}

	return count
}

func readFile(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		log.Fatal(err)
		return []byte{}, err
	}
	defer file.Close()

	var src []byte
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		src = append(src, []byte(scanner.Text())...)
	}

	return src, nil
}

func readLines(path string) ([][]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		log.Fatal(err)
		return [][]byte{}, err
	}
	defer file.Close()

	var src [][]byte
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		buf := scanner.Bytes()
		line := make([]byte, len(buf))
		copy(line, buf)
		src = append(src, line)
	}

	return src, nil
}

func takeNth(a []byte, n int, start int) []byte {
	if n <= 0 {
		log.Fatal("n can't be < 0")
		return []byte{}
	}

	res := make([]byte, (len(a)-start+n-1)/n)
	j := 0
	for i := start; i <= len(a)-n; i += n {
		res[j] = a[i]
		j++
	}

	return res
}

func xorInplace(dst, xorred []byte) {
	xorredLen := len(dst)
	if l := len(xorred); l < xorredLen {
		xorredLen = l
	}

	for i := 0; i < xorredLen; i++ {
		dst[i] = dst[i] ^ xorred[i]
	}
}

func toBigArrayInt(values ...int) []*big.Int {
	var res = make([]*big.Int, len(values))
	for i, v := range values {
		var x = big.NewInt(int64(v))
		res[i] = x
	}
	return res
}

func root(a *big.Int, n int) *big.Int {
	nn := big.NewInt(int64(n))
	r := big.NewInt(1)
	dr := new(big.Int)
	for {

		// (a / x_k^{n-1} - x_k) / n
		dr = dr.Set(a)
		for i := 0; i < n-1; i++ {
			dr.Div(dr, r)
		}

		dr.Sub(dr, r)
		dr.Div(dr, nn)

		if isZero(dr) {
			return r
		}

		r.Add(r, dr)
	}
}

func readLine(message string) []byte {
	reader := bufio.NewReader(os.Stdin)
	fmt.Print(message)

	inp, _ := reader.ReadBytes('\r')
	return inp[:len(inp)-1] // remove trailing \r
}

// go doesn't have a min function - that's surprising
func minInt(a, b int) int {
	if a < b {
		return a
	}

	return b
}
