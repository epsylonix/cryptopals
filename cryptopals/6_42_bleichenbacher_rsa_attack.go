package cryptopals

import (
	"bytes"
	"log"
	"math/big"
)

const minPKSC15PaddingSize = 3

// https://tools.ietf.org/html/rfc3447#appendix-A.2.4
var asn1Sha1DigestInfo = []byte{0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14}

func forgeRsaSignature(message []byte, public *publicKey) []byte {
	if !eq(public.E, big.NewInt(3)) {
		panic("only e=3 supported") // this would probably work with other small e, but
	}

	/*
		the challenge suggests an option of implementing this attack
		using the math that Bleichenbacher used in his presentation of this attack
		but the solution turned out not to be easily portable to any key size.
		Apperently Bleichenbacher used a 3072 bit key so that the solution is easier to derive.
		The PKCS1.5 encoded value looks like 2^3057 - 2^2360 + D * 2^2072 + garbage
		(see Hal Finney notes) where 3057 = 3072 - 15 comes from the fact
		that the first 15 bits of encoded value are zero
		(and the 2072 value is used to cancell out -2^2360).
		2^3057 is convieniently a perfect cube and so the binominal expansion
		of (A+B)^3 = A^3 − 3 A^2 B + 3 A B^2 − B^3 is used to derive a formulae
		for an approximation of a cube root of the forged signature
		that when cubed will look line [forge signature][garbage].

		1024 - 15 = 1009 is not a multiple of 3 so it seems that the same approach
		to derive a closed form solution (without a cube root) doesn't work
		(or I just don't know how to do it).

		Anyway we can just use a cube root and though it is not "a pen and paper solution"
		it will do - we have a computer after all.
	*/

	forgedSignature := make([]byte, public.Size())

	pkcsPrefix := []byte{0, 1, 0xff, 0} // I guess just one byte of 0xFF padding is fine
	hash := sha1(message)

	copy(forgedSignature, pkcsPrefix)
	copy(forgedSignature[len(pkcsPrefix):], asn1Sha1DigestInfo)
	copy(forgedSignature[len(pkcsPrefix)+len(asn1Sha1DigestInfo):], hash[:])

	signed := root(new(big.Int).SetBytes(forgedSignature), int(public.E.Int64()))
	signed.Add(signed, one)
	return signed.Bytes()
}

func signRsa(message []byte, private *privateKey) []byte {
	hash := sha1(message)

	dataToSign := make([]byte, len(asn1Sha1DigestInfo)+len(hash))
	copy(dataToSign, asn1Sha1DigestInfo)
	copy(dataToSign[len(asn1Sha1DigestInfo):], hash[:])

	signature := pkcs15(dataToSign, private.Size())
	signed := decryptRsa(signature, private)

	return signed
}

func pkcs15(data []byte, paddedSize int) []byte {
	if paddedSize-len(data) < minPKSC15PaddingSize {
		panic("not enough room to pad the data to the specified size")
	}

	padded := make([]byte, paddedSize)

	padded[0] = 0
	padded[1] = 1
	i := 2
	for ; i < paddedSize-minPKSC15PaddingSize-len(data); i++ {
		padded[i] = 0xFF
	}
	padded[i] = 0
	i++
	copy(padded[i:], data)

	return padded
}

func checkRsaSignature642(message []byte, signature []byte, public *publicKey) bool {
	s := rightJustify(encryptRsa(signature, public), public.Size())

	// skip padding
	if !bytes.Equal(s[:2], []byte{0, 1}) {
		log.Printf("a valid padding should start with [0x00 0x01]")
		return false
	}

	i := 2
	for ; i < len(s) && s[i] == 0xFF; i++ {
	}

	if i >= len(s) || s[i] != 0 {
		log.Printf("a valid padding should end with 0x00")
		return false
	}
	i++

	i += 15 // for simplicity sake we skip the asn.1 digest info, that's probably a vulnerability on it's own
	expectedMessageHash := s[i : i+sha1Size]
	actualHash := sha1(message)

	return bytes.Equal(expectedMessageHash, actualHash[:])
}

func rightJustify(b []byte, size int) []byte {
	x := make([]byte, size)
	copy(x[size-len(b):], b)
	return x
}
