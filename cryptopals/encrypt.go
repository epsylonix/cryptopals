package cryptopals

import (
	"crypto/aes"
	"encoding/binary"
	"errors"
	"log"
)

type paddingError struct {
	err string
}

func (e *paddingError) Error() string {
	return e.err
}

func ecbEncrypt(src, key []byte) []byte {
	padded := pkcs7(src, 16)
	return ecbEncryptNoPad(padded, key)
}

func ecbEncryptNoPad(src, key []byte) []byte {
	blockSize := 16

	if len(src) == 0 || len(src)%blockSize != 0 {
		panic(errors.New("Data should be divisable by 16"))
	}

	cr, err := aes.NewCipher(key)
	if err != nil {
		log.Fatal(err)
		panic(err)
	}

	resLen := (len(src) + blockSize - 1) / blockSize * blockSize // ceil
	result := make([]byte, resLen)

	i := 0
	for ; i <= len(src)-blockSize; i += blockSize {
		cr.Encrypt(result[i:i+blockSize], src[i:i+blockSize])
	}

	return result
}

func ecbDecrypt(src, key []byte) ([]byte, error) {
	decrypted := ecbDecryptNoPad(src, key)
	return unpkcs7(decrypted, 16)
}

func ecbDecryptNoPad(src, key []byte) []byte {
	cr, err := aes.NewCipher(key)
	if err != nil {
		log.Fatal(err)
		panic(err)
	}

	blockSize := 16
	if len(src)%blockSize != 0 {
		log.Fatal("Invalid input size")
		panic(errors.New("Invalid input size"))
	}

	result := make([]byte, len(src))

	for i := 0; i < len(src)-blockSize+1; i += blockSize {
		cr.Decrypt(result[i:i+blockSize], src[i:i+blockSize])
	}

	return result
}

func pkcs7(data []byte, blockSize byte) []byte {
	m := byte(len(data) % int(blockSize))
	if m == 0 {
		// create last all-padding block
		padded := make([]byte, int(blockSize)+len(data))
		for i := 1; i <= int(blockSize); i++ {
			padded[len(padded)-i] = blockSize
		}
		copy(padded, data)
		return padded
	}

	pad := blockSize - m
	padded := make([]byte, len(data)+int(pad))
	copy(padded[:len(data)], data)
	for i := len(data); i < len(padded); i++ {
		padded[i] = pad
	}

	return padded
}

func unpkcs7(data []byte, blockSize byte) ([]byte, error) {
	if !isPkcs7padded(data, blockSize) {
		return []byte{}, &paddingError{"Not padded with pkcs7"}
	}

	pad := data[len(data)-1]
	return data[:len(data)-int(pad)], nil
}

func isPkcs7padded(data []byte, blockSize byte) bool {
	l := len(data)

	if l == 0 || (l%int(blockSize) != 0) {
		return false
	}

	pad := data[len(data)-1]
	if pad > blockSize || pad == 0 {
		return false
	}

	for i := 1; i <= int(pad); i++ {
		if data[l-i] != pad {
			return false
		}
	}

	return true
}

func cbcDecryptNoPad(src, key []byte, iv []byte) ([]byte, error) {
	blockSize := 16

	if len(src)%blockSize != 0 {
		log.Fatal("Invalid input size")
		panic(errors.New("Invalid input length"))
	}

	if len(iv) != blockSize {
		log.Fatal("Invalid iv")
		panic(errors.New("Invalid IV length"))
	}

	res := make([]byte, len(src))
	prevBlock := iv
	for s := 0; s <= len(src)-blockSize; s += blockSize {
		thisBlock := src[s : s+blockSize]
		decryptedBlock := ecbDecryptNoPad(thisBlock, key)

		plaintext, err := xor(decryptedBlock, prevBlock)
		if err != nil {
			panic(err)
		}
		copy(res[s:], plaintext)

		prevBlock = thisBlock
	}

	return res, nil
}

func cbcDecrypt(src, key []byte, iv []byte) ([]byte, error) {
	res, err := cbcDecryptNoPad(src, key, iv)
	if err != nil {
		return []byte{}, err
	}
	return unpkcs7(res, byte(blockSize))
}

func cbcEncrypt(src, key []byte, iv []byte) []byte {
	blockSize := 16

	if len(iv) != blockSize {
		log.Fatal("Invalid iv")
		panic(errors.New("Invalid IV length"))
	}

	res := pkcs7(src, byte(blockSize))
	prevBlock := iv
	var s int
	for s = 0; s <= len(res)-blockSize; s += blockSize {
		thisBlock, err := xor(res[s:s+blockSize], prevBlock)
		if err != nil {
			panic(err)
		}
		encryptedBlock := ecbEncryptNoPad(thisBlock, key)
		copy(res[s:], encryptedBlock)

		prevBlock = encryptedBlock
	}

	return res
}

func ctrEncrypt(data, key []byte, nonce, initialCounter uint64) ([]byte, uint64) {
	if len(data) == 0 {
		return []byte{}, initialCounter
	}

	const blockSize = 16
	res := make([]byte, len(data))

	rnd := make([]byte, blockSize)
	binary.LittleEndian.PutUint64(rnd, nonce)

	rndCtr := rnd[8:]
	ctr := initialCounter
	blocksCount := (len(data) + blockSize - 1) / blockSize

	for i := 0; i < blocksCount; i++ {
		binary.LittleEndian.PutUint64(rndCtr, ctr)
		encryptedBlock := ecbEncryptNoPad(rnd, key)
		xorInplace(encryptedBlock, data[i*blockSize:])
		copy(res[i*blockSize:], encryptedBlock)
		ctr++
	}

	return res, ctr
}

func ctrDecrypt(data, key []byte, nonce, initialCounter uint64) ([]byte, uint64) {
	const blockSize = 16

	if len(data) == 0 {
		return []byte{}, initialCounter
	}

	res := make([]byte, len(data))

	rnd := make([]byte, blockSize)
	binary.LittleEndian.PutUint64(rnd, nonce)

	rndCtr := rnd[8:]
	ctr := initialCounter
	blocksCount := (len(data) + blockSize - 1) / blockSize

	for i := 0; i < blocksCount; i++ {
		binary.LittleEndian.PutUint64(rndCtr, ctr)
		decryptedBlock := ecbEncryptNoPad(rnd, key)
		xorInplace(decryptedBlock, data[i*blockSize:])
		copy(res[i*blockSize:], decryptedBlock)
		ctr++
	}

	return res, ctr
}
