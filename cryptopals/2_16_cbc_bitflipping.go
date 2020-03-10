package cryptopals

import (
	"errors"
	"regexp"
)

type set216EncryptorDecryptor struct {
	key              []byte
	iv               []byte
	encryptionPrefix []byte
	encryptionSuffix []byte
}

func (ed set216EncryptorDecryptor) encrypt(data []byte) []byte {
	re := regexp.MustCompile(`[\;\=]+`)
	if re.Match(data) {
		panic(errors.New("data can't contain ; or ="))
	}

	res := append(append(ed.encryptionPrefix, data...), ed.encryptionSuffix...)
	return cbcEncrypt(res, ed.key, ed.iv)
}

func (ed set216EncryptorDecryptor) decrypt(data []byte) []byte {
	decrypted, err := cbcDecrypt(data, ed.key, ed.iv)
	if err != nil {
		panic(err)
	}

	return decrypted
}

func makeAdminWithCbcBitflip(ed set216EncryptorDecryptor, blockSize int) []byte {
	// pad prefix to full block so it will be left impact after next block modifications
	prefixPadLen := (blockSize - len(ed.encryptionPrefix)%blockSize) % blockSize
	// pad + block used for attack + target block to put new text in
	plaintextData := make([]byte, prefixPadLen+2*blockSize)
	// target block to put the new text in
	modifiedBlockPlain := plaintextData[prefixPadLen+blockSize : prefixPadLen+2*blockSize]

	encData := ed.encrypt(plaintextData)
	// block used for attack
	bitflipBlockEnc := encData[len(ed.encryptionPrefix)+prefixPadLen : len(ed.encryptionPrefix)+prefixPadLen+blockSize]

	// expected len to be < blocksize - we can't modify 2 conseq blocks with this attack
	newData := []byte(";admin=true")
	// put new data to the end of the target block
	for i := blockSize - 1; i >= blockSize-len(newData); i-- {
		// after decryption data is xored with prev block
		// x - plaintext byte of target block before xoring
		x := bitflipBlockEnc[i] ^ modifiedBlockPlain[i]
		// change prev block byte so that x xored with it
		// became an appropriate char from the newData
		bitflipBlockEnc[i] = x ^ newData[len(newData)-(blockSize-i)]
	}

	return encData
}
