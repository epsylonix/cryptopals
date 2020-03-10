package cryptopals

import (
	"errors"
	"regexp"
)

type set426EncryptorDecryptor struct {
	key              []byte
	nonce            uint64
	initialCtr       uint64
	encryptionPrefix []byte
	encryptionSuffix []byte
}

func (ed *set426EncryptorDecryptor) encrypt(data []byte) []byte {
	ed.nonce++ // decryption will only work for the most recently encrypted data

	re := regexp.MustCompile(`[\;\=]+`)
	if re.Match(data) {
		panic(errors.New("data can't contain ; or ="))
	}

	plaintext := append(append(ed.encryptionPrefix, data...), ed.encryptionSuffix...)
	cyphertext, _ := ctrEncrypt(plaintext, ed.key, ed.nonce, ed.initialCtr)
	return cyphertext
}

func (ed *set426EncryptorDecryptor) decrypt(cyphertext []byte) []byte {
	plaintext, _ := ctrEncrypt(cyphertext, ed.key, ed.nonce, ed.initialCtr)
	return plaintext
}

func makeAdminWithCtrBitflip(prefix, dataToInsert []byte, ed *set426EncryptorDecryptor) []byte {
	placeholder := make([]byte, len(dataToInsert))
	cyphertext := ed.encrypt(placeholder)

	keystream := cyphertext[len(prefix) : len(prefix)+len(placeholder)]
	xorInplace(keystream, dataToInsert)

	return cyphertext
}
