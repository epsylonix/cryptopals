package cryptopals

import (
	"errors"
	"fmt"
)

type notPrintableTextError struct {
	data []byte
}

func (e *notPrintableTextError) Error() string {
	return fmt.Sprintf("string contains invalid chars: %v", e.data)
}

type set427EncryptorDecryptor struct {
	key []byte
}

func (ed *set427EncryptorDecryptor) encrypt(data []byte) []byte {
	return cbcEncrypt(data, ed.key, ed.key)
}

func (ed *set427EncryptorDecryptor) decrypt(data []byte) ([]byte, error) {
	// with padding errors we'll need to deal with manufacturing valid padding too
	// skip it for simplicity
	plaintext, err := cbcDecryptNoPad(data, ed.key, ed.key)
	if err != nil {
		return []byte{}, err
	}

	if !allCharsAreASCIIPrintable(plaintext) {
		return []byte{}, &notPrintableTextError{plaintext}
	}

	return plaintext, nil
}

func allCharsAreASCIIPrintable(data []byte) bool {
	const maxASCIICharCode = 127

	for i := 0; i < len(data); i++ {
		if data[i] > maxASCIICharCode {
			return false
		}
	}

	return true
}

func recoverKeyForCbcWithKeyEqIV(cyphertext []byte, ed *set427EncryptorDecryptor) ([]byte, error) {
	const blockSize = 16
	if len(cyphertext)/blockSize < 2 {
		// we ignore unpadding in this exercize
		return []byte{}, errors.New("at least 2 blocks of cyphertext required")
	}

	newCyphertext := make([]byte, len(cyphertext))
	copy(newCyphertext[0:blockSize], cyphertext[0:blockSize])   // C_1, 0, 0, ...
	copy(newCyphertext[blockSize:], cyphertext[0:blockSize])    // C1, C_1, 0, 0, ...
	copy(newCyphertext[2*blockSize:], cyphertext[2*blockSize:]) // C1, C_1, C_2, C_3, ...

	_, err := ed.decrypt(newCyphertext)
	if err == nil {
		return []byte{}, errors.New("decryptor didn't detect cyphertext corruption")
	}

	if _, ok := err.(*notPrintableTextError); !ok {
		// some other err received, don't know what to do with it
		return []byte{}, err
	}

	decrypted := err.(*notPrintableTextError).data
	// newCyphertext == C_1, C_1, ...
	// decrypted == P_1, decrypted(P_1) ^ C_1, ...
	// so key = decrypted(P_1) ^ P1
	decryptedP1, _ := xor(decrypted[blockSize:2*blockSize], cyphertext[0:blockSize])
	key, err := xor(decryptedP1, decrypted[0:blockSize])
	if err != nil {
		return []byte{}, err
	}

	return key, nil
}
