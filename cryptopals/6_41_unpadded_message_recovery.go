package cryptopals

import (
	"errors"
	"math/big"
)

type rsaDecryptor541 struct {
	// lookup would obviously be more efficient with map
	// but *big.Int won't work as keys, using []byte will allow padding with zeros, etc
	seenEncryptedMessages []*big.Int
	privateKey            *privateKey
}

type rsaEncryptor541 struct {
	publicKey *publicKey
}

func (d *rsaDecryptor541) decrypt(encrypted *big.Int) (*big.Int, error) {
	for _, prev := range d.seenEncryptedMessages {
		if eq(prev, encrypted) {
			return nil, errors.New("seen that already")
		}
	}

	decrypted := decryptRsa(encrypted.Bytes(), d.privateKey)
	d.seenEncryptedMessages = append(d.seenEncryptedMessages, encrypted)
	return new(big.Int).SetBytes(decrypted), nil
}

func (e rsaEncryptor541) encrypt(message []byte) *big.Int {
	b := encryptRsa(message, e.publicKey)
	return new(big.Int).SetBytes(b)
}

// expect that encrypted message has already been decrypted
// and decryptor won'y allow to decrypt it again as is
func unpaddedMessageAttack(d rsaDecryptor541, public *publicKey, encrypted *big.Int) []byte {
	s := new(big.Int)
	sE := new(big.Int)

	for i := int64(3); ; i += 2 {
		s.SetInt64(i)
		sInv, err := mulInv(s, public.N)
		if err != nil {
			// will fail if GCD(s, N) != 1 but that won't happen unless the key is yiny
			continue
		}

		sE.Exp(s, public.E, public.N)
		decrypted, err := d.decrypt(mulMod(sE, encrypted, public.N))
		if err != nil {
			// maybe this 's' has already been used
			continue
		}

		return mulMod(decrypted, sInv, public.N).Bytes()
	}
}
