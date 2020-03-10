package cryptopals

func bruteforceSingleByteXor(ciphertext []byte) *scoredValue {
	keyGenerator := func() chan interface{} {
		c := make(chan interface{})

		go func() {
			for k := 0; k <= 255; k++ {
				c <- byte(k)
			}
			close(c)
		}()

		return c
	}

	decryptor := func(k interface{}) []byte {
		plaintext := make([]byte, len(ciphertext))

		for i := range ciphertext {
			plaintext[i] = ciphertext[i] ^ k.(byte)
		}

		return plaintext
	}

	decrypted := decryptWithKeygen(keyGenerator, decryptor, scoreByCharFreq)
	return decrypted[0]
}
