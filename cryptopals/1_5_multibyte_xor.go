package cryptopals

func repeatingKeyXorEncrypt(data []byte, key []byte) []byte {
	res := make([]byte, len(data))
	keyLen := len(key)

	for i, c := range data {
		res[i] = c ^ key[i%keyLen]
	}

	return res
}
