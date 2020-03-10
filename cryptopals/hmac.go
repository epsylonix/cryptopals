package cryptopals

const (
	opad = 0x5c
	ipad = 0x36
)

func sha1Hmac(data, key []byte) [sha1Size]byte {
	// key0
	key0 := make([]byte, sha1BlockSize)
	if len(key) > sha1BlockSize {
		tmp := sha1(key)
		copy(key0, tmp[:])
	} else {
		copy(key0, key)
	}

	okeypad := make([]byte, sha1BlockSize)
	copy(okeypad, key0)
	for i := 0; i < sha1BlockSize; i++ {
		okeypad[i] ^= opad
	}

	ikeypad := make([]byte, sha1BlockSize)
	copy(ikeypad, key0)
	for i := 0; i < sha1BlockSize; i++ {
		ikeypad[i] ^= ipad
	}

	x1 := sha1(append(ikeypad, data...))
	return sha1(append(okeypad, x1[:]...))
}
