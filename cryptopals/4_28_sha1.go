package cryptopals

func sha1mac(data, key []byte) []byte {
	src := append(key, data...)
	tmp := sha1(src) // sha1(src)[:] won't work - array must be addressable. go is great!
	return tmp[:]
}
