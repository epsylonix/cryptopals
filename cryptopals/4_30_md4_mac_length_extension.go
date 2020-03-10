package cryptopals

import (
	"bytes"
)

func verifyMd4Mac(data, key, sha1sum []byte) bool {
	hash := md4mac(data, key)
	return bytes.Equal(hash, sha1sum)
}

func md4mac(data, key []byte) []byte {
	src := append(key, data...)
	tmp := md4(src)
	return tmp[:]
}

func extendMd4Mac(signedData, dataSha1Mac, dataToAppend []byte, keyLen int) ([]byte, []byte) {
	// recreate padding used during md4 generation for signedData
	padding := makeMd4Pading(len(signedData)+keyLen, md4BlockSize)
	// extend the message with new data inserting original padding inbetween
	extended := make([]byte, len(signedData)+len(padding)+len(dataToAppend))
	copy(extended, signedData)
	copy(extended[len(signedData):], padding)
	copy(extended[len(signedData)+len(padding):], dataToAppend)

	// init md4 state
	var d md4Digest
	d.s[0] = readUint32le(dataSha1Mac, 0)
	d.s[1] = readUint32le(dataSha1Mac, 4)
	d.s[2] = readUint32le(dataSha1Mac, 8)
	d.s[3] = readUint32le(dataSha1Mac, 12)
	d.len = uint64(keyLen + len(signedData) + len(padding)) // len now is the same as it was during original data hashing

	// continue hashing using recreated state of digest
	d.Write(dataToAppend)
	cs := d.checkSum()

	return extended, cs[:]
}

func readUint32le(b []byte, i int) uint32 {
	return uint32(b[i]) | uint32(b[i+1])<<8 | uint32(b[i+2])<<16 | uint32(b[i+3])<<24
}

func makeMd4Pading(dataLen int, blockSize int) []byte {
	paddingLen := blockSize - dataLen%blockSize
	if paddingLen < 9 {
		paddingLen += blockSize
	}

	padding := make([]byte, paddingLen)
	padding[0] = 0x80

	dataLen <<= 3 // length should be in bits, little-endian
	for i := uint(0); i < 8; i++ {
		padding[uint(paddingLen-8)+i] = byte(dataLen >> (i * 8))
	}

	return padding
}
