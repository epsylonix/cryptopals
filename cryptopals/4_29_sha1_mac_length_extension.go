package cryptopals

import (
	"bytes"
)

func verifySha1Mac(data, key, sha1sum []byte) bool {
	hash := sha1mac(data, key)
	return bytes.Equal(hash, sha1sum)
}

func extendSha1Mac(signedData, dataSha1Mac, dataToAppend []byte, keyLen int) ([]byte, []byte) {
	// recreate padding used inside during signedData sha1 generation
	padding := makeSha1Pading(len(signedData)+keyLen, sha1BlockSize)
	// extend the message with new data inserting original padding inbetween
	extended := make([]byte, len(signedData)+len(padding)+len(dataToAppend))
	copy(extended, signedData)
	copy(extended[len(signedData):], padding)
	copy(extended[len(signedData)+len(padding):], dataToAppend)

	// init sha1 state
	var d digest
	d.h[0] = readUint32(dataSha1Mac, 0)
	d.h[1] = readUint32(dataSha1Mac, 4)
	d.h[2] = readUint32(dataSha1Mac, 8)
	d.h[3] = readUint32(dataSha1Mac, 12)
	d.h[4] = readUint32(dataSha1Mac, 16)
	d.len = uint64(keyLen + len(signedData) + len(padding)) // len now is the same as it was during original data hashing

	// continue hashing using recreated state of digest
	d.Write(dataToAppend)
	cs := d.checkSum()

	return extended, cs[:]
}

func readUint32(b []byte, i int) uint32 {
	return uint32(b[i])<<24 | uint32(b[i+1])<<16 | uint32(b[i+2])<<8 | uint32(b[i+3])
}

// makeSha1Pading makes padding needed to pad data of len=dataLen
// to fill a full block of size=blockSize
func makeSha1Pading(dataLen int, blockSize int) []byte {
	// padding is 0b1 + 0 0 0 0 0 .... + 8 bytes of (length in bits of non-padded data)
	// if there is no space for padding, a new block is added
	// so padding length is in range [1 byte=0x80 + 8 bytes for data len]..[blockSize bytes of 1,0,0,... + 8 bytes for data len]

	paddingLen := blockSize - dataLen%blockSize
	if paddingLen < 9 {
		paddingLen += blockSize
	}

	padding := make([]byte, paddingLen)
	padding[0] = 0x80

	dataLen <<= 3 // length should be in bits
	padding[paddingLen-8] = byte(dataLen >> 56)
	padding[paddingLen-7] = byte(dataLen >> 48)
	padding[paddingLen-6] = byte(dataLen >> 40)
	padding[paddingLen-5] = byte(dataLen >> 32)
	padding[paddingLen-4] = byte(dataLen >> 24)
	padding[paddingLen-3] = byte(dataLen >> 16)
	padding[paddingLen-2] = byte(dataLen >> 8)
	padding[paddingLen-1] = byte(dataLen)

	return padding
}
