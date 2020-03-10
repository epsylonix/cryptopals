package cryptopals

import "fmt"

type ctrEditor struct {
	key     []byte
	nonce   uint64
	initCtr uint64
}

func (e *ctrEditor) edit(cyphertext []byte, offset int, newtext []byte) ([]byte, error) {
	if offset+len(newtext) > len(cyphertext) {
		return []byte{}, fmt.Errorf("appends not supported")
	}

	d, _ := ctrDecrypt(cyphertext, e.key, e.nonce, e.initCtr)
	copy(d[offset:], newtext)
	encrypted, _ := ctrEncrypt(d, e.key, e.nonce, e.initCtr)
	return encrypted, nil
}
func recoverCtrEncryptedMessage(cyphertext []byte, editor *ctrEditor) ([]byte, error) {
	zeros := make([]byte, len(cyphertext))
	keystream, err := editor.edit(cyphertext, 0, zeros)
	if err != nil {
		return []byte{}, err
	}

	return xor(keystream, cyphertext)
}
