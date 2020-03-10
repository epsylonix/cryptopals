package cryptopals

import (
	"testing"
)

func testIsPkcs7padded(t *testing.T) {
	assert(t, false, isPkcs7padded([]byte{1, 2, 3}, 3))
	assert(t, false, isPkcs7padded([]byte{1, 2, 3, 3, 3, 2}, 3))
	assert(t, false, isPkcs7padded([]byte{1, 2, 3, 3, 3, 4}, 3))
	assert(t, false, isPkcs7padded([]byte{1, 2, 3, 5, 5, 5}, 3))
	assert(t, false, isPkcs7padded([]byte{1, 2, 3, 1, 2, 0}, 3))

	assert(t, true, isPkcs7padded([]byte{1, 2, 3, 3, 3, 3}, 3))
	assert(t, true, isPkcs7padded([]byte{1, 2, 3, 3, 3, 1}, 3))
	assert(t, true, isPkcs7padded([]byte{1, 2, 3, 3, 2, 2}, 3))
}

func assert(t *testing.T, expected, actual bool) {
	if actual != expected {
		t.Errorf("expected %v, got %v", expected, actual)
		t.FailNow()
	}
}

func TestEcbDecrypt(t *testing.T) {
	src := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6}
	key := []byte("YELLOW SUBMARINE")

	enc := ecbEncrypt(src, key)
	dec, _ := ecbDecrypt(enc, key)

	assertEqualArrays(t, dec, src)
}

func TestCbcEncryptDecryptSinglePartialBlock(t *testing.T) {
	src := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 1, 2, 3, 4, 5}

	key := []byte("0123456789asdfgh")
	iv := []byte("kfjfewfwefwefefc")
	encrypted := cbcEncrypt(src, key, iv)
	decrypted, _ := cbcDecrypt(encrypted, key, iv)

	assertEqualArrays(t, decrypted, src)
}

func TestCbcEncryptDecryptSingleFullBlock(t *testing.T) {
	src := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 1, 2, 3, 4, 5, 6}

	key := []byte("0123456789asdfgh")
	iv := []byte("kfjfewfwefwefefc")
	encrypted := cbcEncrypt(src, key, iv)
	decrypted, _ := cbcDecrypt(encrypted, key, iv)

	assertEqualArrays(t, decrypted, src)
}

func TestCbcEncryptDecryptMultiBlock(t *testing.T) {
	src := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 1, 2, 3, 4, 5, 6, 7}

	key := []byte("0123456789asdfgh")
	iv := []byte("kfjfewfwefwefefc")
	encrypted := cbcEncrypt(src, key, iv)
	decrypted, _ := cbcDecrypt(encrypted, key, iv)

	assertEqualArrays(t, decrypted, src)
}

func TestPkcs7(t *testing.T) {
	src := []byte{50, 50, 50, 50}
	expected := []byte{50, 50, 50, 50, 4, 4, 4, 4}

	assertEqualArrays(t, pkcs7(src, 8), expected)

	src = []byte{50, 50, 50}
	expected = []byte{50, 50, 50, 1}

	assertEqualArrays(t, pkcs7(src, 4), expected)
}

func TestPkcs7FullBlock(t *testing.T) {
	src := []byte{50, 50, 50, 50}
	expected := []byte{50, 50, 50, 50, 4, 4, 4, 4}

	assertEqualArrays(t, pkcs7(src, 4), expected)
}

func TestUnpkcs7(t *testing.T) {
	src := []byte{50, 50, 50, 50, 4, 4, 4, 4}
	expected := []byte{50, 50, 50, 50}

	unpadded, _ := unpkcs7(src, 8)
	assertEqualArrays(t, unpadded, expected)
}

func TestCtrEncrypt(t *testing.T) {
	src := []byte("test this test this")

	key := []byte("YELLOW SUBMARINE")
	var nonce, ctr = uint64(0), uint64(0)
	encrypted, _ := ctrEncrypt(src, key, nonce, ctr)

	decrypted, _ := ctrDecrypt(encrypted, key, nonce, ctr)
	assertEqualArrays(t, src, decrypted)
}
