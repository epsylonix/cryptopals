package cryptopals

import (
	"bytes"
	"fmt"
	"testing"
	"time"
)

func TestHmacSha1TimingLeak(t *testing.T) {
	/*
		This is not going to be fast
		so you might want to use go test -timeout parameter.

		Truth be told, didn't have the patience to test it beyound 30th char,
		but I'm sure it works :)
	*/
	key := []byte("some super secret key")
	comparissonDelay := 50 * time.Millisecond
	data := "Honduras"

	hmac := sha1Hmac([]byte(data), key)
	expectedSignature := hexEncode(hmac[:])
	fmt.Printf("the actual signature is: %s\n", expectedSignature)

	server(hmacTimingLeakingValidator(key, comparissonDelay))

	sig, err := recoverHmacViaTimingLeak(data, 30*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(expectedSignature, sig[:]) {
		t.Fatalf("failed to recover the signature: expected: %s, got: %s", expectedSignature, sig)
	}

	t.Logf("recovered a valid signature: %s\n", sig)
}
