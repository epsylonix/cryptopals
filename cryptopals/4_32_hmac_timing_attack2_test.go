package cryptopals

import (
	"bytes"
	"fmt"
	"testing"
	"time"
)

func TestHmacSha1TimingLeak2(t *testing.T) {
	/*
		this is not going to be fast
		so you might want to use go test -timeout parameter

		With a 5ms delay it might make an error in some char
		(because of some random noise or because the thread was not scheduled to execute exactly after 5ms sleep)
		and from that point the signature recovery will go south, so you might want to increase the comparissonDelay
	*/

	key := []byte("some super secret key")
	comparissonDelay := 5 * time.Millisecond
	data := "Honduras"

	hmac := sha1Hmac([]byte(data), key)
	expectedSignature := hexEncode(hmac[:])
	fmt.Printf("the actual signature is: %s", expectedSignature)

	server(hmacTimingLeakingValidator(key, comparissonDelay))

	sig, err := recoverHmacViaTimingLeak2(data)

	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(expectedSignature, sig[:]) {
		t.Fatalf("failed to recover the signature: expected: %s, got: %s", expectedSignature, sig)
	}

	t.Logf("recovered a valid signature: %s\n", sig)
}
