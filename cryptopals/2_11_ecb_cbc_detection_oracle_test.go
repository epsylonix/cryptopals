package cryptopals

import (
	"testing"
)

func TestAesEcbDetectionOracle(t *testing.T) {
	prefix := randomBytes(10)
	suffix := randomBytes(10)
	data := []byte("0000000000000000000000000000000000000000000000000")

	var detectedAsEcb bool

	for i := 0; i < 1000; i++ {
		toEncrypt := append(append(prefix, data...), suffix...)
		encrypted, encType := encryptWithEcbOrCbc(toEncrypt)

		detectedAsEcb = isEcbEncrypted(encrypted)

		if (detectedAsEcb && encType != "ecb") || (!detectedAsEcb && encType == "ecb") {
			t.Fatalf("%x is encrypted using %s but is not detected as such", encrypted, encType)
		}
	}
}
