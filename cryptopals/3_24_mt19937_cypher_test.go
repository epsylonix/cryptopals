package cryptopals

import (
	"math/rand"
	"testing"
	"time"
)

func TestMt19937KeyRecovery(t *testing.T) {
	rand.Seed(time.Now().UTC().UnixNano())
	key := uint16(rand.Intn(2<<16 - 1))
	ed := newSet324ED(key)

	knownPlaintextTail := []byte("here goes some secret")
	plaintext := append(randomBytes(20), knownPlaintextTail...)
	encrypted := ed.encrypt(plaintext)

	startedAt := time.Now()
	foundKey, err := recoverMt19937Seed(encrypted, knownPlaintextTail, 2<<16-1, 0)
	tookTimeSec := time.Now().Unix() - startedAt.Unix()
	if err != nil {
		t.Fatal(err)
	}

	if uint16(foundKey) != key {
		t.Fatalf("the recovered key is invalid: %v (valid key=%v)\n", foundKey, key)
	}

	t.Logf("recovered the correct key: %v in %v sec\n", foundKey, tookTimeSec)
}

func TestMt19937PasswordRestTokenCracking(t *testing.T) {
	// imitate password reset token encrypted with a timestamp
	knownPlaintextTail := []byte("some_login")
	plaintext := append([]byte("timestamp;"), knownPlaintextTail...)
	ed := newSet324CurTimestampED()
	encrypted := ed.encrypt(plaintext)

	now := int(time.Now().UnixNano())
	foundKey, err := recoverMt19937Seed(encrypted, knownPlaintextTail, now, now-10000)
	if err != nil {
		t.Fatal(err)
	}

	if foundKey != ed.seed {
		t.Fatalf("the recovered key is invalid: %v (valid key=%v)\n", foundKey, ed.seed)
	}

	t.Logf("found the correct timestamp seed: %v\n", foundKey)
}
