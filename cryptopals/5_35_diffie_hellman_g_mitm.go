package cryptopals

import (
	"fmt"
	"math/big"
)

func mitmSet535(fakeG []byte, seesionKey *big.Int, fromAlice, toAlice, fromBob, toBob, controlOut chan []byte) {
	<-fromAlice           // read g, we're replacing that
	aliceP := <-fromAlice // read p

	toBob <- fakeG
	toBob <- aliceP

	// complete the negotiation process (A and B exchange)
	<-fromAlice // Alice's A=g^a, not going to use that
	toBob <- fakeG
	toAlice <- <-fromBob // B = fakeG ^ b

	hash := sha1(seesionKey.Bytes())
	key := hash[0:16]

	decrypt := func(encryptedData []byte) {
		enc := encryptedData[0 : len(encryptedData)-16]
		iv := encryptedData[len(encryptedData)-16 : len(encryptedData)]
		dec, err := cbcDecrypt(enc, key, iv)
		if err != nil {
			fmt.Printf("Mallory failed to decrypt message: %s\n", err)
			controlOut <- []byte("decryption failed")
		}
		fmt.Printf("Mallory decrypted message: %s\n", dec)
		controlOut <- dec
	}

	for {
		select {
		case bin, ok := <-fromAlice:
			if !ok {
				fromAlice = nil
				close(toBob)
				continue
			}

			decrypt(bin)
			toBob <- bin

		case bin, ok := <-fromBob:
			if !ok {
				fromBob = nil
				close(toAlice)
				continue
			}

			decrypt(bin)
			toAlice <- bin
		}

		if fromBob == nil && fromAlice == nil {
			break
		}
	}
}
