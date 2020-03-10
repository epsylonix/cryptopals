package cryptopals

import (
	"fmt"
	"math/big"
)

func targetSet534(name string, initiate bool, in, out, controlIn, controlOut chan []byte) {
	// gen session key
	dh := new(diffieHellman)
	var otherPublic *big.Int

	if initiate {
		dh.init()

		fmt.Printf("%s sending DH parameters and the public key\n", name)
		out <- dh.g.Bytes()
		out <- dh.p.Bytes()
		out <- dh.public.Bytes()
		fmt.Printf("%s waiting for the other side to send a public key\n", name)
		otherPublic = new(big.Int).SetBytes(<-in)
	} else {
		fmt.Printf("%s waiting for the other side to send DH params and a public key\n", name)
		g := new(big.Int).SetBytes(<-in)
		p := new(big.Int).SetBytes(<-in)
		otherPublic = new(big.Int).SetBytes(<-in)

		dh.initCustom(g, p)
		dh.genSessionKey(otherPublic)

		fmt.Printf("%s sending the public key\n", name)
		out <- dh.public.Bytes()
	}

	dh.genSessionKey(otherPublic)
	hash := sha1(dh.session.Bytes())
	key := hash[0:16]

	fmt.Printf("%s built the session key, starting communication\n", name)

	for {
		select {
		case m, ok := <-controlIn:
			if !ok {
				break
			}

			iv := randomBytes(16)
			enc := cbcEncrypt(m, key, iv)
			enc = append(enc, iv...)

			out <- enc
			fmt.Printf("%s sent: %x\n", name, enc)
		case bin, ok := <-in:
			if !ok {
				// waiting for controlIn to be closed
				continue
			}

			fmt.Printf("%s received: %x\n", name, bin)
			enc := bin[0 : len(bin)-16]
			iv := bin[len(bin)-16 : len(bin)]
			dec, err := cbcDecrypt(enc, key, iv)
			if err != nil {
				fmt.Printf("%s failed to decrypt message: %s\n", name, err)
				controlOut <- []byte("decryption failed")
			} else {
				fmt.Printf("%s received: %s\n", name, dec)
				controlOut <- dec
			}
		}
	}
}

func mitmSet534(fromAlice, toAlice, fromBob, toBob, controlOut chan []byte) {
	dh := new(diffieHellman)

	aliceG, aliceP := <-fromAlice, <-fromAlice
	g := new(big.Int).SetBytes(aliceG)
	p := new(big.Int).SetBytes(aliceP)
	toBob <- aliceG
	toBob <- aliceP

	dh.initCustom(g, p)

	fakePublicKey := p
	dh.genSessionKey(fakePublicKey)

	// dh.session is zero in this case
	// because (p**anything) mod p = 0
	hash := sha1(dh.session.Bytes())
	key := hash[0:16]

	decrypt := func(encryptedData []byte) {
		enc := encryptedData[0 : len(encryptedData)-16]
		iv := encryptedData[len(encryptedData)-16 : len(encryptedData)]
		dec, err := cbcDecrypt(enc, key, iv)
		if err != nil {
			panic(err)
		}
		fmt.Printf("Mallory decrypted message: %s\n", dec)
		controlOut <- dec
	}

	aliceSessionGenerated := false
	bobSessionGenerated := false

	for {
		select {
		case bin, ok := <-fromAlice:
			if !ok {
				fromAlice = nil
				close(toBob)
				continue
			}

			if aliceSessionGenerated {
				decrypt(bin)
				toBob <- bin
			} else {
				toBob <- fakePublicKey.Bytes()
				aliceSessionGenerated = true
				fmt.Println("Mallory sent fake public key to Bob")
			}

		case bin, ok := <-fromBob:
			if !ok {
				fromBob = nil
				close(toAlice)
				continue
			}

			if bobSessionGenerated {
				decrypt(bin)
				toAlice <- bin
			} else {
				toAlice <- fakePublicKey.Bytes()
				bobSessionGenerated = true
				fmt.Println("Mallory sent fake public key to Alice")
			}
		}

		if fromBob == nil && fromAlice == nil {
			break
		}
	}
}
