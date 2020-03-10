package cryptopals

import (
	"bytes"
	"fmt"
	"math/big"
)

// client =======================

type simplifiedSrpClient struct {
	password []byte
	g        *big.Int
	n        *big.Int
}

func (sc *simplifiedSrpClient) genVerifier() ([]byte, *big.Int) {
	// v = g ^ H(salt | password) % n
	salt := randomBigInt(16).Bytes()
	xB := sha1(append(salt, sc.password...))
	x := new(big.Int).SetBytes(xB[:])
	verifier := expMod(sc.g, x, sc.n)

	return salt, verifier
}

// client session =======================

type simplifiedSrpClientSession struct {
	sc         *simplifiedSrpClient
	x          *big.Int
	private    *big.Int
	public     *big.Int
	sessionKey []byte
}

func (scs *simplifiedSrpClientSession) init() *simplifiedSrpClientSession {
	scs.private = randomBigIntLessThan(scs.sc.n)         // a
	scs.public = expMod(scs.sc.g, scs.private, scs.sc.n) // A = g^a

	return scs
}

func (scs *simplifiedSrpClientSession) genSessionKey(salt []byte, b *big.Int, u *big.Int) *simplifiedSrpClientSession {
	// B = g^b, salt, u come from the server

	xB := sha1(append(salt, scs.sc.password...))
	scs.x = new(big.Int).SetBytes(xB[:])

	// S = B^(a + u * x)
	aAddUX := new(big.Int).Mul(u, scs.x)
	aAddUX = aAddUX.Add(scs.private, aAddUX)

	s := expMod(b, aAddUX, scs.sc.n)
	tmp := sha1(s.Bytes())
	scs.sessionKey = tmp[:]

	return scs
}

// server =======================

type simplifiedSrpServer struct {
	salt     []byte
	verifier *big.Int
	g        *big.Int
	n        *big.Int
}

// server session =======================

type simplifiedSrpServerSession struct {
	ss         *simplifiedSrpServer
	u          *big.Int
	private    *big.Int
	public     *big.Int
	sessionKey []byte
}

func (sss *simplifiedSrpServerSession) init() *simplifiedSrpServerSession {
	sss.u = randomBigInt(16)                             // 128 bit as per the challege description
	sss.private = randomBigIntLessThan(sss.ss.n)         // b
	sss.public = expMod(sss.ss.g, sss.private, sss.ss.n) // B

	return sss
}

func (sss *simplifiedSrpServerSession) genSessionKey(a *big.Int) *simplifiedSrpServerSession {
	// S = (A * (v ^ u)) ^ b mod n
	vExpU := expMod(sss.ss.verifier, sss.u, sss.ss.n)

	s := expMod(mulMod(vExpU, a, sss.ss.n), sss.private, sss.ss.n)
	tmp := sha1(s.Bytes())
	sss.sessionKey = tmp[:]

	return sss
}

func (sss *simplifiedSrpServerSession) login(sessionKey []byte) bool {
	return bytes.Equal(sessionKey, sss.sessionKey)
}

func recoverSimplifiedSrpPassword(client *simplifiedSrpClientSession, dict []string) (string, error) {
	/*
		  S = (A * v^u)^b mod n = (A * g^(x*u))^b mod n
		  where x = sha(salt|pass)

		  to simplify out task we'll use these params:
		  salt = "", u = 1, b = 1 (B = g)
			then S becomes: S =  A * g^x mod n

			we know S and A, so we have all we need to make offline computations
			for password recovery

			This challenge is not about MITM implementation but about the possiblility
			of offline password recovery which a real SRP is designed to prevent.
			For that reason a password recovert is implemented a not the MITM attack
	*/

	salt := []byte{}
	b := new(big.Int).Set(client.sc.g)
	u := big.NewInt(1)

	g := client.sc.g
	n := client.sc.n

	client.genSessionKey(salt, b, u)

	s := new(big.Int)
	var tmp [20]byte

	for _, pass := range dict {
		tmp = sha1([]byte(pass))
		s.SetBytes(tmp[:])      // x
		s.Exp(g, s, n)          // g ^ x
		s.Mul(s, client.public) // A * g ^ x
		s.Mod(s, n)

		tmp = sha1(s.Bytes())

		if bytes.Equal(tmp[:], client.sessionKey) {
			return pass, nil
		}
	}

	return "", fmt.Errorf("faled to recover the password with that dictionary")
}
