package cryptopals

import (
	"math/big"
	"testing"
)

func TestSrpValidPassLogin(t *testing.T) {
	g := big.NewInt(int64(2))
	n, _ := new(big.Int).SetString("ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff", 16)

	// client-side data
	clientData := srpClient{[]byte("user"), []byte("password"), g, n}

	// server-side data
	salt, v := clientData.genVerifier()
	serverData := srpServer{clientData.username, salt, v, g, n}

	// init session for client
	clSession := new(srpClientSession)
	clSession.sc = &clientData
	clSession.init(serverData.salt)

	// init session for server
	serSession := new(srpServerSession)
	serSession.ss = &serverData
	serSession.init()

	serSession.genSessionKey(clSession.public)
	clSession.genSessionKey(serSession.public, serSession.u)

	if !serSession.login(clSession.loginKey) {
		t.Fatal("failed to login with a valid password")
	}
	t.Log("logged in with a valid password")

	if serSession.login([]byte("invalid password")) {
		t.Fatal("logged in with an invalid password")
	}
	t.Log("failed to log in with an invalid password")
}

func TestSrpZeroKeyLogin(t *testing.T) {
	g := big.NewInt(int64(2))
	n, _ := new(big.Int).SetString("ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff", 16)

	// client-side data
	clientData := srpClient{[]byte("user"), []byte("password"), g, n}

	// server-side data
	salt, v := clientData.genVerifier()
	serverData := srpServer{clientData.username, salt, v, g, n}

	// init session for server
	serSession := new(srpServerSession)
	serSession.ss = &serverData
	serSession.init()

	for _, a := range []*big.Int{big.NewInt(0), n} {
		serSession.genSessionKey(big.NewInt(0))

		// S = (A * v^u) ^ b mod N = 0 when A = 0 or A = x * n
		sessionKey := sha1([]byte{})
		loginKey := sha1Hmac(sessionKey[:], serSession.ss.salt)

		if !serSession.login(loginKey[:]) {
			t.Fatalf("failed to login with a zero session key and a client's A=%x", a)
		}
		t.Logf("logged in with a zero session key and a client's A=%x", a)
	}
}
