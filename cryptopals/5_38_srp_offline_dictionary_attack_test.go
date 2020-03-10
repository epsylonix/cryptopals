package cryptopals

import (
	"math/big"
	"testing"
)

func TestSimplifiedSrp(t *testing.T) {
	g := big.NewInt(int64(2))
	n, _ := new(big.Int).SetString("ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff", 16)

	// client-side data
	srpCl := simplifiedSrpClient{[]byte("pass"), g, n}

	// server-side data
	salt, v := srpCl.genVerifier()
	srpSrv := simplifiedSrpServer{salt, v, g, n}

	// init session for client
	clSession := new(simplifiedSrpClientSession)
	clSession.sc = &srpCl
	clSession.init()

	// init session for server
	srvSession := new(simplifiedSrpServerSession)
	srvSession.ss = &srpSrv
	srvSession.init()

	// generate session keys
	srvSession.genSessionKey(clSession.public)
	clSession.genSessionKey(salt, srvSession.public, srvSession.u)

	if !srvSession.login(clSession.sessionKey) {
		t.Fatalf("different session keys!: %x != %x", srvSession.sessionKey, clSession.sessionKey)
	}

	t.Logf("client and server generated session keys successfully: %x", srvSession.sessionKey)
}

func TestSimplifiedSrpPasswordRecovery(t *testing.T) {
	g := big.NewInt(int64(2))
	n, _ := new(big.Int).SetString("ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff", 16)

	password := "honduras"

	// client-side data
	srpCl := simplifiedSrpClient{[]byte(password), g, n}

	// init session for client
	clSession := new(simplifiedSrpClientSession)
	clSession.sc = &srpCl
	clSession.init()

	dict := []string{
		"password", "test", "12345678", "skynet", password, "travolta",
	}
	recoveredPass, err := recoverSimplifiedSrpPassword(clSession, dict)

	if err != nil {
		t.Fatal(err)
	}

	if recoveredPass != password {
		t.Fatalf("recovered password is incorrect: %s (should be %s)", recoveredPass, password)
	}

	t.Logf("successfully recovered the password: %s", recoveredPass)
}
