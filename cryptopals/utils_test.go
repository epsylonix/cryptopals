package cryptopals

import "testing"

func TestBase64Enc(t *testing.T) {
	assertMatch(t, base64encode, "abcdefghi", "YWJjZGVmZ2hp")
	assertMatch(t, base64encode, "abcdefghi1", "YWJjZGVmZ2hpMQ")
}

func TestBase64Dec(t *testing.T) {
	f := func(x []byte) []byte {
		r, err := base64decode(x)
		if err != nil {
			t.Error(err)
			return []byte{}
		}
		return r
	}
	assertMatch(t, f, "YWJjZGVmZ2hp", "abcdefghi")
	assertMatch(t, f, "YWJjZGVmZ2hpMQ", "abcdefghi1")
	assertMatch(t, f, "YWJjZGVmZ2hpMTI", "abcdefghi12")
}

func TestHexDecode(t *testing.T) {
	var (
		a   []byte
		err error
	)

	a, err = hexDecode([]byte("ff"))
	if err != nil {
		t.Error(err)
	}
	assertEqualArrays(t, a, []byte{255})

	a, err = hexDecode([]byte("1ff"))
	if err != nil {
		t.Error(err)
	}
	assertEqualArrays(t, a, []byte{1, 255})
}

func TestHexEncode(t *testing.T) {
	var a []byte

	a = hexEncode([]byte{255})
	assertEqualArrays(t, a, []byte{'f', 'f'})

	a = hexEncode([]byte([]byte{1, 255}))
	assertEqualArrays(t, a, []byte{'0', '1', 'f', 'f'})
}

func TestHammingDistance(t *testing.T) {
	a := []byte("this is a test")
	b := []byte("wokka wokka!!!")

	if d, _ := HammingDistance(a, b); d != 37 {
		t.Errorf("expected distance to be 37, actual: %v", d)
	}
}

func TestTakeNth(t *testing.T) {
	x := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 0}
	y := takeNth(x, 3, 0)

	assertEqualArrays(t, y, []byte{1, 4, 7, 0})

	y = takeNth(x, 3, 1)
	assertEqualArrays(t, y, []byte{2, 5, 8})
}

func assertMatch(t *testing.T, fn func([]byte) []byte, source, expected string) {
	if actual := string(fn([]byte(source))); actual != expected {
		t.Errorf("Base64enc(%s) = %s, expected: %s", source, actual, expected)
	} else {
		t.Logf("Base64enc(%s) == %s", source, expected)
	}
}

func assertEqualArrays(t *testing.T, a1, a2 []byte) {
	if len(a1) != len(a2) {
		t.Errorf("invalid length: %v != %v", a1, a2)
		t.FailNow()
	}

	for i := 0; i < len(a1); i++ {
		if a1[i] != a2[i] {
			t.Errorf("byte %v doesn't match: %v != %v", i, a1, a2)
		}
	}
}
