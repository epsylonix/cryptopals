package cryptopals

const (
	md4Size      = 16
	md4BlockSize = 64
	_md4Chunk    = 64
)

var (
	shift1 = []uint{3, 7, 11, 19}
	shift2 = []uint{3, 5, 9, 13}
	shift3 = []uint{3, 9, 11, 15}

	xIndex2 = []uint{0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15}
	xIndex3 = []uint{0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15}
)

type md4Digest struct {
	s   [4]uint32
	x   [_md4Chunk]byte
	nx  int
	len uint64
}

func md4(data []byte) [md4Size]byte {
	var d md4Digest
	d.Reset()
	d.Write(data)
	return d.checkSum()
}

func (d *md4Digest) Reset() {
	d.s[0] = 0x67452301
	d.s[1] = 0xEFCDAB89
	d.s[2] = 0x98BADCFE
	d.s[3] = 0x10325476
	d.nx = 0
	d.len = 0
}

func (d *md4Digest) Write(p []byte) (nn int, err error) {
	nn = len(p)
	d.len += uint64(nn)
	if d.nx > 0 {
		n := len(p)
		if n > _md4Chunk-d.nx {
			n = _md4Chunk - d.nx
		}
		for i := 0; i < n; i++ {
			d.x[d.nx+i] = p[i]
		}
		d.nx += n
		if d.nx == _md4Chunk {
			_md4Block(d, d.x[0:])
			d.nx = 0
		}
		p = p[n:]
	}
	n := _md4Block(d, p)
	p = p[n:]
	if len(p) > 0 {
		d.nx = copy(d.x[:], p)
	}
	return
}

func (d *md4Digest) checkSum() [md4Size]byte {
	len := d.len
	var tmp [64]byte
	tmp[0] = 0x80
	if len%64 < 56 {
		d.Write(tmp[0 : 56-len%64])
	} else {
		d.Write(tmp[0 : 64+56-len%64])
	}

	// Length in bits.
	len <<= 3
	for i := uint(0); i < 8; i++ {
		tmp[i] = byte(len >> (8 * i))
	}
	d.Write(tmp[0:8])

	if d.nx != 0 {
		panic("d.nx != 0")
	}

	var hash [md4Size]byte
	h := hash[:]

	// little-endian vs big-endian in sha1
	for _, s := range d.s {
		h[0] = byte(s >> 0)
		h[1] = byte(s >> 8)
		h[2] = byte(s >> 16)
		h[3] = byte(s >> 24)
		h = h[4:]
	}
	return hash
}

func _md4Block(dig *md4Digest, p []byte) int {
	a := dig.s[0]
	b := dig.s[1]
	c := dig.s[2]
	d := dig.s[3]
	n := 0
	var X [16]uint32
	for len(p) >= _md4Chunk {
		aa, bb, cc, dd := a, b, c, d

		j := 0
		for i := 0; i < 16; i++ {
			X[i] = uint32(p[j]) | uint32(p[j+1])<<8 | uint32(p[j+2])<<16 | uint32(p[j+3])<<24
			j += 4
		}

		// Round 1.
		for i := uint(0); i < 16; i++ {
			x := i
			s := shift1[i%4]
			f := ((c ^ d) & b) ^ d
			a += f + X[x]
			a = a<<s | a>>(32-s)
			a, b, c, d = d, a, b, c
		}

		// Round 2.
		for i := uint(0); i < 16; i++ {
			x := xIndex2[i]
			s := shift2[i%4]
			g := (b & c) | (b & d) | (c & d)
			a += g + X[x] + 0x5a827999
			a = a<<s | a>>(32-s)
			a, b, c, d = d, a, b, c
		}

		// Round 3.
		for i := uint(0); i < 16; i++ {
			x := xIndex3[i]
			s := shift3[i%4]
			h := b ^ c ^ d
			a += h + X[x] + 0x6ed9eba1
			a = a<<s | a>>(32-s)
			a, b, c, d = d, a, b, c
		}

		a += aa
		b += bb
		c += cc
		d += dd

		p = p[_md4Chunk:]
		n += _md4Chunk
	}

	dig.s[0] = a
	dig.s[1] = b
	dig.s[2] = c
	dig.s[3] = d
	return n
}
