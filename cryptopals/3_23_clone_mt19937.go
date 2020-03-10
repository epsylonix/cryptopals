package cryptopals

func cloneMt199377(mt *mtRand) *mtRand {
	clonedMt := newRng(0)

	for i := 0; i < mtStateSize; i++ {
		x := mt.nextInt()
		clonedMt.state[i] = untemperMtState(x)
	}

	return clonedMt
}

func untemperMtState(x int) int {
	const u uint = 11
	const s uint = 7
	const t uint = 15
	const l uint = 18

	const bMask = 0x9d2c5680
	const cMask = 0xefc60000

	// tempering looks like this:
	// y = y ^ (y >> u)
	// y = y ^ ((y << s) & bMask)
	// y = y ^ ((y << t) & cMask)
	// y = y ^ (y >> l)

	x = unshiftRightXor(x, l)             // undo  y ^ (y >> l)
	x = unshiftMaskedLeftXor(x, t, cMask) // undo  y ^ ((y << t) & cMask)
	x = unshiftMaskedLeftXor(x, s, bMask) // undo  y = y ^ ((y << s) & bMask)
	return unshiftRightXor(x, u)          // undo  y ^ (y >> u)
}

func unshiftMaskedLeftXor(x int, shift uint, mask int) int {
	res := x & (0xffffffff >> (32 - shift))

	for b := shift; b < 32; b++ {
		m := 1 << b
		res = res | ((x ^ ((res << shift) & mask)) & m)
	}

	return res
}

func unshiftRightXor(x int, shift uint) int {
	res := x & (0xffffffff << (32 - shift))

	for b := 31 - shift; ; b-- {
		m := 1 << b
		res = res | ((x ^ res>>shift) & m)

		if b == 0 {
			break
		}
	}

	return res
}
