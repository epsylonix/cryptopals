package cryptopals

const mtUpperMask int = 1 << 31
const myLowerMask int = 0xFFFFFFFF >> 1
const mtStateSize = 624

// degree of recurrence
const m = 397
const bMask = 0x9d2c5680
const cMask = 0xefc60000

// tempering parameters
const u byte = 11
const s byte = 7
const t byte = 15
const l byte = 18

// twisting matrix row
const a = 0x9908b0df

var aMatr = [2]int{0, a}

type mtRand struct {
	state [mtStateSize]int
	i     int
}

func newRng(seed int) *mtRand {
	mt := mtRand{[mtStateSize]int{}, mtStateSize + 1} // n + 1 will ensure twisting is done before first use
	mt.seed(seed)

	return &mt
}

func (mt *mtRand) seed(seed int) *mtRand {
	const mask = int(0xffffffff)
	mt.state[0] = seed & mask
	for i := 1; i < mtStateSize; i++ {
		mt.state[i] = (69069 * mt.state[i-1]) & mask
	}

	return mt
}

func (mt *mtRand) nextInt() int {
	if mt.i >= mtStateSize {
		//twist
		var j int
		// cycle broken in 3 parts fo performance reasons
		// otherwise 1 loop canp be used with % m applied to all index sums
		for ; j < mtStateSize-m; j++ {
			// top bit of x[i] + 31 lower bits of x[i+1]
			y := (mt.state[j] & mtUpperMask) ^ (mt.state[j+1] & myLowerMask)
			// this is the main recurrence relation of MT
			mt.state[j] = mt.state[j+m] ^ (y >> 1) ^ aMatr[y&1]
		}

		for ; j < m-1; j++ {
			y := (mt.state[j] & mtUpperMask) ^ (mt.state[j+1] & myLowerMask)
			mt.state[j] = mt.state[j-(mtStateSize-m)] ^ (y >> 1) ^ aMatr[y&1]
		}

		y := (mt.state[mtStateSize-1] & mtUpperMask) ^ (mt.state[0] & myLowerMask)
		mt.state[mtStateSize-1] = mt.state[m-1] ^ (y >> 1) ^ aMatr[y&1]

		mt.i = 0
	}

	// tempering
	y := mt.state[mt.i]
	y = y ^ (y >> u)
	y = y ^ ((y << s) & bMask)
	y = y ^ ((y << t) & cMask)
	y = y ^ (y >> l)

	mt.i++

	return y
}
