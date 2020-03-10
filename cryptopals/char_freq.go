package cryptopals

import (
	"strings"
)

/*
	These are not wikipedia-approved :)
	Those listed on the relevant wiki page for english letter frequences
	do not work well here - garbage gets a higher score than rap somehow,
	which is fair I guess but doesn't get the job done.
	After spending some time trying to tweak the frequences so that the actual
	text is scoreed the highest I found a different set of letters probabillities
	that work (for example, here https://pdfs.semanticscholar.org/621e/6225811691892f69e5fd30566a83fb65c528.pdf)
	There is no explanation where they come from in this publication, though.
*/
var engFreq = map[byte]float64{
	'a': 0.0651738, 'b': 0.0124248, 'c': 0.0217339, 'd': 0.0349835,
	'e': 0.1041442, 'f': 0.0197881, 'g': 0.0158610, 'h': 0.0492888,
	'i': 0.0558094, 'j': 0.0009033, 'k': 0.0050529, 'l': 0.0331490,
	'm': 0.0202124, 'n': 0.0564513, 'o': 0.0596302, 'p': 0.0137645,
	'q': 0.0008606, 'r': 0.0497563, 's': 0.0515760, 't': 0.0729357,
	'u': 0.0225134, 'v': 0.0082903, 'w': 0.0171272, 'x': 0.0013692,
	'y': 0.0145984, 'z': 0.0007836, ' ': 0.1918182,
}

var nonAlphaCharScore = 0.0

func scoreByCharFreq(chars []byte) float64 {
	var score float64
	for _, c := range chars {
		freq, ok := engFreq[strings.ToLower(string(c))[0]]
		if ok {
			score += freq
		} else {
			score += nonAlphaCharScore
		}
	}

	return score / float64(len(chars))
}
