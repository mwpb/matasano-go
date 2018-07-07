package cryptopals

import (
	"math"
)

func xor(bytes1 []byte, bytes2 []byte) []byte {
	l1, l2 := float64(len(bytes1)), float64(len(bytes2))
	n := int(math.Max(l1, l2))
	xor := make([]byte, n)
	for i := 0; i < n; i++ {
		i1 := int(math.Mod(float64(i), l1))
		i2 := int(math.Mod(float64(i), l2))
		xor[i] = bytes1[i1] ^ bytes2[i2]
	}
	return xor
}
