package cryptopals

import (
	"encoding/hex"
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

func hexXORSingle(hexes string, r byte) string {
	bytes, _ := hex.DecodeString(hexes)
	xor := make([]byte, 0)
	for i := 0; i < len(bytes); i++ {
		// log.Println(string(hexes[2*i]), string(hexes[2*i+1]), bytes[i], r, bytes[i]^r)
		xor = append(xor, bytes[i]^r)
	}
	// log.Println(xor)
	return string(xor[:])
}

func hexXORAlpha(hexes string) map[byte]string {
	plaintexts := make(map[byte]string, 0)
	for i := 0; i < 255; i++ {
		xor := hexXORSingle(hexes, byte(i))
		plaintexts[byte(i)] = xor
	}
	// log.Println(plaintexts)
	return plaintexts
}
