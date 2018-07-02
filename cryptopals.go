package cryptopals

import (
	"encoding/base64"
	"encoding/hex"
)

func q1(hexes string) string {
	bytes, _ := hex.DecodeString(hexes)
	base64s := base64.StdEncoding.EncodeToString(bytes)
	return base64s
}

func hexXOR(hexes1 string, hexes2 string) string {
	bytes1, _ := hex.DecodeString(hexes1)
	bytes2, _ := hex.DecodeString(hexes2)
	xor := make([]byte, 0)
	for i := 0; i < len(bytes1); i++ {
		xor = append(xor, bytes1[i]^bytes2[i])
	}
	hex_xor := hex.EncodeToString(xor)
	return hex_xor
}
