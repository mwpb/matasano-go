package cryptopals

import (
	"encoding/base64"
	"encoding/hex"
	"log"
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

func hexXORSingle(hexes string, r byte) string {
	bytes, _ := hex.DecodeString(hexes)
	xor := make([]byte, 0)
	for i := 0; i < len(bytes); i++ {
		log.Println(string(hexes[2*i]), string(hexes[2*i+1]), bytes[i], r, bytes[i]^r)
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
	log.Println(plaintexts)
	return plaintexts
}
