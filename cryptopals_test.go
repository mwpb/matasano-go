package cryptopals

import (
	"encoding/base64"
	"encoding/hex"
	"testing"
)

func TestS1C1(t *testing.T) {
	bytes, _ := hex.DecodeString("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d")
	ans := base64.StdEncoding.EncodeToString(bytes)
	if ans != "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t" {
		t.Errorf("s1c1 failed: output is %v", ans)
	}
}

func TestS1C2(t *testing.T) {
	bytes1, _ := hex.DecodeString("1c0111001f010100061a024b53535009181c")
	bytes2, _ := hex.DecodeString("686974207468652062756c6c277320657965")
	ans := hex.EncodeToString(xor(bytes1, bytes2))
	if ans != "746865206b696420646f6e277420706c6179" {
		t.Errorf("s1c2 failed: output is %v", ans)
	}
}

func TestS1C3(t *testing.T) {
	bytes, _ := hex.DecodeString("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
	all := make([][]byte, 256)
	for i := 0; i < 256; i++ {
		ar := [1]byte{byte(i)}
		all[i] = xor(bytes, ar[:])
	}
	ans, _ := minScore(all)
	if string(ans) != "Cooking MC's like a pound of bacon" {
		t.Errorf("s1c3 failed: output is %v", ans)
	}
}
