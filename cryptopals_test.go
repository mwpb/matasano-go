package cryptopals

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"log"
	"math"
	"os"
	"testing"
)

func dummy() {
	log.Println("dummy")
}

func TestS1C1(t *testing.T) {
	block, _ := hex.DecodeString("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d")
	ans := base64.StdEncoding.EncodeToString(block)
	if ans != "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t" {
		t.Errorf("s1c1 failed: output is %v", ans)
	}
}

func TestS1C2(t *testing.T) {
	block1, _ := hex.DecodeString("1c0111001f010100061a024b53535009181c")
	block2, _ := hex.DecodeString("686974207468652062756c6c277320657965")
	ans := hex.EncodeToString(xor(block1, block2))
	if ans != "746865206b696420646f6e277420706c6179" {
		t.Errorf("s1c2 failed: output is %v", ans)
	}
}

func TestS1C3(t *testing.T) {
	block, _ := hex.DecodeString("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
	currentScore := math.Inf(1)
	currentPlain := []byte{}
	for i := 0; i < 256; i++ {
		plain := xor(block, []byte{byte(i)})
		score := score(plain)
		if score < currentScore {
			currentScore = score
			currentPlain = plain
		}
	}
	ans := currentPlain
	if string(ans) != "Cooking MC's like a pound of bacon" {
		t.Errorf("s1c3 failed: output is %v", ans)
	}
}

func TestS1C4(t *testing.T) {
	file, _ := os.Open("4.txt")
	scanner := bufio.NewScanner(file)
	currentScore := math.Inf(1)
	currentPlain := []byte{}
	currentKey := []byte{}
	for scanner.Scan() {
		block, _ := hex.DecodeString(string(scanner.Bytes()))
		for i := 0; i < 256; i++ {
			ar := []byte{byte(i)}
			plain := xor(block, ar)
			score := score(plain)
			if score < currentScore {
				currentScore = score
				currentPlain = plain
				currentKey = ar
			}
		}
	}
	ans := currentPlain
	if string(ans) != "Now that the party is jumping\n" && bytes.Compare(currentKey, []byte{53}) != 0 {
		t.Errorf("s1c4 failed: output is %s and key is %s", ans, currentKey)
	}
}

func TestS1C5(t *testing.T) {
	block := []byte("Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal")
	xor := xor(block, []byte("ICE"))
	ans := hex.EncodeToString(xor)
	if ans != "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f" {
		t.Errorf("s1c5 failed: output is %s", ans)
	}
}
