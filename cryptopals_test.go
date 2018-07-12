package cryptopals

import (
	"log"
)

func dummy() {
	log.Println("dummy")
}

// func TestS1C1(t *testing.T) {
// 	block, _ := hex.DecodeString("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d")
// 	ans := base64.StdEncoding.EncodeToString(block)
// 	if ans != "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t" {
// 		t.Errorf("s1c1 failed: output is %v", ans)
// 	}
// }

// func TestS1C2(t *testing.T) {
// 	block1, _ := hex.DecodeString("1c0111001f010100061a024b53535009181c")
// 	block2, _ := hex.DecodeString("686974207468652062756c6c277320657965")
// 	ans := hex.EncodeToString(xor(block1, block2))
// 	if ans != "746865206b696420646f6e277420706c6179" {
// 		t.Errorf("s1c2 failed: output is %v", ans)
// 	}
// }

// func TestS1C3(t *testing.T) {
// 	block, _ := hex.DecodeString("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
// 	currentScore := math.Inf(1)
// 	currentPlain := []byte{}
// 	currentKey := byte(0)
// 	currentPlain, currentScore, currentKey = moreLikely(block, currentPlain, currentScore, currentKey)
// 	ans := currentPlain
// 	if string(ans) != "Cooking MC's like a pound of bacon" {
// 		t.Errorf("s1c3 failed: output is %v", ans)
// 	}
// }

// func TestS1C4(t *testing.T) {
// 	file, _ := os.Open("4.txt")
// 	scanner := bufio.NewScanner(file)
// 	currentScore := math.Inf(1)
// 	currentPlain := []byte{}
// 	currentKey := byte(0)
// 	for scanner.Scan() {
// 		block, _ := hex.DecodeString(string(scanner.Bytes()))
// 		currentPlain, currentScore, currentKey = moreLikely(block, currentPlain, currentScore, currentKey)
// 	}
// 	ans := currentPlain
// 	if string(ans) != "Now that the party is jumping\n" && currentKey != byte(53) {
// 		t.Errorf("s1c4 failed: output is %s and key is %v", ans, currentKey)
// 	}
// }

// func TestS1C5(t *testing.T) {
// 	block := []byte("Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal")
// 	xor := xor(block, []byte("ICE"))
// 	ans := hex.EncodeToString(xor)
// 	if ans != "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f" {
// 		t.Errorf("s1c5 failed: output is %s", ans)
// 	}
// }

// func TestS1preC6(t *testing.T) {
// 	block1 := []byte("this is a test")
// 	block2 := []byte("wokka wokka!!!")
// 	ans := hamming(block1, block2)
// 	if ans != 37 {
// 		t.Errorf("s1prec6 failed: output is %v", ans)
// 	}
// }

// func TestS1C6(t *testing.T) {
// 	block, _ := ioutil.ReadFile("6.txt")
// 	block, _ = base64.StdEncoding.DecodeString(string(block))
// 	keylength := 0
// 	hdist := math.Inf(1)
// 	for i := 2; i < 41; i++ {
// 		numberOfBlocks := 50 // Assume that the analysis will work when we have over 100 bytes at our disposal.
// 		h := 0
// 		first := block[:i]
// 		for j := 1; j < numberOfBlocks; j++ {
// 			jthBlock := block[j*i : (j+1)*i]
// 			h = h + hamming(first, jthBlock)
// 		}
// 		normalisedHamming := float64(h) / float64(numberOfBlocks*i)
// 		if normalisedHamming < hdist {
// 			hdist = normalisedHamming
// 			keylength = i
// 		}
// 	}
// 	div := len(block) / keylength
// 	rem := len(block) % keylength
// 	key := make([]byte, keylength)
// 	for i := 0; i < keylength; i++ {
// 		extra := 0
// 		if i < rem {
// 			extra = 1
// 		}
// 		ithBlock := make([]byte, div+extra)
// 		for j := 0; j < len(ithBlock); j++ {
// 			ithBlock[j] = block[i+j*keylength]
// 		}
// 		_, _, key[i] = moreLikely(ithBlock, []byte{}, math.Inf(1), byte(0))
// 	}
// 	ans := xor(block, key)
// 	if string(ans)[:33] != "I'm back and I'm ringin' the bell" {
// 		t.Errorf("s1prec6 failed: output is %s", ans)
// 	}
// }

// func TestS1C7(t *testing.T) {
// 	ciphertext, _ := ioutil.ReadFile("7.txt")
// 	ciphertext, _ = base64.StdEncoding.DecodeString(string(ciphertext))

// 	block, _ := aes.NewCipher([]byte("YELLOW SUBMARINE"))

// 	dst := make([]byte, len(ciphertext))
// 	// log.Println(len(ciphertext) / 16)
// 	for i := 0; i < len(ciphertext)/16; i++ {
// 		dstBlock := make([]byte, 16)
// 		cipherblock := ciphertext[i*16 : (i+1)*16]
// 		block.Decrypt(dstBlock, cipherblock)
// 		for j := 0; j < 16; j++ {
// 			dst[16*i+j] = dstBlock[j]
// 		}
// 	}

// 	ans := dst
// 	// log.Println(string(ans))
// 	if len(ans) < 0 {
// 		t.Errorf("s1c7 failed: output is %v", ans)
// 	}
// }

// func TestS1C8(t *testing.T) {
// 	file, _ := os.Open("8.txt")
// 	scanner := bufio.NewScanner(file)
// 	currentCount := 0
// 	currentBlock := []byte{}
// 	for scanner.Scan() {
// 		block, _ := hex.DecodeString(string(scanner.Bytes()))
// 		numberofBlocks := len(block) / 16
// 		count := 0
// 		for i := 0; i < numberofBlocks; i++ {
// 			ithBlock := block[i*16 : (i+1)*16]
// 			for j := 1; j < i; j++ {
// 				jthBlock := block[j*16 : (j+1)*16]
// 				if bytes.Equal(ithBlock, jthBlock) {
// 					count += 1
// 				}
// 			}
// 		}
// 		if count > currentCount {
// 			currentCount = count
// 			currentBlock = block
// 		}
// 	}
// 	ans := hex.EncodeToString(currentBlock)
// 	if ans != "d880619740a8a19b7840a8a31c810a3d08649af70dc06f4fd5d2d69c744cd283e2dd052f6b641dbf9d11b0348542bb5708649af70dc06f4fd5d2d69c744cd2839475c9dfdbc1d46597949d9c7e82bf5a08649af70dc06f4fd5d2d69c744cd28397a93eab8d6aecd566489154789a6b0308649af70dc06f4fd5d2d69c744cd283d403180c98c8f6db1f2a3f9c4040deb0ab51b29933f2c123c58386b06fba186a" {
// 		t.Errorf("s1c8 failed: output is %v", ans)
// 	}
// }
