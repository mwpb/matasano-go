package cryptopals

import (
	"bytes"
	"crypto/aes"
	"encoding/base64"
	"io/ioutil"
	"log"
	"testing"
)

// func TestS2C9(t *testing.T) {
// 	original := []byte("YELLOW SUBMARINE")
// 	ans := pad(original, 20)
// 	expected := append([]byte("YELLOW SUBMARINE"), []byte{4, 4, 4, 4}...)
// 	if bytes.Equal(ans, expected) == false {
// 		t.Errorf("s2c1 failed: output is %v", ans)
// 	}
// }

func TestS2C10(t *testing.T) {
	input, _ := ioutil.ReadFile("10.txt")
	input, _ = base64.StdEncoding.DecodeString(string(input))
	ciphertext := pad(input, 16)
	log.Println(ciphertext)

	block, _ := aes.NewCipher([]byte("YELLOW SUBMARINE"))

	dst := make([]byte, len(ciphertext))
	prevCipherBlock := []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	for i := 0; i < len(ciphertext)/16; i++ {
		dstBlock := make([]byte, 16)
		cipherblock := ciphertext[i*16 : (i+1)*16]
		block.Decrypt(dstBlock, cipherblock)
		for j := 0; j < 16; j++ {
			dst[16*i+j] = xor(prevCipherBlock, dstBlock)[j]
		}
		prevCipherBlock = cipherblock
	}
	// log.Println("dst")
	// log.Println(dst)

	prevCipherBlock = []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	original := make([]byte, len(dst))
	for i := 0; i < len(dst)/16; i++ {
		afterXOR := xor(prevCipherBlock, dst[i*16:(i+1)*16])
		newBlock := make([]byte, 16)
		block.Encrypt(newBlock, afterXOR)
		for j := 0; j < 16; j++ {
			original[16*i+j] = newBlock[j]
		}
		prevCipherBlock = newBlock
	}
	// original = original[16:]
	log.Println("orig")
	log.Println(original)
	ans := original
	if bytes.Equal(ciphertext, original) == false {
		t.Errorf("s2c1 failed: output is %v", ans)
	}
}
