package cryptopals

import (
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
	ciphertext, _ := ioutil.ReadFile("10.txt")
	ciphertext, _ = base64.StdEncoding.DecodeString(string(ciphertext))
	ciphertext = pad(ciphertext, 16)

	block, _ := aes.NewCipher([]byte("YELLOW SUBMARINE"))

	dst := make([]byte, len(ciphertext))
	prevCipherBlock := []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	log.Println(len(prevCipherBlock))
	for i := 0; i < len(ciphertext)/16; i++ {
		dstBlock := make([]byte, 16)
		cipherblock := ciphertext[i*16 : (i+1)*16]
		block.Decrypt(dstBlock, cipherblock)
		for j := 0; j < 16; j++ {
			dst[16*i+j] = xor(prevCipherBlock, dstBlock)[j]
		}
		prevCipherBlock = cipherblock
	}

	ans := dst
	log.Println(string(ans))
	if len(ans) < 0 {
		t.Errorf("s2c1 failed: output is %v", ans)
	}
}
