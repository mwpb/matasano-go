package cryptopals

import (
	"bytes"
	"crypto/aes"
	"encoding/base64"
	"io/ioutil"
	"log"
	"testing"
)

func TestS2C9(t *testing.T) {
	original := []byte("YELLOW SUBMARINE")
	ans := pad(original, 20)
	expected := append([]byte("YELLOW SUBMARINE"), []byte{4, 4, 4, 4}...)
	if bytes.Equal(ans, expected) == false {
		t.Errorf("s2c1 failed: output is %v", ans)
	}
}

func TestS2C10(t *testing.T) {
	ciphertext, _ := ioutil.ReadFile("10.txt")
	ciphertext, _ = base64.StdEncoding.DecodeString(string(ciphertext))
	ciphertext = ciphertext[:16]
	log.Println(ciphertext)

	block, _ := aes.NewCipher([]byte("YELLOW SUBMARINE"))

	dstBlock := make([]byte, 16)
	block.Decrypt(dstBlock, ciphertext)

	ans := dstBlock
	log.Println(string(ans))
	if len(ans) < 0 {
		t.Errorf("s2c1 failed: output is %v", ans)
	}
}
