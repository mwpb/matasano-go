package cryptopals

import (
	"bytes"
	"encoding/base64"
	"io/ioutil"
	"log"
	"testing"
)

func dummy2() {
	log.Println("HI")
}

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
	key := []byte("YELLOW SUBMARINE")
	iv := []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	plaintext := decrypt(ciphertext, key, iv)
	newCiphertext := encrypt(plaintext, key, iv)
	ans := newCiphertext
	if bytes.Equal(ciphertext, newCiphertext) == false {
		t.Errorf("s2c1 failed: output is %v", ans)
	}
}

func TestS2C11(t *testing.T) {
	ans := ""
	if ans != "" {
		t.Errorf("s2c1 failed: output is %v", ans)
	}
}
