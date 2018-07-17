package cryptopals

import (
	"crypto/rand"
	"encoding/base64"
	"log"
	"math/big"
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

// func TestS2C10(t *testing.T) {
// 	ciphertext, _ := ioutil.ReadFile("10.txt")
// 	ciphertext, _ = base64.StdEncoding.DecodeString(string(ciphertext))
// 	key := []byte("YELLOW SUBMARINE")
// 	iv := []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
// 	plaintext := decrypt(ciphertext, key, iv)
// 	newCiphertext := encrypt(plaintext, key, iv)
// 	ans := newCiphertext
// 	if bytes.Equal(ciphertext, newCiphertext) == false {
// 		t.Errorf("s2c1 failed: output is %v", len(ans))
// 	}
// }

func randomECB(plaintext []byte) []byte {
	rand2, _ := rand.Int(rand.Reader, big.NewInt(5))
	preLength := rand2.Int64() + 5
	rand3, _ := rand.Int(rand.Reader, big.NewInt(5))
	postLength := rand3.Int64() + 5
	pre := make([]byte, preLength)
	post := make([]byte, postLength)
	rand.Read(pre)
	rand.Read(post)
	key := make([]byte, 16)
	rand.Read(key)
	ciphertext := make([]byte, len(plaintext))
	ciphertext = encrypt(plaintext, key, []byte{})
	return ciphertext
}

func randomCBC(plaintext []byte) []byte {
	rand2, _ := rand.Int(rand.Reader, big.NewInt(5))
	preLength := rand2.Int64() + 5
	rand3, _ := rand.Int(rand.Reader, big.NewInt(5))
	postLength := rand3.Int64() + 5
	pre := make([]byte, preLength)
	post := make([]byte, postLength)
	rand.Read(pre)
	rand.Read(post)
	key := make([]byte, 16)
	rand.Read(key)
	ciphertext := make([]byte, len(plaintext))
	iv := make([]byte, 16)
	rand.Read(iv)
	ciphertext = encrypt(plaintext, key, iv)
	return ciphertext
}

// func TestS2C11(t *testing.T) {
// 	rand1, _ := rand.Int(rand.Reader, big.NewInt(2))
// 	encryptionMethod := rand1.Int64()
// 	ans := ""
// 	if encryptionMethod == 0 {
// 		ans = encryptionOracle(randomECB)
// 	} else {
// 		ans = encryptionOracle(randomCBC)
// 	}
// 	log.Println(string(ans))
// 	if len(ans) < 0 {
// 		t.Errorf("s2c1 failed: output is %v", ans)
// 	}
// }

var unknownKey [16]byte

func blackBox(extraText []byte) []byte {
	plaintext, _ := base64.StdEncoding.DecodeString("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK")
	return encrypt(append(extraText, plaintext...), unknownKey[:], []byte{})
}

func TestS2C12(t *testing.T) {
	rand.Read(unknownKey[:])
	ans := attackBlackBox(blackBox)
	if string(ans) != "Rollin' in my 5.0\nWith my rag-top down so my hair can blow\nThe girlies on standby waving just to say hi\nDid you stop? No, I just drove by\n" {
		t.Errorf("s2c12 failed: output is %v", ans)
	}
}
