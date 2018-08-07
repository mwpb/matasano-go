package cryptopals

import (
	"log"
	"testing"
)

func decryptBlock(currentBlock []byte, prevBlock []byte, key [16]byte, iv []byte) []byte {
	n := len(currentBlock)
	pre := make([]byte, 16)
	plaintext := make([]byte, n)
	for i := 0; i < 16; i++ {
		for j := 0; j <= i; j++ {
			pre[15-j] = plaintext[15-j] ^ byte(i+1)
		}
		possibles := make([]byte, 0)
		for j := 0; j < 256; j++ {
			pre[15-i] = byte(j)
			validPadding := c17func2(append(pre, currentBlock...), key, iv)
			if validPadding {
				possibles = append(possibles, byte(i+1)^byte(j))
			}
		}
		if len(possibles) == 1 {
			plaintext[15-i] = possibles[0]
		} else {
			plainbyteOne := possibles[0] ^ prevBlock[15]
			if plainbyteOne == byte(1) {
				plaintext[15-i] = possibles[1]
			} else {
				plaintext[15-i] = possibles[0]
			}
		}
	}
	return xor(prevBlock, plaintext)
}

//
//func TestS3C17(t *testing.T) {
//	rand.Read(unknownKey[:])
//	ciphertext, iv := c17func1(unknownKey)
//	n := len(ciphertext)
//	plaintext := make([]byte, n)
//	numberOfBlocks := n / 16
//	for i := 0; i < numberOfBlocks; i++ {
//		currentBlock := ciphertext[n-(i+1)*16 : n-i*16]
//		prevBlock := make([]byte, 16)
//		if i != numberOfBlocks-1 {
//			prevBlock = ciphertext[n-(i+2)*16 : n-(i+1)*16]
//		}
//		plainblock := decryptBlock(currentBlock, prevBlock, unknownKey, iv)
//		copy(plaintext[n-(i+1)*16:n-i*16], plainblock)
//	}
//	plaintext, _ = paddingValidation(plaintext, 16)
//	log.Println(string(plaintext))
//	if false {
//		t.Error("Failed.")
//	}
//}

//func TestS3C18(t *testing.T){
//	input, _ := base64.StdEncoding.DecodeString("L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==")
//	out := ctr(input, []byte("YELLOW SUBMARINE"), make([]byte, 8))
//	log.Println(string(out))
//	if false {
//		t.Error("failed")
//	}
//}

func TestS3C19(t *testing.T) {
	ciphertexts := c19setup(unknownKey[:])
	log.Println(len(ciphertexts))
	if false {
		t.Error("failed")
	}
}
