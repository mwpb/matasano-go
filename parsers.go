package cryptopals

import (
	"bytes"
	"fmt"
	"log"
	"strings"
	"time"
)

func parseCookie(cookie []byte) map[string]string {
	pairs := strings.Split(string(cookie), "&")
	out := make(map[string]string)
	for _, pair := range pairs {
		terms := strings.Split(pair, "=")
		if len(terms) != 2 {
			log.Println("Incorrectly formatted pair.")
		} else {
			out[terms[0]] = terms[1]
		}
	}
	return out
}

func profileFor(email string) []byte {
	email = strings.Replace(email, "&", "", -1)
	email = strings.Replace(email, "=", "", -1)
	unixTimestamp := int(time.Now().Unix())
	out := fmt.Sprintf("email=%s&id=%d&role=user", email, unixTimestamp)
	return []byte(out)
}

func getRepeatedBlock(ciphertext []byte, blocksize int) ([]byte, int) {
	n := len(ciphertext)
	numberOfBlocks := n / blocksize
	for i := 0; i < numberOfBlocks; i++ {
		ithBlock := ciphertext[i*blocksize : (i+1)*blocksize]
		for j := i + 1; j < numberOfBlocks; j++ {
			jthBlock := ciphertext[j*blocksize : (j+1)*blocksize]
			if bytes.Equal(ithBlock, jthBlock) {
				return ithBlock, i * blocksize
			}
		}
	}
	out := make([]byte, blocksize)
	return out, 0
}
