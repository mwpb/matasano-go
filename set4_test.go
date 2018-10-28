package main

// import (
// 	"crypto/rand"
// 	"log"
// 	"os"
// 	"testing"
// )

// func TestS4C25(t *testing.T) {
// 	r, _ := os.Open("./25.txt")
// 	rand.Read(unknownKey[:])
// 	cReader := ctrReader{
// 		reader: r,
// 		block:  make([]byte, 16),
// 		count:  0,
// 		key:    unknownKey[:],
// 	}
// 	for {
// 		b := make([]byte, 1)
// 		_, err := cReader.Read(b)
// 		if err != nil {
// 			break
// 		}
// 		log.Println(b)
// 	}
// 	if false {
// 		t.Error("Failed")
// 	}
// }
