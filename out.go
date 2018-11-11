package main

import (
	"encoding/hex"
	"fmt"
	"io"
	"io/ioutil"
	"log"
)

func cry(r io.Reader) {
	for {
		b := make([]byte, 1)
		_, err := r.Read(b)
		if err != nil {
			break
		}
		fmt.Print(string(b[0]))
	}
	fmt.Println()
}

func readHex(r io.Reader) string {
	bytes, err := ioutil.ReadAll(r)
	if err != nil {
		log.Fatal(err)
	}
	dst := make([]byte, hex.EncodedLen(len(bytes)))
	hex.Encode(dst, bytes)
	return string(dst)
}
