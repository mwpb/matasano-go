package main

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
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

func readersEqual(r io.Reader, s io.Reader) bool {
	for {
		b1 := make([]byte, 1)
		b2 := make([]byte, 1)
		_, err1 := r.Read(b1)
		_, err2 := s.Read(b2)
		// fmt.Println(string(b1[0]), string(b2[0]))
		if err1 != nil {
			if err2 != nil {
				return true
			} else {
				return false
			}
		} else {
			if err2 != nil {
				return false
			} else {
				if b1[0] != b2[0] {
					return false
				}
			}
		}
	}
}

func b64Encoder(r io.Reader) io.Reader {
	pr, pw := io.Pipe()
	encoder := base64.NewEncoder(base64.StdEncoding, pw)
	go func() {
		_, err := io.Copy(encoder, r)
		encoder.Close()

		if err != nil {
			pw.CloseWithError(err)
		} else {
			pw.Close()
		}
	}()
	return pr
}

func hexEncoder(r io.Reader) io.Reader {
	pr, pw := io.Pipe()
	encoder := hex.NewEncoder(pw)
	go func() {
		_, err := io.Copy(encoder, r)

		if err != nil {
			pw.CloseWithError(err)
		} else {
			pw.Close()
		}
	}()
	return pr
}
