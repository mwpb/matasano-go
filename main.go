package main

import (
	// "bytes"
	"encoding/hex"
	// "fmt"
	"io"
	"os"
	// "log"
	"strings"
)

func main() {
	hexes1 := strings.NewReader("1c0111001f010100061a024b53535009181c")
	hexes2 := strings.NewReader("686974207468652062756c6c277320657965")
	plains1 := hex.NewDecoder(hexes1)
	plains2 := hex.NewDecoder(hexes2)
	xor := xorReader(plains1, plains2)
	io.Copy(os.Stdout, xor)
}
