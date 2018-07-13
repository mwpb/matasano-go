package cryptopals

import (
	"log"
	"math"
)

type Block []byte

func xor(block1 Block, block2 Block) Block {
	l1, l2 := float64(len(block1)), float64(len(block2))
	n := int(math.Max(l1, l2))
	xor := make([]byte, n)
	for i := 0; i < n; i++ {
		i1 := int(math.Mod(float64(i), l1))
		i2 := int(math.Mod(float64(i), l2))
		xor[i] = block1[i1] ^ block2[i2]
	}
	return xor
}

func byteHamming(byte1 byte, byte2 byte) int {
	count := 0
	for i := 0; i < 8; i++ {
		power := byte(math.Pow(2.0, float64(i)))
		if byte1&power != byte2&power {
			count += 1
		}
	}
	return count
}

func hamming(block1 Block, block2 Block) int {
	n := int(math.Max(float64(len(block1)), float64(len(block2))))
	// log.Printf("n = %d", n)
	count := 0
	for i := 0; i < n; i++ {
		bit1 := byte(0)
		bit2 := byte(0)
		if i < len(block1) {
			bit1 = block1[i]
		}
		if i < len(block2) {
			bit2 = block2[i]
		}
		count = count + byteHamming(bit1, bit2)
		// log.Println(bit1, bit2)
		// log.Println(count)
	}
	return count
}

func pad(original []byte, blockLength int) []byte {
	rem := len(original) % blockLength
	log.Println(rem)
	n := len(original)
	if rem == 0 {
		return original
	}
	numberOfBlocks := n / blockLength
	outLength := (numberOfBlocks + 1) * blockLength
	out := make([]byte, outLength)
	copy(out, original)
	// log.Println(outLength)
	for i := 0; i < rem; i++ {
		// log.Println(n + i)
		out[n+i] = byte(rem)
	}
	return out
}
