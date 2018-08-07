package cryptopals

import (
	"bytes"
	"crypto/aes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"log"
	"math"
	"math/big"
	"strings"
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
	n := len(original)
	if rem == 0 {
		post := make([]byte, blockLength)
		for i := range post {
			post[i] = byte(blockLength)
		}
		return append(original, post...)
	}
	numberOfBlocks := n / blockLength
	outLength := (numberOfBlocks + 1) * blockLength
	out := make([]byte, outLength)
	copy(out, original)
	for i := 0; i < blockLength-rem; i++ {
		out[n+i] = byte(blockLength - rem)
	}
	return out
}

func encrypt(plaintext []byte, key []byte, iv []byte) []byte {
	plaintext = pad(plaintext, 16)
	n := len(plaintext)
	block, _ := aes.NewCipher(key)
	ciphertext := make([]byte, n)
	for i := 0; i < n/16; i++ {
		if len(iv) == len(key) {
			copy(plaintext[i*16:(i+1)*16], xor(plaintext[i*16:(i+1)*16], iv))
			block.Encrypt(ciphertext[i*16:(i+1)*16], plaintext[i*16:(i+1)*16])
			iv = ciphertext[i*16 : (i+1)*16]
		} else {
			block.Encrypt(ciphertext[i*16:(i+1)*16], plaintext[i*16:(i+1)*16])
		}
	}
	return ciphertext
}

func decrypt(ciphertext []byte, key []byte, iv []byte) []byte {
	if len(ciphertext)%16 != 0 {
		log.Println("Given a ciphertext that does not have length that is a multiple of the blocksize.")
	}
	n := len(ciphertext)
	block, _ := aes.NewCipher(key)
	plaintext := make([]byte, n)
	for i := 0; i < n/16; i++ {
		if len(iv) == len(key) {
			block.Decrypt(plaintext[i*16:(i+1)*16], ciphertext[i*16:(i+1)*16])
			copy(plaintext[i*16:(i+1)*16], xor(plaintext[i*16:(i+1)*16], iv))
			iv = ciphertext[i*16 : (i+1)*16]
		} else {
			block.Decrypt(plaintext[i*16:(i+1)*16], ciphertext[i*16:(i+1)*16])
		}
	}
	return plaintext
}

func encryptionOracle(encrypter func([]byte) []byte) string {
	ciphertext := encrypter([]byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"))
	if bytes.Equal(ciphertext[0:16], ciphertext[16:32]) {
		return "ecb"
	} else {
		return "cbc"
	}
}

func discoverBlockSize(blackBox func([]byte) []byte) (int, int) {
	n := len(blackBox([]byte{}))
	currentPre := make([]byte, 0)
	maxBlockSize := 999
	for i := 0; i < maxBlockSize; i++ {
		out := blackBox(currentPre)
		if len(out) > n {
			return len(out) - n, i
		} else {
			currentPre = append(currentPre, []byte{byte('a')}...)
		}
	}
	log.Println("No appropriate block size found.")
	return -1, -1
}
func prepad(slice []byte) []byte {
	if len(slice) == 0 {
		return make([]byte, 16)
	}
	n := len(slice)
	rem := n % 16
	extraRequired := 16 - rem
	numberOfBlocks := n / 16
	out := make([]byte, (numberOfBlocks+1)*16)
	for i := 0; i < n; i++ {
		out[extraRequired+i] = slice[i]
	}
	return out
}

func blackBoxDict(blackBox func([]byte) []byte, prevFifteen []byte) [][]byte {
	dict := make([][]byte, 256)
	fullSixteen := append(prevFifteen, byte(0))
	for i := 0; i < 256; i++ {
		b := byte(i)
		fullSixteen[15] = b
		out := blackBox(fullSixteen)[:16]
		dict[i] = out
	}
	return dict
}

func reverseLookup(block []byte, dict [][]byte) byte {
	for i := 0; i < 256; i++ {
		if bytes.Equal(dict[i], block) {
			return byte(i)
		}
	}
	log.Println("Byte not found.")
	return byte(0)
}

func shiftAppend(slice []byte, b byte) []byte {
	n := len(slice)
	out := make([]byte, n)
	for i := 0; i < n-1; i++ {
		out[i] = slice[i+1]
	}
	out[n-1] = b
	return out
}

func attackBlackBox(blackBox func([]byte) []byte) []byte {
	ciphertext := blackBox([]byte{})
	cipherlength := len(ciphertext)
	// log.Println(cipherlength)
	blocksize, jumpIndex := discoverBlockSize(blackBox)
	plainlength := cipherlength - (jumpIndex - 1)
	//log.Println(blocksize)
	//isECB := (encryptionOracle(blackBox) == "ecb")
	//log.Println(isECB)
	prevFifteen := make([]byte, 15)
	knownBytes := make([]byte, plainlength)
	dict := make([][]byte, 256)
	for i := 0; i < plainlength; i++ {
		blockStart := 16 * (i / 16)
		blockEnd := 16*(i/16) + 16
		dict = blackBoxDict(blackBox, prevFifteen)
		pre := make([]byte, blocksize-1-(i%16))
		outBlock := blackBox(pre)[blockStart:blockEnd] // computing the same thing multiple times; performance seems fine though
		outByte := reverseLookup(outBlock, dict)
		knownBytes[i] = outByte
		prevFifteen = shiftAppend(prevFifteen, outByte)
	}
	return knownBytes
}

func findRepeatedBlock(slice []byte) int {
	n := len(slice)
	numberofBlocks := n / 16
	for i := 0; i < numberofBlocks; i++ {
		ithBlock := slice[i*16 : (i+1)*16]
		for j := 0; j < i; j++ {
			jthBlock := slice[j*16 : (j+1)*16]
			if bytes.Equal(ithBlock, jthBlock) {
				return j * 16
			}
		}
	}
	return -1
}

func firstBlockAfterPre(preBlackBox func([]byte) []byte) (int, int) {
	testPre := make([]byte, 32)
	for i := 0; i < 16; i++ {
		slice := preBlackBox(testPre)
		//log.Println(i)
		//log.Println(slice)
		initPosition := findRepeatedBlock(slice)
		if initPosition >= 0 {
			return i, initPosition
		}
		testPre = append(testPre, byte(0))
	}
	return -1, -1
}

func attackPreBlackBox(preBlackBox func([]byte) []byte) []byte {
	resetLength, initPosition := firstBlockAfterPre(preBlackBox)
	//log.Println(resetLength, initPosition)
	resetPre := make([]byte, resetLength)
	bBox := func(slice []byte) []byte {
		wholeInput := append(resetPre, slice...)
		out := preBlackBox(wholeInput)[initPosition:]
		return out
	}
	ans := attackBlackBox(bBox)
	return ans
}

func paddingValidation(plaintext []byte, blockSize int) (out []byte, err error) {
	n := len(plaintext)
	if n%blockSize != 0 {
		return plaintext, errors.New("Plaintext length is not multiple of 16.")
	} else if n == 0 {
		return plaintext, errors.New("Plaintext should not be empty.")
	} else {
		lastByte := plaintext[n-1]
		if lastByte == byte(0) {
			return plaintext, errors.New("Byte(0) is not valid padding.")
		}
		claimedPadding := int(lastByte)
		if int(lastByte) > blockSize {
			return plaintext, errors.New("Claimed padding length is greater than blocksize.")
		}
		for i := 0; i < claimedPadding; i++ {
			if plaintext[n-1-i] != lastByte {
				return plaintext, errors.New("Incorrect padding claim.")
			}
		}
		return plaintext[:n-claimedPadding], nil
	}
}

func c16func1(userdata []byte, key [16]byte) []byte {
	userstring := string(userdata)
	userstring = strings.Replace(userstring, ";", "", -1)
	userstring = strings.Replace(userstring, "=", "", -1)
	out := []byte("comment1=cooking%20MCs;userdata=" + userstring + ";comment2=%20like%20a%20pound%20of%20bacon")
	ciphertext := encrypt(out, key[:], make([]byte, 16))
	return ciphertext
}

func c16func2(ciphertext []byte, key [16]byte) bool {
	plaintext := decrypt(ciphertext, key[:], make([]byte, 16))
	log.Println(string(plaintext))
	containsAdmin := strings.Contains(string(plaintext), ";admin=true;")
	return containsAdmin
}

func c17func1(key [16]byte) ([]byte, []byte) {
	plaintexts := [][]byte{
		[]byte("MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc="),
		[]byte("MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic="),
		[]byte("MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw=="),
		[]byte("MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg=="),
		[]byte("MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl"),
		[]byte("MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA=="),
		[]byte("MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw=="),
		[]byte("MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8="),
		[]byte("MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g="),
		[]byte("MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93"),
	}
	//for i:=0;i<len(plaintexts);i++{
	//	log.Println(len(plaintexts[i])%16)
	//}
	randLength, _ := rand.Int(rand.Reader, big.NewInt(10))
	index := randLength.Int64()
	plaintext := plaintexts[index]
	iv := make([]byte, 16)
	ciphertext := encrypt(plaintext, key[:], iv)
	return ciphertext, iv
}

func c17func2(ciphertext []byte, key [16]byte, iv []byte) bool {
	plaintext := decrypt(ciphertext, key[:], iv)
	_, err := paddingValidation(plaintext, 16)
	if err == nil {
		return true
	} else {
		return false
	}
}

func ctr(input []byte, key []byte, iv []byte) []byte {
	r := bytes.NewReader(input)
	out := make([]byte, 0)
	inblock := make([]byte, 16)
	ctr := 0
	plainkey := make([]byte, 16)
	copy(iv, plainkey[:8])
	for {
		n, err := r.Read(inblock)
		if err != nil {
			break
		}
		binary.LittleEndian.PutUint16(plainkey[8:], uint16(ctr))
		ctr += 1
		key := encrypt(plainkey, []byte("YELLOW SUBMARINE"), make([]byte, 0))[:16]
		outblock := xor(key[:n], inblock[:n])
		out = append(out, outblock...)
	}
	return out
}

func c19setup(key []byte) [][]byte {
	plaintexts := [][]byte{
		[]byte("SSBoYXZlIG1ldCB0aGVtIGF0IGNsb3NlIG9mIGRheQ=="),
		[]byte("Q29taW5nIHdpdGggdml2aWQgZmFjZXM="),
		[]byte("RnJvbSBjb3VudGVyIG9yIGRlc2sgYW1vbmcgZ3JleQ=="),
		[]byte("RWlnaHRlZW50aC1jZW50dXJ5IGhvdXNlcy4="),
		[]byte("SSBoYXZlIHBhc3NlZCB3aXRoIGEgbm9kIG9mIHRoZSBoZWFk"),
		[]byte("T3IgcG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA=="),
		[]byte("T3IgaGF2ZSBsaW5nZXJlZCBhd2hpbGUgYW5kIHNhaWQ="),
		[]byte("UG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA=="),
		[]byte("QW5kIHRob3VnaHQgYmVmb3JlIEkgaGFkIGRvbmU="),
		[]byte("T2YgYSBtb2NraW5nIHRhbGUgb3IgYSBnaWJl"),
		[]byte("VG8gcGxlYXNlIGEgY29tcGFuaW9u"),
		[]byte("QXJvdW5kIHRoZSBmaXJlIGF0IHRoZSBjbHViLA=="),
		[]byte("QmVpbmcgY2VydGFpbiB0aGF0IHRoZXkgYW5kIEk="),
		[]byte("QnV0IGxpdmVkIHdoZXJlIG1vdGxleSBpcyB3b3JuOg=="),
		[]byte("QWxsIGNoYW5nZWQsIGNoYW5nZWQgdXR0ZXJseTo="),
		[]byte("QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4="),
		[]byte("VGhhdCB3b21hbidzIGRheXMgd2VyZSBzcGVudA=="),
		[]byte("SW4gaWdub3JhbnQgZ29vZCB3aWxsLA=="),
		[]byte("SGVyIG5pZ2h0cyBpbiBhcmd1bWVudA=="),
		[]byte("VW50aWwgaGVyIHZvaWNlIGdyZXcgc2hyaWxsLg=="),
		[]byte("V2hhdCB2b2ljZSBtb3JlIHN3ZWV0IHRoYW4gaGVycw=="),
		[]byte("V2hlbiB5b3VuZyBhbmQgYmVhdXRpZnVsLA=="),
		[]byte("U2hlIHJvZGUgdG8gaGFycmllcnM/"),
		[]byte("VGhpcyBtYW4gaGFkIGtlcHQgYSBzY2hvb2w="),
		[]byte("QW5kIHJvZGUgb3VyIHdpbmdlZCBob3JzZS4="),
		[]byte("VGhpcyBvdGhlciBoaXMgaGVscGVyIGFuZCBmcmllbmQ="),
		[]byte("V2FzIGNvbWluZyBpbnRvIGhpcyBmb3JjZTs="),
		[]byte("SGUgbWlnaHQgaGF2ZSB3b24gZmFtZSBpbiB0aGUgZW5kLA=="),
		[]byte("U28gc2Vuc2l0aXZlIGhpcyBuYXR1cmUgc2VlbWVkLA=="),
		[]byte("U28gZGFyaW5nIGFuZCBzd2VldCBoaXMgdGhvdWdodC4="),
		[]byte("VGhpcyBvdGhlciBtYW4gSSBoYWQgZHJlYW1lZA=="),
		[]byte("QSBkcnVua2VuLCB2YWluLWdsb3Jpb3VzIGxvdXQu"),
		[]byte("SGUgaGFkIGRvbmUgbW9zdCBiaXR0ZXIgd3Jvbmc="),
		[]byte("VG8gc29tZSB3aG8gYXJlIG5lYXIgbXkgaGVhcnQs"),
		[]byte("WWV0IEkgbnVtYmVyIGhpbSBpbiB0aGUgc29uZzs="),
		[]byte("SGUsIHRvbywgaGFzIHJlc2lnbmVkIGhpcyBwYXJ0"),
		[]byte("SW4gdGhlIGNhc3VhbCBjb21lZHk7"),
		[]byte("SGUsIHRvbywgaGFzIGJlZW4gY2hhbmdlZCBpbiBoaXMgdHVybiw="),
		[]byte("VHJhbnNmb3JtZWQgdXR0ZXJseTo="),
		[]byte("QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4="),
	}
	ciphertexts := make([][]byte, len(plaintexts))
	for i, plaintext := range plaintexts {
		ciphertexts[i] = ctr(plaintext, key, make([]byte, 8))
	}
	return ciphertexts
}
