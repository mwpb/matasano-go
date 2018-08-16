package cryptopals

import (
	"testing"
	"log"
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

//func TestS3C19(t *testing.T) {
//	ciphertexts := c19setup(unknownKey[:])
//	plaintexts := make([]string, len(ciphertexts))
//	key := c19attack(ciphertexts)
//	for j, ciphertext := range ciphertexts {
//		plaintext := string(xor(key, ciphertext))[:len(ciphertext)]
//		log.Println(plaintext)
//		plaintexts[j] = plaintext
//	}
//	if false {
//		t.Error("failed")
//	}
//}

//func TestS3C20(t *testing.T) {
//	file, _ := os.Open("./20.txt")
//	defer file.Close()
//	reader := bufio.NewReader(file)
//	ciphertexts := make([][]byte, 0)
//	for {
//		line, err := reader.ReadBytes('\n')
//		if err != nil { break }
//		plaintext, _ := base64.StdEncoding.DecodeString(string(line))
//		ciphertext := ctr(plaintext, unknownKey[:], make([]byte, 8))
//		ciphertexts = append(ciphertexts, ciphertext)
//	}
//	key := c19attack(ciphertexts)
//	log.Println(len(key))
//	key[0] = ciphertexts[0][0]^byte('I')
//	key[0] = ciphertexts[0][0]^byte('I')
//	key[26] = ciphertexts[2][26]^byte(' ')
//	key[27] = ciphertexts[0][27]^byte('a')
//	key[28] = ciphertexts[0][28]^byte('r')
//	key[29] = ciphertexts[0][29]^byte('n')
//	key[30] = ciphertexts[0][30]^byte('i')
//	key[31] = ciphertexts[0][31]^byte('n')
//	key[32] = ciphertexts[6][32]^byte('u')
//	key[33] = ciphertexts[4][33]^byte('h')
//	key[34] = ciphertexts[4][34]^byte('o')
//	key[35] = ciphertexts[4][35]^byte('r')
//	key[36] = ciphertexts[4][36]^byte('r')
//	key[37] = ciphertexts[4][37]^byte('o')
//	key[38] = ciphertexts[4][38]^byte('r')
//	key[82] = ciphertexts[1][82]^byte('g')
//	key[83] = ciphertexts[1][83]^byte('h')
//	key[84] = ciphertexts[1][84]^byte('t')
//	key[85] = ciphertexts[4][85]^byte('o')
//	key[86] = ciphertexts[4][86]^byte('r')
//	key[87] = ciphertexts[4][87]^byte('r')
//	key[88] = ciphertexts[4][88]^byte('o')
//	key[89] = ciphertexts[4][89]^byte('w')
//	key[90] = ciphertexts[17][90]^byte('b')
//	key[91] = ciphertexts[17][91]^byte('l')
//	key[92] = ciphertexts[17][92]^byte('e')
//	key[93] = ciphertexts[4][93]^byte('i')
//	key[94] = ciphertexts[4][94]^byte('c')
//	key[95] = ciphertexts[4][95]^byte('k')
//	key[96] = ciphertexts[12][96]^byte('n')
//	key[97] = ciphertexts[12][97]^byte('k')
//	key[98] = ciphertexts[26][98]^byte('v')
//	key[99] = ciphertexts[26][99]^byte('e')
//	key[100] = ciphertexts[26][100]^byte(' ')
//	key[101] = ciphertexts[26][101]^byte('t')
//	key[102] = ciphertexts[26][102]^byte('h')
//	key[103] = ciphertexts[26][103]^byte('e')
//	key[104] = ciphertexts[46][104]^byte('u')
//	key[105] = ciphertexts[46][105]^byte('t')
//	key[106] = ciphertexts[46][106]^byte(' ')
//	key[107] = ciphertexts[46][107]^byte('t')
//	key[108] = ciphertexts[46][108]^byte('h')
//	key[109] = ciphertexts[46][109]^byte('e')
//	key[110] = ciphertexts[46][110]^byte(' ')
//	key[111] = ciphertexts[46][111]^byte('m')
//	key[112] = ciphertexts[46][112]^byte('o')
//	key[113] = ciphertexts[46][113]^byte('n')
//	key[114] = ciphertexts[46][114]^byte('e')
//	key[115] = ciphertexts[46][115]^byte('y')
//	key[116] = ciphertexts[26][116]^byte('r')
//	key[117] = ciphertexts[26][117]^byte('y')
//
//
//
//	plaintexts := make([]string, len(ciphertexts))
//	for j, ciphertext := range ciphertexts {
//		plaintext := string(xor(key, ciphertext))[:len(ciphertext)]
//		log.Println(j, plaintext)
//		plaintexts[j] = plaintext
//	}
//	if false {
//		t.Error("failed")
//	}
//}

//func TestS3C22(t *testing.T) {
//	rand2, _ := rand.Int(rand.Reader, big.NewInt(5))
//	time.Sleep(time.Duration(rand2.Int64()) * time.Second)
//	log.Println(int(time.Now().Unix()))
//	mtRand := MTRand{
//		index: recurrenceDegree,
//		state: mtInit(int(time.Now().Unix())),
//	}
//	rand3, _ := rand.Int(rand.Reader, big.NewInt(5))
//	time.Sleep(time.Duration(rand3.Int64()) * time.Second)
//	out := nextRand(mtRand)
//	// attack begins here
//	timeUpper := time.Now().Unix()
//	timeLower := timeUpper - 15
//	possibles := make([]int, 16)
//	for i := int(timeLower); i <= int(timeUpper); i++ {
//		mtRand2 := MTRand{
//			index: recurrenceDegree,
//			state: mtInit(i),
//		}
//		possibles[i-int(timeLower)] = nextRand(mtRand2)
//	}
//	for i, possible := range possibles {
//		if possible == out {
//			log.Println(i)
//			log.Println(i+int(timeLower))
//		}
//	}
//	if false {
//		t.Error("failed")
//	}
//}

func TestInverses(t *testing.T) {
	for i := 0; i < 256; i++ {
		y := i
		x := y ^ ((y << uint(constT)) & constC)
		z := undoT(x)
		if y != z {
			log.Println("Failed")
		}
	}

	if false {
		t.Error("failed")
	}
}
