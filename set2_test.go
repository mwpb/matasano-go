package cryptopals

import (
	"crypto/rand"
	"encoding/base64"
	"log"
	"math/big"
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

// func TestS2C12(t *testing.T) {
// 	rand.Read(unknownKey[:])
// 	ans := attackBlackBox(blackBox)
// 	if string(ans) != "Rollin' in my 5.0\nWith my rag-top down so my hair can blow\nThe girlies on standby waving just to say hi\nDid you stop? No, I just drove by\n" {
// 		t.Errorf("s2c12 failed: output is %v", ans)
// 	}
// }

func profileBlackBox(email []byte) []byte {
	userProfile := profileFor(string(email))
	out := encrypt(userProfile, unknownKey[:], []byte{})
	return out
}

// func TestS2preC13(t *testing.T) {
// 	userProfile := profileFor("fo&&&===o@===&&&==bar.com")
// 	key := make([]byte, 16)
// 	rand.Read(key)
// 	ciphertext := encrypt(userProfile, key, []byte{})
// 	plaintext := decrypt(ciphertext, key, []byte{})
// 	cookie := parseCookie(plaintext)
// 	log.Println(ciphertext)
// 	log.Println(cookie)
// 	ans := cookie
// 	if len(ans) < 0 {
// 		t.Errorf("s2prec13 failed: output is %v", ans)
// 	}
// }

//func TestS2C13(t *testing.T) {
//	rand.Read(unknownKey[:])
//	blocksize, jumpIndex := discoverBlockSize(profileBlackBox)
//	email := make([]byte, 32)
//	prePadding := []byte{}
//	for i := 0; i < 16; i++ {
//		ciphertext := profileBlackBox(email)
//		_, index := getRepeatedBlock(ciphertext, 16)
//		if index != 0 {
//			prePadding = make([]byte, i)
//			break
//		}
//		email = append(email, byte(0))
//	}
//	adminPlain := pad([]byte("admin"), blocksize)
//	attackEmail := append(prePadding, adminPlain...)
//	fakeLastEntry := profileBlackBox(attackEmail)[blocksize : 2*blocksize]
//	getToRightLength := make([]byte, jumpIndex+3)
//	getToRightLength = []byte("a@comp")
//	rightLength := profileBlackBox(getToRightLength)
//	firstTwoEntries := rightLength[:len(rightLength)-16]
//	ans := append(firstTwoEntries, fakeLastEntry...)
//	test := decrypt(ans, unknownKey[:], []byte{})
//	if string(test[len(test)-16:len(test)-11]) != "admin" {
//		t.Errorf("s2c13 failed: output is %v", ans)
//	}
//}

var randLength, _ = rand.Int(rand.Reader, big.NewInt(16))
var preLength = randLength.Int64()
var pre = make([]byte, preLength)

func preBlackBox(extraText []byte) []byte {
	plaintext, _ := base64.StdEncoding.DecodeString("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK")
	return encrypt(append(append(pre, extraText...), plaintext...), unknownKey[:], []byte{})
}

//func TestS2C14(t *testing.T) {
//	rand.Read(pre)
//	ans := attackPreBlackBox(preBlackBox)
//	if string(ans) != "Rollin' in my 5.0\nWith my rag-top down so my hair can blow\nThe girlies on standby waving just to say hi\nDid you stop? No, I just drove by\n" {
//		t.Errorf("s2c14 failed: output is %v", ans)
//	}
//}

//func TestS2C15(t *testing.T) {
//	ans1, err1 := paddingValidation([]byte("ICE ICE BABY\x04\x04\x04\x04"), 16)
//	_, err2 := paddingValidation([]byte("ICE ICE BABY\x05\x05\x05\x05"), 16)
//	_, err3 := paddingValidation([]byte("ICE ICE BABY\x01\x02\x03\x04"), 16)
//	log.Println(string(ans1))
//	check1a := bytes.Equal(ans1 ,[]byte("ICE ICE BABY"))
//	check1b := err1 == nil
//	check2 := err2 != nil
//	check3 := err3 != nil
//	if !(check1a && check1b && check2 && check3) {
//		t.Errorf("s2c15 failed: output is %v", check2)
//	}
//}
//
//func TestS2C16(t *testing.T) {
//	rand.Read(unknownKey[:])
//	sixteen := make([]byte, 16)
//	test := []byte(":admin:true:00")
//	in := append(sixteen, test...)
//	ciphertext := c16func1(in, unknownKey)
//	ciphertext[32] = ciphertext[32] ^ byte(':') ^ byte(';')
//	ciphertext[38] = ciphertext[38] ^ byte(':') ^ byte('=')
//	ciphertext[43] = ciphertext[43] ^ byte(':') ^ byte(';')
//	containsAdmin := c16func2(ciphertext, unknownKey)
//	log.Println(containsAdmin)
//	if false {
//		t.Error("Failed.")
//	}
//}
