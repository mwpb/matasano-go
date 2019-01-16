package main

import (
	"crypto/rand"
	"encoding/base64"
	"log"
	"math/big"
	"testing"
	"bytes"
	"io/ioutil"
	"strings"
)

func dummy2() {
	log.Println("HI")
}

func TestS2C9(t *testing.T) {
	original := []byte("YELLOW SUBMARINE")
	ans := pad(original, 20)
	expected := append([]byte("YELLOW SUBMARINE"), []byte{4, 4, 4, 4}...)
	if bytes.Equal(ans, expected) == false {
		t.Errorf("s2c1 failed: output is %v", ans)
	}
}

func TestS2C10(t *testing.T) {
	ciphertext, _ := ioutil.ReadFile("10.txt")
	ciphertext, _ = base64.StdEncoding.DecodeString(string(ciphertext))
	key := []byte("YELLOW SUBMARINE")
	iv := []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	plaintext := decrypt(ciphertext, key, iv)
	plaintext = unpad(plaintext)
	// newCiphertext := encrypt(plaintext, key, iv)
	// ans := newCiphertext
	ans_str := `I'm back and I'm ringin' the bell
A rockin' on the mike while the fly girls yell
In ecstasy in the back of me
Well that's my DJ Deshay cuttin' all them Z's
Hittin' hard and the girlies goin' crazy
Vanilla's on the mike, man I'm not lazy.

I'm lettin' my drug kick in
It controls my mouth and I begin
To just let it flow, let my concepts go
My posse's to the side yellin', Go Vanilla Go!

Smooth 'cause that's the way I will be
And if you don't give a damn, then
Why you starin' at me
So get off 'cause I control the stage
There's no dissin' allowed
I'm in my own phase
The girlies sa y they love me and that is ok
And I can dance better than any kid n' play

Stage 2 -- Yea the one ya' wanna listen to
It's off my head so let the beat play through
So I can funk it up and make it sound good
1-2-3 Yo -- Knock on some wood
For good luck, I like my rhymes atrocious
Supercalafragilisticexpialidocious
I'm an effect and that you can bet
I can take a fly girl and make her wet.

I'm like Samson -- Samson to Delilah
There's no denyin', You can try to hang
But you'll keep tryin' to get my style
Over and over, practice makes perfect
But not if you're a loafer.

You'll get nowhere, no place, no time, no girls
Soon -- Oh my God, homebody, you probably eat
Spaghetti with a spoon! Come on and say it!

VIP. Vanilla Ice yep, yep, I'm comin' hard like a rhino
Intoxicating so you stagger like a wino
So punks stop trying and girl stop cryin'
Vanilla Ice is sellin' and you people are buyin'
'Cause why the freaks are jockin' like Crazy Glue
Movin' and groovin' trying to sing along
All through the ghetto groovin' this here song
Now you're amazed by the VIP posse.

Steppin' so hard like a German Nazi
Startled by the bases hittin' ground
There's no trippin' on mine, I'm just gettin' down
Sparkamatic, I'm hangin' tight like a fanatic
You trapped me once and I thought that
You might have it
So step down and lend me your ear
'89 in my time! You, '90 is my year.

You're weakenin' fast, YO! and I can tell it
Your body's gettin' hot, so, so I can smell it
So don't be mad and don't be sad
'Cause the lyrics belong to ICE, You can call me Dad
You're pitchin' a fit, so step back and endure
Let the witch doctor, Ice, do the dance to cure
So come up close and don't be square
You wanna battle me -- Anytime, anywhere

You thought that I was weak, Boy, you're dead wrong
So come on, everybody and sing this song

Say -- Play that funky music Say, go white boy, go white boy go
play that funky music Go white boy, go white boy, go
Lay down and boogie and play that funky music till you die.

Play that funky music Come on, Come on, let me hear
Play that funky music white boy you say it, say it
Play that funky music A little louder now
Play that funky music, white boy Come on, Come on, Come on
Play that funky music`
	if !(strings.HasPrefix(string(plaintext), "I'm back and I'm ringin' the bell")) {
		t.Errorf("s2c10 failed: output is %v %v", len(plaintext), len(ans_str))
	}
}

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

func TestS2C11(t *testing.T) {
	rand1, _ := rand.Int(rand.Reader, big.NewInt(2))
	encryptionMethod := rand1.Int64()
	ans := ""
	em_str := ""
	if encryptionMethod == 0 {
		em_str = "ecb"
		ans = encryptionOracle(randomECB)
	} else {
		em_str = "cbc"
		ans = encryptionOracle(randomCBC)
	}
	if (ans != em_str) {
		t.Errorf("s2c11 failed: method was %s ans was %s.", em_str ,ans)
	}
}

var unknownKey [16]byte

func blackBox(extraText []byte) []byte {
	plaintext, _ := base64.StdEncoding.DecodeString("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK")
	return encrypt(append(extraText, plaintext...), unknownKey[:], []byte{})
}

func TestS2C12(t *testing.T) {
	rand.Read(unknownKey[:])
	ans := attackBlackBox(blackBox)
	ans_str := "Rollin' in my 5.0\nWith my rag-top down so my hair can blow\nThe girlies on standby waving just to say hi\nDid you stop? No, I just drove by\n"
	if (string(ans) != ans_str) {
		t.Errorf("s2c12 failed: output is %v\n\n %v", ans, []byte(ans_str))
	}
}

func profileBlackBox(email []byte) []byte {
	userProfile := profileFor(string(email))
	out := encrypt(userProfile, unknownKey[:], []byte{})
	return out
}

func TestS2preC13(t *testing.T) {
	userProfile := profileFor("fo&&&===o@===&&&==bar.com")
	key := make([]byte, 16)
	rand.Read(key)
	ciphertext := encrypt(userProfile, key, []byte{})
	plaintext := decrypt(ciphertext, key, []byte{})
	plaintext = unpad(plaintext)
	cookie := parseCookie(plaintext)
	ans := cookie
	if ((ans["role"] != "user") || (ans["email"] != "foo@bar.com")) {
		t.Errorf("s2prec13 failed: output is %v", ans)
	}
}

func TestS2C13(t *testing.T) {
	rand.Read(unknownKey[:])
	blocksize, jumpIndex := discoverBlockSize(profileBlackBox)
	email := make([]byte, 32)
	prePadding := []byte{}
	for i := 0; i < 16; i++ {
		ciphertext := profileBlackBox(email)
		_, index := getRepeatedBlock(ciphertext, 16)
		if index != 0 {
			prePadding = make([]byte, i)
			break
		}
		email = append(email, byte(0))
	}
	adminPlain := pad([]byte("admin"), blocksize)
	attackEmail := append(prePadding, adminPlain...)
	fakeLastEntry := profileBlackBox(attackEmail)[blocksize : 2*blocksize]
	getToRightLength := make([]byte, jumpIndex+3)
	getToRightLength = []byte("a@comp")
	rightLength := profileBlackBox(getToRightLength)
	firstTwoEntries := rightLength[:len(rightLength)-16]
	ans := append(firstTwoEntries, fakeLastEntry...)
	test := decrypt(ans, unknownKey[:], []byte{})
	test = unpad(test)
	admin_str := string(test[len(test)-5:len(test)])
	if admin_str != "admin" {
		t.Errorf("s2c13 failed: output is %v", ans)
	}
}

var randLength, _ = rand.Int(rand.Reader, big.NewInt(16))
var preLength = randLength.Int64()
var pre = make([]byte, preLength)

func preBlackBox(extraText []byte) []byte {
	plaintext, _ := base64.StdEncoding.DecodeString("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK")
	return encrypt(append(append(pre, extraText...), plaintext...), unknownKey[:], []byte{})
}

func TestS2C14(t *testing.T) {
	rand.Read(pre)
	ans := attackPreBlackBox(preBlackBox)
	if string(ans) != "Rollin' in my 5.0\nWith my rag-top down so my hair can blow\nThe girlies on standby waving just to say hi\nDid you stop? No, I just drove by\n" {
		t.Errorf("s2c14 failed: output is %v", ans)
	}
}

func TestS2C15(t *testing.T) {
	ans1, err1 := paddingValidation([]byte("ICE ICE BABY\x04\x04\x04\x04"), 16)
	_, err2 := paddingValidation([]byte("ICE ICE BABY\x05\x05\x05\x05"), 16)
	_, err3 := paddingValidation([]byte("ICE ICE BABY\x01\x02\x03\x04"), 16)
	check1a := bytes.Equal(ans1 ,[]byte("ICE ICE BABY"))
	check1b := err1 == nil
	check2 := err2 != nil
	check3 := err3 != nil
	if !(check1a && check1b && check2 && check3) {
		t.Errorf("s2c15 failed: output is %v", check2)
	}
}

func TestS2C16(t *testing.T) {
	rand.Read(unknownKey[:])
	sixteen := make([]byte, 16)
	test := []byte(":admin:true:00")
	in := append(sixteen, test...)
	ciphertext := c16func1(in, unknownKey)
	ciphertext[32] = ciphertext[32] ^ byte(':') ^ byte(';')
	ciphertext[38] = ciphertext[38] ^ byte(':') ^ byte('=')
	ciphertext[43] = ciphertext[43] ^ byte(':') ^ byte(';')
	containsAdmin := c16func2(ciphertext, unknownKey)
	if !containsAdmin {
		t.Error("Failed.")
	}
}
