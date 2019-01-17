package main

import (
	"crypto/rand"
	"strings"
	"encoding/base64"
	"testing"
	"bytes"
	"log"
	"os"
	"bufio"
	"math/big"
	"time"
)

func dummy3(){
	log.Println("")
}

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

func TestS3C17(t *testing.T) {
	rand.Read(unknownKey[:])
	ciphertext, iv := c17func1(unknownKey)
	n := len(ciphertext)
	plaintext := make([]byte, n)
	numberOfBlocks := n / 16
	for i := 0; i < numberOfBlocks; i++ {
		currentBlock := ciphertext[n-(i+1)*16 : n-i*16]
		prevBlock := make([]byte, 16)
		if i != numberOfBlocks-1 {
			prevBlock = ciphertext[n-(i+2)*16 : n-(i+1)*16]
		}
		plainblock := decryptBlock(currentBlock, prevBlock, unknownKey, iv)
		copy(plaintext[n-(i+1)*16:n-i*16], plainblock)
	}
	plaintext, _ = paddingValidation(plaintext, 16)
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
	success := false
	for _, p := range(plaintexts) {
		if bytes.Equal(p, plaintext) {
			success = true
		}
	}
	if !success {
		t.Error("Failed.")
	}
}

func TestS3C18(t *testing.T){
	input, _ := base64.StdEncoding.DecodeString("L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==")
	out := ctr(input, []byte("YELLOW SUBMARINE"), make([]byte, 8))
	if string(out) == "Yo, VIP Let's kick it Ice, Ice, baby Ice, Ice, baby" {
		t.Error("failed")
	}
}

func TestS3C19(t *testing.T) {
	ciphertexts := c19setup(unknownKey[:])
	plaintexts := []string{
		"i have met them at close of day",
		"coming with vivid faces",
		"from counter or desk among grey",
		"eighteenth-century houses.",
		"i have passed with a nod of the head",
		"or polite meaningless words,",
		"or have lingered awhile and said",
		"polite meaningless words,",
		"and thought before I had done",
		"of a mocking tale or a gibe",
		"to please a companion",
		"around the fire at the club,",
		"being certain that they and I",
		"but lived where motley is worn:",
		"all changed, changed utterly:",
		"a terrible beauty is born.",
		"that woman's days were spent",
		"in ignorant good will,",
		"her nights in argument",
		"until her voice grew shrill.",
		"what voice more sweet than hers",
		"when young and beautiful,",
		"she rode to harriers?",
		"this man had kept a school",
		"and rode our winged horse.",
		"this other his helper and friend",
		"was coming into his force;",
		"he might have won fame in the end,",
		"so sensitive his nature seemed,",
		"so daring and sweet his thought.",
		"this other man I had dreamed",
		"a drunken, vain-glorious lout.",
		"he had done most bitter wrong",
		"to some who are near my heart,",
		"yet I number him in the song;",
		"he, too, has resigned his part",
		"in the casual comedy;",
		"he, too, has been changed in his turn,",
		"transformed utterly:",
		"a terrible beauty is born.",
	}
	key := c19attack(ciphertexts)
	success := true
	for j, ciphertext := range ciphertexts {
		plaintext := string(xor(key, ciphertext))[:len(ciphertext)]
		if plaintext != plaintexts[j] {
			success = false
			break
		}
	}
	if !success	 {
		t.Error("failed")
	}
}

func TestS3C20(t *testing.T) {
	file, _ := os.Open("./20.txt")
	defer file.Close()
	reader := bufio.NewReader(file)
	ciphertexts := make([][]byte, 0)
	for {
		line, err := reader.ReadBytes('\n')
		if err != nil { break }
		plaintext, _ := base64.StdEncoding.DecodeString(string(line))
		ciphertext := ctr(plaintext, unknownKey[:], make([]byte, 8))
		ciphertexts = append(ciphertexts, ciphertext)
	}
	key := c19attack(ciphertexts)
	// log.Println(len(key))
	key[0] = ciphertexts[0][0]^byte('I')
	key[0] = ciphertexts[0][0]^byte('I')
	key[26] = ciphertexts[2][26]^byte(' ')
	key[27] = ciphertexts[0][27]^byte('a')
	key[28] = ciphertexts[0][28]^byte('r')
	key[29] = ciphertexts[0][29]^byte('n')
	key[30] = ciphertexts[0][30]^byte('i')
	key[31] = ciphertexts[0][31]^byte('n')
	key[32] = ciphertexts[6][32]^byte('u')
	key[33] = ciphertexts[4][33]^byte('h')
	key[34] = ciphertexts[4][34]^byte('o')
	key[35] = ciphertexts[4][35]^byte('r')
	key[36] = ciphertexts[4][36]^byte('r')
	key[37] = ciphertexts[4][37]^byte('o')
	key[38] = ciphertexts[4][38]^byte('r')
	key[82] = ciphertexts[1][82]^byte('g')
	key[83] = ciphertexts[1][83]^byte('h')
	key[84] = ciphertexts[1][84]^byte('t')
	key[85] = ciphertexts[4][85]^byte('o')
	key[86] = ciphertexts[4][86]^byte('r')
	key[87] = ciphertexts[4][87]^byte('r')
	key[88] = ciphertexts[4][88]^byte('o')
	key[89] = ciphertexts[4][89]^byte('w')
	key[90] = ciphertexts[17][90]^byte('b')
	key[91] = ciphertexts[17][91]^byte('l')
	key[92] = ciphertexts[17][92]^byte('e')
	key[93] = ciphertexts[4][93]^byte('i')
	key[94] = ciphertexts[4][94]^byte('c')
	key[95] = ciphertexts[4][95]^byte('k')
	key[96] = ciphertexts[12][96]^byte('n')
	key[97] = ciphertexts[12][97]^byte('k')
	key[98] = ciphertexts[26][98]^byte('v')
	key[99] = ciphertexts[26][99]^byte('e')
	key[100] = ciphertexts[26][100]^byte(' ')
	key[101] = ciphertexts[26][101]^byte('t')
	key[102] = ciphertexts[26][102]^byte('h')
	key[103] = ciphertexts[26][103]^byte('e')
	key[104] = ciphertexts[46][104]^byte('u')
	key[105] = ciphertexts[46][105]^byte('t')
	key[106] = ciphertexts[46][106]^byte(' ')
	key[107] = ciphertexts[46][107]^byte('t')
	key[108] = ciphertexts[46][108]^byte('h')
	key[109] = ciphertexts[46][109]^byte('e')
	key[110] = ciphertexts[46][110]^byte(' ')
	key[111] = ciphertexts[46][111]^byte('m')
	key[112] = ciphertexts[46][112]^byte('o')
	key[113] = ciphertexts[46][113]^byte('n')
	key[114] = ciphertexts[46][114]^byte('e')
	key[115] = ciphertexts[46][115]^byte('y')
	key[116] = ciphertexts[26][116]^byte('r')
	key[117] = ciphertexts[26][117]^byte('y')

	plaintexts := []string{
		`I'm rated "R"...this is a warning, ya better void / Poets are paranoid, DJ's D-stroyed`,
		"Cuz I came back to attack others in spite- / Strike like lightnin', It's quite frightenin'!",
		"But don't be afraid in the dark, in a park / Not a scream or a cry, or a bark, more like a spark;",
		"Ya tremble like a alcoholic, muscles tighten up / What's that, lighten up! You see a sight but",
		"Suddenly you feel like your in a horror flick / You grab your heart then wish for tomorrow quick!",
		"Music's the clue, when I come your warned / Apocalypse Now, when I'm done, ya gone!",
		"Haven't you ever heard of a MC-murderer? / This is the death penalty,and I'm servin' a",
		"Death wish, so come on, step to this / Hysterical idea for a lyrical professionist!",
		"Friday the thirteenth, walking down Elm Street / You come in my realm ya get beat!",
		"This is off limits, so your visions are blurry / All ya see is the meters at a volume",
		"Terror in the styles, never error-files / Indeed I'm known-your exiled!",
		"For those that oppose to be level or next to this / I ain't a devil and this ain't the Exorcist!",
		"Worse than a nightmare, you don't have to sleep a wink / The pain's a migraine every time ya think",
		"Flashbacks interfere, ya start to hear: / The R-A-K-I-M in your ear;",
		"Then the beat is hysterical / That makes Eric go get a ax and chops the wack",
		"Soon the lyrical format is superior / Faces of death remain",
		"MC's decaying, cuz they never stayed / The scene of a crime every night at the show",
		"The fiend of a rhyme on the mic that you know / It's only one capable, breaks-the unbreakable",
		"Melodies-unmakable, pattern-unescapable / A horn if want the style I posses",
		"I bless the child, the earth, the gods and bomb the rest / For those that envy a MC it can be",
		"Hazardous to your health so be friendly / A matter of life and death, just like a etch-a-sketch",
		"Shake 'till your clear, make it disappear, make the next / After the ceremony, let the rhyme rest in peace",
		"If not, my soul'll release! / The scene is recreated, reincarnated, updated, I'm glad you made it",
		"Cuz your about to see a disastrous sight / A performance never again performed on a mic:",
		`Lyrics of fury! A fearified freestyle! / The "R" is in the house-too much tension!`,
		"Make sure the system's loud when I mention / Phrases that's fearsome",
		"You want to hear some sounds that not only pounds but please your eardrums; / I sit back and observe the whole scenery",
		"Then nonchalantly tell you what it mean to me / Strictly business I'm quickly in this mood",
		"And I don't care if the whole crowd's a witness! / I'm a tear you apart but I'm a spare you a heart",
		"Program into the speed of the rhyme, prepare to start / Rhythm's out of the radius, insane as the craziest",
		"Musical madness MC ever made, see it's / Now an emergency, open-heart surgery",
		"Open your mind, you will find every word'll be / Furier than ever, I remain the furture",
		"Battle's tempting...whatever suits ya! / For words the sentence, there's no resemblance",
		"You think you're ruffer, then suffer the consequences! / I'm never dying-terrifying results",
		"I wake ya with hundreds of thousands of volts / Mic-to-mouth resuscitation, rhythm with radiation",
		"Novocain ease the pain it might save him / If not, Eric B.'s the judge, the crowd's the jury",
		"Yo Rakim, what's up? / Yo, I'm doing the knowledge, E., man I'm trying to get paid in full",
		"Well, check this out, since Norby Walters is our agency, right? / True",
		"Kara Lewis is our agent, word up / Zakia and 4th and Broadway is our record company, indeed",
		"Okay, so who we rollin' with then? We rollin' with Rush / Of Rushtown Management",
		"Check this out, since we talking over / This def beat right here that I put together",
		"I wanna hear some of them def rhymes, you know what I'm sayin'? / And together, we can get paid in full",
		"Thinkin' of a master plan / 'Cuz ain't nuthin' but sweat inside my hand",
		"So I dig into my pocket, all my money is spent / So I dig deeper but still comin' up with lint",
		"So I start my mission, leave my residence / Thinkin' how could I get some dead presidents",
		"I need money, I used to be a stick-up kid / So I think of all the devious things I did",
		"I used to roll up, this is a hold up, ain't nuthin' funny / Stop smiling, be still, don't nuthin' move but the money",
		"But now I learned to earn 'cuz I'm righteous / I feel great, so maybe I might just",
		"Search for a nine to five, if I strive / Then maybe I'll stay alive",
		"So I walk up the street whistlin' this / Feelin' out of place 'cuz, man, do I miss",
		"A pen and a paper, a stereo, a tape of / Me and Eric B, and a nice big plate of",
		"Fish, which is my favorite dish / But without no money it's still a wish",
		"'Cuz I don't like to dream about gettin' paid / So I dig into the books of the rhymes that I made",
		"So now to test to see if I got pull / Hit the studio, 'cuz I'm paid in full",
		"Rakim, check this out, yo / You go to your girl house and I'll go to mine",
		"'Cause my girl is definitely mad / 'Cause it took us too long to do this album",
		"Yo, I hear what you're saying / So let's just pump the music up",
		"And count our money / Yo, well check this out, yo Eli",
		"Turn down the bass down / And let the beat just keep on rockin'",
		"And we outta here / Yo, what happened to peace? / Peace",
	}
	success := true
	for j, ciphertext := range ciphertexts {
		plaintext := string(xor(key, ciphertext))[:len(ciphertext)]
		if plaintexts[j] != plaintext {
			success = false
		}
	}
	if !success {
		t.Error("failed")
	}
}

func TestS3C22(t *testing.T) {
	rand2, _ := rand.Int(rand.Reader, big.NewInt(5))
	time.Sleep(time.Duration(rand2.Int64()) * time.Second)
	currrent_time := int(time.Now().Unix())
	mtRand := MTRand{
		index: recurrenceDegree,
		state: mtInit(currrent_time),
	}
	rand3, _ := rand.Int(rand.Reader, big.NewInt(5))
	time.Sleep(time.Duration(rand3.Int64()) * time.Second)
	_, out := nextRand(mtRand)
	// attack begins here
	timeUpper := time.Now().Unix()
	timeLower := timeUpper - 15
	possibles := make([]int, 16)
	for i := int(timeLower); i <= int(timeUpper); i++ {
		mtRand2 := MTRand{
			index: recurrenceDegree,
			state: mtInit(i),
		}
		_, r := nextRand(mtRand2)
		possibles[i-int(timeLower)] = r.state[0]
	}
	ans := -1
	for i, possible := range possibles {
		if possible == out.state[0] {
			// log.Println(i)
			// log.Println(i+int(timeLower))
			ans = i+int(timeLower)
		}
	}
	if currrent_time !=  ans {
		t.Error("failed")
	}
}

func TestInverses(t *testing.T) {
	success := true
	for i := 2552582929; i < 2552582930; i++ {
		x := temper(i)
		z := untemper(x)
		if i != z {
			log.Printf("Temper and untemper not inverse on input %d", i)
			success = false
		}
	}
	if !success {
		t.Error("failed")
	}
}

func TestS3C23(t *testing.T) {
	mtRand := MTRand{
		index: 0,
		state: mtInit(int(time.Now().Unix())),
	}
	allOutputs := make([]int, 624)
	allOutputs[0], mtRand = nextRand(mtRand)
	for i := 1; i < 624; i++ {
		var out int
		out, mtRand = nextRand(mtRand)
		allOutputs[i] = out
	}
	// attack begins
	state := make([]int, 624)
	for i := 0; i < 624; i++ {
		state[i] = untemper(allOutputs[i])
	}
	mtRandClone := MTRand {
		state: state,
		index:recurrenceDegree,
	}
	success := true
	for i:=0;i<1000;i++{
		var out1 int
		var out2 int
		out1, mtRand = nextRand(mtRand)
		out2, mtRandClone = nextRand(mtRandClone)
		if out1 != out2 {
			success = false
			log.Println("Not equal.")
			log.Println(out1, out2)
		}
	}
	if !success {
		t.Error("failed")
	}
}

func TestS3C24Init(t *testing.T) {
	plaintext := make([]byte, 17)
	rand.Read(plaintext[:])
	srReader := mtStreamReader{
		reader: strings.NewReader(string(plaintext)),
		mtRand: MTRand{
			state: mtInit(int(5)),
			index: recurrenceDegree,
		},
	}
	out := make([]byte, 0)
	for {
		b := make([]byte, 1)
		_, err := srReader.Read(b)
		if err != nil {
			break
		}
		out = append(out, b[0])
	}
	srReader2 := mtStreamReader{
		reader: strings.NewReader(string(out)),
		mtRand: MTRand{
			state: mtInit(int(5)),
			index: recurrenceDegree,
		},
	}
	orig := make([]byte, 0)
	for {
		b := make([]byte, 1)
		_, err := srReader2.Read(b)
		if err != nil {
			break
		}
		orig = append(orig, b[0])
	}
	if !(bytes.Equal(plaintext, orig)) {
		t.Error("Failed")
	}
}

func TestS3C24(t *testing.T) {
	plaintext := make([]byte, 14)
	for i, _ := range plaintext {
		plaintext[i] = byte('A')
	}
	preLength, _ := rand.Int(rand.Reader, big.NewInt(20))
	pre := make([]byte, preLength.Int64())
	rand.Read(pre)
	// 16 bit number is 0 through 65535
	seed_array := make([]byte, 2)
	rand.Read(seed_array)
	seed := int(seed_array[0])+(2^8)*int(seed_array[1])
	// log.Print(seed)
	srReader := mtStreamReader{
		reader: strings.NewReader(string(plaintext)),
		mtRand: MTRand{
			state: mtInit(int(seed)), // why this number? 233455
			index: recurrenceDegree,
		},
	}
	out := make([]byte, len(plaintext))
	_, err := srReader.Read(out)
	if err != nil {
		log.Println("Error in reading.")
	}
	ans := -1
	for i := 0; i < 65535; i++ {
		ithSrReader := mtStreamReader{
			reader: strings.NewReader(string(out)),
			mtRand: MTRand{
				state: mtInit(int(i)),
				index: recurrenceDegree,
			},
		}
		orig := make([]byte, len(out))
		ithSrReader.Read(orig)
		if bytes.Equal(orig, plaintext) {
			// log.Println(i)
			ans = i
			break
		}
	}
	if ans != seed {
		t.Error("Failed")
	}
}
