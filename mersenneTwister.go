package cryptopals

import (
	"log"
	"math"
)

// References
//
// Original paper: Mersenne Twister: A 623-dimensionally equidistributed uniform pseudorandom number generator
// http://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.215.1141&rep=rep1&type=pdf
//
// Description of init: page 4 of CRYPTOGRAPHIC MERSENNE TWISTER AND FUBUKI STREAM/BLOCK CIPHER
// https://eprint.iacr.org/2005/165.pdf#page=4
//
// Wiki: https://en.wikipedia.org/wiki/Mersenne_Twister#Pseudocode

var wordSize = 32
var fConst = 1812433253 // This choice appears to be arbitrary.
var recurrenceDegree = 624
var constA = 2567483615  // Why?
var separationPoint = 31 //Why?
var middleWord = 397     //Why?
var constU = 11          //Why?
var constD = 4294967295  //Why?
var constS = 7           //Why?
var constB = 2636928640  //Why?
var constT = 15          //Why?
var constC = 4022730752  //Why?
var constL = 18          //Why?

func lowestBits(n int, numberOfBits int) int {
	multiplier := 0.0
	for i := 0; i < numberOfBits; i++ {
		multiplier = multiplier + math.Pow(2.0, float64(i))
	}
	return n & int(multiplier)
}

func mtInit(seed int) []int {
	mt := make([]int, recurrenceDegree)
	mt[0] = seed
	for i := 1; i < recurrenceDegree; i++ {
		mt[i] = lowestBits(((fConst * (mt[i-1] ^ (mt[i-1] >> uint32(wordSize-2)))) + i), wordSize)
	}
	return mt
}

func applyA(x int) int {
	out := x >> 1
	if x%2 != 0 {
		out = out ^ constA
	}
	return out
}

func twist(prevState []int) []int {
	for i := 0; i < recurrenceDegree; i++ {
		lowerMask := (1 << uint(separationPoint)) - 1
		upperMask := lowestBits(^lowerMask, wordSize)
		x := ((prevState[(i+1)%recurrenceDegree]) & lowerMask) + (prevState[i] & upperMask)
		xA := applyA(x)
		prevState[i] = prevState[(i+middleWord)%recurrenceDegree] ^ xA
	}
	return prevState
}

func temper(y int) int {
	y = y ^ ((y >> uint(constU)) & constD)
	y = y ^ ((y << uint(constS)) & constB)
	y = y ^ ((y << uint(constT)) & constC)
	y = y ^ (y >> uint(constL))
	return y
}

func undoT(y int) int {
	z := 0
	for i := 0; i < constT; i++ {
		bit := getBit(y, i)
		if bit {
			z = setBit(z, i)
		} else {
			z = clearBit(z, i)
		}
	}
	for i := constT; i < 2*constT; i++ {
		bit := getBit(y, i) != (getBit(y, i-constT) && getBit(constC, i))
		if bit {
			z = setBit(z, i)
		} else {
			z = clearBit(z, i)
		}
	}
	for i := 2 * constT; i < recurrenceDegree; i++ {
		bit := getBit(y, i)
		if bit {
			z = setBit(z, i)
		} else {
			z = clearBit(z, i)
		}
	}
	return z
}

func undoL(y int) int {
	for i := recurrenceDegree - constL; i >= 0; i-- {
		bit := getBit(y, i) != getBit(y, i+constL)
		if bit {
			setBit(y, i)
		} else {
			clearBit(y, i)
		}
	}
	return y
}

type MTRand struct {
	index int
	state []int
}

func nextRand(rand MTRand) int {
	index := rand.index
	state := rand.state
	if index >= recurrenceDegree {
		if index > recurrenceDegree {
			log.Println("Generator not seeded.")
		}
		state = twist(state)
	}
	y := state[index-1]
	y = temper(y)
	index += 1
	return lowestBits(y, wordSize)
}
