package cryptopals

import (
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
var constD = 4294967295  // All 1s in binary... length 32... the maximum value for 32 bit unsigned int
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
	y = y ^ ((y >> uint(constU)) & constD) // constD in the MT19937 version is 32 1s so (-)&constD is the identity
	y = y ^ ((y << uint(constS)) & constB)
	y = y ^ ((y << uint(constT)) & constC)
	y = y ^ (y >> uint(constL))
	return y
}

func untemper(y int) int {
	y = undoLeft(y, constL)
	y = undoRightAnd(y, constT, constC)
	y = undoRightAnd(y, constS, constB)
	y = undoLeft(y, constU)
	return y
}

func undoRightAnd(z int, shift int, constant int) int {
	y := 0
	for i := 0; i < shift; i++ {
		bit := getBit(z, i)
		if bit {
			y = setBit(y, i)
		} else {
			y = clearBit(y, i)
		}
	}
	for i := shift; i < recurrenceDegree; i++ {
		bit := getBit(z, i) != (getBit(y, i-shift) && getBit(constant, i))
		if bit {
			y = setBit(y, i)
		} else {
			y = clearBit(y, i)
		}
	}
	return y
}

func undoLeft(y int, shift int) int {
	for i := recurrenceDegree - shift; i >= 0; i-- {
		bit := getBit(y, i) != getBit(y, i+shift)
		if bit {
			y = setBit(y, i)
		} else {
			y = clearBit(y, i)
		}
	}
	return y
}

type MTRand struct {
	index int
	state []int
}

func nextRand(rand MTRand) (int, MTRand) {
	if rand.index == recurrenceDegree {
		rand.state = twist(rand.state)
		rand.index = 0
	}
	y := rand.state[rand.index]
	y = temper(y)
	rand.index += 1
	return lowestBits(y, wordSize), rand
}
