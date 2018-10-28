package main

import "math/bits"

func getBit(n int, index int) bool {
	indicator := (1 << uint(index))
	bit := bits.OnesCount(uint(indicator & n))
	return bit == 1
}

func setBit(n int, index int) int {
	indicator := (1 << uint(index))
	out := indicator | n
	return out
}

func clearBit(n int, index int) int {
	indicator := ^(1 << uint(index))
	out := indicator & n
	return out
}
