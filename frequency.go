package cryptopals

import (
	"math"
	"strings"
	"unicode"
)

func get_frequency(plaintext string) map[string]int {
	n := len(plaintext)
	plaintext = strings.ToLower(plaintext)
	actual_frequency := map[string]int{}
	for i := 97; i < 123; i++ {
		actual_frequency[string(i)] = 0
	}
	actual_frequency[" "] = 0
	actual_frequency["other"] = 0
	for _, r := range plaintext {
		char := string(r)
		if unicode.IsLetter(r) {
			actual_frequency[char] += 1
		} else if char == " " {
			actual_frequency[" "] += 1
		} else {
			actual_frequency["other"] += 1
		}
	}
	actual_frequency["len"] = n
	return actual_frequency
}

var expected_percentage = map[string]float64{
	"a":     8.167,
	"b":     1.492,
	"c":     2.782,
	"d":     4.253,
	"e":     12.70,
	"f":     2.228,
	"g":     2.015,
	"h":     6.094,
	"i":     6.966,
	"j":     0.153,
	"k":     0.772,
	"l":     4.025,
	"m":     2.406,
	"n":     6.749,
	"o":     7.507,
	"p":     1.929,
	"q":     0.095,
	"r":     5.987,
	"s":     6.327,
	"t":     9.056,
	"u":     2.758,
	"v":     0.978,
	"w":     2.360,
	"x":     0.150,
	"y":     1.974,
	"z":     0.074,
	"other": 0.0,
	// " ":     19.18182,
}

func sumMap(inMap map[string]float64) float64 {
	currentTotal := 0.0
	for k, v := range inMap {
		if k != " " {
			currentTotal = currentTotal + v
		}
	}
	// log.Println(currentTotal)
	return currentTotal
}

func score(plaintext string) float64 {
	actual_frequencies := get_frequency(plaintext)
	score := 0.0
	for s, percent := range expected_percentage {
		actual := float64(actual_frequencies[s]) * 100.0 / float64(actual_frequencies["len"]-(actual_frequencies[" "]))
		score = score + math.Pow(percent-actual, 2.0)
	}
	// log.Println(score)
	return score
}

func scores(plaintexts map[byte]string) map[string]float64 {
	scores := make(map[string]float64, 0)
	for _, plaintext := range plaintexts {
		scores[plaintext] = score(plaintext)
	}
	return scores
}

func minScore(plaintexts map[byte]string) (string, float64) {
	scores := scores(plaintexts)
	// log.Println(scores)
	currentMinScore := -1.0
	currentPlaintext := ""
	for plaintext, score := range scores {
		if currentMinScore == -1.0 {
			currentMinScore = score
			currentPlaintext = plaintext
			// log.Println(currentMinScore)
		} else if score < currentMinScore {
			currentMinScore = score
			currentPlaintext = plaintext
			// log.Println(currentMinScore)
		}
	}
	// log.Println(currentPlaintext)
	return currentPlaintext, currentMinScore
}
