package cryptopals

import (
	"math"
)

func get_frequency(bytes []byte) (map[byte]int, int) {
	actual_frequency := map[byte]int{}
	for i := 0; i < 256; i++ {
		actual_frequency[byte(i)] = 0
	}
	for _, r := range bytes {
		actual_frequency[r] += 1
	}
	return actual_frequency, len(bytes)
}

// calculation is in frequency-prep.csv
var expected_percentage = map[byte]float64{32: 19.0, 65: 0.348992722, 66: 0.210528313, 67: 0.284925153, 68: 0.161034768, 69: 0.171980193, 70: 0.125157476, 71: 0.115792187, 72: 0.153581295, 73: 0.277408326, 74: 0.097772174, 75: 0.057863795, 76: 0.132900392, 77: 0.322330407, 78: 0.255168405, 79: 0.131305349, 80: 0.179180248, 81: 0.01448334, 82: 0.181924368, 83: 0.37884885, 84: 0.404303703, 85: 0.071414209, 86: 0.038575449, 87: 0.133162506, 88: 0.009413736, 89: 0.117140023, 9: 0.006968997, 97: 6.538905741, 98: 1.075978388, 99: 2.435312972, 100: 2.943898215, 101: 9.617268335, 102: 1.611099237, 103: 1.499076022, 104: 3.67190128, 105: 5.624057774, 106: 0.081809319, 107: 0.572411816, 108: 3.171641566, 109: 1.822841223, 110: 5.634260336, 111: 5.874909376, 112: 1.559737354, 113: 0.067355793, 114: 5.140348497, 115: 5.200300507, 116: 6.841905566, 117: 2.004143226, 118: 0.811645938, 119: 1.261694089, 120: 0.153512971, 121: 1.319314404, 122: 0.082513672}

func score(bytes []byte) float64 {
	actual_frequencies, n := get_frequency(bytes)
	score := 0.0
	for s, percent := range expected_percentage {
		actual := float64(actual_frequencies[s]) * 100.0 / float64(n)
		score = score + math.Pow(percent-actual, 2.0)
	}
	return score
}

func textscores(all [][]byte) ([][]byte, []float64) {
	scores := make([]float64, len(all))
	texts := make([][]byte, len(all))
	for i, bytes := range all {
		scores[i] = score(bytes)
		texts[i] = bytes
	}
	return texts, scores
}

func minScore(all [][]byte) ([]byte, float64) {
	texts, scores := textscores(all)
	currentMinScore := scores[0]
	currentBytes := texts[0]
	for i, score := range scores {
		if score < currentMinScore {
			currentMinScore = score
			currentBytes = texts[i]
		}
	}
	return currentBytes, currentMinScore
}
