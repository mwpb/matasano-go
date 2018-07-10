package cryptopals

import (
	"math"
)

func asciiFrequency(bytes []byte) ([]int, int) {
	actual_frequency := make([]int, 256)
	for _, b := range bytes {
		actual_frequency[b] += 1
	}
	return actual_frequency, len(bytes)
}

var expected_percentage = []float64{0.0, 0.00006065, 0.0, 0.0, 0.0, 0.0, 0.00000106, 0.0, 0.0, 0.00293149, 3.34137941, 0.0, 0.0, 0.18547217, 0.00004895, 0.0, 0.0, 0.0, 0.00000106, 0.0, 0.00000213, 0.0, 0.0, 0.0, 0.0, 0.00000532, 0.00003724, 0.0, 0.00002873, 0.00000426, 0.0, 0.0, 15.5642948, 0.04978527, 0.06802753, 0.01698134, 0.03367965, 0.02475005, 0.07318184, 0.12332144, 0.32034293, 0.32187517, 0.0301757, 0.02376792, 0.54622705, 0.54272842, 0.89817577, 0.18951134, 0.87509417, 0.69001145, 0.58333936, 0.35612942, 0.2508289, 0.31718267, 0.19594146, 0.16774598, 0.18591588, 0.22559045, 0.29410106, 0.02669941, 0.01375298, 0.05480125, 0.0491628, 0.04812002, 0.00726328, 0.66427076, 0.37643276, 0.53016186, 0.40644459, 0.48421253, 0.31405539, 0.24633325, 0.25824647, 0.43123827, 0.10063673, 0.12922166, 0.38926959, 0.45386978, 0.34613789, 0.28722297, 0.45093829, 0.04384569, 0.41840782, 0.76432864, 0.52705374, 0.1876237, 0.2005265, 0.20786107, 0.03504271, 0.08069304, 0.04324343, 0.03571733, 0.00586617, 0.03564178, 0.00210152, 0.03404462, 0.00204512, 5.47396031, 0.90639884, 2.15659037, 2.2690552, 7.97273557, 1.06169318, 1.36198707, 1.90843545, 5.09892892, 0.13191693, 0.59099954, 3.0237658, 1.73293566, 4.57205181, 5.01976067, 1.3598515, 0.09211893, 4.56808605, 4.28342108, 4.8591556, 2.05072803, 0.73583416, 0.72619164, 0.20670975, 1.01025542, 0.22386348, 0.01061188, 0.11305751, 0.01066934, 0.00361142, 0.0, 0.00104704, 0.00002979, 0.00004043, 0.0000117, 0.00038945, 0.00064908, 0.00000319, 0.00000745, 0.00000638, 0.0, 0.0, 0.00007129, 0.00000638, 0.00000532, 0.00000106, 0.0000117, 0.00007023, 0.00003405, 0.00153012, 0.00058949, 0.00027878, 0.00549907, 0.00054799, 0.00006384, 0.00000426, 0.00010428, 0.00000213, 0.00003618, 0.00002873, 0.00003511, 0.00000319, 0.00002341, 0.84838518, 0.0007874, 0.00015961, 0.02557576, 0.00021813, 0.00049479, 0.00012662, 0.00032773, 0.0001362, 0.0116653, 0.00006384, 0.00271655, 0.0000798, 0.00028942, 0.00186423, 0.00003618, 0.00240584, 0.00022452, 0.00100235, 0.00012875, 0.00098745, 0.00081933, 0.00010002, 0.00502875, 0.00007129, 0.00012343, 0.00057885, 0.01318478, 0.0000681, 0.00010428, 0.00006704, 0.00094914, 0.00013726, 0.00097362, 0.00033412, 0.00191637, 0.00137902, 0.0005033, 0.00000638, 0.00096297, 0.00004469, 0.00128113, 0.00003192, 0.00000958, 0.00000958, 0.00037561, 0.00025005, 0.00002235, 0.00039583, 0.00057566, 0.00000532, 0.00078847, 0.00004256, 0.00013726, 0.00155353, 0.00142371, 0.00009577, 0.0000415, 0.00102256, 0.00000426, 0.00244415, 0.0, 0.00000106, 0.00486701, 0.01774215, 0.02266981, 0.00353055, 0.00239946, 0.02842, 0.00529902, 0.00015322, 0.00826882, 0.01103112, 0.09216681, 0.00512239, 0.00056927, 0.00014578, 0.01743463, 0.00405194, 0.00027027, 0.00003724, 0.00700578, 0.00029474, 0.02382326, 0.006262, 0.00085444, 0.02208032, 0.00000745, 0.00010747, 0.00074697, 0.00674295, 0.00090658, 0.03302206, 0.00067781, 0.00000213, 0.00000426}

func score(block Block) float64 {
	actual_frequencies, n := asciiFrequency(block)
	score := 0.0
	for i, percent := range expected_percentage {
		actual := float64(actual_frequencies[i]) * 100.0 / float64(n)
		score = score + math.Pow(percent-actual, 2.0)
	}
	return score
}

func moreLikely(newBlock Block, currentPlain []byte, currentScore float64, currentKey byte) ([]byte, float64, byte) {
	for i := 0; i < 256; i++ {
		plain := xor(newBlock, []byte{byte(i)})
		score := score(plain)
		if score < currentScore {
			currentScore = score
			currentPlain = plain
			currentKey = byte(i)
			// log.Println(currentScore, currentKey)
		}
	}
	return currentPlain, currentScore, currentKey
}
