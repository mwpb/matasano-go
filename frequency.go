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

var ef = map[byte]float64{
	0:   0.0,
	1:   0.00006065,
	2:   0.0,
	3:   0.0,
	4:   0.0,
	5:   0.0,
	6:   0.00000106,
	7:   0.0,
	8:   0.0,
	9:   0.00293149,
	10:  3.34137941,
	11:  0.0,
	12:  0.0,
	13:  0.18547217,
	14:  0.00004895,
	15:  0.0,
	16:  0.0,
	17:  0.0,
	18:  0.00000106,
	19:  0.0,
	20:  0.00000213,
	21:  0.0,
	22:  0.0,
	23:  0.0,
	24:  0.0,
	25:  0.00000532,
	26:  0.00003724,
	27:  0.0,
	28:  0.00002873,
	29:  0.00000426,
	30:  0.0,
	31:  0.0,
	32:  15.5642948,
	33:  0.04978527,
	34:  0.06802753,
	35:  0.01698134,
	36:  0.03367965,
	37:  0.02475005,
	38:  0.07318184,
	39:  0.12332144,
	40:  0.32034293,
	41:  0.32187517,
	42:  0.0301757,
	43:  0.02376792,
	44:  0.54622705,
	45:  0.54272842,
	46:  0.89817577,
	47:  0.18951134,
	48:  0.87509417,
	49:  0.69001145,
	50:  0.58333936,
	51:  0.35612942,
	52:  0.2508289,
	53:  0.31718267,
	54:  0.19594146,
	55:  0.16774598,
	56:  0.18591588,
	57:  0.22559045,
	58:  0.29410106,
	59:  0.02669941,
	60:  0.01375298,
	61:  0.05480125,
	62:  0.0491628,
	63:  0.04812002,
	64:  0.00726328,
	65:  0.66427076,
	66:  0.37643276,
	67:  0.53016186,
	68:  0.40644459,
	69:  0.48421253,
	70:  0.31405539,
	71:  0.24633325,
	72:  0.25824647,
	73:  0.43123827,
	74:  0.10063673,
	75:  0.12922166,
	76:  0.38926959,
	77:  0.45386978,
	78:  0.34613789,
	79:  0.28722297,
	80:  0.45093829,
	81:  0.04384569,
	82:  0.41840782,
	83:  0.76432864,
	84:  0.52705374,
	85:  0.1876237,
	86:  0.2005265,
	87:  0.20786107,
	88:  0.03504271,
	89:  0.08069304,
	90:  0.04324343,
	91:  0.03571733,
	92:  0.00586617,
	93:  0.03564178,
	94:  0.00210152,
	95:  0.03404462,
	96:  0.00204512,
	97:  5.47396031,
	98:  0.90639884,
	99:  2.15659037,
	100: 2.2690552,
	101: 7.97273557,
	102: 1.06169318,
	103: 1.36198707,
	104: 1.90843545,
	105: 5.09892892,
	106: 0.13191693,
	107: 0.59099954,
	108: 3.0237658,
	109: 1.73293566,
	110: 4.57205181,
	111: 5.01976067,
	112: 1.3598515,
	113: 0.09211893,
	114: 4.56808605,
	115: 4.28342108,
	116: 4.8591556,
	117: 2.05072803,
	118: 0.73583416,
	119: 0.72619164,
	120: 0.20670975,
	121: 1.01025542,
	122: 0.22386348,
	123: 0.01061188,
	124: 0.11305751,
	125: 0.01066934,
	126: 0.00361142,
	127: 0.0,
	128: 0.00104704,
	129: 0.00002979,
	130: 0.00004043,
	131: 0.0000117,
	132: 0.00038945,
	133: 0.00064908,
	134: 0.00000319,
	135: 0.00000745,
	136: 0.00000638,
	137: 0.0,
	138: 0.0,
	139: 0.00007129,
	140: 0.00000638,
	141: 0.00000532,
	142: 0.00000106,
	143: 0.0000117,
	144: 0.00007023,
	145: 0.00003405,
	146: 0.00153012,
	147: 0.00058949,
	148: 0.00027878,
	149: 0.00549907,
	150: 0.00054799,
	151: 0.00006384,
	152: 0.00000426,
	153: 0.00010428,
	154: 0.00000213,
	155: 0.00003618,
	156: 0.00002873,
	157: 0.00003511,
	158: 0.00000319,
	159: 0.00002341,
	160: 0.84838518,
	161: 0.0007874,
	162: 0.00015961,
	163: 0.02557576,
	164: 0.00021813,
	165: 0.00049479,
	166: 0.00012662,
	167: 0.00032773,
	168: 0.0001362,
	169: 0.0116653,
	170: 0.00006384,
	171: 0.00271655,
	172: 0.0000798,
	173: 0.00028942,
	174: 0.00186423,
	175: 0.00003618,
	176: 0.00240584,
	177: 0.00022452,
	178: 0.00100235,
	179: 0.00012875,
	180: 0.00098745,
	181: 0.00081933,
	182: 0.00010002,
	183: 0.00502875,
	184: 0.00007129,
	185: 0.00012343,
	186: 0.00057885,
	187: 0.01318478,
	188: 0.0000681,
	189: 0.00010428,
	190: 0.00006704,
	191: 0.00094914,
	192: 0.00013726,
	193: 0.00097362,
	194: 0.00033412,
	195: 0.00191637,
	196: 0.00137902,
	197: 0.0005033,
	198: 0.00000638,
	199: 0.00096297,
	200: 0.00004469,
	201: 0.00128113,
	202: 0.00003192,
	203: 0.00000958,
	204: 0.00000958,
	205: 0.00037561,
	206: 0.00025005,
	207: 0.00002235,
	208: 0.00039583,
	209: 0.00057566,
	210: 0.00000532,
	211: 0.00078847,
	212: 0.00004256,
	213: 0.00013726,
	214: 0.00155353,
	215: 0.00142371,
	216: 0.00009577,
	217: 0.0000415,
	218: 0.00102256,
	219: 0.00000426,
	220: 0.00244415,
	221: 0.0,
	222: 0.00000106,
	223: 0.00486701,
	224: 0.01774215,
	225: 0.02266981,
	226: 0.00353055,
	227: 0.00239946,
	228: 0.02842,
	229: 0.00529902,
	230: 0.00015322,
	231: 0.00826882,
	232: 0.01103112,
	233: 0.09216681,
	234: 0.00512239,
	235: 0.00056927,
	236: 0.00014578,
	237: 0.01743463,
	238: 0.00405194,
	239: 0.00027027,
	240: 0.00003724,
	241: 0.00700578,
	242: 0.00029474,
	243: 0.02382326,
	244: 0.006262,
	245: 0.00085444,
	246: 0.02208032,
	247: 0.00000745,
	248: 0.00010747,
	249: 0.00074697,
	250: 0.00674295,
	251: 0.00090658,
	252: 0.03302206,
	253: 0.00067781,
	254: 0.00000213,
	255: 0.00000426,
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
