package cryptopals

import (
	"testing"
)

func TestSolutions(t *testing.T) {
	// if q1("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d") != "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t" {
	// 	t.Error("failed")
	// }
	// if hexXOR("1c0111001f010100061a024b53535009181c", "686974207468652062756c6c277320657965") != "746865206b696420646f6e277420706c6179" {
	// 	t.Error("failed")
	// }
	// if ans := get_frequency("range on arrays and slices provides both the index and value for each entry. Above we didn’t need the index, so we ignored it with the blank identifier _. Sometimes we actually want the indexes though.")[" "]; ans != 35 {
	// 	t.Errorf("Answer: %d\n Expecting: %d", ans, 0)
	// }
	// if score("range on arrays and slices provides both the index and value for each entry. Above we didn’t need the index, so we ignored it with the blank identifier _. Sometimes we actually want the indexes though.") < 0 {
	// 	t.Error("Score should be positive.")
	// }
	// if score("euWsUnp11cgdl7KF54EPAa2EliwC3ULngy8WtJIumVzcexpGredaQdXblneOcW3RGuOcRE38z6H86BpUDZqrIaeOIY79iJDwvdL58iQPG9E3IxCAnlX76WAZIYSFsQ3b87PSrGrRBdA2pmyPiPTZdOLpjJWHTtsNyat4wWOWtQ4oFgH4SIwUaaWKehh4Mn6GfNzYM4e4Edg2czXdpaSWaNKc6rXruU") < 0 {
	// 	t.Error("Score should be positive.")
	// }
	// if math.Round(sumMap(expected_percentage)) != 100.0 {
	// 	t.Error("Sum of percentages should be 100")
	// }
	// if len(hexXORAlpha("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")) < 0 {
	// 	t.Error("Length should be positive.")
	// }
	if plaintext, _ := minScore(hexXORAlpha("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")); plaintext != "Cooking MC's like a pound of bacon" {
		t.Errorf("Answer: [%s]\nExpecting: [%s]", plaintext, "Cooking MC's like a pound of bacon")
	}
	// if len(hexXORSingle("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736", 'x')) < 0 {
	// 	t.Error("error")
	// }
}
