package des

import (
	"fmt"
	"testing"
)

type keyTest struct {
	key      []byte
	schedule []string
}

var keyTests = []keyTest{
	{
		key: []byte{0x13, 0x34, 0x57, 0x79, 0x9b, 0xbc, 0xdf, 0xf1},
		schedule: []string{
			`[00011011 00000010 11101111 11111100 01110000 01110010]`,
			`[01111001 10101110 11011001 11011011 11001001 11100101]`,
			`[01010101 11111100 10001010 01000010 11001111 10011001]`,
			`[01110010 10101101 11010110 11011011 00110101 00011101]`,
			`[01111100 11101100 00000111 11101011 01010011 10101000]`,
			`[01100011 10100101 00111110 01010000 01111011 00101111]`,
			`[11101100 10000100 10110111 11110110 00011000 10111100]`,
			`[11110111 10001010 00111010 11000001 00111011 11111011]`,
			`[11100000 11011011 11101011 11101101 11100111 10000001]`,
			`[10110001 11110011 01000111 10111010 01000110 01001111]`,
			`[00100001 01011111 11010011 11011110 11010011 10000110]`,
			`[01110101 01110001 11110101 10010100 01100111 11101001]`,
			`[10010111 11000101 11010001 11111010 10111010 01000001]`,
			`[01011111 01000011 10110111 11110010 11100111 00111010]`,
			`[10111111 10010001 10001101 00111101 00111111 00001010]`,
			`[11001011 00111101 10001011 00001110 00010111 11110101]`,
		},
	},
}

func TestKeySchedule(t *testing.T) {
	for _, test := range keyTests {
		s := generateKeySchedule(test.key)
		for i, k := range s {
			sk := fmt.Sprintf("%08b", k)
			if sk != test.schedule[i] {
				t.Errorf("KeyScheduleFail for round %d\nExpected: %s\n     got: %s", i+1, test.schedule[i], sk)
			}
		}
	}
}
