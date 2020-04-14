package des

// RoundKey is one of the Key Schedule generated keys
type RoundKey []byte

// KeySchedule holds the 16 block-sized derived keys from the input key
// we will generate this before running
type KeySchedule [16]RoundKey

// PermutatedChoice1 or PC1 is part of the key schedule
// it extracts 56bits from the 64bit key (which has parity bits as the high
// bit of each byte)
var PermutatedChoice1 = [56]byte{
	56, 48, 40, 32, 24, 16, 8, 0,
	57, 49, 41, 33, 25, 17, 9, 1,
	58, 50, 42, 34, 26, 18, 10, 2,
	59, 51, 43, 35, 62, 54, 46, 38,
	30, 22, 14, 6, 61, 53, 45, 37,
	29, 21, 13, 5, 60, 52, 44, 36,
	28, 20, 12, 4, 27, 19, 11, 3,
}

// PermutatedChoice2 or PC2 is also part of the key schedule
// it extracts 48 bits from the 56 bit
var PermutatedChoice2 = [48]byte{
	13, 16, 10, 23, 0, 4, 2, 27,
	14, 5, 20, 9, 22, 18, 11, 3,
	25, 7, 15, 6, 26, 19, 12, 1,
	40, 51, 30, 36, 46, 54, 29, 39,
	50, 44, 32, 47, 43, 48, 38, 55,
	33, 52, 45, 41, 49, 35, 28, 31,
}

// var exampleCD = []string{
// 	`[11110000 11001100 10101010 11110101 01010110 01100111 10001111]`,
// 	`[11100001 10011001 01010101 11111010 10101100 11001111 00011110]`,
// 	`[11000011 00110010 10101011 11110101 01011001 10011110 00111101]`,
// 	`[00001100 11001010 10101111 11110101 01100110 01111000 11110101]`,
// 	`[00110011 00101010 10111111 11000101 10011001 11100011 11010101]`,
// 	`[11001100 10101010 11111111 00000110 01100111 10001111 01010101]`,
// 	`[00110010 10101011 11111100 00111001 10011110 00111101 01010101]`,
// 	`[11001010 10101111 11110000 11000110 01111000 11110101 01010110]`,
// 	`[00101010 10111111 11000011 00111001 11100011 11010101 01011001]`,
// 	`[01010101 01111111 10000110 01100011 11000111 10101010 10110011]`,
// 	`[01010101 11111110 00011001 10011111 00011110 10101010 11001100]`,
// 	`[01010111 11111000 01100110 01011100 01111010 10101011 00110011]`,
// 	`[01011111 11100001 10011001 01010001 11101010 10101100 11001111]`,
// 	`[01111111 10000110 01100101 01010111 10101010 10110011 00111100]`,
// 	`[11111110 00011001 10010101 01011110 10101010 11001100 11110001]`,
// 	`[11111000 01100110 01010101 01111010 10101011 00110011 11000111]`,
// 	`[11110000 11001100 10101010 11110101 01010110 01100111 10001111]`,
// }

func generateKeySchedule(key []byte) KeySchedule {
	// fmt.Printf("key0: %08b\n", key)
	// expect a 64bit value.
	cd := applyPermutation(PermutatedChoice1[:], key)

	// fmt.Printf(">>>>: [11110000 11001100 10101010 11110101 01010110 01100111 10001111]\n")
	// fmt.Printf("      %08b :<<< CD0 (0x%X)\n\n", cd, cd)

	schedule := KeySchedule{}
	// we cannot easily "split" into 28 bit sections.
	// so we will just have to work on the whole 56 bit
	// chunk and work out how to rotate each 28 bits seperately.
	for r := 0; r < 16; r++ {
		switch r {
		case 0, 1, 8, 15:
			// shift 1 bit left
			rotateBoth28BitHalves(cd, 1)
		default:
			// shift 2 bits left.
			rotateBoth28BitHalves(cd, 2)
		}
		// fmt.Printf(">>>>: %s\n", exampleCD[r+1])
		// fmt.Printf("      %08b <<<< cd%02d (0x%X)\n\n", cd, r+1, cd)
		// now we pass through PC2 for the key.
		schedule[r] = applyPermutation(PermutatedChoice2[:], cd)
	}
	// fmt.Printf("KeySchedule:\n")
	// for i, k := range schedule {
	// 	fmt.Printf(" %02d: %08b\n", i+1, k)
	// }
	return schedule
}

func reverseSchedule(keySchedule KeySchedule) KeySchedule {
	// the simple but long winded way to do this...
	return KeySchedule{
		keySchedule[15],
		keySchedule[14],
		keySchedule[13],
		keySchedule[12],
		keySchedule[11],
		keySchedule[10],
		keySchedule[9],
		keySchedule[8],
		keySchedule[7],
		keySchedule[6],
		keySchedule[5],
		keySchedule[4],
		keySchedule[3],
		keySchedule[2],
		keySchedule[1],
		keySchedule[0],
	}
}
