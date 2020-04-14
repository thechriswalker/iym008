package des

// FeistelRound performs 1 round of a feistel network with the block
// and the round key. The feistel function f is used as defined elsewhere.
// we assume all the slices are the correct length!
func FeistelRound(data []byte, key RoundKey) []byte {
	// split data into left/right

	// create a copy of our block
	input := make([]byte, BlockSize)
	copy(input, data[:])

	// slice it in half.
	left, right := input[:BlockSize/2], input[BlockSize/2:]

	// apply f (right, key)
	appliedF := FeistelRoundF(right, key)
	// fmt.Printf("fies: %08b\n", appliedF)

	// XOR left with f(right, key) set as new right
	newRight := xor(left, appliedF)
	// fmt.Printf("newR: %08b\n", newRight)
	// right as new left and recreate the output block
	output := make([]byte, BlockSize)
	copy(output[:BlockSize/2], input[BlockSize/2:])
	copy(output[BlockSize/2:], newRight)
	return output
}

// FeistelRoundF is the "f" function in the DES feistel cipher
func FeistelRoundF(right []byte, key RoundKey) []byte {
	// expand the right to 48 bits (E-Box) (with the permutation)
	expanded := applyPermutation(EBoxPermutation[:], right)

	// fmt.Printf("ebox: %08b\n", expanded)
	// fmt.Printf("rkey: %08b\n", key)
	// XOR round key with the expanded right
	xored := xor(expanded, key[:])
	// fmt.Printf("xord: %08b\n", xored)
	// pass each 6bits into the SBoxes each outputing 4 bits for 32 bits output
	sboxed := make([]byte, 4)
	for i := 0; i < 8; i++ {
		// the sboxes work on 6 bits at a time.
		sbox := SBoxes[i]
		// the 2 outer bits are the row.
		outer1 := bitIsSet(xored, i*6)
		inner1 := bitIsSet(xored, i*6+1)
		inner2 := bitIsSet(xored, i*6+2)
		inner3 := bitIsSet(xored, i*6+3)
		inner4 := bitIsSet(xored, i*6+4)
		outer2 := bitIsSet(xored, i*6+5)

		// the 2 outers are used to select the row.
		// the inners to select the column.
		// this is a massive pain in the ass
		row := 0
		if outer1 {
			row |= 2
		}
		if outer2 {
			row |= 1
		}
		col := 0
		if inner1 {
			col |= 8
		}
		if inner2 {
			col |= 4
		}
		if inner3 {
			col |= 2
		}
		if inner4 {
			col |= 1
		}
		sboxValue := []byte{sbox[row][col]}
		// now we need to set those 4 bits of output into the next output
		//fmt.Printf("SBOX %d row:%d, col:%d from bits: %d-%d\n%08b => %08b\n", i, row, col, i*6, i*6+5, xored, sboxValue)
		for b := 0; b < 4; b++ {
			bitSet(sboxed, i*4+b, bitIsSet(sboxValue, 4+b)) // b is an 8 bit value and we only want the final 4
		}
	}
	// fmt.Printf("sbox: %08b\n", sboxed)

	// final round permutation
	return applyPermutation(PostRoundPermutation[:], sboxed)
}

// 00011011 00000010 11101111 11111100 01110000 01110010
// 00011011 00000010 11101101 11111100 01110000 01110010
