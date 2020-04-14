package des

import (
	"encoding/binary"
	"fmt"
)

// XOR the bytes in a slice. a,b assumed to be identical sizes.
func xor(a, b []byte) []byte {
	dst := make([]byte, len(a))
	for i := range dst {
		dst[i] = a[i] ^ b[i]
	}
	return dst
}

// apply a bit permutation following the permutation map.
// in the map the index is the source bit position and the
// value is the output bit position.
func applyPermutation(permutation, data []byte) []byte {
	// bitwise permutation is more tricky. mainly because we can only
	// work on whole bytes
	output := make([]byte, len(permutation)/8)
	for dst, src := range permutation {
		// the index (dst) is where to put it in the output.
		// the value (src) into the permutation is the source bit
		//fmt.Prinln("Applying Permutation bit %d of the src data is set at bit %d if the output")
		srcOn := bitIsSet(data, int(src))
		bitSet(output, dst, srcOn)
	}
	return output
}

// // the same as applyPermutation but takes the index into the permutation
// // as the destination bit position and the value as the source bit position.
// // this one only makes sense works on a one-to-one mapping.
// func applyInversePermutation(permutation, data []byte) []byte {
// 	// bitwise permutation is more tricky. mainly because we can only
// 	// work on whole bytes
// 	output := make([]byte, len(data))
// 	for src, dst := range permutation {
// 		// the index (src) into the permutation is the source bit
// 		// the value (dst) is where to put it in the output.
// 		srcOn := bitIsSet(data, src)
// 		bitSet(output, int(dst), srcOn)
// 	}
// 	return output
// }

// in a slice of bytes, is a particular bit set on?
func bitIsSet(data []byte, pos int) bool {
	if pos/8 >= len(data) {
		fmt.Printf("bitIsSet test: %x, %d\n", data, pos)
		panic("bit out of range")
	}
	b := data[pos/8]
	bb := byte(1 << (7 - (pos % 8)))
	return b&bb != 0
}

// set the particular bit in a slice of bytes to either on or off.
func bitSet(data []byte, pos int, on bool) {
	b := data[pos/8]
	bb := byte(1 << (7 - (pos % 8)))
	if on {
		data[pos/8] = b | bb
	} else {
		data[pos/8] = b &^ bb
	}
}

// most bit rotation functions work on 8,16,32, 64 not 28 bits
// so we have to do this manually.
// we have 56 bits and we want each half to rotate.
// 00000000001111111111222222222233333333334444444444555555
// 01234567890123456789012345678901234567890123456789012345
// 10000000000000000000000000100100000000000000000000000010
// should become:
// 00000000000000000000000001011000000000000000000000000100
//
// the only way I can think of to do this is to split into to 32bit integers
// and rotate those turn back into byte slices and correct the final bits, then
// re-join.
func rotateBoth28BitHalves(b []byte, k int) {
	if k != 1 && k != 2 {
		panic("can only rotate 1 or 2 places")
	}
	// we need to copy as the slices will contain the same data...
	left32 := binary.BigEndian.Uint32(b[:4])
	right32 := binary.BigEndian.Uint32(b[3:])
	// they should both be 4 bytes, but we need to zero the last 4 bit of left
	// and the first 4 bits of right
	//	fmt.Printf("left: %032b, right: %032b\n", left32, right32)

	left32 &= 0xFFFFFFF0
	right32 &= 0x0FFFFFFF

	//fmt.Printf("left: %032b, right: %032b\n", left32, right32)
	// now rotate (func taken from math/bits)
	const n = 32
	s := uint(k) & (n - 1)
	left32 = left32<<s | left32>>(n-s)
	right32 = right32<<s | right32>>(n-s)

	//fmt.Printf("left: %032b, right: %032b\n", left32, right32)

	// now we have the bits rotated, but we need to "fix" the numbers.
	// the left one needs the 28th bit to be whatever is at the final bit.
	// there are 4 bits that may be lost. but we actually only care about a 1 or
	// 2 place rotation.
	if k == 1 {
		if left32&1 != 0 {
			//final bit was set. so we set bit 27
			left32 |= 1 << 4
		} else {
			// turn off bit 27
			left32 = left32 &^ (1 << 4)
		}
		// for the right side we check if the 4th bit is set and set that to the final bit
		if right32&(1<<28) != 0 {
			// was set.
			right32 |= 1
		} else {
			// was not set...
			right32 = right32 &^ 1
		}
	} else {
		// k ==2 and we have to check both bits.
		if left32&1 != 0 {
			//move to position 26
			left32 |= 1 << 4
		} else {
			// turn off bit 26
			left32 = left32 &^ (1 << 4)
		}
		if left32&2 != 0 {
			// move to position 27
			left32 |= 1 << 5
		} else {
			// turn off bit 27
			left32 = left32 &^ (1 << 5)
		}
		// and the right
		if right32&(1<<29) != 0 {
			// was set.
			right32 |= 2
		} else {
			// was not set...
			right32 = right32 &^ 2
		}
		if right32&(1<<28) != 0 {
			// was set.
			right32 |= 1
		} else {
			// was not set...
			right32 = right32 &^ 1
		}
	}
	//fmt.Printf("left: %032b, right: %032b\n", left32, right32)
	// back to byte slices
	binary.BigEndian.PutUint32(b[:4], left32)
	// now take a reference the the final byte which will be blatted in a minute
	left4Bits := b[3] & 0xF0
	// put back the right side
	binary.BigEndian.PutUint32(b[3:], right32)
	// now we need to combine the top bits of b[3] and the bottom bits of left4bits
	right4Bits := b[3] & 0x0F
	b[3] = left4Bits | right4Bits
}

// this is from the go DES implementation which uses a different way of listing the boxes
// general purpose function to perform DES block permutations
func permuteBlock(src uint64, permutation []uint8) (block uint64) {
	for position, n := range permutation {
		bit := (src >> n) & 1
		block |= bit << uint((len(permutation)-1)-position)
	}
	return
}

var initialPermutation = []uint8{
	6, 14, 22, 30, 38, 46, 54, 62,
	4, 12, 20, 28, 36, 44, 52, 60,
	2, 10, 18, 26, 34, 42, 50, 58,
	0, 8, 16, 24, 32, 40, 48, 56,
	7, 15, 23, 31, 39, 47, 55, 63,
	5, 13, 21, 29, 37, 45, 53, 61,
	3, 11, 19, 27, 35, 43, 51, 59,
	1, 9, 17, 25, 33, 41, 49, 57,
}
