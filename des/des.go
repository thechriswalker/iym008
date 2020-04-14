package des

import (
	"fmt"
	"io"
)

const (
	// BlockSize - DES uses 64 bit blocks (8 bytes)
	BlockSize = 8
	// RoundKeySize - is only 6 bytes
	RoundKeySize = 6
)

// DES represent the cipher ready to encrypt/decrypt.
// basically all we have done is create the KeySchedule
type DES struct {
	schedule KeySchedule
	reversed KeySchedule
}

func NewDES(key []byte) *DES {
	if len(key) != BlockSize {
		panic("Invalid DES Key Length")
	}
	schedule := generateKeySchedule(key)
	reversed := reverseSchedule(schedule)
	return &DES{
		schedule: schedule,
		reversed: reversed,
	}
}

func (d *DES) algorithm(block []byte, schedule KeySchedule) []byte {
	if len(block) != BlockSize {
		panic("Invalid DES Block Size")
	}
	curr := applyPermutation(InitialPermutation[:], block)
	var next []byte
	for rnd := 0; rnd < 16; rnd++ {
		// fmt.Printf("\nROUND %02d\n", rnd+1)
		// fmt.Printf("curr: %08b\n", curr)
		next = FeistelRound(curr, schedule[rnd])
		// fmt.Printf("next: %08b\n", next)
		curr = next
	}
	preFinal := make([]byte, BlockSize)

	// we need to reverse the final left/right swap of the last round
	// copy first half of next to second half of preFinal
	copy(preFinal[BlockSize/2:], next[:BlockSize/2])
	// copy second half of next to first half of preFinal
	copy(preFinal[:BlockSize/2], next[BlockSize/2:])
	// now the final inverse permutation
	// fmt.Printf("pref: %08b\n", preFinal)
	final := applyPermutation(FinalPermutation[:], preFinal)
	// fmt.Printf("finl: %08b\n", final)
	return final
}

// EncryptBlock encrypts one block's worth of data
func (d *DES) EncryptBlock(plain []byte) (cipher []byte) {
	//fmt.Println("ENCRYPT")
	return d.algorithm(plain, d.schedule)
}

// DecryptBlock (basically encryptBlock with the schedule backwards)
// There is a way to make the key-schedule an iterator, so we don't
// have to create all the keys up front. But this seems a waste of
// time when the RAM is cheap and we will need the 16 keys over and
// over again during multi-block encryption/decryption. So we will
// pre-generate all the keys and simply apply them the other way.
func (d *DES) DecryptBlock(cipher []byte) (plain []byte) {
	//fmt.Println("DECRYPT")
	return d.algorithm(cipher, d.reversed)
}

// EncryptECB - ECB mode is easiest
// to encrypt a bigger chunk of data we need a "mode". I am
// only going to implement ECB as it is the simplest!
// also I will do it with a reader/writer API as that
// is a very practical way to do things in Go
func (d *DES) EncryptECB(plain io.Reader, cipher io.Writer) error {
	// some notion of padding?
	// I think openssl uses PKCS5 (https://www.cryptosys.net/pki/manpki/pki_paddingschemes.html)
	block := make([]byte, BlockSize)
	var err error
	var n int
	var finalBlock bool
	var finalPad bool
	for {
		n, err = plain.Read(block)
		if err != nil {
			if err != io.EOF {
				return err
			}
			// err is EOF.
			finalBlock = true
			// We need to work out the padding.
			// based on how many bytes we just read.
			for i := n; i < BlockSize; i++ {
				// pad with BlockSize-n at position i
				block[i] = byte(BlockSize - n)
			}
			if n == BlockSize {
				finalPad = true
			}
		}
		// encrypt the block!
		_, err = cipher.Write(d.EncryptBlock(block))
		if err != nil {
			return err
		}
		if finalBlock {
			if finalPad {
				_, err = cipher.Write(d.EncryptBlock([]byte{8, 8, 8, 8, 8, 8, 8, 8}))
				if err != nil {
					return err
				}
			}
			return nil
		}
	}
}

// DecryptECB - ECB mode is easiest
// to encrypt a bigger chunk of data we need a "mode". I am
// only going to implement ECB as it is the simplest!
// also I will do it with a reader/writer API as that
// is a very practical way to do things in Go
func (d *DES) DecryptECB(cipher io.Reader, plain io.Writer) error {
	// some notion of padding?
	// I think openssl uses PKCS5 (https://www.cryptosys.net/pki/manpki/pki_paddingschemes.html)
	block := make([]byte, BlockSize)
	var err error
	var finalBlock bool
	for {
		_, err = cipher.Read(block)
		if err != nil {
			if err != io.EOF {
				return err
			}
			// err is EOF.
			finalBlock = true
			// we need to remember to discard the final padding
		}
		// decrypt the block!

		if finalBlock {
			last := d.DecryptBlock(block)
			// there will ALWAYS be padding, so the final byte of this block will be
			// how many bytes to OMIT from the output (also all the bytes should be identical,
			// but we won't care too much about that)
			finalByte := last[BlockSize-1]
			// it should be 1-8
			if finalByte < 1 || finalByte > 8 {
				return fmt.Errorf("Unexpected Final Padding byte: 0x%02X", finalByte)
			}
			if finalByte != 8 {
				// 8 would mean drop the whole block!
				// anything less means drop the last `finalByte` bytes
				_, err = plain.Write(last[:BlockSize-finalByte])
				if err != nil {
					return err
				}
			}
			return nil
		}
		// otherwise just decrypt into the writer
		_, err = plain.Write(d.DecryptBlock(block))
		if err != nil {
			return err
		}
	}
}
