# DES - Data Encryption Standard

DES is a block cipher working on 64bit blocks with a key length of 56bits.

It uses and Initial Permutation (IP) and then a 16 round Feistel cipher with no final swap, followed by the inverse of the IP.

The reason for using the inverse of the IP at the end is so that the same function can be used for both encrypt and decrypt (which is more of a big deal in hardware!)

openssl has a reference implementation I could use to test...

```
$ openssl enc -des-ecb -K e0e0e0e0f1f1f1f1 -in mesg.plain -out mesg.enc
```
