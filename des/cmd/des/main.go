package main

import (
	"flag"
	"io/ioutil"
	"log"
	"os"

	"thechriswalker.net/crypto/des"
)

var (
	keyfile = flag.String("key", "", "key file containing raw encryption key")
	srcfile = flag.String("src", "-", "where to read data from")
	dstfile = flag.String("dst", "-", "where to write data to")
	decrypt = flag.Bool("d", false, "decrypt instead of encrypt")
)

func main() {
	flag.Parse()
	in := os.Stdin
	out := os.Stdout
	key, err := ioutil.ReadFile(*keyfile)
	if err != nil {
		log.Println("could not open key file:", *keyfile)
		panic(err)
	}
	if *srcfile != "-" {
		in, err = os.Open(*srcfile)
		if err != nil {
			panic(err)
		}
	}
	if *dstfile != "-" {
		out, err = os.Create(*dstfile)
		if err != nil {
			panic(err)
		}
	}
	cipher := des.NewDES(key)
	if *decrypt {
		err = cipher.DecryptECB(in, out)
	} else {
		err = cipher.EncryptECB(in, out)
	}
	if err != nil {
		panic(err)
	}
	in.Close()
	out.Close()
	os.Exit(0)
}
