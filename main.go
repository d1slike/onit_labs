package main

import (
	"bytes"
	"crypto/des"
	"errors"
	"fmt"
	"strings"
	"io/ioutil"
	"bufio"
	"os"
)

func repeatBlocks(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{0}, padding)
	return append(ciphertext, padtext...)
}

func trimBlocks(origData []byte) []byte {
	return bytes.TrimFunc(origData,
		func(r rune) bool {
			return r == rune(0)
		})
}

func desEncrypt(src, key []byte) ([]byte, error) {
	block, err := des.NewCipher(key)
	if err != nil {
		return nil, err
	}
	bs := block.BlockSize()
	src = repeatBlocks(src, bs)
	if len(src)%bs != 0 {
		return nil, errors.New("need a multiple of the blocksize")
	}
	out := make([]byte, len(src))
	dst := out
	for len(src) > 0 {
		block.Encrypt(dst, src[:bs])
		src = src[bs:]
		dst = dst[bs:]
	}
	return out, nil
}

func desDecrypt(src, key []byte) ([]byte, error) {
	block, err := des.NewCipher(key)
	if err != nil {
		return nil, err
	}
	out := make([]byte, len(src))
	dst := out
	bs := block.BlockSize()
	if len(src)%bs != 0 {
		return nil, errors.New("crypto/cipher: input not full blocks")
	}
	for len(src) > 0 {
		block.Decrypt(dst, src[:bs])
		src = src[bs:]
		dst = dst[bs:]
	}
	out = trimBlocks(out)
	return out, nil
}

func main() {
	key := []byte("da8467vL")
	reader := bufio.NewReader(os.Stdin)
	fmt.Println("Please enter one of command:\n" +
		"	enc text - to encrypt file\n" +
		"	dec - to decrypt file\n" +
		"	exit - to exit")
	for {
		fmt.Print("\n>")
		input, _ := reader.ReadString('\n')
		if strings.HasPrefix(input, "enc ") {
			text := input[4:len(input)-1]
			res, e := desEncrypt([]byte(text), key)
			if e != nil {
				fmt.Print("Error occured: ", e)
			} else {
				ioutil.WriteFile("des_example.txt", res, 0644)
				fmt.Println("Successfully encrypted! See des_example.txt")
			}
		} else if strings.HasPrefix(input, "dec") {
			encrypted, e := ioutil.ReadFile("des_example.txt")
			if e != nil {
				fmt.Println("Error occured: ", e)
			} else {
				res, e := desDecrypt(encrypted, key)
				if e != nil {
					fmt.Println("Error occured: ", e)
				} else {
					fmt.Println("Your source text: ", string(res))
				}
			}
		} else if strings.HasPrefix(input, "exit") {
			break
		} else {
			fmt.Println("Unknown command")
		}
	}
}
