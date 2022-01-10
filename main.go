package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"github.com/fatih/color"
	"github.com/jedib0t/go-pretty/v6/table"
	"golang.org/x/crypto/blowfish"
	"golang.org/x/crypto/twofish"
	"io"
	"io/ioutil"
	"log"
	"os"
	"time"
)

func main() {
	println()
	println()
	color.Cyan("Network Security Project")
	color.Cyan("twofish cipher algorithm")
	color.Magenta("by")
	color.Magenta("Arman Salehi & Amir Hossian Hossiani")

	key := "passphrasewhichneedstobe32bytes!"

	fileNameArr := []string{"chat.txt", "lorem.txt", "fight-club.txt", "LOTR.txt"}

	aesInterfaces := make([]interface{}, 0)
	twofishInterfaces := make([]interface{}, 0)
	blowfishInterfaces := make([]interface{}, 0)

	blowfishInterfaces = append(blowfishInterfaces, "blowfish")
	twofishInterfaces = append(twofishInterfaces, "twofish")
	aesInterfaces = append(aesInterfaces, "aes")

	for _, s := range fileNameArr {
		file, err := os.Open("./data/" + s)
		if err != nil {
			log.Fatal(err)
		}
		defer func() {
			if err = file.Close(); err != nil {
				log.Fatal(err)
			}
		}()

		b, err := ioutil.ReadAll(file)
		t1 := time.Now().UnixMicro()
		e := blowfishEncrypt(blowfishChecksizeAndPad(b), []byte(key))
		t2 := time.Now().UnixMicro()
		blowfishInterfaces = append(blowfishInterfaces, fmt.Sprintf("%v µs", t2-t1))
		blowfishInterfaces = append(blowfishInterfaces, fmt.Sprintf("%v characters", len(e)))

		t3 := time.Now().UnixMicro()
		e2 := twoFishEncrypt(b, []byte(key))
		t4 := time.Now().UnixMicro()
		twofishInterfaces = append(twofishInterfaces, fmt.Sprintf("%v µs", t4-t3))
		twofishInterfaces = append(twofishInterfaces, fmt.Sprintf("%v characters", len(e2)))

		t5 := time.Now().UnixMicro()
		e3 := aesEncrypt(b, []byte(key))
		t6 := time.Now().UnixMicro()
		aesInterfaces = append(aesInterfaces, fmt.Sprintf("%v µs", t6-t5))
		aesInterfaces = append(aesInterfaces, fmt.Sprintf("%v characters", len(e3)))

	}

	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)
	t.AppendHeader(table.Row{"cipher algorithms", "chat time", "chat size", "lorem time", "lorem size", "fightclub time", "fightclub size", "LOTR time", "LOTR size"})
	t.AppendRows([]table.Row{blowfishInterfaces})
	t.AppendSeparator()
	t.AppendRows([]table.Row{twofishInterfaces})
	t.AppendSeparator()
	t.AppendRows([]table.Row{aesInterfaces})
	t.AppendSeparator()
	t.Render()

	println()
	println()
	println()

}

func aesEncrypt(stringToEncrypt []byte, key []byte) (encryptedString string) {

	//Since the key is in string, we need to convert decode it to bytes

	plaintext := stringToEncrypt

	//Create a new Cipher Block from the key
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err.Error())
	}

	//Create a new GCM - https://en.wikipedia.org/wiki/Galois/Counter_Mode
	//https://golang.org/pkg/crypto/cipher/#NewGCM.Cyan("Prints text in cyan.")
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}

	//Create a nonce. Nonce should be from GCM
	nonce := make([]byte, aesGCM.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		panic(err.Error())
	}

	//Encrypt the data using aesGCM.Seal
	//Since we don't want to save the nonce somewhere else in this case, we add it as a prefix to the encrypted data. The first nonce argument in Seal is the prefix.
	ciphertext := aesGCM.Seal(nonce, nonce, plaintext, nil)
	return fmt.Sprintf("%x", ciphertext)
}

func aesDecrypt(encryptedString string, keyString string) (decryptedString string) {

	key := []byte(keyString)
	enc, _ := hex.DecodeString(encryptedString)

	//Create a new Cipher Block from the key
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err.Error())
	}

	//Create a new GCM
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}

	//Get the nonce size
	nonceSize := aesGCM.NonceSize()

	//Extract the nonce from the encrypted data
	nonce, ciphertext := enc[:nonceSize], enc[nonceSize:]

	//Decrypt the data
	plaintext, err := aesGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		panic(err.Error())
	}

	return fmt.Sprintf("%s", plaintext)
}

func twoFishEncrypt(data []byte, key []byte) []byte {
	c, err := twofish.NewCipher(key)
	if err != nil {
		panic(" NewCipher " + err.Error())

	}
	encrypted := make([][]byte, 0)
	//lastIndex:=0
	for len(data)%16 != 0 {
		data = append(data, byte(' '))
	}
	for i := 0; i < len(data); i += 16 {
		buf := make([]byte, 16)
		c.Encrypt(buf, data[i:i+16])
		encrypted = append(encrypted, buf)

	}
	//fmt.Println(data[lastIndex:])
	//buf := make([]byte, 16)
	//c.Encrypt(buf, data[lastIndex:])
	//fmt.Println(string(data[lastIndex:]))
	//encrypted=append(encrypted,buf)

	re := make([]byte, 0, len(data))
	for _, b := range encrypted {

		re = append(re, b...)
	}
	return re
}

func twoFishDecrypt(encrypted []byte, key []byte) string {
	c, err := twofish.NewCipher(key)
	if err != nil {
		panic(" NewCipher " + err.Error())

	}
	dec := make([][]byte, 0)
	for i := 0; i < len(encrypted); i += 16 {
		buf := make([]byte, 16)
		c.Decrypt(buf, encrypted[i:i+16])
		dec = append(dec, buf)
	}

	re := make([]byte, 0)
	for _, b := range dec {
		re = append(re, b...)
	}
	return string(re)

}

func blowfishChecksizeAndPad(pt []byte) []byte {
	// calculate modulus of plaintext to blowfish's cipher block size
	// if result is not 0, then we need to pad
	modulus := len(pt) % blowfish.BlockSize
	if modulus != 0 {
		// how many bytes do we need to pad to make pt to be a multiple of blowfish's block size?
		padlen := blowfish.BlockSize - modulus
		// let's add the required padding
		for i := 0; i < padlen; i++ {
			// add the pad, one at a time
			pt = append(pt, 0)
		}
	}
	// return the whole-multiple-of-blowfish.BlockSize-sized plaintext to the calling function
	return pt
}

func blowfishDecrypt(et, key []byte) []byte {
	// create the cipher
	dcipher, err := blowfish.NewCipher(key)
	if err != nil {
		// fix this. its okay for this tester program, but...
		panic(err)
	}
	// make initialisation vector to be the first 8 bytes of ciphertext.
	// see related note in blowfishEncrypt()
	div := et[:blowfish.BlockSize]
	// check last slice of encrypted text, if it's not a modulus of cipher block size, we're in trouble
	decrypted := et[blowfish.BlockSize:]
	if len(decrypted)%blowfish.BlockSize != 0 {
		panic("decrypted is not a multiple of blowfish.BlockSize")
	}
	// ok, we're good... create the decrypter
	dcbc := cipher.NewCBCDecrypter(dcipher, div)
	// decrypt!
	dcbc.CryptBlocks(decrypted, decrypted)
	return decrypted
}

func blowfishEncrypt(ppt, key []byte) []byte {
	// create the cipher
	ecipher, err := blowfish.NewCipher(key)
	if err != nil {
		// fix this. its okay for this tester program, but ....
		panic(err)
	}
	// make ciphertext big enough to store len(ppt)+blowfish.BlockSize
	ciphertext := make([]byte, blowfish.BlockSize+len(ppt))
	// make initialisation vector to be the first 8 bytes of ciphertext. you
	// wouldn't do this normally/in real code, but this IS example code! :)
	eiv := ciphertext[:blowfish.BlockSize]
	// create the encrypter
	ecbc := cipher.NewCBCEncrypter(ecipher, eiv)
	// encrypt the blocks, because block cipher
	ecbc.CryptBlocks(ciphertext[blowfish.BlockSize:], ppt)
	// return ciphertext to calling function
	return ciphertext
}
