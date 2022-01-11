package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
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
		e2 := twoFishEncrypt(twofishChecksizeAndPad(b), []byte(key))
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


	plaintext := stringToEncrypt

	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err.Error())
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}

	nonce := make([]byte, aesGCM.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		panic(err.Error())
	}
	ciphertext := aesGCM.Seal(nonce, nonce, plaintext, nil)
	return fmt.Sprintf("%x", ciphertext)
}


func blowfishChecksizeAndPad(pt []byte) []byte {

	modulus := len(pt) % blowfish.BlockSize
	if modulus != 0 {
		padlen := blowfish.BlockSize - modulus
		for i := 0; i < padlen; i++ {
			pt = append(pt, 0)
		}
	}
	return pt
}



func blowfishEncrypt(ppt, key []byte) []byte {
	ecipher, err := blowfish.NewCipher(key)
	if err != nil {
		panic(err)
	}
	ciphertext := make([]byte, blowfish.BlockSize+len(ppt))

	eiv := ciphertext[:blowfish.BlockSize]
	ecbc := cipher.NewCBCEncrypter(ecipher, eiv)
	ecbc.CryptBlocks(ciphertext[blowfish.BlockSize:], ppt)
	return ciphertext
}


func twofishChecksizeAndPad(pt []byte) []byte {

	modulus := len(pt) % twofish.BlockSize
	if modulus != 0 {
		padlen := twofish.BlockSize - modulus
		for i := 0; i < padlen; i++ {
			pt = append(pt, 0)
		}
	}
	return pt
}

func twoFishEncrypt(ppt, key []byte) []byte {
	ecipher, err := twofish.NewCipher(key)
	if err != nil {
		panic(err)
	}
	ciphertext := make([]byte, twofish.BlockSize+len(ppt))

	eiv := ciphertext[:twofish.BlockSize]
	ecbc := cipher.NewCBCEncrypter(ecipher, eiv)
	ecbc.CryptBlocks(ciphertext[twofish.BlockSize:], ppt)
	return ciphertext
}