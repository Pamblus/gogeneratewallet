package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"hash"
	"log"
	"os"
	
	"strings"
	"sync/atomic"
	"time"

	"github.com/xssnick/tonutils-go/address"
)

func main() {
	// Укажите значения здесь
	threads := uint64(1) // Количество потоков
	suffixes := []string{
		"-------",
		"_____",
		"HITLER",
		"__________",
		"_HITLER",
		"-HITLER",
		"PAMBLUS",
		"TONCOIN",
	} // Желаемые суффиксы через запятую
	caseSensitive := false // Учитывать ли регистр символов
	addEnd := false // Искать суффикс только в конце адреса
	private := false // Сохранять ли приватные ключи в файл
	privateconsole := true// Показывать ли приватные ключи в консоли

	var counter uint64
	var privateKeyCounter uint64

	file, err := os.OpenFile("wallets.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatal("Error opening wallets.txt: ", err)
	}
	defer file.Close()

	privateFile, err := os.OpenFile("privates.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatal("Error opening privates.txt: ", err)
	}
	defer privateFile.Close()

	writeToFile := func(address, privateKey string) {
		_, err := file.WriteString(address + "\n" + privateKey + "\n\n")
		if err != nil {
			log.Println("Error writing to file:", err)
		}
	}

	writePrivateKeyToFile := func(privateKey string, addressCount uint32) {
		if private {
			_, err := privateFile.WriteString(privateKey + " | " + fmt.Sprint(addressCount) + "\n")
			if err != nil {
				log.Println("Error writing to privates.txt:", err)
			}
		}
	}

	for x := uint64(0); x < threads; x++ {
		go generateWallets(caseSensitive, addEnd, suffixes, &counter, &privateKeyCounter, writeToFile, writePrivateKeyToFile, privateconsole)
	}

	log.Println("searching...")
	start := time.Now()
	for {
		time.Sleep(1 * time.Second)
		log.Println("checked", atomic.LoadUint64(&counter)/uint64(time.Since(start).Seconds()), "per second")
	}
}

func generateWallets(caseSensitive, addEnd bool, suffixes []string, counter, privateKeyCounter *uint64, writeToFile func(string, string), writePrivateKeyToFile func(string, uint32), privateconsole bool) {
	var equalityFunc func(a string, b string) bool
	if caseSensitive {
		equalityFunc = func(a, b string) bool {
			return a == b
		}
	} else {
		equalityFunc = func(a, b string) bool {
			return strings.EqualFold(a, b)
		}
	}

	addrFrom := make([]byte, 36)
	addrTo := make([]byte, 48)
	hashDst := make([]byte, 32)

	subwalletIDBytes := []byte{0, 0, 0, 0}

	v3DataCell := []byte{
		0, 80, 0, 0, 0, 0,
		41, 169, 163, 23,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	}

	v3StateInit := []byte{
		2, 1, 52, 0, 0, 0, 0, 132,
		218, 250, 68, 159, 152, 166, 152, 119,
		137, 186, 35, 35, 88, 7, 43, 192,
		247, 109, 196, 82, 64, 2, 165, 208,
		145, 139, 154, 117, 210, 213, 153,
		0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0,
	}

	hash := sha256.New()

	for {
		_, pk, _ := ed25519.GenerateKey(nil)
		key := pk.Public().(ed25519.PublicKey)

		copy(v3DataCell[10:], key)

		addressCount := uint32(0)

		for i := uint32(0); i < 1_000_000_000; i++ {
			atomic.AddUint64(counter, 1)
			addressCount++

			binary.BigEndian.PutUint32(subwalletIDBytes, i)
			getHashV3HashFromKey(hash, subwalletIDBytes, v3DataCell, v3StateInit, hashDst)

			addr := address.NewAddress(0, 0, hashDst).Bounce(true)
			addr.StringToBytes(addrTo, addrFrom)

			for _, suffix := range suffixes {
				if addEnd {
					strCmpOffset := 48 - len(suffix)
					if equalityFunc(suffix, string(addrTo[strCmpOffset:])) {
						address := addr.String()
						privateKey := hex.EncodeToString(pk.Seed())
						log.Println(
							"========== FOUND ==========\n",
							"Address:", address, "\n", "Private key:", privateKey, "\n",
							"========== FOUND ==========",
						)
						writeToFile(address, privateKey)
						if privateconsole {
							log.Println("Private key:", privateKey)
						}
					}
				} else {
					if strings.Contains(string(addrTo), suffix) {
						address := addr.String()
						privateKey := hex.EncodeToString(pk.Seed())
						log.Println(
							"========== FOUND ==========\n",
							"Address:", address, "\n", "Private key:", privateKey, "\n",
							"========== FOUND ==========",
						)
						writeToFile(address, privateKey)
						if privateconsole {
							log.Println("Private key:", privateKey)
						}
					}
				}
			}
		}

		atomic.AddUint64(privateKeyCounter, 1)
		//log.Printf("private(%d) = %d address\n", atomic.LoadUint64(privateKeyCounter), addressCount)
		writePrivateKeyToFile(hex.EncodeToString(pk.Seed()), addressCount)
	}
}

func getHashV3HashFromKey(hash hash.Hash, numCell []byte, dataCell []byte, finalHashBytes []byte, dst []byte) {
	copy(dataCell[6:10], numCell)

	hash.Reset()
	hash.Write(dataCell)
	hash.Sum(finalHashBytes[39:39])

	hash.Reset()
	hash.Write(finalHashBytes)
	hash.Sum(dst[:0])
}
