package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"

	mls "github.com/beka/go-mls"
	"golang.org/x/crypto/pbkdf2"
)

func generateRandomSalt() []byte {
	salt := make([]byte, 12)
	_, err := rand.Read(salt)
	if err != nil {
		panic(err)
	}
	return salt
}

func unhex(h string) []byte {
	b, err := hex.DecodeString(h)
	if err != nil {
		panic(err)
	}
	return b
}

func main() {
	// Define and parse command-line arguments with default values.
	mode := flag.Int("mode", 1, "Encryption mode (1 to 4)")
	seed := flag.String("seed", "default_seed", "Seed for encryption")
	message := flag.String("message", "Hello, World!", "Message to encrypt")
	flag.Parse()

	salt := generateRandomSalt()
	var suite mls.CipherSuite
	var key []byte
	// Choose a proper Cipher Suite based on the encryption mode.
	switch *mode {
	case 1:
		suite = mls.X25519_AES128GCM_SHA256_Ed25519
		key = pbkdf2.Key([]byte(*seed), salt, 10000, 16, sha256.New)
	case 2:
		suite = mls.P256_AES128GCM_SHA256_P256
		key = pbkdf2.Key([]byte(*seed), salt, 10000, 16, sha256.New)
	case 3:
		suite = mls.X25519_CHACHA20POLY1305_SHA256_Ed25519
		key = pbkdf2.Key([]byte(*seed), salt, 10000, 32, sha256.New)
	case 4:
		suite = mls.P521_AES256GCM_SHA512_P521
		key = pbkdf2.Key([]byte(*seed), salt, 10000, 32, sha256.New)
	default:
		fmt.Println("Invalid encryption_mode. Choose a mode from 1 to 4.")
		return
	}

	aead, err := suite.NewAEAD(key)
	if err != nil {
		panic(err)
	}

	aad := unhex("00")
	nonce := unhex("000000000000000000000000")
	encrypted := aead.Seal(nil, nonce, []byte(*message), aad)
	decrypted, err := aead.Open(nil, nonce, encrypted, aad)

	if err != nil {
		panic(err)
	}

	fmt.Printf("Message:\t%s\nSeed:\t\t%s\nSalt:\t\t%x\nType:\t\t%s\n\n", *message, *seed, salt, suite.String())
	fmt.Printf("Key:\t\t%x\nEncrypted:\t%x\nDecrypted:\t%s\n", key, encrypted, decrypted)
}
