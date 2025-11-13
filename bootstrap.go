package apikey

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"golang.org/x/crypto/argon2"
	"time"
)

func GenerateBootstrap() (plain, hash string, expires time.Time, err error) {
	secret := make([]byte, 32)
	if _, err = rand.Read(secret); err != nil {
		fmt.Println(err)
		return
	}
	plain = hex.EncodeToString(secret)
	sum := sha256.Sum256(secret)
	salt := make([]byte, 16)
	if _, err = rand.Read(salt); err != nil {
		fmt.Println(err)
		return
	}

	derived := argon2.IDKey(sum[:], salt, 1, 64*1024, 4, 32)
	hash = hex.EncodeToString(salt) + ":" + hex.EncodeToString(derived)
	expires = time.Now().UTC().Add(24 * time.Hour)
	return
}
