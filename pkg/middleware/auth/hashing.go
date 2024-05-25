package auth

import (
	"encoding/base64"
	"errors"
	mathrand "math/rand"
	"time"

	"golang.org/x/crypto/argon2"
)

func init() {
	mathrand.New(mathrand.NewSource(time.Now().UnixNano()))
}

func GenerateHash(password, salt []byte) string {
	hashed := argon2.IDKey(password, salt, 1, 64*1024, 4, 32)
	return base64.StdEncoding.EncodeToString(hashed)
}

func CompareHash(hashedPassword, plainPassword, salt string) error {
	hashSalt := GenerateHash([]byte(plainPassword), []byte(salt))
	if hashedPassword != hashSalt {
		return errors.New("Hash doesn't match")
	}

	return nil
}

func GenerateRandomAlphaNumeric(n int) string {
	// ascii range (A-Z)
	min := 65
	max := 90

	result := make([]byte, n)
	for i := range result {
		result[i] = byte(mathrand.Intn(max-min+1) + min)
	}

	return string(result)
}
