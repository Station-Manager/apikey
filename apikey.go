package apikey

import (
	"crypto/rand"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"strings"
)

const (
	// DefaultSecretBytes is the number of random bytes used for the secret part
	DefaultSecretBytes = 32
	// MaxPrefixLen is the maximum prefix length allowed (matches DB varchar(10))
	MaxPrefixLen = 10
)

// Generate creates a new API key. The returned fullKey has the form "prefix.secretHex".
// It also returns the prefix and the SHA-512 hex hash of the secret (suitable for storing).
// If prefixLen is <=0 or > MaxPrefixLen it will be clamped to MaxPrefixLen.
func Generate(prefixLen int) (fullKey, prefix, hash string, err error) {
	if prefixLen <= 0 || prefixLen > MaxPrefixLen {
		prefixLen = MaxPrefixLen
	}

	b := make([]byte, DefaultSecretBytes)
	if _, err = rand.Read(b); err != nil {
		return "", "", "", err
	}

	secretHex := hex.EncodeToString(b) // 2*DefaultSecretBytes chars
	prefix = secretHex[:prefixLen]
	fullKey = prefix + "." + secretHex

	h := sha512.Sum512([]byte(secretHex))
	hash = hex.EncodeToString(h[:])
	return
}

// HashSecret returns the SHA-512 hex digest of the secret string.
func HashSecret(secret string) string {
	h := sha512.Sum512([]byte(secret))
	return hex.EncodeToString(h[:])
}

// Parse splits a fullKey into prefix and secret. fullKey is expected to be "prefix.secret".
func Parse(fullKey string) (prefix, secret string, err error) {
	if fullKey == "" {
		return "", "", errors.New("empty key")
	}
	idx := strings.Index(fullKey, ".")
	if idx <= 0 || idx >= len(fullKey)-1 {
		return "", "", errors.New("invalid key format")
	}
	prefix = fullKey[:idx]
	secret = fullKey[idx+1:]
	return
}

// Validate checks that fullKey matches the provided storedHash (hex SHA-512 of the secret).
// It returns true when they match; comparison is done in constant time.
func Validate(fullKey, storedHash string) (bool, error) {
	_, secret, err := Parse(fullKey)
	if err != nil {
		return false, err
	}
	if secret == "" {
		return false, errors.New("empty secret")
	}
	h := HashSecret(secret)
	// constant time compare
	if len(h) != len(storedHash) {
		return false, nil
	}
	if subtle.ConstantTimeCompare([]byte(h), []byte(storedHash)) == 1 {
		return true, nil
	}
	return false, nil
}
