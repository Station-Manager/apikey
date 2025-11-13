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
	// MaxPrefixLen is the maximum prefix length allowed (matches DB varchar(16))
	MaxPrefixLen = 16
)

// Generate creates a new API key. The returned fullKey has the form "prefix.secretHex".
// It also returns the prefix and the SHA-512 hex hash of the secret (suitable for storing).
// If prefixLen is <=0 or > MaxPrefixLen it will be clamped to MaxPrefixLen.
func Generate(prefixLen int) (fullKey, prefix, hash string, err error) {
	if prefixLen <= 0 || prefixLen > MaxPrefixLen {
		prefixLen = MaxPrefixLen
	}

	// Generate the secret bytes and hex-encode as the secret part
	b := make([]byte, DefaultSecretBytes)
	if _, err = rand.Read(b); err != nil {
		return emptyString, emptyString, emptyString, err
	}
	secretHex := hex.EncodeToString(b) // 2*DefaultSecretBytes chars

	// Generate an independent random prefix (hex), not derived from secretHex
	// Ensure we have enough hex characters, so generate ceil(prefixLen/2) bytes
	prefixBytes := (prefixLen + 1) / 2
	pb := make([]byte, prefixBytes)
	if _, err = rand.Read(pb); err != nil {
		return emptyString, emptyString, emptyString, err
	}
	prefixHex := hex.EncodeToString(pb)
	prefix = prefixHex[:prefixLen]

	fullKey = prefix + dotString + secretHex

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
	if fullKey == emptyString {
		return emptyString, emptyString, errors.New("empty key")
	}
	idx := strings.Index(fullKey, dotString)
	if idx <= 0 || idx >= len(fullKey)-1 {
		return emptyString, emptyString, errors.New("invalid key format")
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
	if secret == emptyString {
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
