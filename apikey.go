package apikey

import (
	"crypto/rand"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"strings"
	"unicode/utf8"
)

const (
	// DefaultSecretBytes is the number of random bytes used for the secret part
	DefaultSecretBytes = 32
	// MaxPrefixLen is the maximum prefix length allowed (matches DB varchar(16))
	MaxPrefixLen = 16
)

// Generate creates a new API key.
//
// It returns only text-safe, UTF-8 strings suitable for storage in
// database TEXT/VARCHAR columns:
//   - fullKey: "<prefix>.<secretHex>", where both prefix and secretHex are
//     lowercase hex characters.
//   - prefix: a lowercase hex string of length prefixLen (or MaxPrefixLen when
//     prefixLen is out of range).
//   - hash: the SHA-512 digest of secretHex, hex-encoded.
//
// No raw binary data is ever returned to callers. If prefixLen is <=0 or
// > MaxPrefixLen it will be clamped to MaxPrefixLen.
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

// HashSecret returns the SHA-512 hex digest of the secret string. The
// returned value is a lowercase hex-encoded string, safe for storage in
// TEXT/VARCHAR columns.
func HashSecret(secret string) string {
	h := sha512.Sum512([]byte(secret))
	return hex.EncodeToString(h[:])
}

// Parse splits a fullKey into prefix and secret. fullKey is expected to be
// "prefix.secretHex" where both parts are text-safe UTF-8 strings. The
// returned secret is the hex-encoded secret portion as produced by Generate
// (not raw bytes) and is therefore also safe for logging or text storage but
// must be treated as sensitive.
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
// It returns true when they match; comparison is done in constant time. storedHash is
// expected to be the result of HashSecret and is always a hex-encoded string.
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

// internal helper to assert that strings we generate are valid UTF-8 and contain no NUL
// bytes; used only in tests.
func isTextSafe(s string) bool {
	if !utf8.ValidString(s) {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] == 0 {
			return false
		}
	}
	return true
}
