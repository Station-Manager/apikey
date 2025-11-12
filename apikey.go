package apikey

import (
	"crypto/rand"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"strings"
	"unicode"
)

const (
	// DefaultSecretBytes is the number of random bytes used for the secret part
	DefaultSecretBytes = 32
	// MaxPrefixLen is the maximum prefix length allowed (matches DB varchar(10))
	MaxPrefixLen = 10
)

// Generate creates a new API key. The returned fullKey has the form "prefix.secretHex".
// It also returns the prefix and the SHA-512 hex hash of the secret (suitable for storing).
// If the prefixLen is <=0 or > MaxPrefixLen, it will be clamped to MaxPrefixLen.
func Generate(prefixLen int) (fullKey, prefix, hash string, err error) {
	if prefixLen <= 0 || prefixLen > MaxPrefixLen {
		prefixLen = MaxPrefixLen
	}

	b := make([]byte, DefaultSecretBytes)
	if _, err = rand.Read(b); err != nil {
		return emptyString, emptyString, emptyString, err
	}

	secretHex := hex.EncodeToString(b) // 2*DefaultSecretBytes chars
	prefix = secretHex[:prefixLen]
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

// FormatFullKey returns a human-friendly representation of fullKey where the secret
// portion is split into groups of size groupSize and joined with '-'.
// Example: prefix.0123-4567-89ab...
// If groupSize <= 0 it defaults to 4.
func FormatFullKey(fullKey string, groupSize int) (string, error) {
	if groupSize <= 0 {
		groupSize = 4
	}
	prefix, secret, err := Parse(fullKey)
	if err != nil {
		return emptyString, err
	}
	// remove any existing separators that might already be present
	secret = strings.ReplaceAll(secret, dashString, emptyString)
	secret = strings.ReplaceAll(secret, whiteSpace, emptyString)
	if secret == emptyString {
		return emptyString, errors.New("empty secret")
	}
	groups := splitIntoChunks(secret, groupSize)
	return prefix + dotString + strings.Join(groups, dashString), nil
}

// splitIntoChunks splits s into chunks of size n. The last chunk may be shorter.
func splitIntoChunks(s string, n int) []string {
	if n <= 0 {
		return []string{s}
	}
	var out []string
	for i := 0; i < len(s); i += n {
		end := i + n
		if end > len(s) {
			end = len(s)
		}
		out = append(out, s[i:end])
	}
	return out
}

// SplitFormattedKey takes a formatted key like "pref.0123-4567-89ab" and returns
// the prefix and the raw secret ("0123456789ab") after stripping separators.
func SplitFormattedKey(formatted string) (prefix, secret string, err error) {
	formatted = strings.TrimSpace(formatted)
	if formatted == emptyString {
		return emptyString, emptyString, errors.New("empty input")
	}
	idx := strings.Index(formatted, dotString)
	if idx <= 0 || idx == len(formatted)-1 {
		return emptyString, emptyString, errors.New("invalid format, expected prefix.secret")
	}
	prefix = formatted[:idx]
	secretPart := formatted[idx+1:]

	// remove common separators the formatter may have added
	secret = strings.ReplaceAll(secretPart, dashString, emptyString)
	secret = strings.ReplaceAll(secret, whiteSpace, emptyString)
	secret = strings.ReplaceAll(secret, dotString, emptyString)

	secret = strings.TrimSpace(secret)
	if secret == emptyString {
		return emptyString, emptyString, errors.New("empty secret after stripping separators")
	}

	// basic validation: ensure secret is alphanumeric
	for _, r := range secret {
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) {
			return emptyString, emptyString, errors.New("secret contains invalid characters")
		}
	}
	return prefix, secret, nil
}

// ReassembleFullKey returns the canonical full key (prefix.secret) from a formatted key.
func ReassembleFullKey(formatted string) (string, error) {
	prefix, secret, err := SplitFormattedKey(formatted)
	if err != nil {
		return emptyString, err
	}
	return prefix + dotString + secret, nil
}
