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
	DefaultSecretBytes = 20
	// MaxPrefixLen is the maximum prefix length allowed (matches DB varchar(16))
	MaxPrefixLen = 16
	// SecretSymbolLen is the exact number of non-dash symbols required in a
	// valid user-facing secret. This is enforced in isValidSecret.
	SecretSymbolLen = DefaultSecretBytes
)

// internal constants
const (
	separator = "_"

	// userFriendlyAlphabet is a Base32-like alphabet without ambiguous chars.
	// We don't implement full RFC 4648 padding; we just map random bytes into
	// these characters, which is sufficient for a human-facing secret.
	userFriendlyAlphabet = "ABCDEFGHJKMNPQRSTUVWXYZ23456789" // no I,L,O,0,1
)

// GenerateApiKey creates a new API key.
//
// It returns only text-safe, UTF-8 strings suitable for storage in
// database TEXT/VARCHAR columns:
//   - fullKey: "<prefix>_<secret>", where prefix is lowercase hex and secret
//     is an upper-case user-friendly Base32-like string (possibly with dashes),
//     safe for copy/paste by end users.
//   - prefix: a lowercase hex string of length prefixLen (or MaxPrefixLen when
//     prefixLen is out of range).
//   - hash: the SHA-512 digest of the secret, hex-encoded.
//
// The returned secret is the user-facing sensitive value and is embedded in
// fullKey after the underscore. No raw binary data is ever returned to callers.
// If prefixLen is <=0 or > MaxPrefixLen it will be clamped to MaxPrefixLen.
func GenerateApiKey(prefixLen int) (fullKey, prefix, hash string, err error) {
	if prefixLen <= 0 || prefixLen > MaxPrefixLen {
		prefixLen = MaxPrefixLen
	}

	// Generate the secret bytes and encode as user-friendly secret
	b := make([]byte, DefaultSecretBytes)
	if _, err = rand.Read(b); err != nil {
		return "", "", "", err
	}
	secret := encodeUserFriendly(b)

	// Generate an independent random prefix (hex), not derived from secret
	// Ensure we have enough hex characters, so generate ceil(prefixLen/2) bytes
	prefixBytes := (prefixLen + 1) / 2
	pb := make([]byte, prefixBytes)
	if _, err = rand.Read(pb); err != nil {
		return "", "", "", err
	}
	prefixHex := hex.EncodeToString(pb)
	prefix = prefixHex[:prefixLen]

	fullKey = prefix + separator + secret

	h := sha512.Sum512([]byte(secret))
	hash = hex.EncodeToString(h[:])
	return
}

// HashApiKeySecret returns the SHA-512 hex digest of the user-friendly secret
// string. The returned value is a lowercase hex-encoded string, safe for
// storage in TEXT/VARCHAR columns.
func HashApiKeySecret(secret string) string {
	h := sha512.Sum512([]byte(secret))
	return hex.EncodeToString(h[:])
}

// ParseApiKey splits a fullKey into prefix and secret.
// fullKey is expected to be "prefix_secret" where both parts are text-safe
// UTF-8 strings. The returned secret is the user-friendly secret portion as
// produced by GenerateApiKey and must be treated as sensitive.
func ParseApiKey(fullKey string) (prefix, secret string, err error) {
	if fullKey == "" {
		return "", "", errors.New("empty key")
	}
	idx := strings.Index(fullKey, separator)
	if idx <= 0 || idx >= len(fullKey)-1 {
		return "", "", errors.New("invalid key format")
	}
	prefix = fullKey[:idx]
	secret = fullKey[idx+1:]
	if !isValidPrefix(prefix) || !isValidSecret(secret) {
		return "", "", errors.New("invalid key format")
	}
	return
}

// ValidateApiKey checks that fullKey (API Key) matches the provided storedHash
// (hex SHA-512 of the user-friendly secret). It returns true when they match;
// comparison is done in constant time. storedHash is expected to be the result
// of HashApiKeySecret and is always a hex-encoded string.
func ValidateApiKey(fullKey, storedHash string) (bool, error) {
	_, secret, err := ParseApiKey(fullKey)
	if err != nil {
		return false, err
	}
	if secret == "" {
		return false, errors.New("empty secret")
	}
	h := HashApiKeySecret(secret)
	// constant time compare
	if len(h) != len(storedHash) {
		return false, nil
	}
	if subtle.ConstantTimeCompare([]byte(h), []byte(storedHash)) == 1 {
		return true, nil
	}
	return false, nil
}

// encodeUserFriendly maps random bytes into a user-friendly alphabet and
// groups them with dashes for readability.
func encodeUserFriendly(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	alphabetLen := byte(len(userFriendlyAlphabet))
	var sb strings.Builder
	count := 0
	for _, v := range b {
		idx := int(v % alphabetLen)
		ch := userFriendlyAlphabet[idx]
		sb.WriteByte(byte(ch))
		count++
		// insert dash every 4 chars for readability
		if count%4 == 0 {
			sb.WriteByte('-')
		}
	}
	secret := sb.String()
	// trim trailing dash if we ended exactly on a group boundary
	if strings.HasSuffix(secret, "-") {
		secret = secret[:len(secret)-1]
	}
	return secret
}

// isValidPrefix validates the prefix format: non-empty, lowercase hex, and not
// exceeding MaxPrefixLen.
func isValidPrefix(p string) bool {
	if p == "" || len(p) > MaxPrefixLen {
		return false
	}
	for i := 0; i < len(p); i++ {
		c := p[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

// isValidSecret validates the user-friendly secret. It must be non-empty and
// consist only of characters from userFriendlyAlphabet and optional dashes.
// After removing dashes, the secret must have exactly SecretSymbolLen
// characters.
func isValidSecret(s string) bool {
	if s == "" {
		return false
	}
	plainCount := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '-' {
			continue
		}
		plainCount++
		if !strings.ContainsRune(userFriendlyAlphabet, rune(c)) {
			return false
		}
	}
	if plainCount != SecretSymbolLen {
		return false
	}
	return true
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
