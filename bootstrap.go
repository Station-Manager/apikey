package apikey

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"golang.org/x/crypto/argon2"
	"strings"
	"time"
)

// GenerateBootstrap creates a new one-off bootstrap secret suitable for
// securely provisioning a client or account.
//
// It returns:
//   - plain: a 64-character hex-encoded bootstrap secret that must be sent
//     once to the client (or used in the initial bootstrap request). This
//     value is **not** stored server-side and must be treated as sensitive.
//   - hash: a persistent representation of the secret for storage in the
//     database. The format is:
//     <salt-hex><colonString><argon2id-hash-hex>
//     where:
//   - salt-hex is a 16-byte random salt, hex-encoded.
//   - argon2id-hash-hex is the Argon2ID-derived key of:
//     sha256(secret) with the generated salt, using parameters
//     time=1, memory=64*1024 KiB, threads=4, keyLen=32.
//     This value is used later by ValidateBootstrap to authenticate a
//     presented bootstrap token without ever storing the plaintext secret.
//   - expires: a UTC timestamp set to 24 hours from the time of generation.
//     Callers should persist this value and refuse bootstrap tokens that
//     are presented after this time.
//   - err: a non-nil error if a cryptographically secure random value could
//     not be generated for either the secret or the salt.
//
// The generated secret and salt use crypto/rand for randomness. On error,
// plain, hash, and expires are left at their zero values and err is set.
func GenerateBootstrap() (plain, hash string, expires time.Time, err error) {
	secret := make([]byte, 32)
	if _, err = rand.Read(secret); err != nil {
		fmt.Println(err)
		return
	}
	plain = hex.EncodeToString(secret)
	// IMPORTANT: We hash the raw secret bytes, not the hex string
	sum := sha256.Sum256(secret)
	salt := make([]byte, 16)
	if _, err = rand.Read(salt); err != nil {
		fmt.Println(err)
		return
	}

	derived := argon2.IDKey(sum[:], salt, 1, 64*1024, 4, 32)
	hash = hex.EncodeToString(salt) + colonString + hex.EncodeToString(derived)
	expires = time.Now().UTC().Add(24 * time.Hour)
	return
}

// ValidateBootstrap checks whether the given plaintext bootstrap token
// matches the stored Argon2ID hash produced by GenerateBootstrap.
func ValidateBootstrap(plain, stored string) (bool, error) {
	if plain == emptyString || stored == emptyString {
		return false, errors.New("empty plain or stored value")
	}

	parts := strings.Split(stored, colonString)
	if len(parts) != 2 {
		return false, errors.New("invalid stored bootstrap hash format")
	}

	saltHex, derivedHex := parts[0], parts[1]

	salt, err := hex.DecodeString(saltHex)
	if err != nil {
		return false, errors.New("invalid salt encoding")
	}
	storedDerived, err := hex.DecodeString(derivedHex)
	if err != nil {
		return false, errors.New("invalid hash encoding")
	}

	// Decode the hex-encoded plaintext secret back to raw bytes so we hash
	// the same value that GenerateBootstrap used.
	secretBytes, err := hex.DecodeString(plain)
	if err != nil {
		return false, errors.New("invalid plaintext encoding")
	}
	sum := sha256.Sum256(secretBytes)

	// Argon2ID params must match GenerateBootstrap exactly.
	computed := argon2.IDKey(sum[:], salt, 1, 64*1024, 4, 32)

	// Constant-time comparison.
	if len(computed) != len(storedDerived) {
		return false, nil
	}
	if subtle.ConstantTimeCompare(computed, storedDerived) != 1 {
		return false, nil
	}

	return true, nil
}
