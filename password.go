package apikey

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
)

// Argon2id parameters (sane defaults for interactive logins)
const (
	argonTime     uint32 = 2         // iterations
	argonMemory   uint32 = 64 * 1024 // KiB (64 MiB)
	argonParallel uint8  = 1         // threads
	argonSaltLen         = 16        // bytes
	argonKeyLen          = 32        // bytes
)

// HashPassword derives an Argon2id hash for the provided password and returns
// a PHC-formatted string: $argon2id$v=19$m=<mem>,t=<time>,p=<par>$<saltB64>$<hashB64>
func HashPassword(password string) (string, error) {
	if strings.TrimSpace(password) == emptyString {
		return emptyString, errors.New("password cannot be empty")
	}
	salt := make([]byte, argonSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return emptyString, fmt.Errorf("rand.Read: %w", err)
	}
	h := argon2.IDKey([]byte(password), salt, argonTime, argonMemory, argonParallel, argonKeyLen)
	b64Salt := base64.RawStdEncoding.EncodeToString(salt)
	b64Hash := base64.RawStdEncoding.EncodeToString(h)
	phc := fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s", argonMemory, argonTime, argonParallel, b64Salt, b64Hash)
	return phc, nil
}

// VerifyPassword checks a password against a PHC-formatted Argon2id hash.
// Returns true if it matches, false otherwise.
func VerifyPassword(phc, password string) (bool, error) {
	if !strings.HasPrefix(phc, "$argon2id$") {
		return false, errors.New("unsupported hash format")
	}
	parts := strings.Split(phc, "$")
	// parts: ["", "argon2id", "v=19", "m=..,t=..,p=..", "<salt>", "<hash>"]
	if len(parts) != 6 {
		return false, errors.New("invalid phc format")
	}
	versionPart := parts[2]
	if versionPart != "v=19" {
		return false, errors.New("unsupported argon2 version")
	}
	paramPart := parts[3]
	var mem uint32
	var time uint32
	var par uint8
	for _, kv := range strings.Split(paramPart, ",") {
		kvp := strings.SplitN(kv, "=", 2)
		if len(kvp) != 2 {
			return false, errors.New("invalid argon2 params")
		}
		switch kvp[0] {
		case "m":
			mv, err := strconv.ParseUint(kvp[1], 10, 32)
			if err != nil {
				return false, err
			}
			mem = uint32(mv)
		case "t":
			iv, err := strconv.ParseUint(kvp[1], 10, 32)
			if err != nil {
				return false, err
			}
			time = uint32(iv)
		case "p":
			pv, err := strconv.ParseUint(kvp[1], 10, 8)
			if err != nil {
				return false, err
			}
			par = uint8(pv)
		default:
			return false, errors.New("unknown argon2 param")
		}
	}
	saltB64 := parts[4]
	hashB64 := parts[5]
	salt, err := base64.RawStdEncoding.DecodeString(saltB64)
	if err != nil {
		return false, fmt.Errorf("decode salt: %w", err)
	}
	want, err := base64.RawStdEncoding.DecodeString(hashB64)
	if err != nil {
		return false, fmt.Errorf("decode hash: %w", err)
	}
	got := argon2.IDKey([]byte(password), salt, time, mem, par, uint32(len(want)))
	if len(got) != len(want) {
		return false, nil
	}
	if subtle.ConstantTimeCompare(got, want) == 1 {
		return true, nil
	}
	return false, nil
}
