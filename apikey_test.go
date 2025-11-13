package apikey

import (
	"encoding/hex"
	"strings"
	"testing"
	"time"
)

func TestGenerateAndValidate(t *testing.T) {
	full, prefix, hash, err := Generate(6)
	if err != nil {
		t.Fatalf("Generate error: %v", err)
	}
	if prefix == "" {
		t.Fatalf("expected non-empty prefix")
	}
	if full == "" {
		t.Fatalf("expected non-empty full key")
	}
	ok, err := Validate(full, hash)
	if err != nil {
		t.Fatalf("Validate returned error: %v", err)
	}
	if !ok {
		t.Fatalf("expected generated key to validate")
	}
}

func TestParseInvalid(t *testing.T) {
	_, _, err := Parse("")
	if err == nil {
		t.Fatalf("expected error for empty key")
	}
	_, _, err = Parse("no-dot-here")
	if err == nil {
		t.Fatalf("expected error for invalid format")
	}
}

func TestHashSecret(t *testing.T) {
	s := "mysecret"
	h := HashSecret(s)
	if h == "" {
		t.Fatalf("expected non-empty hash")
	}
	// same input should produce same hash
	h2 := HashSecret(s)
	if h != h2 {
		t.Fatalf("hash should be deterministic")
	}
}

func TestValidateBad(t *testing.T) {
	// generate a key and then tamper the hash
	full, _, hash, err := Generate(4)
	if err != nil {
		t.Fatalf("Generate error: %v", err)
	}
	if len(hash) < 2 {
		t.Fatalf("hash too short")
	}
	bad := hash[:len(hash)-1] + "0"
	ok, err := Validate(full, bad)
	if err != nil {
		t.Fatalf("Validate error: %v", err)
	}
	if ok {
		t.Fatalf("expected validation to fail with bad hash")
	}
}

func TestGeneratePrefixLenBounds(t *testing.T) {
	full, prefix, _, err := Generate(0)
	if err != nil {
		t.Fatalf("Generate error: %v", err)
	}
	if len(prefix) != MaxPrefixLen {
		t.Fatalf("expected prefix length %d, got %d", MaxPrefixLen, len(prefix))
	}
	// ensure full contains prefix and dot
	if full[:len(prefix)] != prefix || full[len(prefix)] != '.' {
		t.Fatalf("full key format unexpected")
	}
	// too large
	full2, prefix2, _, err := Generate(100)
	if err != nil {
		t.Fatalf("Generate error: %v", err)
	}
	if len(prefix2) != MaxPrefixLen {
		t.Fatalf("expected prefix length %d, got %d", MaxPrefixLen, len(prefix2))
	}
	if full2[:len(prefix2)] != prefix2 || full2[len(prefix2)] != '.' {
		t.Fatalf("full key format unexpected")
	}
}

func TestGenerateBootstrap(t *testing.T) {
	plain, hash, expires, err := GenerateBootstrap()
	if err != nil {
		t.Fatalf("GenerateBootstrap error: %v", err)
	}

	// Validate plain key is 64 hex characters (32 bytes encoded)
	if len(plain) != 64 {
		t.Errorf("expected plain key length 64, got %d", len(plain))
	}
	if _, err := hex.DecodeString(plain); err != nil {
		t.Errorf("plain key is not valid hex: %v", err)
	}

	// Validate hash format (salt:derived)
	parts := strings.Split(hash, ":")
	if len(parts) != 2 {
		t.Fatalf("expected hash format 'salt:derived', got %d parts", len(parts))
	}

	// Validate salt is 32 hex characters (16 bytes)
	salt := parts[0]
	if len(salt) != 32 {
		t.Errorf("expected salt length 32, got %d", len(salt))
	}
	if _, err := hex.DecodeString(salt); err != nil {
		t.Errorf("salt is not valid hex: %v", err)
	}

	// Validate derived key is 64 hex characters (32 bytes)
	derived := parts[1]
	if len(derived) != 64 {
		t.Errorf("expected derived key length 64, got %d", len(derived))
	}
	if _, err := hex.DecodeString(derived); err != nil {
		t.Errorf("derived key is not valid hex: %v", err)
	}

	// Validate expiration is approximately 24 hours from now
	now := time.Now().UTC()
	expectedExpiry := now.Add(24 * time.Hour)
	diff := expires.Sub(expectedExpiry)
	if diff < -time.Second || diff > time.Second {
		t.Errorf("expected expiration ~24h from now, got %v (diff: %v)", expires, diff)
	}
}

func TestGenerateBootstrapUniqueness(t *testing.T) {
	plain1, hash1, _, err := GenerateBootstrap()
	if err != nil {
		t.Fatalf("GenerateBootstrap error: %v", err)
	}

	plain2, hash2, _, err := GenerateBootstrap()
	if err != nil {
		t.Fatalf("GenerateBootstrap error: %v", err)
	}

	// Each generation should produce unique values
	if plain1 == plain2 {
		t.Error("expected unique plain keys")
	}
	if hash1 == hash2 {
		t.Error("expected unique hashes")
	}
}

func TestGenerateBootstrapExpirationTiming(t *testing.T) {
	before := time.Now().UTC()
	_, _, expires, err := GenerateBootstrap()
	if err != nil {
		t.Fatalf("GenerateBootstrap error: %v", err)
	}
	after := time.Now().UTC()

	// Expiration should be 24 hours after generation time
	expectedMin := before.Add(24 * time.Hour)
	expectedMax := after.Add(24 * time.Hour)

	if expires.Before(expectedMin) || expires.After(expectedMax) {
		t.Errorf("expiration %v outside expected range [%v, %v]", expires, expectedMin, expectedMax)
	}
}
