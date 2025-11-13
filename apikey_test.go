package apikey

import (
	"testing"
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
	// generate a key and then tamper the hash deterministically
	full, _, hash, err := Generate(4)
	if err != nil {
		t.Fatalf("Generate error: %v", err)
	}
	if len(hash) < 2 {
		t.Fatalf("hash too short")
	}
	b := []rune(hash)
	// flip the first rune to something different
	if b[0] != '0' {
		b[0] = '0'
	} else {
		b[0] = '1'
	}
	bad := string(b)
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
