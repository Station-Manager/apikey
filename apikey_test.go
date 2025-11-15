package apikey

import (
	"strings"
	"testing"
)

func TestGenerateAndValidate(t *testing.T) {
	full, prefix, hash, err := GenerateApiKey(6)
	if err != nil {
		t.Fatalf("GenerateApiKey error: %v", err)
	}
	if prefix == "" {
		t.Fatalf("expected non-empty prefix")
	}
	if full == "" {
		t.Fatalf("expected non-empty full key")
	}
	if !isTextSafe(full) || !isTextSafe(prefix) || !isTextSafe(hash) {
		t.Fatalf("generated values are not text-safe")
	}

	// full must start with prefix + separator
	if !strings.HasPrefix(full, prefix+separator) {
		t.Fatalf("full key should start with prefix and separator")
	}

	ok, err := ValidateApiKey(full, hash)
	if err != nil {
		t.Fatalf("ValidateApiKey returned error: %v", err)
	}
	if !ok {
		t.Fatalf("expected generated key to validate")
	}
}

func TestParseInvalid(t *testing.T) {
	_, _, err := ParseApiKey("")
	if err == nil {
		t.Fatalf("expected error for empty key")
	}
	_, _, err = ParseApiKey("no_separator_here")
	if err == nil {
		t.Fatalf("expected error for invalid format (no separator)")
	}
	_, _, err = ParseApiKey("_nosecret")
	if err == nil {
		t.Fatalf("expected error for missing prefix")
	}
	_, _, err = ParseApiKey("prefix_")
	if err == nil {
		t.Fatalf("expected error for missing secret")
	}
}

func TestHashSecret(t *testing.T) {
	// an example user-friendly secret
	s := "ABCD-EFGH-JKLM-NPQR"
	h := HashApiKeySecret(s)
	if h == "" {
		t.Fatalf("expected non-empty hash")
	}
	if !isTextSafe(h) {
		t.Fatalf("hash is not text-safe")
	}
	// same input should produce same hash
	h2 := HashApiKeySecret(s)
	if h != h2 {
		t.Fatalf("hash should be deterministic")
	}
}

func TestValidateBad(t *testing.T) {
	// generate a key and then tamper the hash deterministically
	full, _, hash, err := GenerateApiKey(4)
	if err != nil {
		t.Fatalf("GenerateApiKey error: %v", err)
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
	ok, err := ValidateApiKey(full, bad)
	if err != nil {
		t.Fatalf("ValidateApiKey error: %v", err)
	}
	if ok {
		t.Fatalf("expected validation to fail with bad hash")
	}
}

func TestGeneratePrefixLenBounds(t *testing.T) {
	full, prefix, _, err := GenerateApiKey(0)
	if err != nil {
		t.Fatalf("GenerateApiKey error: %v", err)
	}
	if len(prefix) != MaxPrefixLen {
		t.Fatalf("expected prefix length %d, got %d", MaxPrefixLen, len(prefix))
	}
	// ensure full contains prefix and separator
	if full[:len(prefix)] != prefix || full[len(prefix)] != []byte(separator)[0] {
		t.Fatalf("full key format unexpected")
	}
	if !isTextSafe(full) || !isTextSafe(prefix) {
		t.Fatalf("generated values are not text-safe")
	}
	// too large
	full2, prefix2, _, err := GenerateApiKey(100)
	if err != nil {
		t.Fatalf("GenerateApiKey error: %v", err)
	}
	if len(prefix2) != MaxPrefixLen {
		t.Fatalf("expected prefix length %d, got %d", MaxPrefixLen, len(prefix2))
	}
	if full2[:len(prefix2)] != prefix2 || full2[len(prefix2)] != []byte(separator)[0] {
		t.Fatalf("full key format unexpected")
	}
	if !isTextSafe(full2) || !isTextSafe(prefix2) {
		t.Fatalf("generated values are not text-safe")
	}
}

func TestGenerateApiKey_SecretFormat(t *testing.T) {
	full, _, _, err := GenerateApiKey(8)
	if err != nil {
		t.Fatalf("GenerateApiKey error: %v", err)
	}
	_, secret, err := ParseApiKey(full)
	if err != nil {
		t.Fatalf("ParseApiKey error: %v", err)
	}
	if secret == "" {
		t.Fatalf("expected non-empty secret")
	}
	// ensure secret uses allowed characters only and has exact symbol length
	if !isValidSecret(secret) {
		t.Fatalf("secret has invalid characters or wrong length: %q", secret)
	}
	plain := strings.ReplaceAll(secret, "-", "")
	if len(plain) != SecretSymbolLen {
		t.Fatalf("expected secret length == %d, got %d", SecretSymbolLen, len(plain))
	}
}

func TestParseApiKey_InvalidSecretChars(t *testing.T) {
	// lowercase letters in secret should be rejected
	full := "abcd12_abcD-efgh-IJKL-MNPQ"
	if _, _, err := ParseApiKey(full); err == nil {
		t.Fatalf("expected error for secret with invalid characters (lowercase)")
	}

	// forbidden characters (e.g., 'O', '0', 'I', '1', 'L') should be rejected
	full = "abcd12_ABCD-EF0H-IJKL-MNPQ"
	if _, _, err := ParseApiKey(full); err == nil {
		t.Fatalf("expected error for secret with forbidden characters")
	}
}

func TestParseApiKey_InvalidSecretLength(t *testing.T) {
	// too short: fewer than SecretSymbolLen non-dash symbols
	shortSecret := strings.Repeat("A", SecretSymbolLen-1)
	full := "abcd12_" + shortSecret
	if _, _, err := ParseApiKey(full); err == nil {
		t.Fatalf("expected error for too-short secret")
	}

	// too long: more than SecretSymbolLen non-dash symbols
	longSecret := strings.Repeat("A", SecretSymbolLen+1)
	full = "abcd12_" + longSecret
	if _, _, err := ParseApiKey(full); err == nil {
		t.Fatalf("expected error for too-long secret")
	}
}

func TestValidateApiKey_InvalidSecretFormat(t *testing.T) {
	// malformed secret should cause ValidateApiKey to return false with an error
	full := "abcd12_ABCD-efgh-IJKL-MNPQ" // lowercase in secret
	ok, err := ValidateApiKey(full, strings.Repeat("0", 128))
	if err == nil {
		t.Fatalf("expected error from ValidateApiKey for malformed secret")
	}
	if ok {
		t.Fatalf("expected ok=false for malformed secret")
	}
}
