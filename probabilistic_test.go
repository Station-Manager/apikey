package apikey

import "testing"

// TestGenerateIndependentPrefixSanity checks, with overwhelming probability,
// that the generated prefix is independent of the secret.
// If the implementation incorrectly derives the prefix from the secret,
// this test would observe matches on every iteration and fail.
func TestGenerateIndependentPrefixSanity(t *testing.T) {
	const (
		N          = 8    // chars to compare (<= MaxPrefixLen)
		iterations = 2000 // fast, and collision probability is vanishingly small
	)
	if N > MaxPrefixLen {
		t.Fatalf("test misconfigured: N(%d) > MaxPrefixLen(%d)", N, MaxPrefixLen)
	}
	matches := 0
	for i := 0; i < iterations; i++ {
		full, prefix, _, err := GenerateApiKey(N)
		if err != nil {
			t.Fatalf("GenerateApiKey failed: %v", err)
		}
		p, secret, err := ParseApiKey(full)
		if err != nil {
			t.Fatalf("ParseApiKey failed: %v", err)
		}
		if p != prefix {
			t.Fatalf("inconsistent prefix: got %q, want %q", p, prefix)
		}
		if len(secret) < N {
			t.Fatalf("secret too short: len=%d, want>=%d", len(secret), N)
		}
		if prefix == secret[:N] {
			matches++
			break // No need to continue; any match strongly suggests dependence
		}
	}
	if matches > 0 {
		t.Fatalf("prefix appears derived from secret: observed %d match(es) where prefix == secret[:%d]", matches, N)
	}
}
