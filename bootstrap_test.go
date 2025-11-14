package apikey

import (
	"strings"
	"testing"
	"time"
)

func TestGenerateBootstrapAndValidate_Success(t *testing.T) {
	plain, stored, expires, err := GenerateBootstrap()
	if err != nil {
		t.Fatalf("GenerateBootstrap error: %v", err)
	}
	if plain == "" {
		t.Fatalf("expected non-empty plaintext secret")
	}
	if stored == "" {
		t.Fatalf("expected non-empty stored hash")
	}
	if !strings.Contains(stored, colonString) {
		t.Fatalf("stored hash %q missing separator %q", stored, colonString)
	}
	if time.Until(expires) <= 0 {
		t.Fatalf("expected expiry in the future, got %v", expires)
	}

	ok, err := ValidateBootstrap(plain, stored)
	if err != nil {
		t.Fatalf("ValidateBootstrap error: %v", err)
	}
	if !ok {
		t.Fatalf("expected bootstrap validation to succeed for generated secret")
	}
}

func TestValidateBootstrap_EmptyInputs(t *testing.T) {
	if ok, err := ValidateBootstrap("", ""); err == nil || ok {
		t.Fatalf("expected error and false for empty inputs, got ok=%v err=%v", ok, err)
	}
}

func TestValidateBootstrap_InvalidFormat(t *testing.T) {
	if ok, err := ValidateBootstrap("foo", "not-a-valid-format"); err == nil || ok {
		t.Fatalf("expected format error and false, got ok=%v err=%v", ok, err)
	}
}

func TestValidateBootstrap_WrongSecret(t *testing.T) {
	plain, stored, _, err := GenerateBootstrap()
	if err != nil {
		t.Fatalf("GenerateBootstrap error: %v", err)
	}
	ok, err := ValidateBootstrap(plain+"deadbeef", stored)
	if err != nil {
		t.Fatalf("ValidateBootstrap error: %v", err)
	}
	if ok {
		t.Fatalf("expected validation to fail for wrong secret")
	}
}
