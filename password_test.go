package apikey

import "testing"

func TestHashAndVerifyPassword(t *testing.T) {
	phc, err := HashPassword("correct horse battery staple")
	if err != nil {
		t.Fatalf("HashPassword error: %v", err)
	}
	ok, err := VerifyPassword(phc, "correct horse battery staple")
	if err != nil || !ok {
		t.Fatalf("VerifyPassword should succeed, ok=%v err=%v", ok, err)
	}
	ok, err = VerifyPassword(phc, "wrong password")
	if err != nil {
		t.Fatalf("VerifyPassword unexpected error for wrong password: %v", err)
	}
	if ok {
		t.Fatalf("VerifyPassword should fail for wrong password")
	}
}

func TestVerifyPassword_BadFormat(t *testing.T) {
	if ok, err := VerifyPassword("$argon2i$v=19$m=65536,t=2,p=1$bad$bad", "pw"); err == nil {
		t.Fatalf("expected error for unsupported format, got ok=%v", ok)
	}
	if ok, err := VerifyPassword("not-phc", "pw"); err == nil {
		t.Fatalf("expected error for invalid format, got ok=%v", ok)
	}
}
