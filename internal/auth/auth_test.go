package auth

import (
	"testing"
)

func TestHashPassword(t *testing.T) {
	password := "mysecretpassword"

	// Test hashing a password
	hash, err := HashPassword(password)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	// Ensure the hash is not empty
	if hash == "" {
		t.Fatal("expected a non-empty hash")
	}
}

func TestCheckPasswordHash(t *testing.T) {
	password := "mysecretpassword"

	// Hash the password first
	hash, err := HashPassword(password)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	// Test checking the correct password
	err = CheckPasswordHash(password, hash)
	if err != nil {
		t.Fatalf("expected no error for correct password, got %v", err)
	}

	// Test checking an incorrect password
	wrongPassword := "wrongpassword"
	err = CheckPasswordHash(wrongPassword, hash)
	if err == nil {
		t.Fatal("expected an error for incorrect password, got nil")
	}
}
