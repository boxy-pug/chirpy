package auth

import (
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"
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
	err = CheckPasswordHash(hash, password)
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

func TestValidateJWT(t *testing.T) {
	secret := "my_secret_key"
	userID := uuid.New()

	// Create a valid token
	token, err := MakeJWT(userID, secret, 1*time.Hour)
	if err != nil {
		t.Fatalf("failed to create JWT: %v", err)
	}

	// Test valid token
	id, err := ValidateJWT(token, secret)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if id != userID {
		t.Errorf("expected user ID %v, got %v", userID, id)
	}

	// Test expired token
	expiredToken, err := MakeJWT(userID, secret, -1*time.Hour) // Create an expired token
	if err != nil {
		t.Fatalf("failed to create JWT: %v", err)
	}

	id, err = ValidateJWT(expiredToken, secret)
	if err == nil {
		t.Fatal("expected an error for expired token, got none")
	}

	// Test token with wrong secret
	wrongSecret := "wrong_secret_key"
	id, err = ValidateJWT(token, wrongSecret)
	if err == nil {
		t.Fatal("expected an error for token signed with wrong secret, got none")
	}
}

func TestGetBearerToken(t *testing.T) {
	tests := []struct {
		name      string
		headers   http.Header
		expected  string
		shouldErr bool
	}{
		{
			name: "Valid token",
			headers: http.Header{
				"Authorization": []string{"Bearer valid_token"},
			},
			expected:  "valid_token",
			shouldErr: false,
		},
		{
			name:      "Missing header",
			headers:   http.Header{},
			expected:  "",
			shouldErr: true,
		},
		{
			name: "Invalid format - missing Bearer",
			headers: http.Header{
				"Authorization": []string{"InvalidToken"},
			},
			expected:  "",
			shouldErr: true,
		},
		{
			name: "Invalid format - extra spaces",
			headers: http.Header{
				"Authorization": []string{"Bearer   "},
			},
			expected:  "",
			shouldErr: true,
		},
		{
			name: "Invalid format - no token",
			headers: http.Header{
				"Authorization": []string{"Bearer "},
			},
			expected:  "",
			shouldErr: true,
		},
		{
			name: "Invalid format - multiple spaces",
			headers: http.Header{
				"Authorization": []string{"Bearer  invalid_token  "},
			},
			expected:  "invalid_token",
			shouldErr: false,
		},
		{
			name: "Invalid format - lower case bearer",
			headers: http.Header{
				"Authorization": []string{"bearer valid_token"},
			},
			expected:  "valid_token",
			shouldErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token, err := GetBearerToken(tt.headers)
			if (err != nil) != tt.shouldErr {
				t.Fatalf("expected error: %v, got: %v", tt.shouldErr, err)
			}
			if token != tt.expected {
				t.Fatalf("expected token: %v, got: %v", tt.expected, token)
			}
		})
	}
}
