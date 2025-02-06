package main

import (
	"testing"
)

func TestBadWordReplacement(t *testing.T) {
	// Define test cases
	testCases := []struct {
		input    string
		expected string
	}{
		{"This is a kerfuffle", "This is a ****"},
		{"I love sharbert and fornax", "I love **** and ****"},
		{"No bad words here", "No bad words here"},
		{"Kerfuffle and FORNAX", "**** and ****"},
		{"Kerfuffle! and FORNAX...", "Kerfuffle! and FORNAX..."},
	}

	// Run each test case
	for _, tc := range testCases {
		t.Run(tc.input, func(t *testing.T) {
			result := badWordReplacement(tc.input)
			if result != tc.expected {
				t.Errorf("expected %q but got %q", tc.expected, result)
			}
		})
	}
}
