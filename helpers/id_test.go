package helpers

import (
	"strings"
	"testing"
)

func TestGenerateID(t *testing.T) {
	t.Run("Generates ID with correct length", func(t *testing.T) {
		testCases := []struct {
			name   string
			length int
		}{
			{"zero length", 0},
			{"single character", 1},
			{"standard lengths", 8},
			{"standard lengths", 16},
			{"standard lengths", 32},
			{"standard lengths", 64},
			{"large length", 1024},
		}

		for _, tc := range testCases {
			id, err := GenerateID(tc.length)
			if err != nil {
				t.Fatalf("Expected no error for length %d, got %v", tc.length, err)
			}
			if len(id) != tc.length {
				t.Errorf("Expected ID length %d, got %d", tc.length, len(id))
			}
		}
	})

	t.Run("Generated IDs contain only valid characters", func(t *testing.T) {
		id, err := GenerateID(100)
		if err != nil {
			t.Fatalf("Expected no error, got %v", err)
		}

		for _, char := range id {
			if !strings.ContainsRune(charset, char) {
				t.Errorf("ID contains invalid character: %c", char)
			}
		}
	})

	t.Run("Generates unique IDs", func(t *testing.T) {
		ids := make(map[string]bool)
		iterations := 1000
		length := 32

		for i := 0; i < iterations; i++ {
			id, err := GenerateID(length)
			if err != nil {
				t.Fatalf("Expected no error on iteration %d, got %v", i, err)
			}
			if ids[id] {
				t.Fatalf("Duplicate ID generated: %s", id)
			}
			ids[id] = true
		}
	})

	t.Run("Generated ID has good character distribution", func(t *testing.T) {
		const length = 10000
		id, err := GenerateID(length)
		if err != nil {
			t.Fatalf("Expected no error, got %v", err)
		}

		charCount := make(map[rune]int)
		for _, char := range id {
			charCount[char]++
		}

		// A simple statistical check: at least half of the available characters
		// should be present in a sufficiently long random string.
		minDistinctChars := len(charset) / 2
		if len(charCount) < minDistinctChars {
			t.Errorf("Poor character distribution: expected at least %d different chars, but got %d in a string of length %d", minDistinctChars, len(charCount), length)
		}
	})
}
