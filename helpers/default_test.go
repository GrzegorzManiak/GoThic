package helpers

import (
	"testing"
	"time"
)

func TestDefaultString(t *testing.T) {
	t.Run("Returns default when value is empty", func(t *testing.T) {
		result := DefaultString("", "default")
		if result != "default" {
			t.Errorf("Expected 'default', got '%s'", result)
		}
	})

	t.Run("Returns value when non-empty", func(t *testing.T) {
		result := DefaultString("custom", "default")
		if result != "custom" {
			t.Errorf("Expected 'custom', got '%s'", result)
		}
	})

	t.Run("Returns empty default when both empty", func(t *testing.T) {
		result := DefaultString("", "")
		if result != "" {
			t.Errorf("Expected empty string, got '%s'", result)
		}
	})

	t.Run("Handles whitespace as non-empty", func(t *testing.T) {
		result := DefaultString(" ", "default")
		if result != " " {
			t.Errorf("Expected ' ', got '%s'", result)
		}
	})
}

func TestDefaultBool(t *testing.T) {
	t.Run("Returns default when value is false", func(t *testing.T) {
		result := DefaultBool(false, true)
		if result != true {
			t.Error("Expected true, got false")
		}
	})

	t.Run("Returns value when true", func(t *testing.T) {
		result := DefaultBool(true, false)
		if result != true {
			t.Error("Expected true, got false")
		}
	})

	t.Run("Returns false default when both false", func(t *testing.T) {
		result := DefaultBool(false, false)
		if result != false {
			t.Error("Expected false, got true")
		}
	})

	t.Run("Returns true when both true", func(t *testing.T) {
		result := DefaultBool(true, true)
		if result != true {
			t.Error("Expected true, got false")
		}
	})
}

func TestDefaultInt(t *testing.T) {
	t.Run("Returns default when value is zero", func(t *testing.T) {
		result := DefaultInt(0, 42)
		if result != 42 {
			t.Errorf("Expected 42, got %d", result)
		}
	})

	t.Run("Returns value when non-zero positive", func(t *testing.T) {
		result := DefaultInt(100, 42)
		if result != 100 {
			t.Errorf("Expected 100, got %d", result)
		}
	})

	t.Run("Returns value when negative", func(t *testing.T) {
		result := DefaultInt(-5, 42)
		if result != -5 {
			t.Errorf("Expected -5, got %d", result)
		}
	})

	t.Run("Returns zero default when both zero", func(t *testing.T) {
		result := DefaultInt(0, 0)
		if result != 0 {
			t.Errorf("Expected 0, got %d", result)
		}
	})

	t.Run("Handles large numbers", func(t *testing.T) {
		result := DefaultInt(1000000, 42)
		if result != 1000000 {
			t.Errorf("Expected 1000000, got %d", result)
		}
	})
}

func TestDefaultInt64(t *testing.T) {
	t.Run("Returns default when value is zero", func(t *testing.T) {
		result := DefaultInt64(0, 42)
		if result != 42 {
			t.Errorf("Expected 42, got %d", result)
		}
	})

	t.Run("Returns value when non-zero positive", func(t *testing.T) {
		result := DefaultInt64(100, 42)
		if result != 100 {
			t.Errorf("Expected 100, got %d", result)
		}
	})

	t.Run("Returns value when negative", func(t *testing.T) {
		result := DefaultInt64(-5, 42)
		if result != -5 {
			t.Errorf("Expected -5, got %d", result)
		}
	})

	t.Run("Returns zero default when both zero", func(t *testing.T) {
		result := DefaultInt64(0, 0)
		if result != 0 {
			t.Errorf("Expected 0, got %d", result)
		}
	})

	t.Run("Handles very large numbers", func(t *testing.T) {
		var largeNum int64 = 9223372036854775807 // Max int64
		result := DefaultInt64(largeNum, 42)
		if result != largeNum {
			t.Errorf("Expected %d, got %d", largeNum, result)
		}
	})

	t.Run("Handles very small negative numbers", func(t *testing.T) {
		var smallNum int64 = -9223372036854775808 // Min int64
		result := DefaultInt64(smallNum, 42)
		if result != smallNum {
			t.Errorf("Expected %d, got %d", smallNum, result)
		}
	})
}

func TestDefaultTimeDuration(t *testing.T) {
	t.Run("Returns default when value is zero", func(t *testing.T) {
		result := DefaultTimeDuration(0, 5*time.Second)
		if result != 5*time.Second {
			t.Errorf("Expected 5s, got %v", result)
		}
	})

	t.Run("Returns value when non-zero", func(t *testing.T) {
		result := DefaultTimeDuration(10*time.Second, 5*time.Second)
		if result != 10*time.Second {
			t.Errorf("Expected 10s, got %v", result)
		}
	})

	t.Run("Returns zero default when both zero", func(t *testing.T) {
		result := DefaultTimeDuration(0, 0)
		if result != 0 {
			t.Errorf("Expected 0, got %v", result)
		}
	})

	t.Run("Handles various time units", func(t *testing.T) {
		testCases := []struct {
			name     string
			value    time.Duration
			def      time.Duration
			expected time.Duration
		}{
			{"Milliseconds", 100 * time.Millisecond, 50 * time.Millisecond, 100 * time.Millisecond},
			{"Minutes", 5 * time.Minute, 1 * time.Minute, 5 * time.Minute},
			{"Hours", 2 * time.Hour, 1 * time.Hour, 2 * time.Hour},
			{"Zero value uses default", 0, 30 * time.Second, 30 * time.Second},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				result := DefaultTimeDuration(tc.value, tc.def)
				if result != tc.expected {
					t.Errorf("Expected %v, got %v", tc.expected, result)
				}
			})
		}
	})

	t.Run("Handles negative durations", func(t *testing.T) {
		result := DefaultTimeDuration(-5*time.Second, 10*time.Second)
		if result != -5*time.Second {
			t.Errorf("Expected -5s, got %v", result)
		}
	})
}

func TestDefaultFunctionsEdgeCases(t *testing.T) {
	t.Run("All default functions are consistent with zero values", func(t *testing.T) {
		// String
		if DefaultString("", "fallback") != "fallback" {
			t.Error("DefaultString failed with empty string")
		}

		// Bool
		if DefaultBool(false, true) != true {
			t.Error("DefaultBool failed with false")
		}

		// Int
		if DefaultInt(0, 123) != 123 {
			t.Error("DefaultInt failed with 0")
		}

		// Int64
		if DefaultInt64(0, 123) != 123 {
			t.Error("DefaultInt64 failed with 0")
		}

		// Duration
		if DefaultTimeDuration(0, 5*time.Second) != 5*time.Second {
			t.Error("DefaultTimeDuration failed with 0")
		}
	})

	t.Run("All default functions preserve non-zero values", func(t *testing.T) {
		// String
		if DefaultString("value", "fallback") != "value" {
			t.Error("DefaultString changed non-empty string")
		}

		// Bool
		if DefaultBool(true, false) != true {
			t.Error("DefaultBool changed true value")
		}

		// Int
		if DefaultInt(456, 123) != 456 {
			t.Error("DefaultInt changed non-zero value")
		}

		// Int64
		if DefaultInt64(456, 123) != 456 {
			t.Error("DefaultInt64 changed non-zero value")
		}

		// Duration
		if DefaultTimeDuration(10*time.Second, 5*time.Second) != 10*time.Second {
			t.Error("DefaultTimeDuration changed non-zero value")
		}
	})
}
