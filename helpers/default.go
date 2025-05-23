package helpers

import "time"

// DefaultString returns the defaultValue if the provided value is an empty string.
// Otherwise, it returns the original value.
func DefaultString(value string, defaultValue string) string {
	if value == "" {
		return defaultValue
	}
	return value
}

// DefaultBool returns the defaultValue if the provided value is false (the zero value for bool).
// Otherwise, it returns the original value (which would be true).
// This is useful when 'false' is considered "not set" and you want to apply a default.
// For example,
func DefaultBool(value bool, defaultValue bool) bool {
	if !value {
		return defaultValue
	}
	return value
}

// DefaultInt returns the defaultValue if the provided value is 0 (the zero value for int).
// Otherwise, it returns the original value.
// Note: If 0 is a legitimate, intentionally set value that is different from "not set",
// this function might not be suitable for that specific field!!
func DefaultInt(value int, defaultValue int) int {
	if value == 0 {
		return defaultValue
	}
	return value
}

// DefaultInt64 returns the defaultValue if the provided value is 0 (the zero value for int64).
// Otherwise, it returns the original value.
// Note: If 0 is a legitimate, intentionally set value that is different from "not set",
// this function might not be suitable for that specific field!!
func DefaultInt64(value int64, defaultValue int64) int64 {
	if value == 0 {
		return defaultValue
	}
	return value
}

// DefaultTimeDuration returns the defaultValue if the provided value is 0 (the zero value for time.Duration).
// Otherwise, it returns the original value.
// Note: If time.Duration(0) is a legitimate, intentionally set value,
// this function might not be suitable for that specific field.
func DefaultTimeDuration(value time.Duration, defaultValue time.Duration) time.Duration {
	if value == 0 {
		return defaultValue
	}
	return value
}
