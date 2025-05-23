package helpers

import (
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
)

// GenerateHMACSignature creates an HMAC-SHA256 signature for the given data.
func GenerateHMACSignature(data []byte, secretKey *[]byte) ([]byte, error) {
	dereferencedKey := *secretKey
	if len(dereferencedKey) == 0 {
		return nil, fmt.Errorf("secret key cannot be empty")
	}

	h := hmac.New(sha256.New, dereferencedKey)
	_, err := h.Write(data)
	if err != nil {
		return nil, fmt.Errorf("failed to write data to hmac: %w", err)
	}

	return h.Sum(nil), nil
}

// VerifyHMACSignature verifies an HMAC-SHA256 signature for the given data.
func VerifyHMACSignature(data []byte, expectedData []byte, secretKey *[]byte) (bool, error) {
	dereferencedKey := *secretKey
	if len(dereferencedKey) == 0 {
		return false, fmt.Errorf("secret key cannot be empty")
	}

	h := hmac.New(sha256.New, dereferencedKey)
	_, err := h.Write(data)
	if err != nil {
		return false, fmt.Errorf("failed to write data to hmac for verification: %w", err)
	}

	calculatedSignature := h.Sum(nil)

	// - Use hmac.Equal for constant-time comparison to prevent timing attacks.
	return hmac.Equal(calculatedSignature, expectedData), nil
}
