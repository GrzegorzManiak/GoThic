package helpers

import (
	"crypto/rand"
	"fmt"
	"math/big"
)

const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

func GenerateID(length int) (string, error) {
	b := make([]byte, length)
	maxInt := big.NewInt(int64(len(charset)))

	for i := range b {
		n, err := rand.Int(rand.Reader, maxInt)
		if err != nil {
			return "", fmt.Errorf("crypto/rand.Int failed: %w", err)
		}
		b[i] = charset[n.Int64()]
	}

	return string(b), nil
}
