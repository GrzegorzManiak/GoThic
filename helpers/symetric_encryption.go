package helpers

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
)

const (
	// AESKeySize32 is for AES-256 (32 bytes)
	AESKeySize32 = 32
	// AESKeySize24 is for AES-192 (24 bytes)
	AESKeySize24 = 24
	// AESKeySize16 is for AES-128 (16 bytes)
	AESKeySize16 = 16
)

// GenerateSymmetricKey creates a new random key of the specified size in bytes.
// Common sizes are 16 (AES-128), 24 (AES-192), or 32 (AES-256).
func GenerateSymmetricKey(size int) ([]byte, error) {
	if size != AESKeySize16 && size != AESKeySize24 && size != AESKeySize32 {
		return nil, fmt.Errorf("invalid key size: must be %d, %d, or %d bytes", AESKeySize16, AESKeySize24, AESKeySize32)
	}
	key := make([]byte, size)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, fmt.Errorf("failed to generate symmetric key: %w", err)
	}
	return key, nil
}

// SymmetricEncrypt encrypts plaintext using AES-GCM with the given key.
func SymmetricEncrypt(key *[]byte, plaintext []byte, associatedData []byte) ([]byte, error) {
	dereferencedKey := *key
	if dereferencedKey == nil {
		return nil, fmt.Errorf("key cannot be nil")
	}

	block, err := aes.NewCipher(dereferencedKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher block: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM AEAD: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	ciphertext := gcm.Seal(nil, nonce, plaintext, associatedData)
	return append(nonce, ciphertext...), nil
}

// SymmetricDecrypt decrypts ciphertext (which must include a prepended nonce) using AES-GCM.
func SymmetricDecrypt(key *[]byte, ciphertextWithNonce []byte, associatedData []byte) ([]byte, error) {
	dereferencedKey := *key
	if dereferencedKey == nil {
		return nil, fmt.Errorf("key cannot be nil")
	}

	block, err := aes.NewCipher(dereferencedKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher block: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM AEAD: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertextWithNonce) < nonceSize {
		return nil, fmt.Errorf("ciphertext is too short (missing nonce)")
	}

	nonce, ciphertext := ciphertextWithNonce[:nonceSize], ciphertextWithNonce[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, associatedData)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt or authenticate data: %w", err)
	}

	return plaintext, nil
}
