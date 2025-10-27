package helpers

import (
	"bytes"
	"testing"
)

func TestGenerateSymmetricKey(t *testing.T) {
	t.Run("Generates AES-128 key (16 bytes)", func(t *testing.T) {
		key, err := GenerateSymmetricKey(AESKeySize16)
		if err != nil {
			t.Fatalf("Expected no error, got %v", err)
		}
		if len(key) != AESKeySize16 {
			t.Errorf("Expected key length %d, got %d", AESKeySize16, len(key))
		}
	})

	t.Run("Generates AES-192 key (24 bytes)", func(t *testing.T) {
		key, err := GenerateSymmetricKey(AESKeySize24)
		if err != nil {
			t.Fatalf("Expected no error, got %v", err)
		}
		if len(key) != AESKeySize24 {
			t.Errorf("Expected key length %d, got %d", AESKeySize24, len(key))
		}
	})

	t.Run("Generates AES-256 key (32 bytes)", func(t *testing.T) {
		key, err := GenerateSymmetricKey(AESKeySize32)
		if err != nil {
			t.Fatalf("Expected no error, got %v", err)
		}
		if len(key) != AESKeySize32 {
			t.Errorf("Expected key length %d, got %d", AESKeySize32, len(key))
		}
	})

	t.Run("Returns error for invalid key size", func(t *testing.T) {
		invalidSizes := []int{0, 8, 10, 15, 17, 20, 25, 31, 33, 64}

		for _, size := range invalidSizes {
			_, err := GenerateSymmetricKey(size)
			if err == nil {
				t.Errorf("Expected error for invalid key size %d, got none", size)
			}
		}
	})

	t.Run("Generates unique keys", func(t *testing.T) {
		key1, err1 := GenerateSymmetricKey(AESKeySize32)
		key2, err2 := GenerateSymmetricKey(AESKeySize32)

		if err1 != nil || err2 != nil {
			t.Fatalf("Expected no errors, got %v, %v", err1, err2)
		}

		if bytes.Equal(key1, key2) {
			t.Error("Two consecutive key generations produced identical keys")
		}
	})

	t.Run("Generated keys are truly random", func(t *testing.T) {
		keys := make(map[string]bool)
		iterations := 100

		for i := 0; i < iterations; i++ {
			key, err := GenerateSymmetricKey(AESKeySize32)
			if err != nil {
				t.Fatalf("Expected no error on iteration %d, got %v", i, err)
			}
			keyStr := string(key)
			if keys[keyStr] {
				t.Error("Duplicate key generated")
			}
			keys[keyStr] = true
		}

		if len(keys) != iterations {
			t.Errorf("Expected %d unique keys, got %d", iterations, len(keys))
		}
	})
}

func TestSymmetricEncryptDecrypt(t *testing.T) {
	t.Run("Encrypt and decrypt simple plaintext", func(t *testing.T) {
		key, err := GenerateSymmetricKey(AESKeySize32)
		if err != nil {
			t.Fatalf("Failed to generate key: %v", err)
		}

		plaintext := []byte("Hello, World!")
		ciphertext, err := SymmetricEncrypt(key, plaintext, nil)
		if err != nil {
			t.Fatalf("Failed to encrypt: %v", err)
		}

		decrypted, err := SymmetricDecrypt(key, ciphertext, nil)
		if err != nil {
			t.Fatalf("Failed to decrypt: %v", err)
		}

		if !bytes.Equal(plaintext, decrypted) {
			t.Errorf("Decrypted data doesn't match original. Expected %s, got %s", plaintext, decrypted)
		}
	})

	t.Run("Encrypt and decrypt with associated data", func(t *testing.T) {
		key, _ := GenerateSymmetricKey(AESKeySize32)
		plaintext := []byte("Secret message")
		associatedData := []byte("metadata-context")

		ciphertext, err := SymmetricEncrypt(key, plaintext, associatedData)
		if err != nil {
			t.Fatalf("Failed to encrypt: %v", err)
		}

		decrypted, err := SymmetricDecrypt(key, ciphertext, associatedData)
		if err != nil {
			t.Fatalf("Failed to decrypt: %v", err)
		}

		if !bytes.Equal(plaintext, decrypted) {
			t.Error("Decrypted data doesn't match original with associated data")
		}
	})

	t.Run("Decrypt fails with wrong key", func(t *testing.T) {
		key1, _ := GenerateSymmetricKey(AESKeySize32)
		key2, _ := GenerateSymmetricKey(AESKeySize32)
		plaintext := []byte("Secret")

		ciphertext, err := SymmetricEncrypt(key1, plaintext, nil)
		if err != nil {
			t.Fatalf("Failed to encrypt: %v", err)
		}

		_, err = SymmetricDecrypt(key2, ciphertext, nil)
		if err == nil {
			t.Error("Expected decryption to fail with wrong key")
		}
	})

	t.Run("Decrypt fails with wrong associated data", func(t *testing.T) {
		key, _ := GenerateSymmetricKey(AESKeySize32)
		plaintext := []byte("Secret")
		associatedData1 := []byte("context1")
		associatedData2 := []byte("context2")

		ciphertext, err := SymmetricEncrypt(key, plaintext, associatedData1)
		if err != nil {
			t.Fatalf("Failed to encrypt: %v", err)
		}

		_, err = SymmetricDecrypt(key, ciphertext, associatedData2)
		if err == nil {
			t.Error("Expected decryption to fail with wrong associated data")
		}
	})

	t.Run("Decrypt fails with corrupted ciphertext", func(t *testing.T) {
		key, _ := GenerateSymmetricKey(AESKeySize32)
		plaintext := []byte("Secret")

		ciphertext, err := SymmetricEncrypt(key, plaintext, nil)
		if err != nil {
			t.Fatalf("Failed to encrypt: %v", err)
		}

		// Corrupt the ciphertext
		ciphertext[len(ciphertext)-1] ^= 0xFF

		_, err = SymmetricDecrypt(key, ciphertext, nil)
		if err == nil {
			t.Error("Expected decryption to fail with corrupted ciphertext")
		}
	})

	t.Run("Handles empty plaintext", func(t *testing.T) {
		key, _ := GenerateSymmetricKey(AESKeySize32)
		plaintext := []byte("")

		ciphertext, err := SymmetricEncrypt(key, plaintext, nil)
		if err != nil {
			t.Fatalf("Failed to encrypt empty plaintext: %v", err)
		}

		decrypted, err := SymmetricDecrypt(key, ciphertext, nil)
		if err != nil {
			t.Fatalf("Failed to decrypt empty plaintext: %v", err)
		}

		if !bytes.Equal(plaintext, decrypted) {
			t.Error("Decrypted empty data doesn't match")
		}
	})

	t.Run("Handles large plaintext", func(t *testing.T) {
		key, _ := GenerateSymmetricKey(AESKeySize32)
		plaintext := make([]byte, 1024*1024) // 1MB
		for i := range plaintext {
			plaintext[i] = byte(i % 256)
		}

		ciphertext, err := SymmetricEncrypt(key, plaintext, nil)
		if err != nil {
			t.Fatalf("Failed to encrypt large plaintext: %v", err)
		}

		decrypted, err := SymmetricDecrypt(key, ciphertext, nil)
		if err != nil {
			t.Fatalf("Failed to decrypt large plaintext: %v", err)
		}

		if !bytes.Equal(plaintext, decrypted) {
			t.Error("Decrypted large data doesn't match original")
		}
	})

	t.Run("Each encryption produces different ciphertext", func(t *testing.T) {
		key, _ := GenerateSymmetricKey(AESKeySize32)
		plaintext := []byte("Same message")

		ciphertext1, _ := SymmetricEncrypt(key, plaintext, nil)
		ciphertext2, _ := SymmetricEncrypt(key, plaintext, nil)

		if bytes.Equal(ciphertext1, ciphertext2) {
			t.Error("Two encryptions of same plaintext produced identical ciphertext (nonce not randomized)")
		}
	})

	t.Run("Works with all key sizes", func(t *testing.T) {
		keySizes := []int{AESKeySize16, AESKeySize24, AESKeySize32}
		plaintext := []byte("Test message")

		for _, size := range keySizes {
			t.Run(string(rune(size)), func(t *testing.T) {
				key, _ := GenerateSymmetricKey(size)

				ciphertext, err := SymmetricEncrypt(key, plaintext, nil)
				if err != nil {
					t.Fatalf("Failed to encrypt with key size %d: %v", size, err)
				}

				decrypted, err := SymmetricDecrypt(key, ciphertext, nil)
				if err != nil {
					t.Fatalf("Failed to decrypt with key size %d: %v", size, err)
				}

				if !bytes.Equal(plaintext, decrypted) {
					t.Errorf("Round-trip failed with key size %d", size)
				}
			})
		}
	})

	t.Run("Ciphertext is longer than plaintext due to nonce and tag", func(t *testing.T) {
		key, _ := GenerateSymmetricKey(AESKeySize32)
		plaintext := []byte("Short")

		ciphertext, err := SymmetricEncrypt(key, plaintext, nil)
		if err != nil {
			t.Fatalf("Failed to encrypt: %v", err)
		}

		// GCM adds nonce (12 bytes) and authentication tag (16 bytes)
		expectedMinLength := len(plaintext) + 12 + 16
		if len(ciphertext) < expectedMinLength {
			t.Errorf("Ciphertext too short. Expected at least %d bytes, got %d", expectedMinLength, len(ciphertext))
		}
	})

	t.Run("Decrypt fails with truncated ciphertext", func(t *testing.T) {
		key, _ := GenerateSymmetricKey(AESKeySize32)

		// Create a ciphertext that's too short (less than nonce size)
		shortCiphertext := []byte("short")

		_, err := SymmetricDecrypt(key, shortCiphertext, nil)
		if err == nil {
			t.Error("Expected error when decrypting truncated ciphertext")
		}
	})

	t.Run("Handles nil associated data consistently", func(t *testing.T) {
		key, _ := GenerateSymmetricKey(AESKeySize32)
		plaintext := []byte("Message")

		ciphertext, err := SymmetricEncrypt(key, plaintext, nil)
		if err != nil {
			t.Fatalf("Failed to encrypt: %v", err)
		}

		// Both nil and empty slice should work the same for associated data
		decrypted1, err1 := SymmetricDecrypt(key, ciphertext, nil)
		decrypted2, err2 := SymmetricDecrypt(key, ciphertext, []byte{})

		if err1 != nil || err2 != nil {
			t.Fatalf("Failed to decrypt: %v, %v", err1, err2)
		}

		if !bytes.Equal(decrypted1, plaintext) || !bytes.Equal(decrypted2, plaintext) {
			t.Error("Decryption with nil/empty associated data failed")
		}
	})
}
