package security

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"

	"golang.org/x/crypto/pbkdf2"
)

// EncryptionService provides encryption and decryption capabilities
type EncryptionService struct {
	key []byte
	gcm cipher.AEAD
}

// NewEncryptionService creates a new encryption service
func NewEncryptionService() (*EncryptionService, error) {
	// Get encryption key from environment variable
	keyString := os.Getenv("ENCRYPTION_KEY")
	if keyString == "" {
		return nil, errors.New("ENCRYPTION_KEY environment variable not set")
	}

	// Derive key using PBKDF2
	salt := []byte("typosentinel-salt") // In production, use random salt per installation
	key := pbkdf2.Key([]byte(keyString), salt, 100000, 32, sha256.New)

	// Create AES cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	// Create GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	return &EncryptionService{
		key: key,
		gcm: gcm,
	}, nil
}

// Encrypt encrypts plaintext data
func (e *EncryptionService) Encrypt(plaintext []byte) (string, error) {
	// Create a random nonce
	nonce := make([]byte, e.gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Encrypt the data
	ciphertext := e.gcm.Seal(nonce, nonce, plaintext, nil)

	// Encode to base64 for storage
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// Decrypt decrypts ciphertext data
func (e *EncryptionService) Decrypt(ciphertext string) ([]byte, error) {
	// Decode from base64
	data, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return nil, fmt.Errorf("failed to decode base64: %w", err)
	}

	// Check minimum length
	nonceSize := e.gcm.NonceSize()
	if len(data) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}

	// Extract nonce and ciphertext
	nonce, ciphertext_bytes := data[:nonceSize], data[nonceSize:]

	// Decrypt the data
	plaintext, err := e.gcm.Open(nil, nonce, ciphertext_bytes, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt: %w", err)
	}

	return plaintext, nil
}

// EncryptString encrypts a string
func (e *EncryptionService) EncryptString(plaintext string) (string, error) {
	return e.Encrypt([]byte(plaintext))
}

// DecryptString decrypts to a string
func (e *EncryptionService) DecryptString(ciphertext string) (string, error) {
	plaintext, err := e.Decrypt(ciphertext)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}

// EncryptSensitiveData encrypts sensitive data fields
func (e *EncryptionService) EncryptSensitiveData(data map[string]interface{}) (map[string]interface{}, error) {
	sensitiveFields := []string{
		"password", "token", "secret", "key", "credential",
		"api_key", "access_token", "refresh_token", "private_key",
		"database_url", "connection_string",
	}

	result := make(map[string]interface{})
	for k, v := range data {
		// Check if field is sensitive
		isSensitive := false
		for _, field := range sensitiveFields {
			if k == field || len(k) > len(field) && k[len(k)-len(field):] == field {
				isSensitive = true
				break
			}
		}

		if isSensitive {
			if str, ok := v.(string); ok && str != "" {
				encrypted, err := e.EncryptString(str)
				if err != nil {
					return nil, fmt.Errorf("failed to encrypt field %s: %w", k, err)
				}
				result[k] = encrypted
			} else {
				result[k] = v
			}
		} else {
			result[k] = v
		}
	}

	return result, nil
}

// DecryptSensitiveData decrypts sensitive data fields
func (e *EncryptionService) DecryptSensitiveData(data map[string]interface{}) (map[string]interface{}, error) {
	sensitiveFields := []string{
		"password", "token", "secret", "key", "credential",
		"api_key", "access_token", "refresh_token", "private_key",
		"database_url", "connection_string",
	}

	result := make(map[string]interface{})
	for k, v := range data {
		// Check if field is sensitive
		isSensitive := false
		for _, field := range sensitiveFields {
			if k == field || len(k) > len(field) && k[len(k)-len(field):] == field {
				isSensitive = true
				break
			}
		}

		if isSensitive {
			if str, ok := v.(string); ok && str != "" {
				decrypted, err := e.DecryptString(str)
				if err != nil {
					return nil, fmt.Errorf("failed to decrypt field %s: %w", k, err)
				}
				result[k] = decrypted
			} else {
				result[k] = v
			}
		} else {
			result[k] = v
		}
	}

	return result, nil
}

// GenerateEncryptionKey generates a new encryption key
func GenerateEncryptionKey() (string, error) {
	key := make([]byte, 32) // 256-bit key
	if _, err := rand.Read(key); err != nil {
		return "", fmt.Errorf("failed to generate key: %w", err)
	}
	return base64.StdEncoding.EncodeToString(key), nil
}

// ValidateEncryptionKey validates an encryption key
func ValidateEncryptionKey(key string) error {
	decoded, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		return fmt.Errorf("invalid base64 encoding: %w", err)
	}

	if len(decoded) != 32 {
		return fmt.Errorf("key must be 32 bytes (256 bits), got %d bytes", len(decoded))
	}

	return nil
}

// RotateEncryptionKey rotates the encryption key
func (e *EncryptionService) RotateEncryptionKey(newKeyString string) error {
	// Validate new key
	if err := ValidateEncryptionKey(newKeyString); err != nil {
		return fmt.Errorf("invalid new key: %w", err)
	}

	// Derive new key
	salt := []byte("typosentinel-salt")
	newKey := pbkdf2.Key([]byte(newKeyString), salt, 100000, 32, sha256.New)

	// Create new cipher
	block, err := aes.NewCipher(newKey)
	if err != nil {
		return fmt.Errorf("failed to create new cipher: %w", err)
	}

	// Create new GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("failed to create new GCM: %w", err)
	}

	// Update service
	e.key = newKey
	e.gcm = gcm

	return nil
}