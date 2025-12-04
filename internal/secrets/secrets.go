package secrets

import (
	"fmt"
	"io/ioutil"
	"os"
	"strings"
)

// SecretManager interface for managing secrets
type SecretManager interface {
	GetSecret(key string) (string, error)
	SetSecret(key, value string) error
	DeleteSecret(key string) error
	ListSecrets() ([]string, error)
}

// Provider interface for secret providers
type Provider interface {
	Get(key string) (string, error)
}

// EnvProvider environment-based secret provider
type EnvProvider struct{}

// Get retrieves a secret from environment variables
func (e EnvProvider) Get(key string) (string, error) {
	value := os.Getenv(key)
	if value == "" {
		return "", fmt.Errorf("secret not found: %s", key)
	}
	return value, nil
}

// FileProvider file-based secret provider
type FileProvider struct {
	path string
}

// NewFileProvider creates a new file-based secret provider
func NewFileProvider(path string) (*FileProvider, error) {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return nil, fmt.Errorf("secrets file not found: %s", path)
	}
	return &FileProvider{path: path}, nil
}

// Get retrieves a secret from a file
func (f *FileProvider) Get(key string) (string, error) {
	data, err := ioutil.ReadFile(f.path)
	if err != nil {
		return "", fmt.Errorf("failed to read secrets file: %w", err)
	}

	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		parts := strings.SplitN(line, "=", 2)
		if len(parts) == 2 && strings.TrimSpace(parts[0]) == key {
			return strings.TrimSpace(parts[1]), nil
		}
	}

	return "", fmt.Errorf("secret not found: %s", key)
}

// VaultProvider HashiCorp Vault-based secret provider
type VaultProvider struct {
	addr  string
	token string
}

// NewVaultProvider creates a new Vault-based secret provider
func NewVaultProvider(addr, token string) *VaultProvider {
	return &VaultProvider{addr: addr, token: token}
}

// Get retrieves a secret from Vault
func (v *VaultProvider) Get(key string) (string, error) {
	// Simplified implementation - would integrate with actual Vault client
	return os.Getenv(key), nil
}

// EnvSecretManager environment-based secret manager
type EnvSecretManager struct{}

// NewEnvSecretManager creates a new environment secret manager
func NewEnvSecretManager() *EnvSecretManager {
	return &EnvSecretManager{}
}

// GetSecret gets a secret from environment variables
func (e *EnvSecretManager) GetSecret(key string) (string, error) {
	value := os.Getenv(key)
	if value == "" {
		return "", fmt.Errorf("secret not found: %s", key)
	}
	return value, nil
}

// SetSecret sets a secret (not implemented for env manager)
func (e *EnvSecretManager) SetSecret(key, value string) error {
	return fmt.Errorf("cannot set secrets in environment manager")
}

// DeleteSecret deletes a secret (not implemented for env manager)
func (e *EnvSecretManager) DeleteSecret(key string) error {
	return fmt.Errorf("cannot delete secrets in environment manager")
}

// ListSecrets lists all secrets (not implemented for env manager)
func (e *EnvSecretManager) ListSecrets() ([]string, error) {
	return []string{}, fmt.Errorf("cannot list secrets in environment manager")
}

// ValidateSecret validates if a secret is properly formatted
func ValidateSecret(secret, secretType string) error {
	switch strings.ToLower(secretType) {
	case "token":
		if len(secret) < 10 {
			return fmt.Errorf("token too short")
		}
	case "api_key":
		if len(secret) < 16 {
			return fmt.Errorf("API key too short")
		}
	case "password":
		if len(secret) < 8 {
			return fmt.Errorf("password too short")
		}
	}
	return nil
}

// SecureString masks sensitive parts of a string
func SecureString(s string) string {
	if len(s) <= 8 {
		return "****"
	}
	return s[:4] + "****" + s[len(s)-4:]
}
