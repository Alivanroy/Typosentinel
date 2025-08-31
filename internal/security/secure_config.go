package security

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"regexp"
	"strings"
)

// SecureConfigValidator validates security configuration
type SecureConfigValidator struct{}

// NewSecureConfigValidator creates a new secure config validator
func NewSecureConfigValidator() *SecureConfigValidator {
	return &SecureConfigValidator{}
}

// ValidateJWTSecret validates JWT secret strength
func (v *SecureConfigValidator) ValidateJWTSecret(secret string) error {
	if secret == "" {
		return fmt.Errorf("JWT secret is required")
	}

	if len(secret) < 32 {
		return fmt.Errorf("JWT secret must be at least 32 characters long")
	}

	// Check for common weak secrets
	weakSecrets := []string{
		"test-secret-key",
		"development-secret",
		"your-secret-key",
		"secret",
		"password",
		"12345",
		"admin",
	}

	secretLower := strings.ToLower(secret)
	for _, weak := range weakSecrets {
		if strings.Contains(secretLower, weak) {
			return fmt.Errorf("JWT secret contains weak patterns")
		}
	}

	return nil
}

// ValidateAdminPassword validates admin password strength
func (v *SecureConfigValidator) ValidateAdminPassword(password string) error {
	if password == "" {
		return fmt.Errorf("admin password is required")
	}

	if len(password) < 12 {
		return fmt.Errorf("admin password must be at least 12 characters long")
	}

	// Check for uppercase letters
	if matched, _ := regexp.MatchString(`[A-Z]`, password); !matched {
		return fmt.Errorf("admin password must contain at least one uppercase letter")
	}

	// Check for lowercase letters
	if matched, _ := regexp.MatchString(`[a-z]`, password); !matched {
		return fmt.Errorf("admin password must contain at least one lowercase letter")
	}

	// Check for numbers
	if matched, _ := regexp.MatchString(`[0-9]`, password); !matched {
		return fmt.Errorf("admin password must contain at least one number")
	}

	// Check for special characters
	if matched, _ := regexp.MatchString(`[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]`, password); !matched {
		return fmt.Errorf("admin password must contain at least one special character")
	}

	// Check for common weak passwords
	weakPasswords := []string{
		"password",
		"admin",
		"123456",
		"qwerty",
		"letmein",
		"welcome",
		"monkey",
		"dragon",
	}

	passwordLower := strings.ToLower(password)
	for _, weak := range weakPasswords {
		if strings.Contains(passwordLower, weak) {
			return fmt.Errorf("admin password contains weak patterns")
		}
	}

	return nil
}

// ValidateAPIKeys validates API key configuration
func (v *SecureConfigValidator) ValidateAPIKeys(keys []string) error {
	if len(keys) == 0 {
		return nil // API keys are optional
	}

	for i, key := range keys {
		if len(key) < 32 {
			return fmt.Errorf("API key %d must be at least 32 characters long", i+1)
		}

		// Check for weak patterns
		if strings.Contains(strings.ToLower(key), "test") ||
			strings.Contains(strings.ToLower(key), "demo") ||
			strings.Contains(strings.ToLower(key), "example") {
			return fmt.Errorf("API key %d contains weak patterns", i+1)
		}
	}

	return nil
}

// ValidateEncryptionKey validates encryption key strength
func (v *SecureConfigValidator) ValidateEncryptionKey(key string) error {
	if key == "" {
		return fmt.Errorf("encryption key is required")
	}

	if len(key) < 32 {
		return fmt.Errorf("encryption key must be at least 32 characters long")
	}

	// For AES-256, we need exactly 32 bytes
	if len(key) != 32 {
		return fmt.Errorf("encryption key must be exactly 32 characters for AES-256")
	}

	return nil
}

// GenerateSecureSecret generates a cryptographically secure secret
func (v *SecureConfigValidator) GenerateSecureSecret(length int) (string, error) {
	if length < 32 {
		length = 32
	}

	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("failed to generate secure secret: %w", err)
	}

	return hex.EncodeToString(bytes), nil
}

// ValidateProductionConfig validates all security configuration for production
func (v *SecureConfigValidator) ValidateProductionConfig() error {
	var errors []string

	// Validate JWT secret
	jwtSecret := os.Getenv("TYPOSENTINEL_JWT_SECRET")
	if err := v.ValidateJWTSecret(jwtSecret); err != nil {
		errors = append(errors, fmt.Sprintf("JWT Secret: %v", err))
	}

	// Validate admin password
	adminPassword := os.Getenv("TYPOSENTINEL_ADMIN_PASSWORD")
	if err := v.ValidateAdminPassword(adminPassword); err != nil {
		errors = append(errors, fmt.Sprintf("Admin Password: %v", err))
	}

	// Validate encryption key
	encryptionKey := os.Getenv("TYPOSENTINEL_ENCRYPTION_KEY")
	if encryptionKey != "" {
		if err := v.ValidateEncryptionKey(encryptionKey); err != nil {
			errors = append(errors, fmt.Sprintf("Encryption Key: %v", err))
		}
	}

	// Validate API keys
	apiKeysEnv := os.Getenv("TYPOSENTINEL_API_KEYS")
	if apiKeysEnv != "" {
		apiKeys := strings.Split(apiKeysEnv, ",")
		if err := v.ValidateAPIKeys(apiKeys); err != nil {
			errors = append(errors, fmt.Sprintf("API Keys: %v", err))
		}
	}

	// Check for development/test environment variables in production
	environment := os.Getenv("TYPOSENTINEL_ENVIRONMENT")
	if environment == "production" {
		if os.Getenv("TYPOSENTINEL_ENABLE_TEST_TOKENS") == "true" {
			errors = append(errors, "Test tokens are enabled in production environment")
		}

		if os.Getenv("TYPOSENTINEL_DISABLE_AUTH") == "true" {
			errors = append(errors, "Authentication is disabled in production environment")
		}

		if os.Getenv("TYPOSENTINEL_DEBUG") == "true" {
			errors = append(errors, "Debug mode is enabled in production environment")
		}
	}

	if len(errors) > 0 {
		return fmt.Errorf("security configuration validation failed:\n- %s", strings.Join(errors, "\n- "))
	}

	return nil
}

// GetSecurityRecommendations provides security configuration recommendations
func (v *SecureConfigValidator) GetSecurityRecommendations() []string {
	recommendations := []string{
		"Use a strong JWT secret (minimum 32 characters, cryptographically random)",
		"Set a complex admin password (minimum 12 characters with mixed case, numbers, and symbols)",
		"Enable HTTPS in production with valid TLS certificates",
		"Configure rate limiting to prevent brute force attacks",
		"Enable audit logging for all authentication events",
		"Use environment variables for all sensitive configuration",
		"Regularly rotate secrets and API keys",
		"Implement proper session management with secure timeouts",
		"Enable CSRF protection for web interfaces",
		"Configure security headers (HSTS, CSP, X-Frame-Options, etc.)",
		"Use strong encryption for data at rest",
		"Implement proper input validation and sanitization",
		"Enable database connection encryption",
		"Configure proper CORS policies",
		"Implement proper error handling without information disclosure",
	}

	return recommendations
}
