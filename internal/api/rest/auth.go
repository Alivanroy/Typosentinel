package rest

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/Alivanroy/Typosentinel/pkg/logger"
)

// JWTClaims represents the claims in a JWT token
type JWTClaims struct {
	Subject   string `json:"sub"`
	Name      string `json:"name"`
	Role      string `json:"role"`
	IssuedAt  int64  `json:"iat"`
	ExpiresAt int64  `json:"exp"`
	Issuer    string `json:"iss"`
}

// JWTHeader represents the header of a JWT token
type JWTHeader struct {
	Algorithm string `json:"alg"`
	Type      string `json:"typ"`
}

// JWTValidator provides JWT token validation functionality
type JWTValidator struct {
	secretKey string
	issuer    string
}

// NewJWTValidator creates a new JWT validator
func NewJWTValidator(secretKey, issuer string) *JWTValidator {
	return &JWTValidator{
		secretKey: secretKey,
		issuer:    issuer,
	}
}

// ValidateToken validates a JWT token and returns the claims
func (v *JWTValidator) ValidateToken(tokenString string) (*JWTClaims, error) {
	// Split the token into parts
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid token format")
	}

	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("failed to decode header: %w", err)
	}

	var header JWTHeader
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, fmt.Errorf("failed to parse header: %w", err)
	}

	// Check algorithm
	if header.Algorithm != "HS256" {
		return nil, fmt.Errorf("unsupported algorithm: %s", header.Algorithm)
	}

	// Decode payload
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("failed to decode payload: %w", err)
	}

	var claims JWTClaims
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		return nil, fmt.Errorf("failed to parse claims: %w", err)
	}

	// Verify signature
	expectedSignature := v.generateSignature(parts[0] + "." + parts[1])
	if !hmac.Equal([]byte(parts[2]), []byte(expectedSignature)) {
		return nil, fmt.Errorf("invalid signature")
	}

	// Check expiration
	if claims.ExpiresAt > 0 && time.Now().Unix() > claims.ExpiresAt {
		return nil, fmt.Errorf("token expired")
	}

	// Check issuer
	if v.issuer != "" && claims.Issuer != v.issuer {
		return nil, fmt.Errorf("invalid issuer")
	}

	logger.DebugWithContext("JWT token validated successfully", map[string]interface{}{
		"subject": claims.Subject,
		"name":    claims.Name,
		"role":    claims.Role,
	})

	return &claims, nil
}

// GenerateToken generates a new JWT token for the given claims
func (v *JWTValidator) GenerateToken(subject, name, role string, expirationHours int) (string, error) {
	header := JWTHeader{
		Algorithm: "HS256",
		Type:      "JWT",
	}

	claims := JWTClaims{
		Subject:   subject,
		Name:      name,
		Role:      role,
		IssuedAt:  time.Now().Unix(),
		ExpiresAt: time.Now().Add(time.Duration(expirationHours) * time.Hour).Unix(),
		Issuer:    v.issuer,
	}

	headerBytes, err := json.Marshal(header)
	if err != nil {
		return "", fmt.Errorf("failed to marshal header: %w", err)
	}

	claimsBytes, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("failed to marshal claims: %w", err)
	}

	headerEncoded := base64.RawURLEncoding.EncodeToString(headerBytes)
	claimsEncoded := base64.RawURLEncoding.EncodeToString(claimsBytes)

	payload := headerEncoded + "." + claimsEncoded
	signature := v.generateSignature(payload)

	return payload + "." + signature, nil
}

// generateSignature generates HMAC-SHA256 signature for the payload
func (v *JWTValidator) generateSignature(payload string) string {
	h := hmac.New(sha256.New, []byte(v.secretKey))
	h.Write([]byte(payload))
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil))
}

// GetTestTokens returns a map of test tokens for development/testing
func GetTestTokens() map[string]string {
	validator := NewJWTValidator("test-secret-key", "typosentinel")

	// Generate test tokens
	adminToken, _ := validator.GenerateToken("admin", "Administrator", "admin", 24)
	userToken, _ := validator.GenerateToken("user", "Regular User", "user", 24)
	readonlyToken, _ := validator.GenerateToken("readonly", "Read Only User", "readonly", 24)

	return map[string]string{
		adminToken:    "admin",
		userToken:     "user",
		readonlyToken: "readonly",
		// Legacy tokens for backward compatibility
		"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c": "admin",
		"valid-jwt-token": "jwt_user",
	}
}
