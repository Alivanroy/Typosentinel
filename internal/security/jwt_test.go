package security

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/Alivanroy/Typosentinel/internal/auth"
	"github.com/Alivanroy/Typosentinel/pkg/logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// MockUserRepository for testing
type MockUserRepository struct {
	users map[string]*User
}

func NewMockUserRepository() *MockUserRepository {
	return &MockUserRepository{
		users: make(map[string]*User),
	}
}

func (m *MockUserRepository) GetUserByUsername(ctx context.Context, username string) (*User, error) {
	for _, user := range m.users {
		if user.Username == username {
			return user, nil
		}
	}
	return nil, fmt.Errorf("user not found")
}

func (m *MockUserRepository) GetUserByID(ctx context.Context, userID string) (*User, error) {
	if user, exists := m.users[userID]; exists {
		return user, nil
	}
	return nil, fmt.Errorf("user not found")
}

func (m *MockUserRepository) GetUserByEmail(ctx context.Context, email string) (*User, error) {
	for _, user := range m.users {
		if user.Email == email {
			return user, nil
		}
	}
	return nil, fmt.Errorf("user not found")
}

func (m *MockUserRepository) CreateUser(ctx context.Context, user *User) error {
	m.users[user.ID] = user
	return nil
}

func (m *MockUserRepository) UpdateUser(ctx context.Context, user *User) error {
	m.users[user.ID] = user
	return nil
}

func (m *MockUserRepository) UpdateUserPassword(ctx context.Context, userID, hashedPassword string) error {
	if user, exists := m.users[userID]; exists {
		user.PasswordHash = hashedPassword
		user.PasswordChangedAt = time.Now()
		return nil
	}
	return fmt.Errorf("user not found")
}

func (m *MockUserRepository) UpdateLastLogin(ctx context.Context, userID, clientIP string) error {
	if user, exists := m.users[userID]; exists {
		user.LastLoginAt = time.Now()
		user.LastLoginIP = clientIP
		return nil
	}
	return fmt.Errorf("user not found")
}

func (m *MockUserRepository) IncrementFailedLoginAttempts(ctx context.Context, userID string) error {
	if user, exists := m.users[userID]; exists {
		user.FailedLoginAttempts++
		return nil
	}
	return fmt.Errorf("user not found")
}

func (m *MockUserRepository) ResetFailedLoginAttempts(ctx context.Context, userID string) error {
	if user, exists := m.users[userID]; exists {
		user.FailedLoginAttempts = 0
		return nil
	}
	return fmt.Errorf("user not found")
}

func (m *MockUserRepository) LockUser(ctx context.Context, userID string, lockDuration time.Duration) error {
	if user, exists := m.users[userID]; exists {
		lockUntil := time.Now().Add(lockDuration)
		user.LockedUntil = &lockUntil
		return nil
	}
	return fmt.Errorf("user not found")
}

func (m *MockUserRepository) UnlockUser(ctx context.Context, userID string) error {
	if user, exists := m.users[userID]; exists {
		user.LockedUntil = nil
		return nil
	}
	return fmt.Errorf("user not found")
}

func (m *MockUserRepository) DeleteUser(ctx context.Context, userID string) error {
	delete(m.users, userID)
	return nil
}

func (m *MockUserRepository) ListUsers(ctx context.Context, limit, offset int) ([]*User, error) {
	var users []*User
	for _, user := range m.users {
		users = append(users, user)
	}
	return users, nil
}

func (m *MockUserRepository) AssignRole(ctx context.Context, userID, roleName, assignedBy string) error {
	if user, exists := m.users[userID]; exists {
		user.Roles = append(user.Roles, roleName)
		return nil
	}
	return fmt.Errorf("user not found")
}

func (m *MockUserRepository) RemoveRole(ctx context.Context, userID, roleName string) error {
	if user, exists := m.users[userID]; exists {
		for i, role := range user.Roles {
			if role == roleName {
				user.Roles = append(user.Roles[:i], user.Roles[i+1:]...)
				break
			}
		}
		return nil
	}
	return fmt.Errorf("user not found")
}

func (m *MockUserRepository) GetUserRoles(ctx context.Context, userID string) ([]string, error) {
	if user, exists := m.users[userID]; exists {
		return user.Roles, nil
	}
	return nil, fmt.Errorf("user not found")
}

func (m *MockUserRepository) LogSecurityEvent(ctx context.Context, event *AuditEvent) error {
	// Mock implementation - just return nil
	return nil
}

func createTestAuthService() *AuthService {
	config := &SecurityConfig{
		JWT: JWTSecurityConfig{
			SecretKey:              "test-secret-key-for-jwt-signing",
			AccessTokenExpiration:  time.Hour,
			RefreshTokenExpiration: 24 * time.Hour,
			Issuer:                 "typosentinel-test",
			Audience:               "typosentinel-test-api",
		},
		Authentication: AuthSecurityConfig{
			PasswordMinLength: 8,
		},
	}
	
	testLogger := logger.New()
	rbacEngine := &auth.RBACEngine{}
	mockRepo := NewMockUserRepository()
	
	return NewAuthService(config, testLogger, rbacEngine, mockRepo)
}

func createTestUser() *User {
	return &User{
		ID:                "test-user-id",
		Username:          "testuser",
		Email:             "test@example.com",
		PasswordHash:      "$2a$10$test.hash.here",
		PasswordChangedAt: time.Now(),
		IsActive:          true,
		IsVerified:        true,
		MFAEnabled:        false,
		Roles:             []string{"user"},
		CreatedAt:         time.Now(),
		UpdatedAt:         time.Now(),
	}
}

func TestJWTTokenGeneration(t *testing.T) {
	// Create test dependencies
	config := &SecurityConfig{
		JWT: JWTSecurityConfig{
			SecretKey:              "test-secret-key-for-jwt-signing",
			AccessTokenExpiration:  time.Hour,
			RefreshTokenExpiration: 24 * time.Hour,
			Issuer:                 "typosentinel-test",
			Audience:               "typosentinel-test-api",
		},
		Authentication: AuthSecurityConfig{
			PasswordMinLength: 8,
		},
	}
	
	testLogger := logger.New()
	rbacEngine := &auth.RBACEngine{}
	mockRepo := NewMockUserRepository()
	
	// Create auth service
	authService := NewAuthService(config, testLogger, rbacEngine, mockRepo)
	user := createTestUser()
	sessionID := "test-session-id"

	// Test JWT token generation
	token, err := authService.generateJWTToken(user, sessionID)
	require.NoError(t, err)
	assert.NotEmpty(t, token)
	assert.NotEqual(t, "jwt_token", token) // Should not be the placeholder

	// Token should have 3 parts (header.payload.signature)
	parts := strings.Split(token, ".")
	assert.Len(t, parts, 3)

	// Test refresh token generation
	refreshToken, err := authService.generateRefreshToken(user.ID, sessionID)
	require.NoError(t, err)
	assert.NotEmpty(t, refreshToken)
	assert.NotEqual(t, "refresh_token", refreshToken) // Should not be the placeholder

	// Refresh token should have 3 parts
	refreshParts := strings.Split(refreshToken, ".")
	assert.Len(t, refreshParts, 3)

	// Tokens should be different
	assert.NotEqual(t, token, refreshToken)
}

func TestJWTTokenValidation(t *testing.T) {
	authService := createTestAuthService()
	user := createTestUser()
	sessionID := "test-session-id"

	// Generate a token
	token, err := authService.generateJWTToken(user, sessionID)
	require.NoError(t, err)

	// Validate the token
	claims, err := authService.ValidateJWTToken(token)
	require.NoError(t, err)
	assert.NotNil(t, claims)

	// Check claims
	assert.Equal(t, user.ID, claims.Subject)
	assert.Equal(t, user.Username, claims.Name)
	assert.Equal(t, user.PrimaryRole(), claims.Role)
	assert.Equal(t, sessionID, claims.SessionID)
	assert.Equal(t, "typosentinel-test", claims.Issuer)
	assert.Equal(t, "typosentinel-test-api", claims.Audience)
	assert.NotEmpty(t, claims.TokenID)
	assert.True(t, claims.IssuedAt > 0)
	assert.True(t, claims.ExpiresAt > claims.IssuedAt)
}

func TestRefreshTokenValidation(t *testing.T) {
	authService := createTestAuthService()
	user := createTestUser()
	sessionID := "test-session-id"

	// Generate a refresh token
	refreshToken, err := authService.generateRefreshToken(user.ID, sessionID)
	require.NoError(t, err)

	// Validate the refresh token
	claims, err := authService.ValidateRefreshToken(refreshToken)
	require.NoError(t, err)
	assert.NotNil(t, claims)

	// Check claims
	assert.Equal(t, user.ID, claims.Subject)
	assert.Equal(t, sessionID, claims.SessionID)
	assert.Equal(t, "typosentinel-test", claims.Issuer)
	assert.Equal(t, "typosentinel-test-api", claims.Audience)
	assert.Equal(t, "refresh", claims.Type)
	assert.NotEmpty(t, claims.TokenID)
	assert.True(t, claims.IssuedAt > 0)
	assert.True(t, claims.ExpiresAt > claims.IssuedAt)
}

func TestInvalidTokenValidation(t *testing.T) {
	authService := createTestAuthService()

	// Test invalid token format
	_, err := authService.ValidateJWTToken("invalid.token")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid token format")

	// Test completely invalid token
	_, err = authService.ValidateJWTToken("not-a-token")
	assert.Error(t, err)

	// Test empty token
	_, err = authService.ValidateJWTToken("")
	assert.Error(t, err)
}

func TestTokenRefresh(t *testing.T) {
	authService := createTestAuthService()
	user := createTestUser()
	sessionID := "test-session-id"

	// Add user to mock repository
	mockRepo := authService.userRepository.(*MockUserRepository)
	mockRepo.users[user.ID] = user

	// Generate a refresh token
	refreshToken, err := authService.generateRefreshToken(user.ID, sessionID)
	require.NoError(t, err)

	// Use refresh token to get new access token
	ctx := context.Background()
	response, err := authService.RefreshAccessToken(ctx, refreshToken)
	require.NoError(t, err)
	assert.True(t, response.Success)
	assert.NotEmpty(t, response.Token)
	assert.Equal(t, user.ID, response.UserID)
	assert.Equal(t, user.Username, response.Username)
	assert.Equal(t, user.PrimaryRole(), response.Role)

	// Validate the new access token
	claims, err := authService.ValidateJWTToken(response.Token)
	require.NoError(t, err)
	assert.Equal(t, user.ID, claims.Subject)
	assert.Equal(t, sessionID, claims.SessionID)
}

func TestExpiredTokenValidation(t *testing.T) {
	// Create auth service with short token expiration
	config := &SecurityConfig{
		JWT: JWTSecurityConfig{
			SecretKey:              "test-secret-key-that-is-long-enough-for-security",
			AccessTokenExpiration:  1 * time.Second, // Expires in 1 second
			RefreshTokenExpiration: 1 * time.Second,
			Issuer:                 "typosentinel-test",
			Audience:               "typosentinel-test-api",
			Algorithm:              "HS256",
		},
		Authentication: AuthSecurityConfig{
			PasswordMinLength: 8,
		},
	}

	testLogger := logger.New()
	rbacEngine := &auth.RBACEngine{}
	userRepo := NewMockUserRepository()
	authService := NewAuthService(config, testLogger, rbacEngine, userRepo)

	user := createTestUser()
	sessionID := "test-session-id"

	// Generate token (will expire in 1 second)
	token, err := authService.generateJWTToken(user, sessionID)
	require.NoError(t, err)
	afterGeneration := time.Now()

	// Calculate expected expiration time
	expectedExpiration := afterGeneration.Add(1 * time.Second)
	
	// Wait for token to expire - wait until we're sure we're in the next second
	for time.Now().Unix() <= expectedExpiration.Unix() {
		time.Sleep(10 * time.Millisecond)
	}
	
	// Add a small buffer to ensure we're definitely past expiration
	time.Sleep(100 * time.Millisecond)

	// Try to validate expired token
	_, err = authService.ValidateJWTToken(token)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "token expired")
}