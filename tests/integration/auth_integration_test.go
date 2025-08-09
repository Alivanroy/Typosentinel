package integration

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"

	"github.com/Alivanroy/Typosentinel/internal/auth"
	"github.com/Alivanroy/Typosentinel/internal/config"
	"github.com/Alivanroy/Typosentinel/internal/security"
	"github.com/Alivanroy/Typosentinel/pkg/logger"
)

// AuthIntegrationTestSuite tests basic authentication functionality
type AuthIntegrationTestSuite struct {
	suite.Suite
	logger     *logger.Logger
	rbacEngine *auth.RBACEngine
	ctx        context.Context
}

// SetupSuite initializes the test environment
func (suite *AuthIntegrationTestSuite) SetupSuite() {
	suite.ctx = context.Background()

	// Initialize logger
	suite.logger = logger.New()

	// Initialize RBAC engine with minimal config
	authzConfig := &config.AuthzConfig{
		Enabled: true,
		Model:   "rbac",
		Roles: []config.RoleConfig{
			{
				Name:        "admin",
				Description: "Administrator",
				Permissions: []string{"*"},
			},
			{
				Name:        "user",
				Description: "Standard user",
				Permissions: []string{"read:own", "write:own"},
			},
		},
	}
	suite.rbacEngine = auth.NewRBACEngine(authzConfig)
}

// Test RBAC engine initialization
func (suite *AuthIntegrationTestSuite) TestA001_RBACEngineInitialization() {
	// Test that roles were loaded correctly
	adminRole, exists := suite.rbacEngine.GetRole("admin")
	assert.True(suite.T(), exists, "Admin role should exist")
	assert.NotNil(suite.T(), adminRole, "Admin role should not be nil")
	assert.Equal(suite.T(), "admin", adminRole.Name)
	assert.Equal(suite.T(), "Administrator", adminRole.Description)

	userRole, exists := suite.rbacEngine.GetRole("user")
	assert.True(suite.T(), exists, "User role should exist")
	assert.NotNil(suite.T(), userRole, "User role should not be nil")
	assert.Equal(suite.T(), "user", userRole.Name)
	assert.Equal(suite.T(), "Standard user", userRole.Description)
}

// Test token store functionality
func (suite *AuthIntegrationTestSuite) TestA002_TokenStoreOperations() {
	tokenStore := security.NewInMemoryTokenStore()

	// Test storing a refresh token
	tokenID := "test-token-id"
	userID := "test-user-id"
	tokenHash := "test-refresh-token-hash"
	expiresAt := time.Now().Add(24 * time.Hour)

	tokenInfo := &security.RefreshTokenInfo{
		TokenID:   tokenID,
		TokenHash: tokenHash,
		UserID:    userID,
		SessionID: "test-session-id",
		ExpiresAt: expiresAt,
	}

	err := tokenStore.StoreRefreshToken(suite.ctx, tokenInfo)
	require.NoError(suite.T(), err, "Should be able to store refresh token")

	// Test retrieving token info
	retrievedToken, err := tokenStore.GetRefreshToken(suite.ctx, tokenID)
	require.NoError(suite.T(), err, "Should be able to retrieve token info")
	assert.Equal(suite.T(), userID, retrievedToken.UserID)
	assert.Equal(suite.T(), tokenHash, retrievedToken.TokenHash)

	// Test validating refresh token
	validatedToken, err := tokenStore.ValidateRefreshToken(suite.ctx, tokenHash)
	require.NoError(suite.T(), err, "Should be able to validate token")
	assert.NotNil(suite.T(), validatedToken, "Token should be valid")
	assert.Equal(suite.T(), userID, validatedToken.UserID)

	// Test revoking token
	err = tokenStore.RevokeRefreshToken(suite.ctx, tokenID, "test-admin", "test revocation")
	require.NoError(suite.T(), err, "Should be able to revoke token")

	// Test that revoked token is no longer valid
	_, err = tokenStore.ValidateRefreshToken(suite.ctx, tokenHash)
	assert.Error(suite.T(), err, "Revoked token should not be valid")
}

// Test security configuration
func (suite *AuthIntegrationTestSuite) TestA003_SecurityConfiguration() {
	securityConfig := &security.SecurityConfig{
		Authentication: security.AuthSecurityConfig{
			MinPasswordLength:    8,
			RequireUppercase:     true,
			RequireLowercase:     true,
			RequireNumbers:       true,
			RequireSymbols:       false,
			PasswordMaxAge:       90 * 24 * time.Hour,
			PasswordHistoryCount: 5,
			MaxLoginAttempts:     3,
			LockoutDuration:      15 * time.Minute,
		},
		Session: security.SessionConfig{
			IdleTimeout: 30 * time.Minute,
		},
	}

	// Test that configuration is properly structured
	assert.Equal(suite.T(), 8, securityConfig.Authentication.MinPasswordLength)
	assert.True(suite.T(), securityConfig.Authentication.RequireUppercase)
	assert.True(suite.T(), securityConfig.Authentication.RequireLowercase)
	assert.True(suite.T(), securityConfig.Authentication.RequireNumbers)
	assert.False(suite.T(), securityConfig.Authentication.RequireSymbols)
	assert.Equal(suite.T(), 3, securityConfig.Authentication.MaxLoginAttempts)
	assert.Equal(suite.T(), 15*time.Minute, securityConfig.Authentication.LockoutDuration)
	assert.Equal(suite.T(), 30*time.Minute, securityConfig.Session.IdleTimeout)
}

// Test permission checking
func (suite *AuthIntegrationTestSuite) TestA004_PermissionChecking() {
	// Create a test user
	testUser := &auth.User{
		ID:       "test-user-1",
		Username: "testuser",
		Roles:    []string{"user"},
	}

	// Test permission checking
	hasPermission := suite.rbacEngine.CheckPermission(suite.ctx, testUser, auth.Permission("read:own"))
	assert.True(suite.T(), hasPermission, "User should have read:own permission")

	hasPermission = suite.rbacEngine.CheckPermission(suite.ctx, testUser, auth.Permission("write:own"))
	assert.True(suite.T(), hasPermission, "User should have write:own permission")

	// Test admin user
	adminUser := &auth.User{
		ID:       "admin-user-1",
		Username: "admin",
		Roles:    []string{"admin"},
	}

	hasPermission = suite.rbacEngine.CheckPermission(suite.ctx, adminUser, auth.Permission("admin:delete"))
	assert.True(suite.T(), hasPermission, "Admin should have admin:delete permission (wildcard)")
}

// Test cleanup operations
func (suite *AuthIntegrationTestSuite) TestA005_CleanupOperations() {
	tokenStore := security.NewInMemoryTokenStore()

	// Store some tokens with different expiration times
	now := time.Now()
	
	// Expired token
	expiredToken := &security.RefreshTokenInfo{
		TokenID:   "expired-token",
		TokenHash: "expired-token-hash",
		UserID:    "user1",
		SessionID: "session1",
		ExpiresAt: now.Add(-1 * time.Hour),
	}
	err := tokenStore.StoreRefreshToken(suite.ctx, expiredToken)
	require.NoError(suite.T(), err)

	// Valid token
	validToken := &security.RefreshTokenInfo{
		TokenID:   "valid-token",
		TokenHash: "valid-token-hash",
		UserID:    "user2",
		SessionID: "session2",
		ExpiresAt: now.Add(1 * time.Hour),
	}
	err = tokenStore.StoreRefreshToken(suite.ctx, validToken)
	require.NoError(suite.T(), err)

	// Test cleanup
	err = tokenStore.CleanupExpiredTokens(suite.ctx)
	require.NoError(suite.T(), err, "Should be able to cleanup expired tokens")

	// Verify expired token is gone
	_, err = tokenStore.GetRefreshToken(suite.ctx, "expired-token")
	assert.Error(suite.T(), err, "Expired token should be removed")

	// Verify valid token still exists
	_, err = tokenStore.GetRefreshToken(suite.ctx, "valid-token")
	assert.NoError(suite.T(), err, "Valid token should still exist")
}

// Test runner
func TestAuthIntegrationSuite(t *testing.T) {
	suite.Run(t, new(AuthIntegrationTestSuite))
}