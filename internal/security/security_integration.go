package security

import (
	"context"
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/Alivanroy/Typosentinel/internal/auth"
	"github.com/Alivanroy/Typosentinel/pkg/logger"
)

// SecurityEvent represents a security event
type SecurityEvent struct {
	Type        string                 `json:"type"`
	Severity    string                 `json:"severity"`
	Description string                 `json:"description"`
	UserID      string                 `json:"user_id,omitempty"`
	IPAddress   string                 `json:"ip_address"`
	Timestamp   int64                  `json:"timestamp"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// SecurityManager provides a unified interface for all security components
type SecurityManager struct {
	config      *SecurityConfig
	logger      *logger.Logger
	rbacEngine  *auth.RBACEngine
	middleware  *SecurityMiddleware
	authService *AuthService
}

// NewSecurityManager creates a new security manager instance with a nil user repository (for backward compatibility)
func NewSecurityManager(logger *logger.Logger, rbacEngine *auth.RBACEngine) (*SecurityManager, error) {
	return NewSecurityManagerWithUserRepository(logger, rbacEngine, nil)
}

// NewSecurityManagerWithUserRepository creates a new security manager instance with a user repository
func NewSecurityManagerWithUserRepository(logger *logger.Logger, rbacEngine *auth.RBACEngine, userRepository UserRepository) (*SecurityManager, error) {
	// Load security configuration
	config, err := LoadSecurityConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to load security configuration: %w", err)
	}

	// Generate secure keys if not provided
	if config.JWT.SecretKey == "" {
		secretKey, err := GenerateSecureJWTSecret()
		if err != nil {
			return nil, fmt.Errorf("failed to generate JWT secret: %w", err)
		}
		config.JWT.SecretKey = secretKey
		logger.Info("Generated secure JWT secret key", map[string]interface{}{})
	}

	if config.Encryption.EncryptSensitiveData && config.Encryption.EncryptionKey == "" {
		encryptionKey, err := GenerateSecureEncryptionKey()
		if err != nil {
			return nil, fmt.Errorf("failed to generate encryption key: %w", err)
		}
		config.Encryption.EncryptionKey = encryptionKey
		logger.Info("Generated secure encryption key", map[string]interface{}{})
	}

	// Create security components
	middleware := NewSecurityMiddleware(config, logger, rbacEngine)
	
	// Create a default in-memory token store (this should be injected in real usage)
	tokenStore := NewInMemoryTokenStore()
	authService := NewAuthService(config, logger, rbacEngine, userRepository, tokenStore)

	sm := &SecurityManager{
		config:      config,
		logger:      logger,
		rbacEngine:  rbacEngine,
		middleware:  middleware,
		authService: authService,
	}

	logger.Info("Security manager initialized", map[string]interface{}{
		"jwt_enabled":        config.JWT.SecretKey != "",
		"rate_limiting":      config.RateLimit.GlobalEnabled,
		"rbac_enabled":       config.RBAC.Enabled,
		"audit_enabled":      config.AuditLogging.Enabled,
		"encryption_enabled": config.Encryption.EncryptSensitiveData,
	})

	return sm, nil
}

// GetConfig returns the security configuration
func (sm *SecurityManager) GetConfig() *SecurityConfig {
	return sm.config
}

// GetMiddleware returns the security middleware
func (sm *SecurityManager) GetMiddleware() *SecurityMiddleware {
	return sm.middleware
}

// GetAuthService returns the authentication service
func (sm *SecurityManager) GetAuthService() *AuthService {
	return sm.authService
}

// SetupSecurityMiddleware configures security middleware for a Gin router
func (sm *SecurityManager) SetupSecurityMiddleware(router *gin.Engine) {
	// Apply security headers to all routes
	router.Use(sm.middleware.SecurityHeaders())

	// Apply audit logging
	router.Use(sm.middleware.AuditLogger())

	// Apply enhanced rate limiting
	router.Use(sm.middleware.EnhancedRateLimit())

	// Apply login attempt limiting
	router.Use(sm.middleware.LoginAttemptLimiter())

	sm.logger.Info("Security middleware configured", map[string]interface{}{
		"security_headers": true,
		"audit_logging":    sm.config.AuditLogging.Enabled,
		"rate_limiting":    sm.config.RateLimit.GlobalEnabled,
		"login_limiting":   true,
	})
}

// SetupAuthenticatedRoutes configures authentication middleware for protected routes
func (sm *SecurityManager) SetupAuthenticatedRoutes(router *gin.RouterGroup) {
	// Apply JWT authentication
	router.Use(sm.middleware.EnhancedJWTAuth())

	sm.logger.Info("Authentication middleware configured for protected routes", map[string]interface{}{
		"jwt_auth": true,
	})
}

// RequirePermission returns a middleware that requires a specific permission
func (sm *SecurityManager) RequirePermission(permission string) gin.HandlerFunc {
	return sm.middleware.RequirePermission(permission)
}

// RequireRole returns a middleware that requires a specific role
func (sm *SecurityManager) RequireRole(role string) gin.HandlerFunc {
	return func(c *gin.Context) {
		userRole, exists := c.Get("user_role")
		if !exists {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "User not authenticated",
			})
			c.Abort()
			return
		}

		if userRole.(string) != role {
			sm.logger.Warn("Role access denied", map[string]interface{}{
				"required_role": role,
				"user_role":     userRole,
				"path":          c.Request.URL.Path,
			})
			c.JSON(http.StatusForbidden, gin.H{
				"error": "Insufficient role privileges",
			})
			c.Abort()
			return
		}

		c.Next()
	}
}

// RequireAnyRole returns a middleware that requires any of the specified roles
func (sm *SecurityManager) RequireAnyRole(roles ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		userRole, exists := c.Get("user_role")
		if !exists {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "User not authenticated",
			})
			c.Abort()
			return
		}

		userRoleStr := userRole.(string)
		for _, role := range roles {
			if userRoleStr == role {
				c.Next()
				return
			}
		}

		sm.logger.Warn("Role access denied", map[string]interface{}{
			"required_roles": roles,
			"user_role":      userRoleStr,
			"path":           c.Request.URL.Path,
		})
		c.JSON(http.StatusForbidden, gin.H{
			"error": "Insufficient role privileges",
		})
		c.Abort()
	}
}

// Authenticate performs user authentication
func (sm *SecurityManager) Authenticate(ctx context.Context, req *AuthRequest, clientIP, userAgent string) (*AuthResponse, error) {
	return sm.authService.Authenticate(ctx, req, clientIP, userAgent)
}

// ChangePassword changes a user's password
func (sm *SecurityManager) ChangePassword(ctx context.Context, userID string, req *PasswordChangeRequest) error {
	return sm.authService.ChangePassword(ctx, userID, req)
}

// ValidateSession validates a user session
func (sm *SecurityManager) ValidateSession(sessionID string) (*Session, error) {
	return sm.authService.ValidateSession(sessionID)
}

// InvalidateSession invalidates a user session
func (sm *SecurityManager) InvalidateSession(sessionID string) {
	sm.authService.InvalidateSession(sessionID)
}

// RevokeToken revokes a JWT token
func (sm *SecurityManager) RevokeToken(tokenID string) {
	sm.middleware.RevokeToken(tokenID)
}

// GetActiveSessions returns active sessions for a user
func (sm *SecurityManager) GetActiveSessions(userID string) []*Session {
	return sm.authService.GetActiveSessions(userID)
}

// SecurityHealthCheck performs a security health check
func (sm *SecurityManager) SecurityHealthCheck() map[string]interface{} {
	health := map[string]interface{}{
		"status": "healthy",
		"checks": map[string]interface{}{},
	}

	checks := health["checks"].(map[string]interface{})

	// Check JWT configuration
	if sm.config.JWT.SecretKey != "" && len(sm.config.JWT.SecretKey) >= 32 {
		checks["jwt_config"] = "ok"
	} else {
		checks["jwt_config"] = "warning - weak or missing JWT secret"
		health["status"] = "degraded"
	}

	// Check encryption configuration
	if sm.config.Encryption.EncryptSensitiveData {
		if sm.config.Encryption.EncryptionKey != "" {
			checks["encryption"] = "ok"
		} else {
			checks["encryption"] = "error - encryption enabled but no key configured"
			health["status"] = "unhealthy"
		}
	} else {
		checks["encryption"] = "disabled"
	}

	// Check RBAC
	if sm.config.RBAC.Enabled && sm.rbacEngine != nil {
		checks["rbac"] = "ok"
	} else {
		checks["rbac"] = "disabled or not configured"
	}

	// Check rate limiting
	if sm.config.RateLimit.GlobalEnabled {
		checks["rate_limiting"] = "ok"
	} else {
		checks["rate_limiting"] = "disabled"
	}

	// Check audit logging
	if sm.config.AuditLogging.Enabled {
		checks["audit_logging"] = "ok"
	} else {
		checks["audit_logging"] = "disabled"
	}

	return health
}

// GetSecurityMetrics returns security-related metrics
func (sm *SecurityManager) GetSecurityMetrics() map[string]interface{} {
	metrics := map[string]interface{}{
		"active_sessions":  len(sm.authService.sessions),
		"rate_limiters":    len(sm.middleware.rateLimiters),
		"login_attempts":   len(sm.middleware.loginAttempts),
		"revoked_tokens":   len(sm.middleware.revokedTokens),
		"configuration": map[string]interface{}{
			"jwt_enabled":        sm.config.JWT.SecretKey != "",
			"rate_limiting":      sm.config.RateLimit.GlobalEnabled,
			"rbac_enabled":       sm.config.RBAC.Enabled,
			"audit_enabled":      sm.config.AuditLogging.Enabled,
			"encryption_enabled": sm.config.Encryption.EncryptSensitiveData,
			"mfa_required":       sm.config.Authentication.RequireMFA,
		},
	}

	return metrics
}

// SecurityEventHandler handles security events
type SecurityEventHandler struct {
	logger *logger.Logger
}

// NewSecurityEventHandler creates a new security event handler
func NewSecurityEventHandler(logger *logger.Logger) *SecurityEventHandler {
	return &SecurityEventHandler{
		logger: logger,
	}
}

// HandleSecurityEvent handles a security event
func (seh *SecurityEventHandler) HandleSecurityEvent(event SecurityEvent) {
	seh.logger.Warn("Security event detected", map[string]interface{}{
		"event_type":  event.Type,
		"severity":    event.Severity,
		"description": event.Description,
		"user_id":     event.UserID,
		"ip_address":  event.IPAddress,
		"timestamp":   event.Timestamp,
		"metadata":    event.Metadata,
	})

	// Handle specific event types
	switch event.Type {
	case "failed_login":
		seh.handleFailedLogin(event)
	case "suspicious_activity":
		seh.handleSuspiciousActivity(event)
	case "permission_denied":
		seh.handlePermissionDenied(event)
	case "rate_limit_exceeded":
		seh.handleRateLimitExceeded(event)
	}
}

func (seh *SecurityEventHandler) handleFailedLogin(event SecurityEvent) {
	// Could implement additional logic like IP blocking, alerting, etc.
	seh.logger.Warn("Failed login attempt", map[string]interface{}{
		"ip_address": event.IPAddress,
		"user_id":    event.UserID,
		"attempts":   event.Metadata["attempts"],
	})
}

func (seh *SecurityEventHandler) handleSuspiciousActivity(event SecurityEvent) {
	// Could implement additional logic like alerting security team
	seh.logger.Error("Suspicious activity detected", map[string]interface{}{
		"description": event.Description,
		"ip_address":  event.IPAddress,
		"user_id":     event.UserID,
		"details":     event.Metadata,
	})
}

func (seh *SecurityEventHandler) handlePermissionDenied(event SecurityEvent) {
	// Could implement additional logic like tracking unauthorized access attempts
	seh.logger.Warn("Permission denied", map[string]interface{}{
		"user_id":    event.UserID,
		"resource":   event.Metadata["resource"],
		"permission": event.Metadata["permission"],
	})
}

func (seh *SecurityEventHandler) handleRateLimitExceeded(event SecurityEvent) {
	// Could implement additional logic like temporary IP blocking
	seh.logger.Warn("Rate limit exceeded", map[string]interface{}{
		"ip_address": event.IPAddress,
		"endpoint":   event.Metadata["endpoint"],
		"limit":      event.Metadata["limit"],
	})
}