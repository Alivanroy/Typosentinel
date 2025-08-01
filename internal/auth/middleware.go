package auth

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

// AuthorizationMiddleware provides RBAC-based authorization
type AuthorizationMiddleware struct {
	rbac       *RBACEngine
	authManager *AuthManager
	enabled    bool
}

// NewAuthorizationMiddleware creates a new authorization middleware
func NewAuthorizationMiddleware(rbac *RBACEngine, authManager *AuthManager, enabled bool) *AuthorizationMiddleware {
	return &AuthorizationMiddleware{
		rbac:        rbac,
		authManager: authManager,
		enabled:     enabled,
	}
}

// RequirePermission creates a middleware that requires a specific permission
func (am *AuthorizationMiddleware) RequirePermission(permission Permission) gin.HandlerFunc {
	return func(c *gin.Context) {
		if !am.enabled {
			c.Next()
			return
		}

		user := am.getCurrentUser(c)
		if user == nil {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error":   "Unauthorized",
				"message": "Authentication required",
			})
			c.Abort()
			return
		}

		if !am.rbac.CheckPermission(c.Request.Context(), user, permission) {
			c.JSON(http.StatusForbidden, gin.H{
				"error":   "Forbidden",
				"message": "Insufficient permissions",
				"required_permission": string(permission),
			})
			c.Abort()
			return
		}

		c.Next()
	}
}

// RequireRole creates a middleware that requires a specific role
func (am *AuthorizationMiddleware) RequireRole(role string) gin.HandlerFunc {
	return func(c *gin.Context) {
		if !am.enabled {
			c.Next()
			return
		}

		user := am.getCurrentUser(c)
		if user == nil {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error":   "Unauthorized",
				"message": "Authentication required",
			})
			c.Abort()
			return
		}

		if !user.HasRole(role) {
			c.JSON(http.StatusForbidden, gin.H{
				"error":   "Forbidden",
				"message": "Insufficient role privileges",
				"required_role": role,
				"user_roles": user.Roles,
			})
			c.Abort()
			return
		}

		c.Next()
	}
}

// RequireAnyRole creates a middleware that requires any of the specified roles
func (am *AuthorizationMiddleware) RequireAnyRole(roles ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		if !am.enabled {
			c.Next()
			return
		}

		user := am.getCurrentUser(c)
		if user == nil {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error":   "Unauthorized",
				"message": "Authentication required",
			})
			c.Abort()
			return
		}

		if !user.HasAnyRole(roles...) {
			c.JSON(http.StatusForbidden, gin.H{
				"error":   "Forbidden",
				"message": "Insufficient role privileges",
				"required_roles": roles,
				"user_roles": user.Roles,
			})
			c.Abort()
			return
		}

		c.Next()
	}
}

// RequireAction creates a middleware that checks if user can perform a specific action
func (am *AuthorizationMiddleware) RequireAction(actionType, resource string) gin.HandlerFunc {
	return func(c *gin.Context) {
		if !am.enabled {
			c.Next()
			return
		}

		user := am.getCurrentUser(c)
		if user == nil {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error":   "Unauthorized",
				"message": "Authentication required",
			})
			c.Abort()
			return
		}

		action := &Action{
			Type:       actionType,
			Resource:   resource,
			Attributes: am.extractActionAttributes(c),
		}

		allowed, err := am.rbac.CheckAction(c.Request.Context(), user, action)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error":   "Authorization Error",
				"message": "Failed to check authorization",
			})
			c.Abort()
			return
		}

		if !allowed {
			c.JSON(http.StatusForbidden, gin.H{
				"error":   "Forbidden",
				"message": "Action not permitted",
				"action":  actionType,
				"resource": resource,
			})
			c.Abort()
			return
		}

		c.Next()
	}
}

// ResourceOwnershipMiddleware checks if user owns the resource
func (am *AuthorizationMiddleware) ResourceOwnershipMiddleware(resourceParam string) gin.HandlerFunc {
	return func(c *gin.Context) {
		if !am.enabled {
			c.Next()
			return
		}

		user := am.getCurrentUser(c)
		if user == nil {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error":   "Unauthorized",
				"message": "Authentication required",
			})
			c.Abort()
			return
		}

		// Check if user has admin permissions (can access any resource)
		if am.rbac.CheckPermission(c.Request.Context(), user, PermissionScanAll) {
			c.Next()
			return
		}

		// Get resource identifier from URL parameter
		resourceID := c.Param(resourceParam)
		if resourceID == "" {
			c.JSON(http.StatusBadRequest, gin.H{
				"error":   "Bad Request",
				"message": "Resource identifier required",
			})
			c.Abort()
			return
		}

		// Check if user owns the resource or has access to it
		if !am.userOwnsResource(user, resourceID) {
			c.JSON(http.StatusForbidden, gin.H{
				"error":   "Forbidden",
				"message": "Access denied to resource",
				"resource": resourceID,
			})
			c.Abort()
			return
		}

		c.Next()
	}
}

// AdminOnlyMiddleware restricts access to admin users only
func (am *AuthorizationMiddleware) AdminOnlyMiddleware() gin.HandlerFunc {
	return am.RequireRole("security_admin")
}

// SecurityAnalystOrAdminMiddleware allows security analysts and admins
func (am *AuthorizationMiddleware) SecurityAnalystOrAdminMiddleware() gin.HandlerFunc {
	return am.RequireAnyRole("security_admin", "security_analyst")
}

// getCurrentUser retrieves the current user from the context
func (am *AuthorizationMiddleware) getCurrentUser(c *gin.Context) *User {
	// Try to get user from context (set by authentication middleware)
	if userInterface, exists := c.Get("user"); exists {
		if user, ok := userInterface.(*User); ok {
			return user
		}
	}

	// Try to get user ID from context and fetch user
	if userIDInterface, exists := c.Get("user_id"); exists {
		if userID, ok := userIDInterface.(string); ok {
			user, err := am.authManager.GetUser(c.Request.Context(), userID)
			if err == nil {
				return user
			}
		}
	}

	return nil
}

// extractActionAttributes extracts attributes from the request context
func (am *AuthorizationMiddleware) extractActionAttributes(c *gin.Context) map[string]string {
	attributes := make(map[string]string)

	// Add request method
	attributes["method"] = c.Request.Method

	// Add request path
	attributes["path"] = c.Request.URL.Path

	// Add client IP
	attributes["client_ip"] = c.ClientIP()

	// Add user agent
	attributes["user_agent"] = c.Request.UserAgent()

	// Add any custom headers
	if orgHeader := c.GetHeader("X-Organization"); orgHeader != "" {
		attributes["organization"] = orgHeader
	}

	if projectHeader := c.GetHeader("X-Project"); projectHeader != "" {
		attributes["project"] = projectHeader
	}

	return attributes
}

// userOwnsResource checks if a user owns or has access to a specific resource
func (am *AuthorizationMiddleware) userOwnsResource(user *User, resourceID string) bool {
	// This is a simplified implementation
	// In a real system, this would check against a database or resource registry

	// Check if resource ID contains user identifier
	if strings.Contains(resourceID, user.ID) || strings.Contains(resourceID, user.Username) {
		return true
	}

	// Check user attributes for resource access patterns
	if allowedResources, exists := user.Attributes["allowed_resources"]; exists {
		allowedList := strings.Split(allowedResources, ",")
		for _, allowed := range allowedList {
			if strings.TrimSpace(allowed) == resourceID {
				return true
			}
		}
	}

	// Check if user has organization-level access
	if userOrg, exists := user.Attributes["organization"]; exists {
		if strings.HasPrefix(resourceID, userOrg+"/") {
			return true
		}
	}

	return false
}

// SetUserInContext sets the authenticated user in the request context
func SetUserInContext(c *gin.Context, user *User) {
	c.Set("user", user)
	c.Set("user_id", user.ID)
	c.Set("user_roles", user.Roles)
}

// GetUserFromContext retrieves the user from the request context
func GetUserFromContext(c *gin.Context) (*User, bool) {
	if userInterface, exists := c.Get("user"); exists {
		if user, ok := userInterface.(*User); ok {
			return user, true
		}
	}
	return nil, false
}

// GetUserPermissions returns all permissions for the current user
func (am *AuthorizationMiddleware) GetUserPermissions(c *gin.Context) gin.HandlerFunc {
	return func(c *gin.Context) {
		user := am.getCurrentUser(c)
		if user == nil {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error":   "Unauthorized",
				"message": "Authentication required",
			})
			return
		}

		permissions := am.rbac.GetUserPermissions(user)
		permissionStrings := make([]string, len(permissions))
		for i, perm := range permissions {
			permissionStrings[i] = string(perm)
		}

		c.JSON(http.StatusOK, gin.H{
			"user_id":     user.ID,
			"username":    user.Username,
			"roles":       user.Roles,
			"permissions": permissionStrings,
		})
	}
}