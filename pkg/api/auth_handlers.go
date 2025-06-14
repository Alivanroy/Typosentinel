package api

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/typosentinel/typosentinel/internal/auth"
)

// Authentication endpoints

// login handles user login
func (s *Server) login(c *gin.Context) {
	var req auth.LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Authenticate user
	response, err := s.userService.Login(c.Request.Context(), &req)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, response)
}

// refreshToken handles token refresh
func (s *Server) refreshToken(c *gin.Context) {
	var req struct {
		RefreshToken string `json:"refresh_token" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Refresh tokens
	tokens, err := s.authService.RefreshToken(req.RefreshToken)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid refresh token"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"tokens": tokens})
}

// logout handles user logout (token invalidation would be implemented with a token blacklist)
func (s *Server) logout(c *gin.Context) {
	// In a full implementation, we would add the token to a blacklist
	// For now, we just return success as the client should discard the token
	c.JSON(http.StatusOK, gin.H{"message": "Logged out successfully"})
}

// User management endpoints

// createUser handles user creation (admin only)
func (s *Server) createUser(c *gin.Context) {
	// Check permissions
	if !s.hasPermission(c, auth.PermissionUserCreate) {
		c.JSON(http.StatusForbidden, gin.H{"error": "Insufficient permissions"})
		return
	}

	var req auth.CreateUserRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Create user
	user, err := s.userService.CreateUser(c.Request.Context(), &req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusCreated, user)
}

// getUser handles user retrieval
func (s *Server) getUser(c *gin.Context) {
	userID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID"})
		return
	}

	// Check permissions (users can view their own profile, admins can view any)
	currentUserID := c.GetString("user_id")
	if userID.String() != currentUserID && !s.hasPermission(c, auth.PermissionUserRead) {
		c.JSON(http.StatusForbidden, gin.H{"error": "Insufficient permissions"})
		return
	}

	user, err := s.userService.GetUser(c.Request.Context(), userID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, user)
}

// getCurrentUser handles current user profile retrieval
func (s *Server) getCurrentUser(c *gin.Context) {
	userID, err := uuid.Parse(c.GetString("user_id"))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Invalid user context"})
		return
	}

	user, err := s.userService.GetUser(c.Request.Context(), userID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, user)
}

// updateUser handles user updates
func (s *Server) updateUser(c *gin.Context) {
	userID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID"})
		return
	}

	// Check permissions (users can update their own profile, admins can update any)
	currentUserID := c.GetString("user_id")
	if userID.String() != currentUserID && !s.hasPermission(c, auth.PermissionUserUpdate) {
		c.JSON(http.StatusForbidden, gin.H{"error": "Insufficient permissions"})
		return
	}

	var req auth.UpdateUserRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Non-admins cannot change role or active status
	if userID.String() == currentUserID && !s.hasPermission(c, auth.PermissionUserUpdate) {
		req.Role = nil
		req.IsActive = nil
	}

	user, err := s.userService.UpdateUser(c.Request.Context(), userID, &req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, user)
}

// deleteUser handles user deletion (admin only)
func (s *Server) deleteUser(c *gin.Context) {
	if !s.hasPermission(c, auth.PermissionUserDelete) {
		c.JSON(http.StatusForbidden, gin.H{"error": "Insufficient permissions"})
		return
	}

	userID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID"})
		return
	}

	// Prevent self-deletion
	currentUserID := c.GetString("user_id")
	if userID.String() == currentUserID {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Cannot delete your own account"})
		return
	}

	err = s.userService.DeleteUser(c.Request.Context(), userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "User deleted successfully"})
}

// listUsers handles user listing (admin only)
func (s *Server) listUsers(c *gin.Context) {
	if !s.hasPermission(c, auth.PermissionUserRead) {
		c.JSON(http.StatusForbidden, gin.H{"error": "Insufficient permissions"})
		return
	}

	// Parse pagination parameters
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "20"))
	offset, _ := strconv.Atoi(c.DefaultQuery("offset", "0"))

	if limit > 100 {
		limit = 100
	}

	orgID, err := uuid.Parse(c.GetString("organization_id"))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Invalid organization context"})
		return
	}

	users, total, err := s.userService.ListUsers(c.Request.Context(), orgID, limit, offset)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"users": users,
		"total": total,
		"limit": limit,
		"offset": offset,
	})
}

// changePassword handles password changes
func (s *Server) changePassword(c *gin.Context) {
	var req struct {
		CurrentPassword string `json:"current_password" binding:"required"`
		NewPassword     string `json:"new_password" binding:"required,min=8"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	userID, err := uuid.Parse(c.GetString("user_id"))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Invalid user context"})
		return
	}

	err = s.userService.ChangePassword(c.Request.Context(), userID, req.CurrentPassword, req.NewPassword)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Password changed successfully"})
}

// Organization management endpoints

// createOrganization handles organization creation (admin only)
func (s *Server) createOrganization(c *gin.Context) {
	if !s.hasPermission(c, auth.PermissionAdminAccess) {
		c.JSON(http.StatusForbidden, gin.H{"error": "Insufficient permissions"})
		return
	}

	var req auth.CreateOrganizationRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	org, err := s.orgService.CreateOrganization(c.Request.Context(), &req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusCreated, org)
}

// getOrganization handles organization retrieval
func (s *Server) getOrganization(c *gin.Context) {
	orgID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid organization ID"})
		return
	}

	// Check permissions (users can view their own org, admins can view any)
	currentOrgID := c.GetString("organization_id")
	if orgID.String() != currentOrgID && !s.hasPermission(c, auth.PermissionAdminAccess) {
		c.JSON(http.StatusForbidden, gin.H{"error": "Insufficient permissions"})
		return
	}

	org, err := s.orgService.GetOrganization(c.Request.Context(), orgID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, org)
}

// getCurrentOrganization handles current organization retrieval
func (s *Server) getCurrentOrganization(c *gin.Context) {
	orgID, err := uuid.Parse(c.GetString("organization_id"))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Invalid organization context"})
		return
	}

	org, err := s.orgService.GetOrganization(c.Request.Context(), orgID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, org)
}

// updateOrganization handles organization updates
func (s *Server) updateOrganization(c *gin.Context) {
	orgID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid organization ID"})
		return
	}

	// Check permissions (org members can update their own org, admins can update any)
	currentOrgID := c.GetString("organization_id")
	if orgID.String() != currentOrgID && !s.hasPermission(c, auth.PermissionAdminAccess) {
		c.JSON(http.StatusForbidden, gin.H{"error": "Insufficient permissions"})
		return
	}

	if !s.hasPermission(c, auth.PermissionOrgUpdate) {
		c.JSON(http.StatusForbidden, gin.H{"error": "Insufficient permissions"})
		return
	}

	var req auth.UpdateOrganizationRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	org, err := s.orgService.UpdateOrganization(c.Request.Context(), orgID, &req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, org)
}

// deleteOrganization handles organization deletion (admin only)
func (s *Server) deleteOrganization(c *gin.Context) {
	if !s.hasPermission(c, auth.PermissionAdminAccess) {
		c.JSON(http.StatusForbidden, gin.H{"error": "Insufficient permissions"})
		return
	}

	orgID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid organization ID"})
		return
	}

	// Prevent deletion of own organization
	currentOrgID := c.GetString("organization_id")
	if orgID.String() == currentOrgID {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Cannot delete your own organization"})
		return
	}

	err = s.orgService.DeleteOrganization(c.Request.Context(), orgID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Organization deleted successfully"})
}

// listOrganizations handles organization listing (admin only)
func (s *Server) listOrganizations(c *gin.Context) {
	if !s.hasPermission(c, auth.PermissionAdminAccess) {
		c.JSON(http.StatusForbidden, gin.H{"error": "Insufficient permissions"})
		return
	}

	// Parse pagination parameters
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "20"))
	offset, _ := strconv.Atoi(c.DefaultQuery("offset", "0"))

	if limit > 100 {
		limit = 100
	}

	orgs, total, err := s.orgService.ListOrganizations(c.Request.Context(), limit, offset)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"organizations": orgs,
		"total":         total,
		"limit":         limit,
		"offset":        offset,
	})
}

// getOrganizationStats handles organization statistics retrieval
func (s *Server) getOrganizationStats(c *gin.Context) {
	orgID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid organization ID"})
		return
	}

	// Check permissions
	currentOrgID := c.GetString("organization_id")
	if orgID.String() != currentOrgID && !s.hasPermission(c, auth.PermissionAdminAccess) {
		c.JSON(http.StatusForbidden, gin.H{"error": "Insufficient permissions"})
		return
	}

	stats, err := s.orgService.GetOrganizationStats(c.Request.Context(), orgID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, stats)
}

// Helper functions

// hasPermission checks if the current user has a specific permission
func (s *Server) hasPermission(c *gin.Context, permission string) bool {
	claims, exists := c.Get("claims")
	if !exists {
		return false
	}

	userClaims, ok := claims.(*auth.Claims)
	if !ok {
		return false
	}

	return userClaims.HasPermission(permission)
}

// requirePermission is a middleware that checks for specific permissions
func (s *Server) requirePermission(permission string) gin.HandlerFunc {
	return func(c *gin.Context) {
		if !s.hasPermission(c, permission) {
			c.JSON(http.StatusForbidden, gin.H{"error": "Insufficient permissions"})
			c.Abort()
			return
		}
		c.Next()
	}
}

// requireRole is a middleware that checks for specific roles
func (s *Server) requireRole(role string) gin.HandlerFunc {
	return func(c *gin.Context) {
		claims, exists := c.Get("claims")
		if !exists {
			c.JSON(http.StatusForbidden, gin.H{"error": "Invalid user context"})
			c.Abort()
			return
		}

		userClaims, ok := claims.(*auth.Claims)
		if !ok {
			c.JSON(http.StatusForbidden, gin.H{"error": "Invalid user context"})
			c.Abort()
			return
		}

		if !userClaims.HasRole(role) {
			c.JSON(http.StatusForbidden, gin.H{"error": "Insufficient role"})
			c.Abort()
			return
		}
		c.Next()
	}
}