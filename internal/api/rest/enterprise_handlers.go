package rest

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/Alivanroy/Typosentinel/internal/auth"
	"github.com/Alivanroy/Typosentinel/internal/storage"
	"github.com/gin-gonic/gin"
)

// EnterpriseHandlers provides HTTP handlers for enterprise features
type EnterpriseHandlers struct {
	policyManager  *auth.EnterprisePolicyManager
	rbacEngine     *auth.RBACEngine
	authMiddleware *auth.AuthorizationMiddleware
	violationStore *storage.ViolationStore
	logger         Logger
}

// Logger interface for handlers
type Logger interface {
	Info(msg string, fields ...interface{})
	Warn(msg string, fields ...interface{})
	Error(msg string, fields ...interface{})
	Debug(msg string, fields ...interface{})
}

// NewEnterpriseHandlers creates new enterprise handlers
func NewEnterpriseHandlers(policyManager *auth.EnterprisePolicyManager, rbacEngine *auth.RBACEngine, authMiddleware *auth.AuthorizationMiddleware, violationStore *storage.ViolationStore, logger Logger) *EnterpriseHandlers {
	return &EnterpriseHandlers{
		policyManager:  policyManager,
		rbacEngine:     rbacEngine,
		authMiddleware: authMiddleware,
		violationStore: violationStore,
		logger:         logger,
	}
}

// RegisterRoutes registers enterprise API routes
func (eh *EnterpriseHandlers) RegisterRoutes(router *gin.RouterGroup) {
	// Policy management routes
	policyGroup := router.Group("/policies")
	{
		policyGroup.GET("", eh.authMiddleware.RequirePermission("policies:read"), eh.ListPolicies)
		policyGroup.POST("", eh.authMiddleware.RequirePermission("policies:create"), eh.CreatePolicy)
		policyGroup.GET("/:id", eh.authMiddleware.RequirePermission("policies:read"), eh.GetPolicy)
		policyGroup.PUT("/:id", eh.authMiddleware.RequirePermission("policies:update"), eh.UpdatePolicy)
		policyGroup.DELETE("/:id", eh.authMiddleware.RequirePermission("policies:delete"), eh.DeletePolicy)
		policyGroup.POST("/:id/evaluate", eh.authMiddleware.RequirePermission("policies:evaluate"), eh.EvaluatePolicy)
	}

	// Policy templates routes
	templateGroup := router.Group("/policy-templates")
	{
		templateGroup.GET("", eh.authMiddleware.RequirePermission("policies:read"), eh.ListPolicyTemplates)
		templateGroup.GET("/:id", eh.authMiddleware.RequirePermission("policies:read"), eh.GetPolicyTemplate)
		templateGroup.POST("/:id/create-policy", eh.authMiddleware.RequirePermission("policies:create"), eh.CreatePolicyFromTemplate)
	}

	// RBAC management routes
	rbacGroup := router.Group("/rbac")
	{
		rbacGroup.GET("/roles", eh.authMiddleware.RequirePermission("rbac:read"), eh.ListRoles)
		rbacGroup.POST("/roles", eh.authMiddleware.RequirePermission("rbac:create"), eh.CreateRole)
		rbacGroup.GET("/roles/:id", eh.authMiddleware.RequirePermission("rbac:read"), eh.GetRole)
		rbacGroup.PUT("/roles/:id", eh.authMiddleware.RequirePermission("rbac:update"), eh.UpdateRole)
		rbacGroup.DELETE("/roles/:id", eh.authMiddleware.RequirePermission("rbac:delete"), eh.DeleteRole)
		rbacGroup.GET("/users/:userId/permissions", eh.authMiddleware.RequirePermission("rbac:read"), eh.GetUserPermissions)
		rbacGroup.POST("/users/:userId/check-permission", eh.authMiddleware.RequirePermission("rbac:read"), eh.CheckUserPermission)
	}

	// Policy enforcement routes
	enforcementGroup := router.Group("/enforcement")
	{
		enforcementGroup.GET("/settings", eh.authMiddleware.RequirePermission("enforcement:read"), eh.GetEnforcementSettings)
		enforcementGroup.PUT("/settings", eh.authMiddleware.RequirePermission("enforcement:update"), eh.UpdateEnforcementSettings)
		enforcementGroup.POST("/evaluate", eh.authMiddleware.RequirePermission("enforcement:evaluate"), eh.EvaluateAndEnforce)
	}

	// Approval workflow routes
	approvalGroup := router.Group("/approvals")
	{
		approvalGroup.GET("/violations", eh.authMiddleware.RequirePermission("approvals:read"), eh.ListViolations)
		approvalGroup.GET("/violations/:id", eh.authMiddleware.RequirePermission("approvals:read"), eh.GetViolation)
		approvalGroup.POST("/violations/:id/approve", eh.authMiddleware.RequirePermission("approvals:approve"), eh.ApproveViolation)
		approvalGroup.POST("/violations/:id/reject", eh.authMiddleware.RequirePermission("approvals:approve"), eh.RejectViolation)
	}
}

// Policy Management Handlers

// ListPolicies handles GET /api/v1/enterprise/policies
func (eh *EnterpriseHandlers) ListPolicies(c *gin.Context) {
	policies := eh.policyManager.ListPolicies()

	response := map[string]interface{}{
		"policies": policies,
		"total":    len(policies),
	}

	c.JSON(http.StatusOK, response)
}

// CreatePolicy handles POST /api/v1/enterprise/policies
func (eh *EnterpriseHandlers) CreatePolicy(c *gin.Context) {
	var policy auth.SecurityPolicy
	if err := c.ShouldBindJSON(&policy); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}

	// Set creation metadata
	policy.CreatedAt = time.Now()
	policy.UpdatedAt = time.Now()
	policy.CreatedBy = eh.getCurrentUser(c)

	eh.policyManager.AddPolicy(&policy)
	eh.logger.Info("Policy created successfully", "policy_id", policy.ID)

	c.JSON(http.StatusCreated, policy)
}

// GetPolicy handles GET /api/v1/enterprise/policies/{id}
func (eh *EnterpriseHandlers) GetPolicy(c *gin.Context) {
	policyID := c.Param("id")

	policy, err := eh.policyManager.GetPolicy(policyID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Policy not found"})
		return
	}

	c.JSON(http.StatusOK, policy)
}

// UpdatePolicy handles PUT /api/v1/enterprise/policies/{id}
func (eh *EnterpriseHandlers) UpdatePolicy(c *gin.Context) {
	policyID := c.Param("id")

	var policy auth.SecurityPolicy
	if err := c.ShouldBindJSON(&policy); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}

	// Ensure ID matches
	policy.ID = policyID
	policy.UpdatedAt = time.Now()

	eh.policyManager.AddPolicy(&policy)
	eh.logger.Info("Policy updated successfully", "policy_id", policy.ID)

	c.JSON(http.StatusOK, policy)
}

// DeletePolicy handles DELETE /api/v1/enterprise/policies/{id}
func (eh *EnterpriseHandlers) DeletePolicy(c *gin.Context) {
	policyID := c.Param("id")

	eh.policyManager.RemovePolicy(policyID)
	eh.logger.Info("Policy deleted successfully", "policy_id", policyID)

	c.Status(http.StatusNoContent)
}

// EvaluatePolicy handles POST /api/v1/enterprise/policies/{id}/evaluate
func (eh *EnterpriseHandlers) EvaluatePolicy(c *gin.Context) {
	policyID := c.Param("id")

	var evalCtx auth.PolicyEvaluationContext
	if err := c.ShouldBindJSON(&evalCtx); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}

	// Get the specific policy
	policy, err := eh.policyManager.GetPolicyTemplate(policyID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Policy not found"})
		return
	}

	// Evaluate and enforce policies
	result, err := eh.policyManager.EvaluateAndEnforce(c.Request.Context(), &evalCtx)
	if err != nil {
		eh.logger.Error("Failed to evaluate policy", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to evaluate policy: %v", err)})
		return
	}

	response := map[string]interface{}{
		"policy":     policy,
		"evaluation": result,
		"timestamp":  time.Now(),
	}

	c.JSON(http.StatusOK, response)
}

// Policy Template Handlers

// ListPolicyTemplates handles GET /api/v1/enterprise/policy-templates
func (eh *EnterpriseHandlers) ListPolicyTemplates(c *gin.Context) {
	templates := eh.policyManager.ListPolicyTemplates()

	response := map[string]interface{}{
		"templates": templates,
		"total":     len(templates),
	}

	c.JSON(http.StatusOK, response)
}

// GetPolicyTemplate handles GET /api/v1/enterprise/policy-templates/{id}
func (eh *EnterpriseHandlers) GetPolicyTemplate(c *gin.Context) {
	templateID := c.Param("id")

	template, err := eh.policyManager.GetPolicyTemplate(templateID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Template not found"})
		return
	}

	c.JSON(http.StatusOK, template)
}

// CreatePolicyFromTemplate handles POST /api/v1/enterprise/policy-templates/{id}/create-policy
func (eh *EnterpriseHandlers) CreatePolicyFromTemplate(c *gin.Context) {
	templateID := c.Param("id")

	var request struct {
		PolicyID       string                 `json:"policy_id"`
		Customizations map[string]interface{} `json:"customizations"`
	}

	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}

	policy, err := eh.policyManager.CreatePolicyFromTemplate(templateID, request.PolicyID, request.Customizations)
	if err != nil {
		eh.logger.Error("Failed to create policy from template", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to create policy: %v", err)})
		return
	}

	c.JSON(http.StatusCreated, policy)
}

// RBAC Management Handlers

// ListRoles handles GET /api/v1/enterprise/rbac/roles
func (eh *EnterpriseHandlers) ListRoles(c *gin.Context) {
	roles := eh.rbacEngine.ListRoles()

	response := map[string]interface{}{
		"roles": roles,
		"total": len(roles),
	}

	c.JSON(http.StatusOK, response)
}

// CreateRole handles POST /api/v1/enterprise/rbac/roles
func (eh *EnterpriseHandlers) CreateRole(c *gin.Context) {
	var role auth.Role
	if err := c.ShouldBindJSON(&role); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}

	eh.rbacEngine.AddRole(&role)
	eh.logger.Info("Role created successfully", "role_id", role.Name)

	c.JSON(http.StatusCreated, role)
}

// GetRole handles GET /api/v1/enterprise/rbac/roles/{id}
func (eh *EnterpriseHandlers) GetRole(c *gin.Context) {
	roleID := c.Param("id")

	role, exists := eh.rbacEngine.GetRole(roleID)
	if !exists {
		c.JSON(http.StatusNotFound, gin.H{"error": "Role not found"})
		return
	}

	c.JSON(http.StatusOK, role)
}

// UpdateRole handles PUT /api/v1/enterprise/rbac/roles/{id}
func (eh *EnterpriseHandlers) UpdateRole(c *gin.Context) {
	roleID := c.Param("id")

	var role auth.Role
	if err := c.ShouldBindJSON(&role); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}

	// Ensure name matches
	role.Name = roleID

	eh.rbacEngine.AddRole(&role)
	eh.logger.Info("Role updated successfully", "role_id", role.Name)

	c.JSON(http.StatusOK, role)
}

// DeleteRole handles DELETE /api/v1/enterprise/rbac/roles/{id}
func (eh *EnterpriseHandlers) DeleteRole(c *gin.Context) {
	roleID := c.Param("id")
	if roleID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Role ID is required"})
		return
	}

	// Check if RBAC engine is available
	if eh.rbacEngine == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "RBAC engine not available"})
		return
	}

	// Remove the role
	err := eh.rbacEngine.RemoveRole(roleID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message":   fmt.Sprintf("Role '%s' deleted successfully", roleID),
		"timestamp": time.Now().UTC(),
	})
}

// GetUserPermissions handles GET /api/v1/enterprise/rbac/users/{userId}/permissions
func (eh *EnterpriseHandlers) GetUserPermissions(c *gin.Context) {
	userID := c.Param("userId")

	user := &auth.User{ID: userID}
	permissions := eh.rbacEngine.GetUserPermissions(user)

	response := map[string]interface{}{
		"user_id":     userID,
		"permissions": permissions,
		"total":       len(permissions),
	}

	c.JSON(http.StatusOK, response)
}

// CheckUserPermission handles POST /api/v1/enterprise/rbac/users/{userId}/check-permission
func (eh *EnterpriseHandlers) CheckUserPermission(c *gin.Context) {
	userID := c.Param("userId")

	var request struct {
		Permission string `json:"permission"`
	}

	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}

	user := &auth.User{ID: userID}
	hasPermission := eh.rbacEngine.CheckPermission(c.Request.Context(), user, auth.Permission(request.Permission))

	response := map[string]interface{}{
		"user_id":        userID,
		"permission":     request.Permission,
		"has_permission": hasPermission,
		"checked_at":     time.Now(),
	}

	c.JSON(http.StatusOK, response)
}

// Policy Enforcement Handlers

// GetEnforcementSettings handles GET /api/v1/enterprise/enforcement/settings
func (eh *EnterpriseHandlers) GetEnforcementSettings(c *gin.Context) {
	settings := eh.policyManager.GetEnforcementSettings()

	c.JSON(http.StatusOK, settings)
}

// UpdateEnforcementSettings handles PUT /api/v1/enterprise/enforcement/settings
func (eh *EnterpriseHandlers) UpdateEnforcementSettings(c *gin.Context) {
	var settings auth.PolicyEnforcement
	if err := c.ShouldBindJSON(&settings); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}

	if err := eh.policyManager.UpdateEnforcementSettings(&settings); err != nil {
		eh.logger.Error("Failed to update enforcement settings", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to update settings: %v", err)})
		return
	}

	c.JSON(http.StatusOK, settings)
}

// EvaluateAndEnforce handles POST /api/v1/enterprise/enforcement/evaluate
func (eh *EnterpriseHandlers) EvaluateAndEnforce(c *gin.Context) {
	var evalCtx auth.PolicyEvaluationContext
	if err := c.ShouldBindJSON(&evalCtx); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}

	result, err := eh.policyManager.EvaluateAndEnforce(c.Request.Context(), &evalCtx)
	if err != nil {
		eh.logger.Error("Failed to evaluate and enforce policies", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to evaluate policies: %v", err)})
		return
	}

	c.JSON(http.StatusOK, result)
}

// Approval Workflow Handlers

// ListViolations handles GET /api/v1/enterprise/approvals/violations
func (eh *EnterpriseHandlers) ListViolations(c *gin.Context) {
	// Parse query parameters
	status := c.Query("status")
	policyName := c.Query("policy_name")
	pageStr := c.DefaultQuery("page", "1")
	limitStr := c.DefaultQuery("limit", "10")

	page, err := strconv.Atoi(pageStr)
	if err != nil || page < 1 {
		page = 1
	}

	limit, err := strconv.Atoi(limitStr)
	if err != nil || limit < 1 || limit > 100 {
		limit = 10
	}

	offset := (page - 1) * limit

	// Validate sorting parameters
	sortBy := c.DefaultQuery("sort_by", "created_at")
	sortOrder := c.DefaultQuery("sort_order", "desc")

	allowedSortColumns := map[string]bool{
		"created_at":  true,
		"severity":    true,
		"status":      true,
		"policy_id":   true,
		"policy_name": true,
		"resolved_at": true,
	}

	sb := strings.ToLower(sortBy)
	if sb != "" && !allowedSortColumns[sb] {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":    "invalid sort_by",
			"allowed":  []string{"created_at", "severity", "status", "policy_id", "policy_name", "resolved_at"},
			"received": sortBy,
		})
		return
	}

	so := strings.ToLower(sortOrder)
	if so != "asc" && so != "desc" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":    "invalid sort_order",
			"allowed":  []string{"asc", "desc"},
			"received": sortOrder,
		})
		return
	}

	// Create filter
	filter := storage.ListViolationsOptions{
		Status:    status,
		PolicyID:  policyName, // Using PolicyID field instead of PolicyName
		Limit:     limit,
		Offset:    offset,
		SortBy:    sb,
		SortOrder: so,
	}

	// Get violations from store
	violations, total, err := eh.violationStore.ListViolations(c.Request.Context(), &filter)
	if err != nil {
		eh.logger.Error("Failed to list violations", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to retrieve violations",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"violations": violations,
		"total":      total,
		"page":       page,
		"per_page":   limit,
	})
}

// GetViolation handles GET /api/v1/enterprise/approvals/violations/{id}
func (eh *EnterpriseHandlers) GetViolation(c *gin.Context) {
	violationID := c.Param("id")

	// Get violation from store
	violation, err := eh.violationStore.GetViolation(c.Request.Context(), violationID)
	if err != nil {
		if err == storage.ErrViolationNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "Violation not found"})
			return
		}
		eh.logger.Error("Failed to get violation", "violation_id", violationID, "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve violation"})
		return
	}

	c.JSON(http.StatusOK, violation)
}

// ApproveViolation handles POST /api/v1/enterprise/approvals/violations/{id}/approve
func (eh *EnterpriseHandlers) ApproveViolation(c *gin.Context) {
	violationID := c.Param("id")

	var request struct {
		Reason string `json:"reason"`
	}

	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}

	currentUser := eh.getCurrentUser(c)

	// Update violation status
	err := eh.violationStore.UpdateViolationStatus(c.Request.Context(), violationID, storage.ViolationStatusApproved, currentUser, request.Reason)
	if err != nil {
		if err == storage.ErrViolationNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "Violation not found"})
			return
		}
		eh.logger.Error("Failed to approve violation", "violation_id", violationID, "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to approve violation"})
		return
	}

	response := map[string]interface{}{
		"violation_id": violationID,
		"status":       "approved",
		"reason":       request.Reason,
		"approved_at":  time.Now(),
		"approved_by":  currentUser,
	}

	eh.logger.Info("Violation approved", "violation_id", violationID, "reason", request.Reason)

	c.JSON(http.StatusOK, response)
}

// RejectViolation handles POST /api/v1/enterprise/approvals/violations/{id}/reject
func (eh *EnterpriseHandlers) RejectViolation(c *gin.Context) {
	violationID := c.Param("id")

	var request struct {
		Reason string `json:"reason"`
	}

	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}

	currentUser := eh.getCurrentUser(c)

	// Update violation status
	err := eh.violationStore.UpdateViolationStatus(c.Request.Context(), violationID, storage.ViolationStatusRejected, currentUser, request.Reason)
	if err != nil {
		if err == storage.ErrViolationNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "Violation not found"})
			return
		}
		eh.logger.Error("Failed to reject violation", "violation_id", violationID, "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to reject violation"})
		return
	}

	response := map[string]interface{}{
		"violation_id": violationID,
		"status":       "rejected",
		"reason":       request.Reason,
		"rejected_at":  time.Now(),
		"rejected_by":  currentUser,
	}

	eh.logger.Info("Violation rejected", "violation_id", violationID, "reason", request.Reason)

	c.JSON(http.StatusOK, response)
}

// Helper Methods

// getCurrentUser extracts the current user from the authentication context
func (eh *EnterpriseHandlers) getCurrentUser(c *gin.Context) string {
	// Try to get user from JWT token or session
	if userID, exists := c.Get("user_id"); exists {
		if userStr, ok := userID.(string); ok {
			return userStr
		}
	}

	// Try to get from Authorization header
	authHeader := c.GetHeader("Authorization")
	if authHeader != "" {
		// Extract user from token (simplified implementation)
		// In a real implementation, you would decode the JWT token
		return "authenticated_user"
	}

	// Try to get from X-User-ID header (for service-to-service calls)
	if userID := c.GetHeader("X-User-ID"); userID != "" {
		return userID
	}

	// Default fallback
	return "system"
}
