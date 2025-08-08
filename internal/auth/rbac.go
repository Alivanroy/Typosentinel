package auth

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/Alivanroy/Typosentinel/internal/config"
)

// Permission represents a specific permission
type Permission string

// Common permissions
const (
	PermissionScanAll        Permission = "scan:all"
	PermissionScanRead       Permission = "scan:read"
	PermissionScanExecute    Permission = "scan:execute"
	PermissionScanOwnRepos   Permission = "scan:own_repos"
	PermissionReportsAll     Permission = "reports:all"
	PermissionReportsRead    Permission = "reports:read"
	PermissionReportsOwnRepos Permission = "reports:own_repos"
	PermissionConfigWrite    Permission = "config:write"
	PermissionConfigRead     Permission = "config:read"
	PermissionUsersManage    Permission = "users:manage"
	PermissionUsersRead      Permission = "users:read"
	PermissionPoliciesManage Permission = "policies:manage"
	PermissionPoliciesRead   Permission = "policies:read"
)

// Action represents an action being performed
type Action struct {
	Type       string            `json:"type"`
	Resource   string            `json:"resource"`
	Attributes map[string]string `json:"attributes"`
}

// Role represents a role with permissions
type Role struct {
	Name        string       `json:"name"`
	Description string       `json:"description"`
	Permissions []Permission `json:"permissions"`
	Inherits    []string     `json:"inherits"`
	cachedPerms []Permission // cached resolved permissions
	lastUpdate  time.Time    // last time permissions were resolved
}

// Policy represents an authorization policy
type Policy struct {
	Name       string            `json:"name"`
	Effect     string            `json:"effect"` // "allow" or "deny"
	Actions    []string          `json:"actions"`
	Resources  []string          `json:"resources"`
	Conditions map[string]string `json:"conditions"`
}

// RBACEngine handles role-based access control
type RBACEngine struct {
	roles    map[string]*Role
	policies map[string]*Policy
	mu       sync.RWMutex
	config   *config.AuthzConfig
}

// NewRBACEngine creates a new RBAC engine
func NewRBACEngine(config *config.AuthzConfig) *RBACEngine {
	rbac := &RBACEngine{
		roles:    make(map[string]*Role),
		policies: make(map[string]*Policy),
		config:   config,
	}

	// Load roles from configuration
	if config != nil {
		for _, roleConfig := range config.Roles {
			role := &Role{
				Name:        roleConfig.Name,
				Description: roleConfig.Description,
				Permissions: make([]Permission, len(roleConfig.Permissions)),
				Inherits:    roleConfig.Inherits,
			}
			for i, perm := range roleConfig.Permissions {
				role.Permissions[i] = Permission(perm)
			}
			rbac.roles[role.Name] = role
		}

		// Load policies from configuration
		for _, policyConfig := range config.Policies {
			policy := &Policy{
				Name:       policyConfig.Name,
				Effect:     policyConfig.Effect,
				Actions:    policyConfig.Actions,
				Resources:  policyConfig.Resources,
				Conditions: policyConfig.Conditions,
			}
			rbac.policies[policy.Name] = policy
		}
	}

	return rbac
}

// AddRole adds a new role to the RBAC engine
func (rbac *RBACEngine) AddRole(role *Role) {
	rbac.mu.Lock()
	defer rbac.mu.Unlock()
	rbac.roles[role.Name] = role
}

// GetRole retrieves a role by name
func (rbac *RBACEngine) GetRole(name string) (*Role, bool) {
	rbac.mu.RLock()
	defer rbac.mu.RUnlock()
	role, exists := rbac.roles[name]
	return role, exists
}

// AddPolicy adds a new policy to the RBAC engine
func (rbac *RBACEngine) AddPolicy(policy *Policy) {
	rbac.mu.Lock()
	defer rbac.mu.Unlock()
	rbac.policies[policy.Name] = policy
}

// GetPolicy retrieves a policy by name
func (rbac *RBACEngine) GetPolicy(name string) (*Policy, bool) {
	rbac.mu.RLock()
	defer rbac.mu.RUnlock()
	policy, exists := rbac.policies[name]
	return policy, exists
}

// CheckPermission checks if a user has a specific permission
func (rbac *RBACEngine) CheckPermission(ctx context.Context, user *User, permission Permission) bool {
	if user == nil {
		return false
	}

	// Check each role the user has
	for _, roleName := range user.Roles {
		if rbac.roleHasPermission(roleName, permission) {
			return true
		}
	}

	return false
}

// CheckAction checks if a user can perform a specific action
func (rbac *RBACEngine) CheckAction(ctx context.Context, user *User, action *Action) (bool, error) {
	if user == nil {
		return false, fmt.Errorf("user is nil")
	}

	// First check role-based permissions
	permission := Permission(fmt.Sprintf("%s:%s", action.Type, action.Resource))
	if rbac.CheckPermission(ctx, user, permission) {
		// Check policies for additional restrictions
		return rbac.evaluatePolicies(ctx, user, action)
	}

	// Check for wildcard permissions
	wildcardPermission := Permission(fmt.Sprintf("%s:*", action.Type))
	if rbac.CheckPermission(ctx, user, wildcardPermission) {
		return rbac.evaluatePolicies(ctx, user, action)
	}

	return false, nil
}

// roleHasPermission checks if a role has a specific permission
func (rbac *RBACEngine) roleHasPermission(roleName string, permission Permission) bool {
	rbac.mu.RLock()
	role, exists := rbac.roles[roleName]
	rbac.mu.RUnlock()

	if !exists {
		return false
	}

	// Check cached permissions first
	if time.Since(role.lastUpdate) < 5*time.Minute && len(role.cachedPerms) > 0 {
		for _, perm := range role.cachedPerms {
			if perm == permission || rbac.matchesWildcard(string(perm), string(permission)) {
				return true
			}
		}
		return false
	}

	// Resolve permissions including inherited ones
	allPermissions := rbac.resolveRolePermissions(role)

	// Cache the resolved permissions
	rbac.mu.Lock()
	role.cachedPerms = allPermissions
	role.lastUpdate = time.Now()
	rbac.mu.Unlock()

	// Check if permission exists
	for _, perm := range allPermissions {
		if perm == permission || rbac.matchesWildcard(string(perm), string(permission)) {
			return true
		}
	}

	return false
}

// resolveRolePermissions resolves all permissions for a role including inherited ones
func (rbac *RBACEngine) resolveRolePermissions(role *Role) []Permission {
	permissionSet := make(map[Permission]bool)
	visited := make(map[string]bool)

	// Recursive function to collect permissions
	var collectPermissions func(roleName string)
	collectPermissions = func(roleName string) {
		if visited[roleName] {
			return // Avoid circular dependencies
		}
		visited[roleName] = true

		currentRole, exists := rbac.roles[roleName]
		if !exists {
			return
		}

		// Add direct permissions
		for _, perm := range currentRole.Permissions {
			permissionSet[perm] = true
		}

		// Add inherited permissions
		for _, inheritedRole := range currentRole.Inherits {
			collectPermissions(inheritedRole)
		}
	}

	collectPermissions(role.Name)

	// Convert set to slice
	permissions := make([]Permission, 0, len(permissionSet))
	for perm := range permissionSet {
		permissions = append(permissions, perm)
	}

	return permissions
}

// evaluatePolicies evaluates policies for additional access control
func (rbac *RBACEngine) evaluatePolicies(ctx context.Context, user *User, action *Action) (bool, error) {
	rbac.mu.RLock()
	defer rbac.mu.RUnlock()

	allowed := true // Default to allow if no denying policies

	for _, policy := range rbac.policies {
		if rbac.policyApplies(policy, action) {
			if policy.Effect == "deny" {
				// Check if conditions match
				if rbac.evaluateConditions(policy.Conditions, user, action) {
					return false, nil // Explicit deny
				}
			} else if policy.Effect == "allow" {
				// Allow policies don't override deny policies
				continue
			}
		}
	}

	return allowed, nil
}

// policyApplies checks if a policy applies to the given action
func (rbac *RBACEngine) policyApplies(policy *Policy, action *Action) bool {
	// Check if action type matches
	actionMatches := false
	for _, policyAction := range policy.Actions {
		if policyAction == "*" || policyAction == action.Type {
			actionMatches = true
			break
		}
	}

	if !actionMatches {
		return false
	}

	// Check if resource matches
	resourceMatches := false
	for _, policyResource := range policy.Resources {
		if policyResource == "*" || rbac.matchesWildcard(policyResource, action.Resource) {
			resourceMatches = true
			break
		}
	}

	return resourceMatches
}

// evaluateConditions evaluates policy conditions
func (rbac *RBACEngine) evaluateConditions(conditions map[string]string, user *User, action *Action) bool {
	for key, expectedValue := range conditions {
		actualValue := rbac.getConditionValue(key, user, action)
		if actualValue != expectedValue {
			return false
		}
	}
	return true
}

// getConditionValue gets the actual value for a condition key
func (rbac *RBACEngine) getConditionValue(key string, user *User, action *Action) string {
	switch {
	case strings.HasPrefix(key, "user."):
		field := strings.TrimPrefix(key, "user.")
		switch field {
		case "id":
			return user.ID
		case "username":
			return user.Username
		case "email":
			return user.Email
		default:
			if value, exists := user.Attributes[field]; exists {
				return value
			}
		}
	case strings.HasPrefix(key, "action."):
		field := strings.TrimPrefix(key, "action.")
		switch field {
		case "type":
			return action.Type
		case "resource":
			return action.Resource
		default:
			if value, exists := action.Attributes[field]; exists {
				return value
			}
		}
	case strings.HasPrefix(key, "time."):
		field := strings.TrimPrefix(key, "time.")
		switch field {
		case "hour":
			return fmt.Sprintf("%d", time.Now().Hour())
		case "day_of_week":
			return time.Now().Weekday().String()
		}
	}
	return ""
}

// matchesWildcard checks if a pattern with wildcards matches a string
func (rbac *RBACEngine) matchesWildcard(pattern, str string) bool {
	if pattern == "*" {
		return true
	}

	// Simple wildcard matching - can be enhanced with more sophisticated patterns
	if strings.HasSuffix(pattern, "*") {
		prefix := strings.TrimSuffix(pattern, "*")
		return strings.HasPrefix(str, prefix)
	}

	if strings.HasPrefix(pattern, "*") {
		suffix := strings.TrimPrefix(pattern, "*")
		return strings.HasSuffix(str, suffix)
	}

	return pattern == str
}

// GetUserPermissions returns all permissions for a user
func (rbac *RBACEngine) GetUserPermissions(user *User) []Permission {
	if user == nil {
		return nil
	}

	permissionSet := make(map[Permission]bool)

	for _, roleName := range user.Roles {
		if role, exists := rbac.GetRole(roleName); exists {
			permissions := rbac.resolveRolePermissions(role)
			for _, perm := range permissions {
				permissionSet[perm] = true
			}
		}
	}

	permissions := make([]Permission, 0, len(permissionSet))
	for perm := range permissionSet {
		permissions = append(permissions, perm)
	}

	return permissions
}

// ListRoles returns all available roles
func (rbac *RBACEngine) ListRoles() []*Role {
	rbac.mu.RLock()
	defer rbac.mu.RUnlock()

	roles := make([]*Role, 0, len(rbac.roles))
	for _, role := range rbac.roles {
		roles = append(roles, role)
	}

	return roles
}

// ListPolicies returns all available policies
func (rbac *RBACEngine) ListPolicies() []*Policy {
	rbac.mu.RLock()
	defer rbac.mu.RUnlock()

	policies := make([]*Policy, 0, len(rbac.policies))
	for _, policy := range rbac.policies {
		policies = append(policies, policy)
	}

	return policies
}

// ValidateRoleConfiguration validates role configuration for circular dependencies
func (rbac *RBACEngine) ValidateRoleConfiguration() error {
	rbac.mu.RLock()
	defer rbac.mu.RUnlock()

	// Check for circular dependencies in role inheritance
	for roleName := range rbac.roles {
		visited := make(map[string]bool)
		if rbac.hasCircularDependency(roleName, visited) {
			return fmt.Errorf("circular dependency detected in role inheritance for role: %s", roleName)
		}
	}

	return nil
}

// hasCircularDependency checks for circular dependencies in role inheritance
func (rbac *RBACEngine) hasCircularDependency(roleName string, visited map[string]bool) bool {
	if visited[roleName] {
		return true
	}

	role, exists := rbac.roles[roleName]
	if !exists {
		return false
	}

	visited[roleName] = true

	for _, inheritedRole := range role.Inherits {
		if rbac.hasCircularDependency(inheritedRole, visited) {
			return true
		}
	}

	delete(visited, roleName)
	return false
}

// RemoveRole removes a role from the RBAC engine
func (rbac *RBACEngine) RemoveRole(roleName string) error {
	if roleName == "" {
		return fmt.Errorf("role name cannot be empty")
	}

	rbac.mu.Lock()
	defer rbac.mu.Unlock()

	// Check if role exists
	if _, exists := rbac.roles[roleName]; !exists {
		return fmt.Errorf("role '%s' does not exist", roleName)
	}

	// Check if any other roles inherit from this role
	for _, role := range rbac.roles {
		for _, inheritedRole := range role.Inherits {
			if inheritedRole == roleName {
				return fmt.Errorf("cannot remove role '%s': it is inherited by role '%s'", roleName, role.Name)
			}
		}
	}

	// Remove the role
	delete(rbac.roles, roleName)

	return nil
}