package multitenant

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// TenantManager manages multi-tenant operations
type TenantManager struct {
	tenants     map[string]*Tenant
	mu          sync.RWMutex
	config      *MultiTenantConfig
	metrics     *TenantMetricsManager
	resources   *ResourceManager
	isolation   *IsolationManager
	auditLogger *AuditLogger
}

// NewTenantManager creates a new tenant manager
func NewTenantManager(config *MultiTenantConfig) *TenantManager {
	if config == nil {
		config = &MultiTenantConfig{
			MaxTenants:        1000,
			DefaultQuotas:     getDefaultQuotas(),
			IsolationLevel:    IsolationLevelStrict,
			ResourcePooling:   true,
			AuditingEnabled:   true,
			MetricsEnabled:    true,
			AutoScaling:       true,
			DataRetentionDays: 90,
			BackupEnabled:     true,
			EncryptionEnabled: true,
		}
	}

	return &TenantManager{
		tenants:     make(map[string]*Tenant),
		config:      config,
		metrics:     NewTenantMetrics(),
		resources:   NewResourceManager(config),
		isolation:   NewIsolationManager(config),
		auditLogger: NewAuditLogger(config),
	}
}

// CreateTenant creates a new tenant
func (tm *TenantManager) CreateTenant(ctx context.Context, request *CreateTenantRequest) (*Tenant, error) {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	// Validate request
	if err := tm.validateCreateRequest(request); err != nil {
		return nil, fmt.Errorf("invalid create request: %w", err)
	}

	// Check tenant limits
	if len(tm.tenants) >= tm.config.MaxTenants {
		return nil, fmt.Errorf("maximum tenant limit reached: %d", tm.config.MaxTenants)
	}

	// Check if tenant already exists
	if _, exists := tm.tenants[request.ID]; exists {
		return nil, fmt.Errorf("tenant already exists: %s", request.ID)
	}

	// Create tenant
	tenant := &Tenant{
		ID:          request.ID,
		Name:        request.Name,
		Description: request.Description,
		Owner:       request.Owner,
		Plan:        request.Plan,
		Quotas:      tm.mergeQuotas(request.Quotas),
		Settings:    request.Settings,
		Status:      TenantStatusActive,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
		Metadata:    request.Metadata,
	}

	// Initialize tenant resources
	if err := tm.initializeTenantResources(ctx, tenant); err != nil {
		return nil, fmt.Errorf("failed to initialize tenant resources: %w", err)
	}

	// Store tenant
	tm.tenants[tenant.ID] = tenant

	// Update metrics
	tm.metrics.IncrementTenantCount()
	tm.metrics.RecordTenantCreation(tenant.ID, tenant.Plan)

	// Audit log
	tm.auditLogger.LogTenantCreation(ctx, tenant)

	return tenant, nil
}

// GetTenant retrieves a tenant by ID
func (tm *TenantManager) GetTenant(ctx context.Context, tenantID string) (*Tenant, error) {
	tm.mu.RLock()
	defer tm.mu.RUnlock()

	tenant, exists := tm.tenants[tenantID]
	if !exists {
		return nil, fmt.Errorf("tenant not found: %s", tenantID)
	}

	return tenant, nil
}

// UpdateTenant updates an existing tenant
func (tm *TenantManager) UpdateTenant(ctx context.Context, tenantID string, request *UpdateTenantRequest) (*Tenant, error) {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	tenant, exists := tm.tenants[tenantID]
	if !exists {
		return nil, fmt.Errorf("tenant not found: %s", tenantID)
	}

	// Update fields
	if request.Name != "" {
		tenant.Name = request.Name
	}
	if request.Description != "" {
		tenant.Description = request.Description
	}
	if request.Plan != "" {
		tenant.Plan = request.Plan
	}
	if request.Quotas != nil {
		tenant.Quotas = tm.mergeQuotas(request.Quotas)
	}
	if request.Settings != nil {
		tenant.Settings = request.Settings
	}
	if request.Status != "" {
		tenant.Status = request.Status
	}

	tenant.UpdatedAt = time.Now()

	// Audit log
	tm.auditLogger.LogTenantUpdate(ctx, tenant, request)

	return tenant, nil
}

// DeleteTenant deletes a tenant
func (tm *TenantManager) DeleteTenant(ctx context.Context, tenantID string) error {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	tenant, exists := tm.tenants[tenantID]
	if !exists {
		return fmt.Errorf("tenant not found: %s", tenantID)
	}

	// Clean up tenant resources
	if err := tm.cleanupTenantResources(ctx, tenant); err != nil {
		return fmt.Errorf("failed to cleanup tenant resources: %w", err)
	}

	// Remove from map
	delete(tm.tenants, tenantID)

	// Update metrics
	tm.metrics.DecrementTenantCount()
	tm.metrics.RecordTenantDeletion(tenantID)

	// Audit log
	tm.auditLogger.LogTenantDeletion(ctx, tenant)

	return nil
}

// ListTenants lists all tenants with optional filtering
func (tm *TenantManager) ListTenants(ctx context.Context, filter *TenantFilter) ([]*Tenant, error) {
	tm.mu.RLock()
	defer tm.mu.RUnlock()

	var result []*Tenant
	for _, tenant := range tm.tenants {
		if filter == nil || tm.matchesFilter(tenant, filter) {
			result = append(result, tenant)
		}
	}

	return result, nil
}

// GetTenantUsage returns usage statistics for a tenant
func (tm *TenantManager) GetTenantUsage(ctx context.Context, tenantID string) (*TenantUsage, error) {
	tenant, err := tm.GetTenant(ctx, tenantID)
	if err != nil {
		return nil, err
	}

	return tm.resources.GetTenantUsage(ctx, tenant)
}

// EnforceTenantQuotas enforces quotas for a tenant operation
func (tm *TenantManager) EnforceTenantQuotas(ctx context.Context, tenantID string, operation *QuotaOperation) error {
	tenant, err := tm.GetTenant(ctx, tenantID)
	if err != nil {
		return err
	}

	return tm.resources.EnforceQuotas(ctx, tenant, operation)
}

// GetTenantMetrics returns metrics for all tenants
func (tm *TenantManager) GetTenantMetrics(ctx context.Context) (*TenantMetricsSnapshot, error) {
	return tm.metrics.GetSnapshot(), nil
}

// Helper methods

func (tm *TenantManager) validateCreateRequest(request *CreateTenantRequest) error {
	if request.ID == "" {
		return fmt.Errorf("tenant ID is required")
	}
	if request.Name == "" {
		return fmt.Errorf("tenant name is required")
	}
	if request.Owner == "" {
		return fmt.Errorf("tenant owner is required")
	}
	if request.Plan == "" {
		request.Plan = "basic"
	}
	return nil
}

func (tm *TenantManager) mergeQuotas(requestQuotas *TenantQuotas) *TenantQuotas {
	quotas := tm.config.DefaultQuotas
	if requestQuotas != nil {
		if requestQuotas.MaxRepositories > 0 {
			quotas.MaxRepositories = requestQuotas.MaxRepositories
		}
		if requestQuotas.MaxScansPerDay > 0 {
			quotas.MaxScansPerDay = requestQuotas.MaxScansPerDay
		}
		if requestQuotas.MaxUsers > 0 {
			quotas.MaxUsers = requestQuotas.MaxUsers
		}
		if requestQuotas.MaxStorageGB > 0 {
			quotas.MaxStorageGB = requestQuotas.MaxStorageGB
		}
		if requestQuotas.MaxAPICallsPerHour > 0 {
			quotas.MaxAPICallsPerHour = requestQuotas.MaxAPICallsPerHour
		}
	}
	return quotas
}

func (tm *TenantManager) initializeTenantResources(ctx context.Context, tenant *Tenant) error {
	// Initialize database schema/namespace
	if err := tm.isolation.InitializeTenantIsolation(ctx, tenant); err != nil {
		return fmt.Errorf("failed to initialize isolation: %w", err)
	}

	// Initialize resource pools
	if err := tm.resources.InitializeTenantResources(ctx, tenant); err != nil {
		return fmt.Errorf("failed to initialize resources: %w", err)
	}

	return nil
}

func (tm *TenantManager) cleanupTenantResources(ctx context.Context, tenant *Tenant) error {
	// Cleanup isolation
	if err := tm.isolation.CleanupTenantIsolation(ctx, tenant); err != nil {
		return fmt.Errorf("failed to cleanup isolation: %w", err)
	}

	// Cleanup resources
	if err := tm.resources.CleanupTenantResources(ctx, tenant); err != nil {
		return fmt.Errorf("failed to cleanup resources: %w", err)
	}

	return nil
}

func (tm *TenantManager) matchesFilter(tenant *Tenant, filter *TenantFilter) bool {
	if filter.Status != "" && tenant.Status != filter.Status {
		return false
	}
	if filter.Plan != "" && tenant.Plan != filter.Plan {
		return false
	}
	if filter.Owner != "" && tenant.Owner != filter.Owner {
		return false
	}
	return true
}

func getDefaultQuotas() *TenantQuotas {
	return &TenantQuotas{
		MaxRepositories:    100,
		MaxScansPerDay:     1000,
		MaxUsers:           50,
		MaxStorageGB:       10,
		MaxAPICallsPerHour: 10000,
		MaxPolicies:        20,
		MaxIntegrations:    10,
		MaxRetentionDays:   90,
	}
}

// TenantContext provides tenant-aware context
type TenantContext struct {
	context.Context
	TenantID string
	Tenant   *Tenant
}

// NewTenantContext creates a new tenant context
func NewTenantContext(ctx context.Context, tenantID string, tenant *Tenant) *TenantContext {
	return &TenantContext{
		Context:  ctx,
		TenantID: tenantID,
		Tenant:   tenant,
	}
}

// GetTenantID returns the tenant ID from context
func GetTenantID(ctx context.Context) (string, bool) {
	if tc, ok := ctx.(*TenantContext); ok {
		return tc.TenantID, true
	}
	return "", false
}

// GetTenant returns the tenant from context
func GetTenant(ctx context.Context) (*Tenant, bool) {
	if tc, ok := ctx.(*TenantContext); ok {
		return tc.Tenant, true
	}
	return nil, false
}

// TenantMiddleware provides tenant isolation middleware
type TenantMiddleware struct {
	manager *TenantManager
}

// NewTenantMiddleware creates a new tenant middleware
func NewTenantMiddleware(manager *TenantManager) *TenantMiddleware {
	return &TenantMiddleware{
		manager: manager,
	}
}

// WithTenant wraps a function with tenant context
func (tm *TenantMiddleware) WithTenant(tenantID string, fn func(context.Context) error) func(context.Context) error {
	return func(ctx context.Context) error {
		tenant, err := tm.manager.GetTenant(ctx, tenantID)
		if err != nil {
			return err
		}

		tenantCtx := NewTenantContext(ctx, tenantID, tenant)
		return fn(tenantCtx)
	}
}
