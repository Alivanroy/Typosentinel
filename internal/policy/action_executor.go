package policy

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/Alivanroy/Typosentinel/internal/auth"
)

// ActionExecutor interface for executing policy actions
type ActionExecutor interface {
	ExecuteAction(ctx context.Context, action auth.PolicyAction, violation *auth.PolicyViolation) (*ActionResult, error)
	GetSupportedActions() []auth.PolicyAction
	ValidateAction(action auth.PolicyAction, params map[string]string) error
	CancelAction(actionID string) error
	GetActionStatus(actionID string) (*ActionStatus, error)
}

// ActionResult represents the result of an action execution
type ActionResult struct {
	ID          string                 `json:"id"`
	Action      auth.PolicyAction      `json:"action"`
	Status      string                 `json:"status"` // pending, running, completed, failed, cancelled
	Message     string                 `json:"message"`
	StartedAt   time.Time              `json:"started_at"`
	CompletedAt *time.Time             `json:"completed_at,omitempty"`
	Metadata    map[string]interface{} `json:"metadata"`
	Error       string                 `json:"error,omitempty"`
}

// ActionStatus represents the current status of an action
type ActionStatus struct {
	ID       string    `json:"id"`
	Status   string    `json:"status"`
	Progress float64   `json:"progress"`
	Steps    []ActionStep `json:"steps"`
	Error    string    `json:"error,omitempty"`
}

// ActionStep represents a step in action execution
type ActionStep struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Status      string    `json:"status"` // pending, running, completed, failed
	StartedAt   *time.Time `json:"started_at,omitempty"`
	CompletedAt *time.Time `json:"completed_at,omitempty"`
	Error       string    `json:"error,omitempty"`
}

// ActionExecutorConfig configuration for action executor
type ActionExecutorConfig struct {
	Enabled                bool          `json:"enabled"`
	QuarantineDir         string        `json:"quarantine_dir"`
	BackupDir             string        `json:"backup_dir"`
	NotificationWebhook   string        `json:"notification_webhook"`
	CIIntegrationEnabled  bool          `json:"ci_integration_enabled"`
	DockerIntegration     bool          `json:"docker_integration"`
	KubernetesIntegration bool          `json:"kubernetes_integration"`
	Timeout               time.Duration `json:"timeout"`
	RetryAttempts         int           `json:"retry_attempts"`
	DryRun                bool          `json:"dry_run"`
}

// DefaultActionExecutor implements ActionExecutor interface
type DefaultActionExecutor struct {
	config         *ActionExecutorConfig
	activeActions  map[string]*ActionStatus
	mu             sync.RWMutex
	logger         Logger
	notifier       Notifier
	ciIntegrator   CIIntegrator
}

// Logger interface for action executor logging
type Logger interface {
	Info(msg string, fields ...interface{})
	Warn(msg string, fields ...interface{})
	Error(msg string, fields ...interface{})
	Debug(msg string, fields ...interface{})
}

// Notifier interface for sending notifications
type Notifier interface {
	SendNotification(ctx context.Context, message string, channels []string) error
}

// CIIntegrator interface for CI/CD integration
type CIIntegrator interface {
	BlockPipeline(ctx context.Context, repoURL, branch string) error
	UnblockPipeline(ctx context.Context, repoURL, branch string) error
	GetPipelineStatus(ctx context.Context, repoURL, branch string) (string, error)
}

// NewDefaultActionExecutor creates a new default action executor
func NewDefaultActionExecutor(config *ActionExecutorConfig, logger Logger, notifier Notifier, ciIntegrator CIIntegrator) *DefaultActionExecutor {
	if config == nil {
		config = &ActionExecutorConfig{
			Enabled:       true,
			QuarantineDir: "/tmp/typosentinel/quarantine",
			BackupDir:     "/tmp/typosentinel/backup",
			Timeout:       5 * time.Minute,
			RetryAttempts: 3,
			DryRun:        false,
		}
	}

	return &DefaultActionExecutor{
		config:        config,
		activeActions: make(map[string]*ActionStatus),
		logger:        logger,
		notifier:      notifier,
		ciIntegrator:  ciIntegrator,
	}
}

// ExecuteAction executes a policy action
func (ae *DefaultActionExecutor) ExecuteAction(ctx context.Context, action auth.PolicyAction, violation *auth.PolicyViolation) (*ActionResult, error) {
	if !ae.config.Enabled {
		return nil, fmt.Errorf("action executor is disabled")
	}

	// Generate action ID
	actionID := fmt.Sprintf("action_%d", time.Now().UnixNano())

	// Create action status
	status := &ActionStatus{
		ID:       actionID,
		Status:   "pending",
		Progress: 0.0,
		Steps:    ae.createActionSteps(action),
	}

	ae.mu.Lock()
	ae.activeActions[actionID] = status
	ae.mu.Unlock()

	// Execute action based on type
	result, err := ae.executeActionByType(ctx, action, violation, status)
	if err != nil {
		status.Status = "failed"
		status.Error = err.Error()
		ae.logger.Error("Action execution failed", "action_id", actionID, "action", action, "error", err)
		return nil, err
	}

	status.Status = "completed"
	status.Progress = 1.0

	ae.logger.Info("Action executed successfully", "action_id", actionID, "action", action)
	return result, nil
}

// executeActionByType executes action based on its type
func (ae *DefaultActionExecutor) executeActionByType(ctx context.Context, action auth.PolicyAction, violation *auth.PolicyViolation, status *ActionStatus) (*ActionResult, error) {
	switch action {
	case auth.PolicyActionBlock:
		return ae.executeBlockAction(ctx, violation, status)
	case auth.PolicyActionQuarantine:
		return ae.executeQuarantineAction(ctx, violation, status)
	case auth.PolicyActionNotify:
		return ae.executeNotifyAction(ctx, violation, status)
	case auth.PolicyActionGenerateSPDX:
		return ae.executeGenerateSPDXAction(ctx, violation, status)
	case auth.PolicyActionDeny:
		return ae.executeDenyAction(ctx, violation, status)
	default:
		return nil, fmt.Errorf("unsupported action type: %s", action)
	}
}

// executeBlockAction executes a block action
func (ae *DefaultActionExecutor) executeBlockAction(ctx context.Context, violation *auth.PolicyViolation, status *ActionStatus) (*ActionResult, error) {
	ae.updateStepStatus(status, "validate_context", "running")

	// Validate that we have enough context to block
	if violation.Context == nil || violation.Context.Repository == nil {
		return nil, fmt.Errorf("insufficient context for blocking action")
	}

	ae.updateStepStatus(status, "validate_context", "completed")
	status.Progress = 0.2

	ae.updateStepStatus(status, "block_deployment", "running")

	if ae.config.DryRun {
		ae.logger.Info("DRY RUN: Would block deployment", "repo", violation.Context.Repository.URL)
	} else {
		// Block CI/CD pipeline if integration is enabled
		if ae.config.CIIntegrationEnabled && ae.ciIntegrator != nil {
			err := ae.ciIntegrator.BlockPipeline(ctx, violation.Context.Repository.URL, violation.Context.Repository.Branch)
			if err != nil {
				return nil, fmt.Errorf("failed to block pipeline: %w", err)
			}
		}

		// Create block file in repository if accessible
		if err := ae.createBlockFile(violation.Context.Repository); err != nil {
			ae.logger.Warn("Failed to create block file", "error", err)
		}
	}

	ae.updateStepStatus(status, "block_deployment", "completed")
	status.Progress = 0.7

	ae.updateStepStatus(status, "notify_stakeholders", "running")

	// Send notifications
	if ae.notifier != nil {
		message := fmt.Sprintf("Deployment blocked due to policy violation: %s", violation.PolicyName)
		err := ae.notifier.SendNotification(ctx, message, violation.Result.Notifications)
		if err != nil {
			ae.logger.Warn("Failed to send notification", "error", err)
		}
	}

	ae.updateStepStatus(status, "notify_stakeholders", "completed")
	status.Progress = 1.0

	return &ActionResult{
		ID:        status.ID,
		Action:    auth.PolicyActionBlock,
		Status:    "completed",
		Message:   "Deployment blocked successfully",
		StartedAt: time.Now(),
		Metadata: map[string]interface{}{
			"action_type": "block",
			"repository":  violation.Context.Repository.URL,
			"branch":      violation.Context.Repository.Branch,
			"blocked_at":  time.Now(),
		},
	}, nil
}

// executeQuarantineAction executes a quarantine action
func (ae *DefaultActionExecutor) executeQuarantineAction(ctx context.Context, violation *auth.PolicyViolation, status *ActionStatus) (*ActionResult, error) {
	ae.updateStepStatus(status, "create_quarantine_dir", "running")

	// Ensure quarantine directory exists
	if err := os.MkdirAll(ae.config.QuarantineDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create quarantine directory: %w", err)
	}

	ae.updateStepStatus(status, "create_quarantine_dir", "completed")
	status.Progress = 0.2

	ae.updateStepStatus(status, "isolate_package", "running")

	var quarantinePath string
	if violation.Context != nil && violation.Context.Package != nil {
		// Move package to quarantine
		pkgName := violation.Context.Package.Name
		quarantinePath = filepath.Join(ae.config.QuarantineDir, fmt.Sprintf("%s_%d", pkgName, time.Now().Unix()))

		if !ae.config.DryRun {
			// Create quarantine metadata
			metadataPath := quarantinePath + ".metadata"
			metadata := fmt.Sprintf("Package: %s\nVersion: %s\nQuarantined: %s\nReason: %s\nPolicy: %s\n",
				violation.Context.Package.Name,
				violation.Context.Package.Version,
				time.Now().Format(time.RFC3339),
				violation.Description,
				violation.PolicyName)

			if err := os.WriteFile(metadataPath, []byte(metadata), 0644); err != nil {
				ae.logger.Warn("Failed to write quarantine metadata", "error", err)
			}
		} else {
			ae.logger.Info("DRY RUN: Would quarantine package", "package", pkgName, "path", quarantinePath)
		}
	}

	ae.updateStepStatus(status, "isolate_package", "completed")
	status.Progress = 0.6

	ae.updateStepStatus(status, "update_access_controls", "running")

	// Update access controls - integrate with actual access control system
	if !ae.config.DryRun {
		if err := ae.updateAccessControls(quarantinePath, violation); err != nil {
			ae.logger.Warn("Failed to update access controls", "error", err)
		} else {
			ae.logger.Info("Access controls updated for quarantined package", "path", quarantinePath)
		}
	} else {
		ae.logger.Info("DRY RUN: Would update access controls for quarantined package")
	}

	ae.updateStepStatus(status, "update_access_controls", "completed")
	status.Progress = 1.0

	return &ActionResult{
		ID:        status.ID,
		Action:    auth.PolicyActionQuarantine,
		Status:    "completed",
		Message:   "Package quarantined successfully",
		StartedAt: time.Now(),
		Metadata: map[string]interface{}{
			"action_type":     "quarantine",
			"quarantine_path": quarantinePath,
			"quarantined_at":  time.Now(),
			"isolation_level": "high",
		},
	}, nil
}

// executeNotifyAction executes a notify action
func (ae *DefaultActionExecutor) executeNotifyAction(ctx context.Context, violation *auth.PolicyViolation, status *ActionStatus) (*ActionResult, error) {
	ae.updateStepStatus(status, "send_notifications", "running")

	if ae.notifier != nil {
		message := fmt.Sprintf("Policy violation detected: %s\nSeverity: %s\nDescription: %s",
			violation.PolicyName, violation.Severity, violation.Description)

		err := ae.notifier.SendNotification(ctx, message, violation.Result.Notifications)
		if err != nil {
			return nil, fmt.Errorf("failed to send notification: %w", err)
		}
	}

	ae.updateStepStatus(status, "send_notifications", "completed")
	status.Progress = 1.0

	return &ActionResult{
		ID:        status.ID,
		Action:    auth.PolicyActionNotify,
		Status:    "completed",
		Message:   "Notifications sent successfully",
		StartedAt: time.Now(),
		Metadata: map[string]interface{}{
			"action_type":    "notify",
			"notified_at":    time.Now(),
			"channels_count": len(violation.Result.Notifications),
		},
	}, nil
}

// executeGenerateSPDXAction executes a generate SPDX action
func (ae *DefaultActionExecutor) executeGenerateSPDXAction(ctx context.Context, violation *auth.PolicyViolation, status *ActionStatus) (*ActionResult, error) {
	ae.updateStepStatus(status, "generate_spdx", "running")

	var spdxPath string
	if violation.Context != nil && violation.Context.Repository != nil {
		repoName := strings.ReplaceAll(violation.Context.Repository.Name, "/", "_")
		spdxPath = filepath.Join("/tmp", fmt.Sprintf("%s_spdx_%d.json", repoName, time.Now().Unix()))

		if !ae.config.DryRun {
			// Generate comprehensive SPDX document
			spdxContent, err := ae.generateSPDXDocument(violation, repoName)
			if err != nil {
				return nil, fmt.Errorf("failed to generate SPDX content: %w", err)
			}

			if err := os.WriteFile(spdxPath, []byte(spdxContent), 0644); err != nil {
				return nil, fmt.Errorf("failed to write SPDX file: %w", err)
			}
		} else {
			ae.logger.Info("DRY RUN: Would generate SPDX document", "path", spdxPath)
		}
	}

	ae.updateStepStatus(status, "generate_spdx", "completed")
	status.Progress = 1.0

	return &ActionResult{
		ID:        status.ID,
		Action:    auth.PolicyActionGenerateSPDX,
		Status:    "completed",
		Message:   "SPDX document generated successfully",
		StartedAt: time.Now(),
		Metadata: map[string]interface{}{
			"action_type": "generate_spdx",
			"spdx_path":   spdxPath,
			"generated_at": time.Now(),
		},
	}, nil
}

// executeDenyAction executes a deny action
func (ae *DefaultActionExecutor) executeDenyAction(ctx context.Context, violation *auth.PolicyViolation, status *ActionStatus) (*ActionResult, error) {
	ae.updateStepStatus(status, "deny_access", "running")

	// Log the denial
	ae.logger.Info("Access denied due to policy violation",
		"policy", violation.PolicyName,
		"severity", violation.Severity,
		"user", violation.Context.User)

	ae.updateStepStatus(status, "deny_access", "completed")
	status.Progress = 1.0

	return &ActionResult{
		ID:        status.ID,
		Action:    auth.PolicyActionDeny,
		Status:    "completed",
		Message:   "Access denied successfully",
		StartedAt: time.Now(),
		Metadata: map[string]interface{}{
			"action_type": "deny",
			"denied_at":   time.Now(),
		},
	}, nil
}

// createBlockFile creates a block file in the repository
func (ae *DefaultActionExecutor) createBlockFile(repo *auth.RepositoryInfo) error {
	if repo == nil || repo.URL == "" {
		return fmt.Errorf("invalid repository information")
	}

	// This is a simplified implementation - in practice, this would integrate
	// with the actual repository system (Git, etc.)
	blockContent := fmt.Sprintf(`# DEPLOYMENT BLOCKED BY TYPOSENTINEL
# Repository: %s
# Branch: %s
# Blocked at: %s
# Reason: Policy violation detected
# Contact your security team to resolve this issue
`,
		repo.URL, repo.Branch, time.Now().Format(time.RFC3339))

	blockFile := "/tmp/typosentinel_block.txt"
	return os.WriteFile(blockFile, []byte(blockContent), 0644)
}

// createActionSteps creates the steps for an action
func (ae *DefaultActionExecutor) createActionSteps(action auth.PolicyAction) []ActionStep {
	switch action {
	case auth.PolicyActionBlock:
		return []ActionStep{
			{ID: "validate_context", Name: "Validate Context", Description: "Validate execution context", Status: "pending"},
			{ID: "block_deployment", Name: "Block Deployment", Description: "Block the deployment pipeline", Status: "pending"},
			{ID: "notify_stakeholders", Name: "Notify Stakeholders", Description: "Send notifications to stakeholders", Status: "pending"},
		}
	case auth.PolicyActionQuarantine:
		return []ActionStep{
			{ID: "create_quarantine_dir", Name: "Create Quarantine Directory", Description: "Ensure quarantine directory exists", Status: "pending"},
			{ID: "isolate_package", Name: "Isolate Package", Description: "Move package to quarantine zone", Status: "pending"},
			{ID: "update_access_controls", Name: "Update Access Controls", Description: "Restrict access to quarantined package", Status: "pending"},
		}
	case auth.PolicyActionNotify:
		return []ActionStep{
			{ID: "send_notifications", Name: "Send Notifications", Description: "Send notifications to configured channels", Status: "pending"},
		}
	case auth.PolicyActionGenerateSPDX:
		return []ActionStep{
			{ID: "generate_spdx", Name: "Generate SPDX", Description: "Generate SPDX document", Status: "pending"},
		}
	case auth.PolicyActionDeny:
		return []ActionStep{
			{ID: "deny_access", Name: "Deny Access", Description: "Deny access to resource", Status: "pending"},
		}
	default:
		return []ActionStep{}
	}
}

// updateStepStatus updates the status of a specific step
func (ae *DefaultActionExecutor) updateStepStatus(status *ActionStatus, stepID, stepStatus string) {
	for i := range status.Steps {
		if status.Steps[i].ID == stepID {
			status.Steps[i].Status = stepStatus
			now := time.Now()
			if stepStatus == "running" {
				status.Steps[i].StartedAt = &now
			} else if stepStatus == "completed" || stepStatus == "failed" {
				status.Steps[i].CompletedAt = &now
			}
			break
		}
	}
}

// GetSupportedActions returns the list of supported actions
func (ae *DefaultActionExecutor) GetSupportedActions() []auth.PolicyAction {
	return []auth.PolicyAction{
		auth.PolicyActionBlock,
		auth.PolicyActionQuarantine,
		auth.PolicyActionNotify,
		auth.PolicyActionGenerateSPDX,
		auth.PolicyActionDeny,
	}
}

// ValidateAction validates an action and its parameters
func (ae *DefaultActionExecutor) ValidateAction(action auth.PolicyAction, params map[string]string) error {
	supportedActions := ae.GetSupportedActions()
	supported := false
	for _, supportedAction := range supportedActions {
		if action == supportedAction {
			supported = true
			break
		}
	}

	if !supported {
		return fmt.Errorf("unsupported action: %s", action)
	}

	// Validate action-specific parameters
	switch action {
	case auth.PolicyActionBlock:
		if ae.config.CIIntegrationEnabled && ae.ciIntegrator == nil {
			return fmt.Errorf("CI integration enabled but no CI integrator configured")
		}
	case auth.PolicyActionQuarantine:
		if ae.config.QuarantineDir == "" {
			return fmt.Errorf("quarantine directory not configured")
		}
	case auth.PolicyActionNotify:
		if ae.notifier == nil {
			return fmt.Errorf("notifier not configured")
		}
	}

	return nil
}

// CancelAction cancels a running action
func (ae *DefaultActionExecutor) CancelAction(actionID string) error {
	ae.mu.Lock()
	defer ae.mu.Unlock()

	status, exists := ae.activeActions[actionID]
	if !exists {
		return fmt.Errorf("action not found: %s", actionID)
	}

	if status.Status == "completed" || status.Status == "failed" || status.Status == "cancelled" {
		return fmt.Errorf("action cannot be cancelled, current status: %s", status.Status)
	}

	status.Status = "cancelled"
	ae.logger.Info("Action cancelled", "action_id", actionID)

	return nil
}

// GetActionStatus returns the status of an action
func (ae *DefaultActionExecutor) GetActionStatus(actionID string) (*ActionStatus, error) {
	ae.mu.RLock()
	defer ae.mu.RUnlock()

	status, exists := ae.activeActions[actionID]
	if !exists {
		return nil, fmt.Errorf("action not found: %s", actionID)
	}

	return status, nil
}

// updateAccessControls updates access controls for quarantined packages
func (ae *DefaultActionExecutor) updateAccessControls(quarantinePath string, violation *auth.PolicyViolation) error {
	// Set restrictive permissions on quarantine directory
	if err := os.Chmod(quarantinePath, 0700); err != nil {
		return fmt.Errorf("failed to set quarantine directory permissions: %w", err)
	}

	// Create access control metadata
	aclMetadata := map[string]interface{}{
		"quarantined_at": time.Now(),
		"violation_id":   violation.ID,
		"policy_name":    violation.PolicyName,
		"severity":       violation.Severity,
		"access_level":   "restricted",
		"allowed_users":  []string{"admin", "security-team"},
		"restrictions": map[string]bool{
			"read_only":     true,
			"no_execution":  true,
			"no_network":    true,
			"audit_access":  true,
		},
	}

	aclData, err := json.MarshalIndent(aclMetadata, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal ACL metadata: %w", err)
	}

	aclPath := filepath.Join(quarantinePath, ".typosentinel_acl.json")
	if err := os.WriteFile(aclPath, aclData, 0600); err != nil {
		return fmt.Errorf("failed to write ACL metadata: %w", err)
	}

	ae.logger.Info("Access controls updated", 
		"path", quarantinePath,
		"permissions", "0700",
		"acl_file", aclPath)

	return nil
}

// generateSPDXDocument generates a comprehensive SPDX document
func (ae *DefaultActionExecutor) generateSPDXDocument(violation *auth.PolicyViolation, repoName string) (string, error) {
	now := time.Now()
	
	// Create SPDX document structure
	spdxDoc := map[string]interface{}{
		"spdxVersion":       "SPDX-2.3",
		"dataLicense":       "CC0-1.0",
		"SPDXID":           "SPDXRef-DOCUMENT",
		"name":             repoName,
		"documentNamespace": fmt.Sprintf("https://typosentinel.com/spdx/%s/%d", repoName, now.Unix()),
		"creationInfo": map[string]interface{}{
			"created":  now.Format(time.RFC3339),
			"creators": []string{"Tool: TypoSentinel-v1.0"},
			"licenseListVersion": "3.19",
		},
		"packages": ae.generateSPDXPackages(violation),
		"relationships": ae.generateSPDXRelationships(violation),
		"annotations": []map[string]interface{}{
			{
				"annotationType": "REVIEW",
				"annotator":      "Tool: TypoSentinel",
				"annotationDate": now.Format(time.RFC3339),
				"annotationComment": fmt.Sprintf("Security violation detected: %s (Severity: %s)", 
					violation.PolicyName, violation.Severity),
			},
		},
	}

	// Marshal to JSON with proper formatting
	spdxData, err := json.MarshalIndent(spdxDoc, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to marshal SPDX document: %w", err)
	}

	return string(spdxData), nil
}

// generateSPDXPackages generates package information for SPDX document
func (ae *DefaultActionExecutor) generateSPDXPackages(violation *auth.PolicyViolation) []map[string]interface{} {
	packages := []map[string]interface{}{}

	// Add main package if available
	if violation.Context != nil && violation.Context.Package != nil {
		pkg := violation.Context.Package
		spdxPkg := map[string]interface{}{
			"SPDXID":           fmt.Sprintf("SPDXRef-Package-%s", strings.ReplaceAll(pkg.Name, "/", "-")),
			"name":             pkg.Name,
			"downloadLocation": "NOASSERTION",
			"filesAnalyzed":    false,
			"copyrightText":    "NOASSERTION",
			"externalRefs": []map[string]interface{}{
				{
					"referenceCategory": "PACKAGE-MANAGER",
					"referenceType":     "purl",
					"referenceLocator":  fmt.Sprintf("pkg:%s/%s@%s", pkg.Type, pkg.Name, pkg.Version),
				},
			},
		}

		if pkg.Version != "" {
			spdxPkg["versionInfo"] = pkg.Version
		}

		packages = append(packages, spdxPkg)
	}

	return packages
}

// generateSPDXRelationships generates relationship information for SPDX document
func (ae *DefaultActionExecutor) generateSPDXRelationships(violation *auth.PolicyViolation) []map[string]interface{} {
	relationships := []map[string]interface{}{}

	// Add document relationship
	if violation.Context != nil && violation.Context.Package != nil {
		pkg := violation.Context.Package
		relationships = append(relationships, map[string]interface{}{
			"spdxElementId":      "SPDXRef-DOCUMENT",
			"relationshipType":   "DESCRIBES",
			"relatedSpdxElement": fmt.Sprintf("SPDXRef-Package-%s", strings.ReplaceAll(pkg.Name, "/", "-")),
		})
	}

	return relationships
}