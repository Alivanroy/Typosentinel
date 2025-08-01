package orchestrator

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/Alivanroy/Typosentinel/internal/config"
	"github.com/Alivanroy/Typosentinel/internal/repository"
	"github.com/robfig/cron/v3"
)

// EnhancedScanScheduler provides advanced scheduling capabilities for repository scanning
type EnhancedScanScheduler struct {
	scheduler       *ScanScheduler
	discoveryService *repository.DiscoveryService
	repoManager     repository.RepositoryManager
	config          *config.RepositoryConfig
	cron            *cron.Cron
	mu              sync.RWMutex
	running         bool
	stopChan        chan struct{}
	logger          *log.Logger

	// Enhanced features
	policyEngine    PolicyEngine
	notificationMgr NotificationManager
	metrics         MetricsCollector
	auditLogger     AuditLogger
}

// PolicyEngine interface for policy-based scanning
type PolicyEngine interface {
	EvaluateRepository(repo *repository.Repository) (*ScanPolicy, error)
	GetDefaultPolicy() *ScanPolicy
	ValidatePolicy(policy *ScanPolicy) error
}

// NotificationManager interface for sending notifications
type NotificationManager interface {
	SendScanStarted(scan *ScheduledScan) error
	SendScanCompleted(scan *ScheduledScan, result *repository.ScanResult) error
	SendScanFailed(scan *ScheduledScan, err error) error
	SendDiscoveryCompleted(results []repository.DiscoveryResult) error
}

// MetricsCollector interface for collecting metrics
type MetricsCollector interface {
	RecordScanDuration(platform string, duration time.Duration)
	RecordScanResult(platform string, success bool)
	RecordRepositoriesDiscovered(platform string, count int)
	RecordPolicyViolations(platform string, count int)
	IncrementScanCounter(platform string, scanType string)
}

// AuditLogger interface for audit logging
type AuditLogger interface {
	LogScanScheduled(scan *ScheduledScan, user string) error
	LogScanStarted(scan *ScheduledScan) error
	LogScanCompleted(scan *ScheduledScan, result *repository.ScanResult) error
	LogPolicyViolation(repo *repository.Repository, policy *ScanPolicy, violation string) error
	LogDiscoveryEvent(platform string, repoCount int, duration time.Duration) error
}

// ScanPolicy represents a scanning policy
type ScanPolicy struct {
	ID                string                 `json:"id"`
	Name              string                 `json:"name"`
	Description       string                 `json:"description"`
	Enabled           bool                   `json:"enabled"`
	Priority          int                    `json:"priority"`
	Schedule          string                 `json:"schedule"`
	Targets           []ScanTarget           `json:"targets"`
	ScanOptions       repository.ScanOptions `json:"scan_options"`
	OutputFormats     []string               `json:"output_formats"`
	Notifications     []NotificationConfig   `json:"notifications"`
	RetryPolicy       RetryPolicy            `json:"retry_policy"`
	Timeout           time.Duration          `json:"timeout"`
	Concurrency       int                    `json:"concurrency"`
	Filters           []RepositoryFilter     `json:"filters"`
	Metadata          map[string]interface{} `json:"metadata"`
	CreatedAt         time.Time              `json:"created_at"`
	UpdatedAt         time.Time              `json:"updated_at"`
	CreatedBy         string                 `json:"created_by"`
}

// NotificationConfig represents notification configuration
type NotificationConfig struct {
	Type      string                 `json:"type"`      // email, slack, webhook, etc.
	Target    string                 `json:"target"`    // email address, webhook URL, etc.
	Events    []string               `json:"events"`    // scan_started, scan_completed, scan_failed, etc.
	Template  string                 `json:"template"`  // notification template
	Enabled   bool                   `json:"enabled"`
	Metadata  map[string]interface{} `json:"metadata"`
}

// RetryPolicy represents retry configuration
type RetryPolicy struct {
	MaxRetries    int           `json:"max_retries"`
	RetryInterval time.Duration `json:"retry_interval"`
	BackoffFactor float64       `json:"backoff_factor"`
	MaxInterval   time.Duration `json:"max_interval"`
}

// RepositoryFilter represents repository filtering criteria
type RepositoryFilter struct {
	Languages    []string `json:"languages,omitempty"`
	MinStars     int      `json:"min_stars,omitempty"`
	MaxStars     int      `json:"max_stars,omitempty"`
	MinSize      int64    `json:"min_size,omitempty"`
	MaxSize      int64    `json:"max_size,omitempty"`
	IncludeForks bool     `json:"include_forks"`
	IncludePrivate bool   `json:"include_private"`
	IncludeArchived bool  `json:"include_archived"`
	NamePatterns []string `json:"name_patterns,omitempty"`
	ExcludePatterns []string `json:"exclude_patterns,omitempty"`
	LastUpdatedAfter *time.Time `json:"last_updated_after,omitempty"`
	LastUpdatedBefore *time.Time `json:"last_updated_before,omitempty"`
}

// EnhancedScanResult extends ScanResult with additional metadata
type EnhancedScanResult struct {
	*repository.ScanResult
	PolicyViolations []PolicyViolation     `json:"policy_violations"`
	Metrics          ScanMetrics           `json:"metrics"`
	AuditTrail       []AuditEvent          `json:"audit_trail"`
	Metadata         map[string]interface{} `json:"metadata"`
}

// PolicyViolation represents a policy violation
type PolicyViolation struct {
	PolicyID    string    `json:"policy_id"`
	RuleID      string    `json:"rule_id"`
	Severity    string    `json:"severity"`
	Message     string    `json:"message"`
	Repository  string    `json:"repository"`
	File        string    `json:"file,omitempty"`
	Line        int       `json:"line,omitempty"`
	Timestamp   time.Time `json:"timestamp"`
}

// ScanMetrics represents scan performance metrics
type ScanMetrics struct {
	StartTime         time.Time     `json:"start_time"`
	EndTime           time.Time     `json:"end_time"`
	Duration          time.Duration `json:"duration"`
	RepositoriesScanned int         `json:"repositories_scanned"`
	FilesScanned      int           `json:"files_scanned"`
	PackagesAnalyzed  int           `json:"packages_analyzed"`
	VulnerabilitiesFound int        `json:"vulnerabilities_found"`
	PolicyViolations  int           `json:"policy_violations"`
	ErrorCount        int           `json:"error_count"`
	WarningCount      int           `json:"warning_count"`
	CPUUsage          float64       `json:"cpu_usage"`
	MemoryUsage       int64         `json:"memory_usage"`
}

// AuditEvent represents an audit event
type AuditEvent struct {
	ID        string                 `json:"id"`
	Timestamp time.Time              `json:"timestamp"`
	Event     string                 `json:"event"`
	User      string                 `json:"user"`
	Resource  string                 `json:"resource"`
	Action    string                 `json:"action"`
	Result    string                 `json:"result"`
	Metadata  map[string]interface{} `json:"metadata"`
}

// NewEnhancedScanScheduler creates a new enhanced scan scheduler
func NewEnhancedScanScheduler(
	scheduler *ScanScheduler,
	discoveryService *repository.DiscoveryService,
	repoManager repository.RepositoryManager,
	config *config.RepositoryConfig,
) *EnhancedScanScheduler {
	return &EnhancedScanScheduler{
		scheduler:        scheduler,
		discoveryService: discoveryService,
		repoManager:      repoManager,
		config:           config,
		cron:             cron.New(cron.WithSeconds()),
		stopChan:         make(chan struct{}),
		logger:           log.New(log.Writer(), "[EnhancedScheduler] ", log.LstdFlags),
	}
}

// SetPolicyEngine sets the policy engine
func (es *EnhancedScanScheduler) SetPolicyEngine(engine PolicyEngine) {
	es.policyEngine = engine
}

// SetNotificationManager sets the notification manager
func (es *EnhancedScanScheduler) SetNotificationManager(mgr NotificationManager) {
	es.notificationMgr = mgr
}

// SetMetricsCollector sets the metrics collector
func (es *EnhancedScanScheduler) SetMetricsCollector(collector MetricsCollector) {
	es.metrics = collector
}

// SetAuditLogger sets the audit logger
func (es *EnhancedScanScheduler) SetAuditLogger(logger AuditLogger) {
	es.auditLogger = logger
}

// Start starts the enhanced scan scheduler
func (es *EnhancedScanScheduler) Start(ctx context.Context) error {
	es.mu.Lock()
	defer es.mu.Unlock()

	if es.running {
		return fmt.Errorf("enhanced scheduler is already running")
	}

	// Start the underlying scheduler
	if err := es.scheduler.Start(ctx); err != nil {
		return fmt.Errorf("failed to start underlying scheduler: %w", err)
	}

	// Start discovery service if configured
	if es.config.Discovery.Enabled {
		if err := es.discoveryService.Start(ctx); err != nil {
			es.logger.Printf("Failed to start discovery service: %v", err)
		}
	}

	// Schedule discovery-based scans
	if err := es.scheduleDiscoveryScans(ctx); err != nil {
		return fmt.Errorf("failed to schedule discovery scans: %w", err)
	}

	// Start cron scheduler
	es.cron.Start()

	// Start monitoring goroutines
	go es.monitorScans(ctx)
	go es.processDiscoveryResults(ctx)

	es.running = true
	es.logger.Println("Enhanced scan scheduler started")

	return nil
}

// Stop stops the enhanced scan scheduler
func (es *EnhancedScanScheduler) Stop() error {
	es.mu.Lock()
	defer es.mu.Unlock()

	if !es.running {
		return nil
	}

	// Stop cron scheduler
	es.cron.Stop()

	// Stop discovery service
	if es.discoveryService != nil {
		es.discoveryService.Stop()
	}

	// Stop underlying scheduler
	if err := es.scheduler.Stop(); err != nil {
		es.logger.Printf("Error stopping underlying scheduler: %v", err)
	}

	// Signal stop to goroutines
	close(es.stopChan)

	es.running = false
	es.logger.Println("Enhanced scan scheduler stopped")

	return nil
}

// SchedulePolicyBasedScan schedules a scan based on a policy
func (es *EnhancedScanScheduler) SchedulePolicyBasedScan(ctx context.Context, policy *ScanPolicy) error {
	if es.policyEngine == nil {
		return fmt.Errorf("policy engine not configured")
	}

	// Validate policy
	if err := es.policyEngine.ValidatePolicy(policy); err != nil {
		return fmt.Errorf("invalid policy: %w", err)
	}

	// Convert policy to scheduled scan
	scan := es.policyToScheduledScan(policy)

	// Schedule the scan
	if err := es.scheduler.AddSchedule(scan); err != nil {
		return fmt.Errorf("failed to create scheduled scan: %w", err)
	}

	// Add to cron if it has a schedule
	if policy.Schedule != "" {
		_, err := es.cron.AddFunc(policy.Schedule, func() {
			es.executePolicyBasedScan(ctx, policy)
		})
		if err != nil {
			return fmt.Errorf("failed to add cron job: %w", err)
		}
	}

	// Log audit event
	if es.auditLogger != nil {
		es.auditLogger.LogScanScheduled(scan, "system")
	}

	return nil
}

// DiscoverAndSchedule discovers repositories and schedules scans based on policies
func (es *EnhancedScanScheduler) DiscoverAndSchedule(ctx context.Context, platforms []string) error {
	if es.discoveryService == nil {
		return fmt.Errorf("discovery service not configured")
	}

	// Perform discovery
	results, err := es.discoveryService.DiscoverOnce(ctx)
	if err != nil {
		return fmt.Errorf("discovery failed: %w", err)
	}

	// Process discovery results
	for _, result := range results {
		// Check if there were any errors in discovery
		if len(result.Errors) > 0 {
			es.logger.Printf("Discovery errors for platform %s: %v", result.Platform, result.Errors)
			// Continue processing even with errors
		}

		// Schedule scans for discovered repositories
		for _, repo := range result.Repositories {
			if err := es.scheduleRepositoryScan(ctx, *repo); err != nil {
				es.logger.Printf("Failed to schedule scan for repository %s: %v", repo.FullName, err)
			}
		}

		// Record metrics
		if es.metrics != nil {
			es.metrics.RecordRepositoriesDiscovered(result.Platform, len(result.Repositories))
		}

		// Log audit event
		if es.auditLogger != nil {
			es.auditLogger.LogDiscoveryEvent(result.Platform, len(result.Repositories), result.Duration)
		}
	}

	// Send notification
	if es.notificationMgr != nil {
		var discoveryResults []repository.DiscoveryResult
		for _, result := range results {
			discoveryResults = append(discoveryResults, result)
		}
		es.notificationMgr.SendDiscoveryCompleted(discoveryResults)
	}

	return nil
}

// GetScheduledScansWithPolicies returns scheduled scans with their associated policies
func (es *EnhancedScanScheduler) GetScheduledScansWithPolicies() ([]*ScheduledScanWithPolicy, error) {
	scans := es.scheduler.ListSchedules()

	var result []*ScheduledScanWithPolicy
	for _, scan := range scans {
		policy := es.getScanPolicy(scan)
		result = append(result, &ScheduledScanWithPolicy{
			ScheduledScan: scan,
			Policy:        policy,
		})
	}

	return result, nil
}

// ScheduledScanWithPolicy combines a scheduled scan with its policy
type ScheduledScanWithPolicy struct {
	*ScheduledScan
	Policy *ScanPolicy `json:"policy"`
}

// scheduleDiscoveryScans schedules scans based on discovery configuration
func (es *EnhancedScanScheduler) scheduleDiscoveryScans(ctx context.Context) error {
	if !es.config.Discovery.Enabled {
		return nil
	}

	// Schedule periodic discovery
	_, err := es.cron.AddFunc("@every "+es.config.Discovery.Interval.String(), func() {
		platforms := es.config.GetEnabledPlatforms()
		if err := es.DiscoverAndSchedule(ctx, platforms); err != nil {
			es.logger.Printf("Scheduled discovery failed: %v", err)
		}
	})

	return err
}

// scheduleRepositoryScan schedules a scan for a specific repository
func (es *EnhancedScanScheduler) scheduleRepositoryScan(ctx context.Context, repo repository.Repository) error {
	// Get policy for repository
	var policy *ScanPolicy
	if es.policyEngine != nil {
		p, err := es.policyEngine.EvaluateRepository(&repo)
		if err != nil {
			es.logger.Printf("Failed to evaluate policy for repository %s: %v", repo.FullName, err)
			policy = es.policyEngine.GetDefaultPolicy()
		} else {
			policy = p
		}
	} else {
		// Use default policy
		policy = es.getDefaultScanPolicy()
	}

	if !policy.Enabled {
		return nil // Skip disabled policies
	}

	// Create scheduled scan
	scan := &ScheduledScan{
		ID:          fmt.Sprintf("auto-%s-%d", repo.FullName, time.Now().Unix()),
		Name:        fmt.Sprintf("Auto scan for %s", repo.FullName),
		Description: fmt.Sprintf("Automatically scheduled scan for repository %s", repo.FullName),
		Schedule:    policy.Schedule,
		Targets: []ScanTarget{{
			Type:         "repository",
			Repositories: []string{repo.FullName},
		}},
		Options:    policy.ScanOptions,
		Output:     []OutputConfig{{Format: "json"}},
		Policies:   []PolicyConfig{{Name: policy.ID, Enabled: true}},
		Enabled:    true,
		CreatedAt:  time.Now(),
		UpdatedAt:  time.Now(),
	}

	return es.scheduler.AddSchedule(scan)
}

// executePolicyBasedScan executes a scan based on a policy
func (es *EnhancedScanScheduler) executePolicyBasedScan(ctx context.Context, policy *ScanPolicy) {
	start := time.Now()

	// Create scan from policy
	scan := es.policyToScheduledScan(policy)

	// Log scan started
	if es.auditLogger != nil {
		es.auditLogger.LogScanStarted(scan)
	}

	// Send notification
	if es.notificationMgr != nil {
		es.notificationMgr.SendScanStarted(scan)
	}

	// Execute scan
	scanErr := es.scheduler.TriggerSchedule(scan.ID)
	if scanErr != nil {
		es.logger.Printf("Failed to execute policy-based scan %s: %v", policy.ID, scanErr)
		
		// Send failure notification
		if es.notificationMgr != nil {
			es.notificationMgr.SendScanFailed(scan, scanErr)
		}
		return
	}

	// Create a mock result for now (in real implementation, this would come from the scan)
	result := &repository.ScanResult{
		ScanID:    scan.ID,
		StartTime: start,
		EndTime:   time.Now(),
		Status:    "completed",
	}

	// Record metrics
	if es.metrics != nil {
		duration := time.Since(start)
		es.metrics.RecordScanDuration("policy", duration)
		es.metrics.RecordScanResult("policy", scanErr == nil)
		es.metrics.IncrementScanCounter("policy", "scheduled")
	}

	// Log completion
	if es.auditLogger != nil {
		es.auditLogger.LogScanCompleted(scan, result)
	}

	// Send completion notification
	if es.notificationMgr != nil {
		es.notificationMgr.SendScanCompleted(scan, result)
	}
}

// policyToScheduledScan converts a policy to a scheduled scan
func (es *EnhancedScanScheduler) policyToScheduledScan(policy *ScanPolicy) *ScheduledScan {
	return &ScheduledScan{
		ID:          policy.ID,
		Name:        policy.Name,
		Description: policy.Description,
		Schedule:    policy.Schedule,
		Targets:     policy.Targets,
		Options:     policy.ScanOptions,
		Output:      []OutputConfig{{Format: "json"}},
		Policies:    []PolicyConfig{{Name: policy.ID, Enabled: true}},
		Enabled:     policy.Enabled,
		CreatedAt:   policy.CreatedAt,
		UpdatedAt:   policy.UpdatedAt,
	}
}

// getScanPolicy retrieves the policy for a scheduled scan
func (es *EnhancedScanScheduler) getScanPolicy(scan *ScheduledScan) *ScanPolicy {
	// This would typically look up the policy from a policy store
	// For now, return a default policy
	return es.getDefaultScanPolicy()
}

// getDefaultScanPolicy returns a default scan policy
func (es *EnhancedScanScheduler) getDefaultScanPolicy() *ScanPolicy {
	return &ScanPolicy{
		ID:          "default",
		Name:        "Default Scan Policy",
		Description: "Default policy for repository scanning",
		Enabled:     true,
		Priority:    1,
		Schedule:    "0 2 * * *", // Daily at 2 AM
		ScanOptions: repository.ScanOptions{
			DeepScan:    true,
			IncludeDev:  false,
			Timeout:     30 * time.Minute,
		},
		OutputFormats: []string{"json", "sarif"},
		Timeout:       30 * time.Minute,
		Concurrency:   2,
		RetryPolicy: RetryPolicy{
			MaxRetries:    3,
			RetryInterval: 5 * time.Minute,
			BackoffFactor: 2.0,
			MaxInterval:   30 * time.Minute,
		},
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
}

// monitorScans monitors running scans and handles timeouts
func (es *EnhancedScanScheduler) monitorScans(ctx context.Context) {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-es.stopChan:
			return
		case <-ticker.C:
			es.checkScanTimeouts()
		}
	}
}

// processDiscoveryResults processes discovery results in the background
func (es *EnhancedScanScheduler) processDiscoveryResults(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-es.stopChan:
			return
		case <-ticker.C:
			// Process any pending discovery results
			es.processPendingDiscoveryResults(ctx)
		}
	}
}

// checkScanTimeouts checks for and handles scan timeouts
func (es *EnhancedScanScheduler) checkScanTimeouts() {
	// Implementation would check for running scans that have exceeded their timeout
	// and take appropriate action (cancel, retry, etc.)
}

// processPendingDiscoveryResults processes any pending discovery results
func (es *EnhancedScanScheduler) processPendingDiscoveryResults(ctx context.Context) {
	// Implementation would process discovery results that haven't been
	// converted to scheduled scans yet
}

// GetEnhancedStats returns enhanced statistics about the scheduler
func (es *EnhancedScanScheduler) GetEnhancedStats() map[string]interface{} {
	es.mu.RLock()
	defer es.mu.RUnlock()

	stats := map[string]interface{}{
		"running":              es.running,
		"discovery_enabled":    es.config.Discovery.Enabled,
		"policy_engine_enabled": es.policyEngine != nil,
		"notifications_enabled": es.notificationMgr != nil,
		"metrics_enabled":      es.metrics != nil,
		"audit_enabled":        es.auditLogger != nil,
	}

	// Add discovery stats if available
	if es.discoveryService != nil {
		stats["discovery_stats"] = es.discoveryService.GetDiscoveryStats()
	}

	// Add scheduler stats
	if schedulerStats := es.scheduler.GetMetrics(); schedulerStats != nil {
		stats["scheduler_stats"] = schedulerStats
	}

	return stats
}