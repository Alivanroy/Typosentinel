package webhook

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/Alivanroy/Typosentinel/pkg/logger"
	"github.com/Alivanroy/Typosentinel/pkg/types"
)

// ScanTriggerImpl implements the ScanTrigger interface
type ScanTriggerImpl struct {
	logger    logger.Logger
	scanner   Scanner
	scans     map[string]*ScanStatus
	scansMux  sync.RWMutex
	config    *ScanTriggerConfig
}

// ScanTriggerConfig configuration for scan trigger
type ScanTriggerConfig struct {
	MaxConcurrentScans int           `json:"max_concurrent_scans"`
	DefaultTimeout     time.Duration `json:"default_timeout"`
	QueueSize          int           `json:"queue_size"`
	RetryAttempts      int           `json:"retry_attempts"`
	RetryDelay         time.Duration `json:"retry_delay"`
}

// Scanner interface for performing scans
type Scanner interface {
	Scan(ctx context.Context, request *ScanRequest) (*types.ScanResult, error)
	ValidateRequest(request *ScanRequest) error
}

// DefaultScanner implements the Scanner interface
type DefaultScanner struct {
	logger logger.Logger
}

// NewScanTriggerImpl creates a new scan trigger implementation
func NewScanTriggerImpl(logger logger.Logger, scanner Scanner, config *ScanTriggerConfig) *ScanTriggerImpl {
	if config == nil {
		config = &ScanTriggerConfig{
			MaxConcurrentScans: 10,
			DefaultTimeout:     30 * time.Minute,
			QueueSize:          100,
			RetryAttempts:      3,
			RetryDelay:         5 * time.Second,
		}
	}

	if scanner == nil {
		scanner = &DefaultScanner{logger: logger}
	}

	return &ScanTriggerImpl{
		logger:  logger,
		scanner: scanner,
		scans:   make(map[string]*ScanStatus),
		config:  config,
	}
}

// TriggerScan triggers a new scan
func (st *ScanTriggerImpl) TriggerScan(ctx context.Context, request *ScanRequest) (*ScanResponse, error) {
	// Validate request
	if err := st.scanner.ValidateRequest(request); err != nil {
		return nil, fmt.Errorf("invalid scan request: %w", err)
	}

	// Check concurrent scan limit
	st.scansMux.RLock()
	runningScans := 0
	for _, scan := range st.scans {
		if scan.Status == "running" || scan.Status == "queued" {
			runningScans++
		}
	}
	st.scansMux.RUnlock()

	if runningScans >= st.config.MaxConcurrentScans {
		return nil, fmt.Errorf("maximum concurrent scans reached (%d)", st.config.MaxConcurrentScans)
	}

	// Create scan status
	scanStatus := &ScanStatus{
		ScanID:    request.ID,
		Status:    "queued",
		Progress:  0.0,
		StartedAt: time.Now(),
		Metadata:  make(map[string]interface{}),
	}

	// Store scan status
	st.scansMux.Lock()
	st.scans[request.ID] = scanStatus
	st.scansMux.Unlock()

	// Start scan in goroutine
	go st.executeScan(ctx, request, scanStatus)

	// Return response
	response := &ScanResponse{
		ScanID:    request.ID,
		Status:    "queued",
		Message:   "Scan queued successfully",
		StartedAt: time.Now(),
		ETA:       st.estimateETA(request),
		Callback:  request.Callback,
	}

	st.logger.Info("Scan triggered", map[string]interface{}{
		"scan_id":    request.ID,
		"repository": request.Repository,
		"branch":     request.Branch,
		"provider":   request.Provider,
	})

	return response, nil
}

// GetScanStatus returns the status of a scan
func (st *ScanTriggerImpl) GetScanStatus(ctx context.Context, scanID string) (*ScanStatus, error) {
	st.scansMux.RLock()
	scanStatus, exists := st.scans[scanID]
	st.scansMux.RUnlock()

	if !exists {
		return nil, fmt.Errorf("scan not found: %s", scanID)
	}

	// Return a copy to avoid race conditions
	statusCopy := *scanStatus
	return &statusCopy, nil
}

// executeScan executes a scan in a separate goroutine
func (st *ScanTriggerImpl) executeScan(ctx context.Context, request *ScanRequest, status *ScanStatus) {
	defer func() {
		if r := recover(); r != nil {
			st.logger.Error("Scan execution panicked", map[string]interface{}{
				"scan_id": request.ID,
				"panic":   r,
			})
			st.updateScanStatus(status, "failed", 0.0, fmt.Sprintf("Scan panicked: %v", r), nil)
		}
	}()

	// Set timeout
	timeout := request.Timeout
	if timeout == 0 {
		timeout = st.config.DefaultTimeout
	}

	scanCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// Update status to running
	st.updateScanStatus(status, "running", 0.0, "Scan started", nil)

	st.logger.Info("Starting scan execution", map[string]interface{}{
		"scan_id":    request.ID,
		"repository": request.Repository,
		"branch":     request.Branch,
	})

	// Execute scan with retry logic
	var result *types.ScanResult
	var err error

	for attempt := 0; attempt <= st.config.RetryAttempts; attempt++ {
		if attempt > 0 {
			st.logger.Info("Retrying scan", map[string]interface{}{
				"scan_id": request.ID,
				"attempt": attempt,
			})
			time.Sleep(st.config.RetryDelay)
		}

		// Update progress
		progress := float64(attempt) / float64(st.config.RetryAttempts+1) * 50.0 // First 50% for attempts
		st.updateScanStatus(status, "running", progress, fmt.Sprintf("Scan attempt %d", attempt+1), nil)

		result, err = st.scanner.Scan(scanCtx, request)
		if err == nil {
			break
		}

		st.logger.Warn("Scan attempt failed", map[string]interface{}{
			"scan_id": request.ID,
			"attempt": attempt,
			"error":   err.Error(),
		})
	}

	if err != nil {
		st.logger.Error("Scan failed after all attempts", map[string]interface{}{
			"scan_id": request.ID,
			"error":   err.Error(),
		})
		st.updateScanStatus(status, "failed", 0.0, err.Error(), nil)
		return
	}

	// Update progress to 100%
	st.updateScanStatus(status, "processing", 90.0, "Processing results", nil)

	// Process results
	processedResult := st.processResults(result, request)

	// Complete scan
	now := time.Now()
	st.updateScanStatus(status, "completed", 100.0, "Scan completed successfully", processedResult)
	status.CompletedAt = &now

	st.logger.Info("Scan completed", map[string]interface{}{
		"scan_id":       request.ID,
		"duration":      time.Since(status.StartedAt),
		"threats_found": len(processedResult.Packages),
	})

	// Send callback if configured
	if request.Callback != "" {
		go st.sendCallback(request.Callback, status)
	}
}

// updateScanStatus updates the scan status
func (st *ScanTriggerImpl) updateScanStatus(status *ScanStatus, newStatus string, progress float64, message string, result *types.ScanResult) {
	st.scansMux.Lock()
	defer st.scansMux.Unlock()

	status.Status = newStatus
	status.Progress = progress
	status.Results = result

	if message != "" {
		if status.Metadata == nil {
			status.Metadata = make(map[string]interface{})
		}
		status.Metadata["last_message"] = message
		status.Metadata["updated_at"] = time.Now()
	}

	if newStatus == "failed" {
		status.Error = message
	}
}

// processResults processes scan results
func (st *ScanTriggerImpl) processResults(result *types.ScanResult, request *ScanRequest) *types.ScanResult {
	// Add metadata from request
	if result.Metadata == nil {
		result.Metadata = make(map[string]interface{})
	}

	result.Metadata["webhook_trigger"] = map[string]interface{}{
		"provider":   request.Provider,
		"event":      request.Event,
		"trigger":    request.Trigger,
		"repository": request.Repository,
		"branch":     request.Branch,
		"commit":     request.Commit,
		"paths":      request.Paths,
	}

	// Add scan timing
	result.Metadata["scan_timing"] = map[string]interface{}{
		"triggered_at": time.Now(),
		"scan_id":      request.ID,
	}

	return result
}

// estimateETA estimates the completion time for a scan
func (st *ScanTriggerImpl) estimateETA(request *ScanRequest) string {
	// Simple estimation based on repository size and complexity
	baseTime := 5 * time.Minute

	// Adjust based on paths
	if len(request.Paths) > 100 {
		baseTime += 10 * time.Minute
	} else if len(request.Paths) > 10 {
		baseTime += 2 * time.Minute
	}

	// Add current queue time
	st.scansMux.RLock()
	queuedScans := 0
	for _, scan := range st.scans {
		if scan.Status == "queued" {
			queuedScans++
		}
	}
	st.scansMux.RUnlock()

	queueTime := time.Duration(queuedScans) * baseTime / time.Duration(st.config.MaxConcurrentScans)
	totalTime := baseTime + queueTime

	return time.Now().Add(totalTime).Format(time.RFC3339)
}

// sendCallback sends a callback notification
func (st *ScanTriggerImpl) sendCallback(callbackURL string, status *ScanStatus) {
	st.logger.Info("Sending scan callback", map[string]interface{}{
		"scan_id":      status.ScanID,
		"callback_url": callbackURL,
		"status":       status.Status,
	})

	// This would implement HTTP callback to the provided URL
	// For now, just log the callback
	st.logger.Debug("Callback would be sent", map[string]interface{}{
		"url":    callbackURL,
		"status": status,
	})
}

// CleanupCompletedScans removes old completed scans from memory
func (st *ScanTriggerImpl) CleanupCompletedScans(maxAge time.Duration) {
	st.scansMux.Lock()
	defer st.scansMux.Unlock()

	cutoff := time.Now().Add(-maxAge)
	cleaned := 0

	for scanID, scan := range st.scans {
		if (scan.Status == "completed" || scan.Status == "failed") && scan.StartedAt.Before(cutoff) {
			delete(st.scans, scanID)
			cleaned++
		}
	}

	if cleaned > 0 {
		st.logger.Info("Cleaned up completed scans", map[string]interface{}{
			"cleaned_count": cleaned,
			"max_age":       maxAge,
		})
	}
}

// GetScanStatistics returns scan statistics
func (st *ScanTriggerImpl) GetScanStatistics() map[string]interface{} {
	st.scansMux.RLock()
	defer st.scansMux.RUnlock()

	stats := map[string]interface{}{
		"total_scans":     len(st.scans),
		"running_scans":   0,
		"queued_scans":    0,
		"completed_scans": 0,
		"failed_scans":    0,
	}

	for _, scan := range st.scans {
		switch scan.Status {
		case "running":
			stats["running_scans"] = stats["running_scans"].(int) + 1
		case "queued":
			stats["queued_scans"] = stats["queued_scans"].(int) + 1
		case "completed":
			stats["completed_scans"] = stats["completed_scans"].(int) + 1
		case "failed":
			stats["failed_scans"] = stats["failed_scans"].(int) + 1
		}
	}

	return stats
}

// DefaultScanner implementation

// Scan performs a security scan
func (ds *DefaultScanner) Scan(ctx context.Context, request *ScanRequest) (*types.ScanResult, error) {
	ds.logger.Info("Performing security scan", map[string]interface{}{
		"scan_id":    request.ID,
		"repository": request.Repository,
		"branch":     request.Branch,
	})

	// Simulate scan execution
	time.Sleep(2 * time.Second)

	// Create mock scan result
	result := &types.ScanResult{
		Target:    request.Repository,
		CreatedAt: time.Now(),
		Packages:  []*types.Package{},
		Metadata: map[string]interface{}{
			"scan_type": "webhook_triggered",
			"branch":    request.Branch,
			"commit":    request.Commit,
			"paths":     request.Paths,
		},
	}

	// Add some mock packages if paths are provided
	for i := range request.Paths {
		if i >= 5 { // Limit to 5 packages for demo
			break
		}

		pkg := &types.Package{
			Name:       fmt.Sprintf("package-%d", i+1),
			Version:    "1.0.0",
			Registry:   "npm",
			Threats:    []types.Threat{},
			AnalyzedAt: time.Now(),
		}

		// Add mock threat for demonstration
		if i%2 == 0 {
			threat := types.Threat{
				Type:        types.ThreatTypeTyposquatting,
				Severity:    types.SeverityMedium,
				Description: fmt.Sprintf("Potential typosquatting detected in %s", pkg.Name),
				Evidence:    []types.Evidence{{Type: "similarity", Value: "0.85", Description: "Package name similarity"}},
				DetectedAt:  time.Now(),
				Package:     pkg.Name,
				Registry:    pkg.Registry,
			}
			pkg.Threats = append(pkg.Threats, threat)
		}

		result.Packages = append(result.Packages, pkg)
	}

	ds.logger.Info("Scan completed", map[string]interface{}{
		"scan_id":        request.ID,
		"packages_found": len(result.Packages),
		"threats_found":  ds.countThreats(result.Packages),
	})

	return result, nil
}

// ValidateRequest validates a scan request
func (ds *DefaultScanner) ValidateRequest(request *ScanRequest) error {
	if request.ID == "" {
		return fmt.Errorf("scan ID is required")
	}

	if request.Repository == "" {
		return fmt.Errorf("repository is required")
	}

	if request.Branch == "" {
		request.Branch = "main" // Default branch
	}

	if request.Trigger == "" {
		request.Trigger = "webhook"
	}

	if request.Provider == "" {
		request.Provider = "generic"
	}

	if request.Priority == "" {
		request.Priority = "normal"
	}

	return nil
}

// countThreats counts total threats in packages
func (ds *DefaultScanner) countThreats(packages []*types.Package) int {
	count := 0
	for _, pkg := range packages {
		count += len(pkg.Threats)
	}
	return count
}