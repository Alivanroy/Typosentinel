package orchestrator

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/Alivanroy/Typosentinel/internal/repository"
	"github.com/google/uuid"
)

// ScanCoordinator manages multi-repository scanning operations
type ScanCoordinator struct {
	queue           JobQueue
	workerPool      *WorkerPool
	rateLimiter     *RateLimitedExecutor
	repoManager     *repository.Manager
	discoveryService *repository.DiscoveryService
	config          *CoordinatorConfig
	ctx             context.Context
	cancel          context.CancelFunc
	wg              sync.WaitGroup
	mu              sync.RWMutex
	activeScans     map[string]*ScanOperation
	metrics         *CoordinatorMetrics
}

// CoordinatorConfig contains configuration for the scan coordinator
type CoordinatorConfig struct {
	MaxConcurrentScans    int           `json:"max_concurrent_scans"`
	ScanTimeout           time.Duration `json:"scan_timeout"`
	BatchSize             int           `json:"batch_size"`
	RetryAttempts         int           `json:"retry_attempts"`
	RetryDelay            time.Duration `json:"retry_delay"`
	ProgressUpdateInterval time.Duration `json:"progress_update_interval"`
	CleanupInterval       time.Duration `json:"cleanup_interval"`
	MaxScanHistory        int           `json:"max_scan_history"`
	EnableMetrics         bool          `json:"enable_metrics"`
	EnableProgressTracking bool         `json:"enable_progress_tracking"`
}

// DefaultCoordinatorConfig returns default configuration
func DefaultCoordinatorConfig() *CoordinatorConfig {
	return &CoordinatorConfig{
		MaxConcurrentScans:     10,
		ScanTimeout:            2 * time.Hour,
		BatchSize:              50,
		RetryAttempts:          3,
		RetryDelay:             30 * time.Second,
		ProgressUpdateInterval: 30 * time.Second,
		CleanupInterval:        1 * time.Hour,
		MaxScanHistory:         100,
		EnableMetrics:          true,
		EnableProgressTracking: true,
	}
}

// ScanOperation represents an ongoing scan operation
type ScanOperation struct {
	ID               string                 `json:"id"`
	Type             string                 `json:"type"`
	Platform         string                 `json:"platform"`
	Target           string                 `json:"target"`
	Status           ScanStatus             `json:"status"`
	StartedAt        time.Time              `json:"started_at"`
	CompletedAt      *time.Time             `json:"completed_at,omitempty"`
	Progress         *ScanProgress          `json:"progress,omitempty"`
	Options          map[string]interface{} `json:"options"`
	Results          *ScanResults           `json:"results,omitempty"`
	Error            string                 `json:"error,omitempty"`
	JobIDs           []string               `json:"job_ids"`
	Metadata         map[string]interface{} `json:"metadata"`
	
	// Internal fields
	ctx              context.Context
	cancel           context.CancelFunc
	mu               sync.RWMutex
	completedJobs    int
	totalJobs        int
	lastUpdate       time.Time
}

// ScanStatus represents the status of a scan operation
type ScanStatus string

const (
	ScanStatusPending    ScanStatus = "pending"
	ScanStatusRunning    ScanStatus = "running"
	ScanStatusCompleted  ScanStatus = "completed"
	ScanStatusFailed     ScanStatus = "failed"
	ScanStatusCancelled  ScanStatus = "cancelled"
	ScanStatusPartial    ScanStatus = "partial"
)

// ScanProgress tracks the progress of a scan operation
type ScanProgress struct {
	TotalRepositories    int       `json:"total_repositories"`
	ScannedRepositories  int       `json:"scanned_repositories"`
	FailedRepositories   int       `json:"failed_repositories"`
	SkippedRepositories  int       `json:"skipped_repositories"`
	PercentageComplete   float64   `json:"percentage_complete"`
	EstimatedCompletion  time.Time `json:"estimated_completion"`
	CurrentRepository    string    `json:"current_repository,omitempty"`
	ThroughputPerMinute  float64   `json:"throughput_per_minute"`
	LastUpdated          time.Time `json:"last_updated"`
}

// ScanResults contains the results of a scan operation
type ScanResults struct {
	TotalRepositories   int                      `json:"total_repositories"`
	ScannedRepositories int                      `json:"scanned_repositories"`
	ThreatsFound        int                      `json:"threats_found"`
	PackagesAnalyzed    int                      `json:"packages_analyzed"`
	ScanDuration        time.Duration            `json:"scan_duration"`
	RepositoryResults   []*RepositoryResult      `json:"repository_results"`
	Summary             *ScanSummary             `json:"summary"`
	Metrics             map[string]interface{}   `json:"metrics"`
}

// RepositoryResult contains results for a single repository
type RepositoryResult struct {
	Repository    *repository.Repository `json:"repository"`
	Status        string                 `json:"status"`
	Threats       []interface{}          `json:"threats"`
	Packages      []interface{}          `json:"packages"`
	ScanDuration  time.Duration          `json:"scan_duration"`
	Error         string                 `json:"error,omitempty"`
	Metadata      map[string]interface{} `json:"metadata"`
}

// ScanSummary provides a high-level summary of scan results
type ScanSummary struct {
	HighRiskThreats    int     `json:"high_risk_threats"`
	MediumRiskThreats  int     `json:"medium_risk_threats"`
	LowRiskThreats     int     `json:"low_risk_threats"`
	MostCommonThreats  []string `json:"most_common_threats"`
	TopRiskyPackages   []string `json:"top_risky_packages"`
	Recommendations    []string `json:"recommendations"`
}

// CoordinatorMetrics contains metrics for the coordinator
type CoordinatorMetrics struct {
	TotalScans          int64         `json:"total_scans"`
	ActiveScans         int           `json:"active_scans"`
	CompletedScans      int64         `json:"completed_scans"`
	FailedScans         int64         `json:"failed_scans"`
	CancelledScans      int64         `json:"cancelled_scans"`
	AverageScanDuration time.Duration `json:"average_scan_duration"`
	TotalRepositories   int64         `json:"total_repositories"`
	TotalThreats        int64         `json:"total_threats"`
	ThroughputPerHour   float64       `json:"throughput_per_hour"`
	LastUpdated         time.Time     `json:"last_updated"`
}

// NewScanCoordinator creates a new scan coordinator
func NewScanCoordinator(
	queue JobQueue,
	workerPool *WorkerPool,
	rateLimiter *RateLimitedExecutor,
	repoManager *repository.Manager,
	discoveryService *repository.DiscoveryService,
	config *CoordinatorConfig,
) *ScanCoordinator {
	if config == nil {
		config = DefaultCoordinatorConfig()
	}
	
	ctx, cancel := context.WithCancel(context.Background())
	
	return &ScanCoordinator{
		queue:            queue,
		workerPool:       workerPool,
		rateLimiter:      rateLimiter,
		repoManager:      repoManager,
		discoveryService: discoveryService,
		config:           config,
		ctx:              ctx,
		cancel:           cancel,
		activeScans:      make(map[string]*ScanOperation),
		metrics:          &CoordinatorMetrics{},
	}
}

// Start starts the scan coordinator
func (sc *ScanCoordinator) Start() error {
	log.Printf("Starting scan coordinator...")
	
	// Start background tasks
	if sc.config.EnableProgressTracking {
		sc.wg.Add(1)
		go sc.progressTracker()
	}
	
	if sc.config.EnableMetrics {
		sc.wg.Add(1)
		go sc.metricsUpdater()
	}
	
	sc.wg.Add(1)
	go sc.cleanupWorker()
	
	log.Printf("Scan coordinator started successfully")
	return nil
}

// Stop stops the scan coordinator
func (sc *ScanCoordinator) Stop() error {
	log.Printf("Stopping scan coordinator...")
	
	// Cancel all active scans
	sc.mu.Lock()
	for _, scan := range sc.activeScans {
		scan.cancel()
	}
	sc.mu.Unlock()
	
	sc.cancel()
	sc.wg.Wait()
	
	log.Printf("Scan coordinator stopped")
	return nil
}

// StartRepositoryScan starts a scan for a single repository
func (sc *ScanCoordinator) StartRepositoryScan(platform, target string, options map[string]interface{}) (*ScanOperation, error) {
	return sc.startScan("repository", platform, target, options)
}

// StartOrganizationScan starts a scan for all repositories in an organization
func (sc *ScanCoordinator) StartOrganizationScan(platform, organization string, options map[string]interface{}) (*ScanOperation, error) {
	return sc.startScan("organization", platform, organization, options)
}

// StartBulkScan starts a bulk scan for multiple targets
func (sc *ScanCoordinator) StartBulkScan(platform string, targets []string, options map[string]interface{}) (*ScanOperation, error) {
	// Create a bulk scan operation
	bulkOptions := make(map[string]interface{})
	for k, v := range options {
		bulkOptions[k] = v
	}
	bulkOptions["targets"] = targets
	
	return sc.startScan("bulk", platform, "bulk", bulkOptions)
}

// startScan creates and starts a new scan operation
func (sc *ScanCoordinator) startScan(scanType, platform, target string, options map[string]interface{}) (*ScanOperation, error) {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	
	// Check concurrent scan limit
	if len(sc.activeScans) >= sc.config.MaxConcurrentScans {
		return nil, fmt.Errorf("maximum concurrent scans (%d) reached", sc.config.MaxConcurrentScans)
	}
	
	// Create scan operation
	scanID := uuid.New().String()[:8]
	ctx, cancel := context.WithTimeout(sc.ctx, sc.config.ScanTimeout)
	
	scan := &ScanOperation{
		ID:        scanID,
		Type:      scanType,
		Platform:  platform,
		Target:    target,
		Status:    ScanStatusPending,
		StartedAt: time.Now(),
		Options:   options,
		Metadata:  make(map[string]interface{}),
		ctx:       ctx,
		cancel:    cancel,
	}
	
	if sc.config.EnableProgressTracking {
		scan.Progress = &ScanProgress{
			LastUpdated: time.Now(),
		}
	}
	
	sc.activeScans[scanID] = scan
	sc.metrics.TotalScans++
	
	// Start the scan asynchronously
	go sc.executeScan(scan)
	
	log.Printf("Started %s scan %s for %s on %s", scanType, scanID, target, platform)
	return scan, nil
}

// executeScan executes a scan operation
func (sc *ScanCoordinator) executeScan(scan *ScanOperation) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("Scan %s panicked: %v", scan.ID, r)
			sc.updateScanStatus(scan, ScanStatusFailed, fmt.Sprintf("panic: %v", r))
		}
	}()
	
	log.Printf("Executing scan %s (type: %s, platform: %s, target: %s)", 
		scan.ID, scan.Type, scan.Platform, scan.Target)
	
	sc.updateScanStatus(scan, ScanStatusRunning, "")
	
	var err error
	switch scan.Type {
	case "repository":
		err = sc.executeRepositoryScan(scan)
	case "organization":
		err = sc.executeOrganizationScan(scan)
	case "bulk":
		err = sc.executeBulkScan(scan)
	default:
		err = fmt.Errorf("unknown scan type: %s", scan.Type)
	}
	
	if err != nil {
		log.Printf("Scan %s failed: %v", scan.ID, err)
		sc.updateScanStatus(scan, ScanStatusFailed, err.Error())
	} else {
		log.Printf("Scan %s completed successfully", scan.ID)
		sc.updateScanStatus(scan, ScanStatusCompleted, "")
	}
}

// executeRepositoryScan executes a single repository scan
func (sc *ScanCoordinator) executeRepositoryScan(scan *ScanOperation) error {
	// Create scan job
	job := &ScanJob{
		ID:        uuid.New().String(),
		Type:      "repository",
		Platform:  scan.Platform,
		Target:    scan.Target,
		Status:    JobStatusPending,
		CreatedAt: time.Now(),
		Options:   scan.Options,
		Metadata:  map[string]interface{}{"scan_id": scan.ID},
	}
	
	// Enqueue job
	if err := sc.queue.Enqueue(scan.ctx, job); err != nil {
		return fmt.Errorf("failed to enqueue repository scan job: %w", err)
	}
	
	scan.mu.Lock()
	scan.JobIDs = []string{job.ID}
	scan.totalJobs = 1
	if scan.Progress != nil {
		scan.Progress.TotalRepositories = 1
	}
	scan.mu.Unlock()
	
	// Wait for job completion
	return sc.waitForJobs(scan, []string{job.ID})
}

// executeOrganizationScan executes an organization-wide scan
func (sc *ScanCoordinator) executeOrganizationScan(scan *ScanOperation) error {
	// Discover repositories in the organization
	filter := &repository.RepositoryFilter{
		IncludeArchived:   false,
		IncludeForks:      false,
		IncludePrivate:    true,
		HasPackageManager: true,
		MinStars:          0,
		MaxSize:           500 * 1024 * 1024, // 500MB default
	}
	
	if filterOptions, ok := scan.Options["filter"]; ok {
		if filterMap, ok := filterOptions.(map[string]interface{}); ok {
			// Parse include_archived option
			if includeArchived, exists := filterMap["include_archived"]; exists {
				if archived, ok := includeArchived.(bool); ok {
					filter.IncludeArchived = archived
				} else if archivedStr, ok := includeArchived.(string); ok {
					filter.IncludeArchived = archivedStr == "true"
				}
			}
			
			// Parse include_forks option
			if includeForks, exists := filterMap["include_forks"]; exists {
				if forks, ok := includeForks.(bool); ok {
					filter.IncludeForks = forks
				} else if forksStr, ok := includeForks.(string); ok {
					filter.IncludeForks = forksStr == "true"
				}
			}
			
			// Parse include_private option
			if includePrivate, exists := filterMap["include_private"]; exists {
				if private, ok := includePrivate.(bool); ok {
					filter.IncludePrivate = private
				} else if privateStr, ok := includePrivate.(string); ok {
					filter.IncludePrivate = privateStr == "true"
				}
			}
			
			// Parse has_package_manager option
			if hasPackageManager, exists := filterMap["has_package_manager"]; exists {
				if pkgMgr, ok := hasPackageManager.(bool); ok {
					filter.HasPackageManager = pkgMgr
				} else if pkgMgrStr, ok := hasPackageManager.(string); ok {
					filter.HasPackageManager = pkgMgrStr == "true"
				}
			}
			
			// Parse min_stars option
			if minStars, exists := filterMap["min_stars"]; exists {
				if stars, ok := minStars.(int); ok {
					filter.MinStars = stars
				} else if starsFloat, ok := minStars.(float64); ok {
					filter.MinStars = int(starsFloat)
				}
			}
			
			// Parse max_size option (in MB)
			if maxSize, exists := filterMap["max_size"]; exists {
				if size, ok := maxSize.(int); ok {
					filter.MaxSize = int64(size) * 1024 * 1024 // Convert MB to bytes
				} else if sizeFloat, ok := maxSize.(float64); ok {
					filter.MaxSize = int64(sizeFloat) * 1024 * 1024 // Convert MB to bytes
				}
			}
			
			// Parse languages filter
			if languages, exists := filterMap["languages"]; exists {
				if langSlice, ok := languages.([]interface{}); ok {
					filter.Languages = make([]string, 0, len(langSlice))
					for _, lang := range langSlice {
						if langStr, ok := lang.(string); ok {
							filter.Languages = append(filter.Languages, langStr)
						}
					}
				} else if langSlice, ok := languages.([]string); ok {
					filter.Languages = langSlice
				}
			}
			
			// Parse topics filter
			if topics, exists := filterMap["topics"]; exists {
				if topicSlice, ok := topics.([]interface{}); ok {
					filter.Topics = make([]string, 0, len(topicSlice))
					for _, topic := range topicSlice {
						if topicStr, ok := topic.(string); ok {
							filter.Topics = append(filter.Topics, topicStr)
						}
					}
				} else if topicSlice, ok := topics.([]string); ok {
					filter.Topics = topicSlice
				}
			}
			
			// Parse name_pattern filter (single pattern)
			if namePattern, exists := filterMap["name_pattern"]; exists {
				if pattern, ok := namePattern.(string); ok {
					filter.NamePattern = pattern
				}
			}
			
			// Parse exclude_patterns filter
			if excludePatterns, exists := filterMap["exclude_patterns"]; exists {
				if patternSlice, ok := excludePatterns.([]interface{}); ok {
					filter.ExcludePatterns = make([]string, 0, len(patternSlice))
					for _, pattern := range patternSlice {
						if patternStr, ok := pattern.(string); ok {
							filter.ExcludePatterns = append(filter.ExcludePatterns, patternStr)
						}
					}
				} else if patternSlice, ok := excludePatterns.([]string); ok {
					filter.ExcludePatterns = patternSlice
				}
			}
		}
	}
	
	repos, err := sc.discoverRepositories(scan.Platform, scan.Target, filter)
	if err != nil {
		return fmt.Errorf("failed to discover repositories: %w", err)
	}
	
	if len(repos) == 0 {
		return fmt.Errorf("no repositories found for organization: %s", scan.Target)
	}
	
	log.Printf("Discovered %d repositories for organization %s", len(repos), scan.Target)
	
	// Update scan progress
	scan.mu.Lock()
	scan.totalJobs = len(repos)
	if scan.Progress != nil {
		scan.Progress.TotalRepositories = len(repos)
	}
	scan.mu.Unlock()
	
	// Create jobs in batches
	jobIDs := make([]string, 0, len(repos))
	batchSize := sc.config.BatchSize
	
	for i := 0; i < len(repos); i += batchSize {
		end := i + batchSize
		if end > len(repos) {
			end = len(repos)
		}
		
		batch := repos[i:end]
		batchJobIDs, err := sc.createRepositoryJobs(scan, batch)
		if err != nil {
			return fmt.Errorf("failed to create jobs for batch %d-%d: %w", i, end, err)
		}
		
		jobIDs = append(jobIDs, batchJobIDs...)
		
		// Small delay between batches to avoid overwhelming the queue
		if i+batchSize < len(repos) {
			time.Sleep(100 * time.Millisecond)
		}
	}
	
	scan.mu.Lock()
	scan.JobIDs = jobIDs
	scan.mu.Unlock()
	
	// Wait for all jobs to complete
	return sc.waitForJobs(scan, jobIDs)
}

// executeBulkScan executes a bulk scan for multiple targets
func (sc *ScanCoordinator) executeBulkScan(scan *ScanOperation) error {
	targetsInterface, ok := scan.Options["targets"]
	if !ok {
		return fmt.Errorf("no targets specified for bulk scan")
	}
	
	targets, ok := targetsInterface.([]string)
	if !ok {
		return fmt.Errorf("invalid targets format for bulk scan")
	}
	
	if len(targets) == 0 {
		return fmt.Errorf("no targets provided for bulk scan")
	}
	
	log.Printf("Starting bulk scan for %d targets", len(targets))
	
	// Update scan progress
	scan.mu.Lock()
	scan.totalJobs = len(targets)
	if scan.Progress != nil {
		scan.Progress.TotalRepositories = len(targets)
	}
	scan.mu.Unlock()
	
	// Create jobs for each target
	jobIDs := make([]string, 0, len(targets))
	batchSize := sc.config.BatchSize
	
	for i := 0; i < len(targets); i += batchSize {
		end := i + batchSize
		if end > len(targets) {
			end = len(targets)
		}
		
		batch := targets[i:end]
		batchJobIDs, err := sc.createBulkJobs(scan, batch)
		if err != nil {
			return fmt.Errorf("failed to create jobs for batch %d-%d: %w", i, end, err)
		}
		
		jobIDs = append(jobIDs, batchJobIDs...)
		
		// Small delay between batches
		if i+batchSize < len(targets) {
			time.Sleep(100 * time.Millisecond)
		}
	}
	
	scan.mu.Lock()
	scan.JobIDs = jobIDs
	scan.mu.Unlock()
	
	// Wait for all jobs to complete
	return sc.waitForJobs(scan, jobIDs)
}

// discoverRepositories discovers repositories for a given organization
func (sc *ScanCoordinator) discoverRepositories(platform, organization string, filter *repository.RepositoryFilter) ([]*repository.Repository, error) {
	connector, err := sc.repoManager.GetConnector(platform)
	if err != nil {
		return nil, fmt.Errorf("failed to get connector for platform %s: %w", platform, err)
	}
	
	// Use rate limiter for API calls
	var repos []*repository.Repository
	err = sc.rateLimiter.Execute(context.Background(), platform, func() error {
		var execErr error
		repos, execErr = connector.ListRepositories(context.Background(), organization, filter)
		return execErr
	})
	
	if err != nil {
		return nil, fmt.Errorf("failed to list repositories: %w", err)
	}
	
	return repos, nil
}

// createRepositoryJobs creates scan jobs for a batch of repositories
func (sc *ScanCoordinator) createRepositoryJobs(scan *ScanOperation, repos []*repository.Repository) ([]string, error) {
	jobIDs := make([]string, 0, len(repos))
	
	for _, repo := range repos {
		job := &ScanJob{
			ID:        uuid.New().String(),
			Type:      "repository",
			Platform:  scan.Platform,
			Target:    fmt.Sprintf("%s/%s", repo.Owner, repo.Name),
			Status:    JobStatusPending,
			CreatedAt: time.Now(),
			Options:   scan.Options,
			Metadata: map[string]interface{}{
				"scan_id":     scan.ID,
				"repository": repo,
			},
		}
		
		if err := sc.queue.Enqueue(scan.ctx, job); err != nil {
			return nil, fmt.Errorf("failed to enqueue job for repository %s/%s: %w", repo.Owner, repo.Name, err)
		}
		
		jobIDs = append(jobIDs, job.ID)
	}
	
	return jobIDs, nil
}

// createBulkJobs creates scan jobs for a batch of targets
func (sc *ScanCoordinator) createBulkJobs(scan *ScanOperation, targets []string) ([]string, error) {
	jobIDs := make([]string, 0, len(targets))
	
	for _, target := range targets {
		job := &ScanJob{
			ID:        uuid.New().String(),
			Type:      "repository",
			Platform:  scan.Platform,
			Target:    target,
			Status:    JobStatusPending,
			CreatedAt: time.Now(),
			Options:   scan.Options,
			Metadata: map[string]interface{}{
				"scan_id": scan.ID,
				"target":  target,
			},
		}
		
		if err := sc.queue.Enqueue(scan.ctx, job); err != nil {
			return nil, fmt.Errorf("failed to enqueue job for target %s: %w", target, err)
		}
		
		jobIDs = append(jobIDs, job.ID)
	}
	
	return jobIDs, nil
}

// waitForJobs waits for all jobs to complete and collects results
func (sc *ScanCoordinator) waitForJobs(scan *ScanOperation, jobIDs []string) error {
	log.Printf("Waiting for %d jobs to complete for scan %s", len(jobIDs), scan.ID)
	
	completedJobs := make(map[string]*ScanJob)
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	
	for {
		select {
		case <-scan.ctx.Done():
			return scan.ctx.Err()
		case <-ticker.C:
			// Check job statuses
			allCompleted := true
			for _, jobID := range jobIDs {
				if _, completed := completedJobs[jobID]; completed {
					continue
				}
				
				job, err := sc.queue.GetJob(scan.ctx, jobID)
				if err != nil {
					log.Printf("Failed to get job %s status: %v", jobID, err)
					allCompleted = false
					continue
				}
				
				if job.Status == JobStatusCompleted || job.Status == JobStatusFailed {
					completedJobs[jobID] = job
					sc.updateJobProgress(scan)
				} else {
					allCompleted = false
				}
			}
			
			if allCompleted {
				// Collect and process results
				return sc.processJobResults(scan, completedJobs)
			}
		}
	}
}

// updateJobProgress updates scan progress based on completed jobs
func (sc *ScanCoordinator) updateJobProgress(scan *ScanOperation) {
	scan.mu.Lock()
	defer scan.mu.Unlock()
	
	scan.completedJobs++
	scan.lastUpdate = time.Now()
	
	if scan.Progress != nil {
		scan.Progress.ScannedRepositories = scan.completedJobs
		if scan.totalJobs > 0 {
			scan.Progress.PercentageComplete = float64(scan.completedJobs) / float64(scan.totalJobs) * 100
		}
		
		// Calculate throughput
		duration := time.Since(scan.StartedAt)
		if duration > 0 {
			scan.Progress.ThroughputPerMinute = float64(scan.completedJobs) / duration.Minutes()
		}
		
		// Estimate completion time
		if scan.Progress.ThroughputPerMinute > 0 {
			remainingJobs := scan.totalJobs - scan.completedJobs
			remainingMinutes := float64(remainingJobs) / scan.Progress.ThroughputPerMinute
			scan.Progress.EstimatedCompletion = time.Now().Add(time.Duration(remainingMinutes) * time.Minute)
		}
		
		scan.Progress.LastUpdated = time.Now()
	}
}

// processJobResults processes completed job results and generates scan results
func (sc *ScanCoordinator) processJobResults(scan *ScanOperation, completedJobs map[string]*ScanJob) error {
	log.Printf("Processing results for %d completed jobs in scan %s", len(completedJobs), scan.ID)
	
	results := &ScanResults{
		TotalRepositories:   len(completedJobs),
		ScanDuration:        time.Since(scan.StartedAt),
		RepositoryResults:   make([]*RepositoryResult, 0, len(completedJobs)),
		Metrics:             make(map[string]interface{}),
	}
	
	var totalThreats, totalPackages int
	var successfulScans int
	
	for _, job := range completedJobs {
		repoResult := &RepositoryResult{
			Status:       string(job.Status),
			ScanDuration: job.CompletedAt.Sub(job.CreatedAt),
			Metadata:     job.Metadata,
		}
		
		if job.Status == JobStatusCompleted && job.Result != nil {
			successfulScans++
			
			// Extract repository info
			if repoInterface, ok := job.Metadata["repository"]; ok {
				if repo, ok := repoInterface.(*repository.Repository); ok {
					repoResult.Repository = repo
				}
			}
			
			// Extract threats and packages from job result
			if threats, ok := job.Result["threats"]; ok {
				if threatList, ok := threats.([]interface{}); ok {
					repoResult.Threats = threatList
					totalThreats += len(threatList)
				}
			}
			
			if packages, ok := job.Result["packages"]; ok {
				if packageList, ok := packages.([]interface{}); ok {
					repoResult.Packages = packageList
					totalPackages += len(packageList)
				}
			}
		} else if job.Status == JobStatusFailed {
			repoResult.Error = job.Error
			if scan.Progress != nil {
				scan.mu.Lock()
				scan.Progress.FailedRepositories++
				scan.mu.Unlock()
			}
		}
		
		results.RepositoryResults = append(results.RepositoryResults, repoResult)
	}
	
	results.ScannedRepositories = successfulScans
	results.ThreatsFound = totalThreats
	results.PackagesAnalyzed = totalPackages
	
	// Generate summary
	results.Summary = sc.generateScanSummary(results)
	
	// Add metrics
	results.Metrics["success_rate"] = float64(successfulScans) / float64(len(completedJobs))
	results.Metrics["average_scan_time"] = results.ScanDuration.Seconds() / float64(len(completedJobs))
	results.Metrics["threats_per_repository"] = float64(totalThreats) / float64(successfulScans)
	
	// Update scan with results
	scan.mu.Lock()
	scan.Results = results
	completedAt := time.Now()
	scan.CompletedAt = &completedAt
	scan.mu.Unlock()
	
	log.Printf("Scan %s completed: %d repositories, %d threats, %d packages", 
		scan.ID, results.ScannedRepositories, results.ThreatsFound, results.PackagesAnalyzed)
	
	return nil
}

// generateScanSummary generates a summary of scan results
func (sc *ScanCoordinator) generateScanSummary(results *ScanResults) *ScanSummary {
	// Initialize threat counters
	var highRisk, mediumRisk, lowRisk int
	threatTypes := make(map[string]int)
	riskyPackages := make(map[string]int)
	
	// Analyze threats from all repository results
	for _, repoResult := range results.RepositoryResults {
		for _, threat := range repoResult.Threats {
			// Convert threat to map for analysis
			if threatMap, ok := threat.(map[string]interface{}); ok {
				// Categorize by risk level
				if riskLevel, exists := threatMap["risk_level"]; exists {
					switch riskLevel {
					case "high", "critical":
						highRisk++
					case "medium", "moderate":
						mediumRisk++
					case "low", "info":
						lowRisk++
					default:
						// Default to medium risk if unknown
						mediumRisk++
					}
				} else {
					// If no risk level specified, categorize by threat type
					if threatType, exists := threatMap["type"]; exists {
						switch threatType {
						case "typosquatting", "dependency_confusion", "malicious_package":
							highRisk++
						case "suspicious_package", "outdated_dependency", "vulnerability":
							mediumRisk++
						default:
							lowRisk++
						}
					} else {
						// Default categorization
						mediumRisk++
					}
				}
				
				// Count threat types
				if threatType, exists := threatMap["type"]; exists {
					if typeStr, ok := threatType.(string); ok {
						threatTypes[typeStr]++
					}
				}
				
				// Track risky packages
				if packageName, exists := threatMap["package"]; exists {
					if pkgStr, ok := packageName.(string); ok {
						riskyPackages[pkgStr]++
					}
				} else if packageName, exists := threatMap["package_name"]; exists {
					if pkgStr, ok := packageName.(string); ok {
						riskyPackages[pkgStr]++
					}
				}
			}
		}
	}
	
	// Find most common threat types
	mostCommonThreats := make([]string, 0, len(threatTypes))
	for threatType := range threatTypes {
		mostCommonThreats = append(mostCommonThreats, threatType)
	}
	
	// Sort threat types by frequency (simple bubble sort for small datasets)
	for i := 0; i < len(mostCommonThreats)-1; i++ {
		for j := 0; j < len(mostCommonThreats)-i-1; j++ {
			if threatTypes[mostCommonThreats[j]] < threatTypes[mostCommonThreats[j+1]] {
				mostCommonThreats[j], mostCommonThreats[j+1] = mostCommonThreats[j+1], mostCommonThreats[j]
			}
		}
	}
	
	// Limit to top 5 most common threats
	if len(mostCommonThreats) > 5 {
		mostCommonThreats = mostCommonThreats[:5]
	}
	
	// Find top risky packages
	topRiskyPackages := make([]string, 0, len(riskyPackages))
	for packageName := range riskyPackages {
		topRiskyPackages = append(topRiskyPackages, packageName)
	}
	
	// Sort packages by risk frequency
	for i := 0; i < len(topRiskyPackages)-1; i++ {
		for j := 0; j < len(topRiskyPackages)-i-1; j++ {
			if riskyPackages[topRiskyPackages[j]] < riskyPackages[topRiskyPackages[j+1]] {
				topRiskyPackages[j], topRiskyPackages[j+1] = topRiskyPackages[j+1], topRiskyPackages[j]
			}
		}
	}
	
	// Limit to top 10 risky packages
	if len(topRiskyPackages) > 10 {
		topRiskyPackages = topRiskyPackages[:10]
	}
	
	// Generate recommendations based on findings
	recommendations := sc.generateRecommendations(highRisk, mediumRisk, lowRisk, mostCommonThreats, results)
	
	return &ScanSummary{
		HighRiskThreats:   highRisk,
		MediumRiskThreats: mediumRisk,
		LowRiskThreats:    lowRisk,
		MostCommonThreats: mostCommonThreats,
		TopRiskyPackages:  topRiskyPackages,
		Recommendations:   recommendations,
	}
}

// generateRecommendations generates actionable recommendations based on scan results
func (sc *ScanCoordinator) generateRecommendations(highRisk, mediumRisk, lowRisk int, commonThreats []string, results *ScanResults) []string {
	recommendations := make([]string, 0)
	
	// High-risk threat recommendations
	if highRisk > 0 {
		recommendations = append(recommendations, fmt.Sprintf("Immediate action required: %d high-risk threats detected", highRisk))
		recommendations = append(recommendations, "Review and remove suspicious packages immediately")
	}
	
	// Typosquatting-specific recommendations
	for _, threat := range commonThreats {
		switch threat {
		case "typosquatting":
			recommendations = append(recommendations, "Enable typosquatting protection in your package manager")
			recommendations = append(recommendations, "Implement package name verification before installation")
		case "dependency_confusion":
			recommendations = append(recommendations, "Configure private package registry priorities")
			recommendations = append(recommendations, "Use scoped packages where possible")
		case "malicious_package":
			recommendations = append(recommendations, "Implement package integrity verification")
			recommendations = append(recommendations, "Use package signing and verification")
		case "vulnerability":
			recommendations = append(recommendations, "Update vulnerable dependencies to latest secure versions")
			recommendations = append(recommendations, "Enable automated vulnerability scanning in CI/CD")
		case "outdated_dependency":
			recommendations = append(recommendations, "Regularly update dependencies to latest stable versions")
			recommendations = append(recommendations, "Implement dependency update automation")
		}
	}
	
	// General recommendations based on scan scope
	if results.ScannedRepositories > 10 {
		recommendations = append(recommendations, "Consider implementing organization-wide security policies")
		recommendations = append(recommendations, "Set up centralized dependency management")
	}
	
	// Package volume recommendations
	if results.PackagesAnalyzed > 100 {
		recommendations = append(recommendations, "Implement automated dependency scanning in CI/CD pipelines")
		recommendations = append(recommendations, "Consider using dependency lock files for reproducible builds")
	}
	
	// Medium/Low risk recommendations
	if mediumRisk > 0 || lowRisk > 0 {
		recommendations = append(recommendations, "Schedule regular security reviews for medium and low-risk findings")
		recommendations = append(recommendations, "Implement continuous monitoring for dependency changes")
	}
	
	// Default recommendations if no specific threats found
	if len(recommendations) == 0 {
		recommendations = append(recommendations, "Maintain current security practices")
		recommendations = append(recommendations, "Continue regular dependency scanning")
		recommendations = append(recommendations, "Stay updated with security advisories")
	}
	
	// Limit recommendations to avoid overwhelming users
	if len(recommendations) > 8 {
		recommendations = recommendations[:8]
	}
	
	return recommendations
}

// updateScanStatus updates the status of a scan operation
func (sc *ScanCoordinator) updateScanStatus(scan *ScanOperation, status ScanStatus, errorMsg string) {
	scan.mu.Lock()
	defer scan.mu.Unlock()
	
	scan.Status = status
	if errorMsg != "" {
		scan.Error = errorMsg
	}
	
	if status == ScanStatusCompleted || status == ScanStatusFailed || status == ScanStatusCancelled {
		completedAt := time.Now()
		scan.CompletedAt = &completedAt
		
		// Update metrics
		sc.mu.Lock()
		switch status {
		case ScanStatusCompleted:
			sc.metrics.CompletedScans++
		case ScanStatusFailed:
			sc.metrics.FailedScans++
		case ScanStatusCancelled:
			sc.metrics.CancelledScans++
		}
		sc.mu.Unlock()
		
		// Remove from active scans
		go func() {
			time.Sleep(1 * time.Minute) // Keep for a minute for status queries
			sc.mu.Lock()
			delete(sc.activeScans, scan.ID)
			sc.mu.Unlock()
		}()
	}
}

// GetScan returns information about a scan operation
func (sc *ScanCoordinator) GetScan(scanID string) (*ScanOperation, error) {
	sc.mu.RLock()
	defer sc.mu.RUnlock()
	
	scan, exists := sc.activeScans[scanID]
	if !exists {
		return nil, fmt.Errorf("scan %s not found", scanID)
	}
	
	// Return a copy to avoid race conditions
	scan.mu.RLock()
	defer scan.mu.RUnlock()
	
	scanCopy := *scan
	return &scanCopy, nil
}

// ListScans returns a list of all active scans
func (sc *ScanCoordinator) ListScans() []*ScanOperation {
	sc.mu.RLock()
	defer sc.mu.RUnlock()
	
	scans := make([]*ScanOperation, 0, len(sc.activeScans))
	for _, scan := range sc.activeScans {
		scan.mu.RLock()
		scanCopy := *scan
		scan.mu.RUnlock()
		scans = append(scans, &scanCopy)
	}
	
	return scans
}

// CancelScan cancels a running scan
func (sc *ScanCoordinator) CancelScan(scanID string) error {
	sc.mu.RLock()
	scan, exists := sc.activeScans[scanID]
	sc.mu.RUnlock()
	
	if !exists {
		return fmt.Errorf("scan %s not found", scanID)
	}
	
	scan.cancel()
	sc.updateScanStatus(scan, ScanStatusCancelled, "cancelled by user")
	
	log.Printf("Scan %s cancelled", scanID)
	return nil
}

// GetMetrics returns current coordinator metrics
func (sc *ScanCoordinator) GetMetrics() *CoordinatorMetrics {
	sc.mu.RLock()
	defer sc.mu.RUnlock()
	
	// Create a copy of metrics
	metrics := *sc.metrics
	metrics.ActiveScans = len(sc.activeScans)
	return &metrics
}

// Background workers

// progressTracker updates scan progress periodically
func (sc *ScanCoordinator) progressTracker() {
	defer sc.wg.Done()
	
	ticker := time.NewTicker(sc.config.ProgressUpdateInterval)
	defer ticker.Stop()
	
	for {
		select {
		case <-sc.ctx.Done():
			return
		case <-ticker.C:
			sc.updateAllScanProgress()
		}
	}
}

// updateAllScanProgress updates progress for all active scans
func (sc *ScanCoordinator) updateAllScanProgress() {
	sc.mu.RLock()
	scans := make([]*ScanOperation, 0, len(sc.activeScans))
	for _, scan := range sc.activeScans {
		scans = append(scans, scan)
	}
	sc.mu.RUnlock()
	
	for _, scan := range scans {
		if scan.Status == ScanStatusRunning && scan.Progress != nil {
			// Update progress based on job completion
			sc.updateJobProgress(scan)
		}
	}
}

// metricsUpdater updates coordinator metrics periodically
func (sc *ScanCoordinator) metricsUpdater() {
	defer sc.wg.Done()
	
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()
	
	for {
		select {
		case <-sc.ctx.Done():
			return
		case <-ticker.C:
			sc.updateMetrics()
		}
	}
}

// updateMetrics calculates and updates coordinator metrics
func (sc *ScanCoordinator) updateMetrics() {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	
	sc.metrics.ActiveScans = len(sc.activeScans)
	sc.metrics.LastUpdated = time.Now()
	
	// Calculate average scan duration
	totalDuration := time.Duration(0)
	completedCount := int64(0)
	
	for _, scan := range sc.activeScans {
		if scan.CompletedAt != nil {
			totalDuration += scan.CompletedAt.Sub(scan.StartedAt)
			completedCount++
		}
	}
	
	if completedCount > 0 {
		sc.metrics.AverageScanDuration = totalDuration / time.Duration(completedCount)
	}
	
	// Calculate throughput
	if sc.metrics.LastUpdated.Sub(time.Time{}) > time.Hour {
		hoursSinceStart := time.Since(sc.metrics.LastUpdated.Add(-time.Hour)).Hours()
		if hoursSinceStart > 0 {
			sc.metrics.ThroughputPerHour = float64(sc.metrics.CompletedScans) / hoursSinceStart
		}
	}
}

// cleanupWorker performs periodic cleanup of old scan data
func (sc *ScanCoordinator) cleanupWorker() {
	defer sc.wg.Done()
	
	ticker := time.NewTicker(sc.config.CleanupInterval)
	defer ticker.Stop()
	
	for {
		select {
		case <-sc.ctx.Done():
			return
		case <-ticker.C:
			sc.performCleanup()
		}
	}
}

// performCleanup removes old completed scans
func (sc *ScanCoordinator) performCleanup() {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	
	cutoff := time.Now().Add(-24 * time.Hour) // Remove scans older than 24 hours
	var toRemove []string
	
	for scanID, scan := range sc.activeScans {
		if scan.CompletedAt != nil && scan.CompletedAt.Before(cutoff) {
			toRemove = append(toRemove, scanID)
		}
	}
	
	for _, scanID := range toRemove {
		delete(sc.activeScans, scanID)
		log.Printf("Cleaned up old scan: %s", scanID)
	}
	
	if len(toRemove) > 0 {
		log.Printf("Cleanup completed: removed %d old scans", len(toRemove))
	}
}