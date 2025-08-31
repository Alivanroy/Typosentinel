package orchestrator

import (
	"context"
	"fmt"
	"log"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/Alivanroy/Typosentinel/internal/repository"
	"github.com/google/uuid"
)

// WorkerStatus represents the status of a worker
type WorkerStatus string

const (
	WorkerStatusIdle    WorkerStatus = "idle"
	WorkerStatusBusy    WorkerStatus = "busy"
	WorkerStatusStopped WorkerStatus = "stopped"
	WorkerStatusError   WorkerStatus = "error"
)

// Worker represents a scan worker
type Worker struct {
	ID             string                 `json:"id"`
	Status         WorkerStatus           `json:"status"`
	CurrentJob     *ScanJob               `json:"current_job,omitempty"`
	StartedAt      time.Time              `json:"started_at"`
	LastActivity   time.Time              `json:"last_activity"`
	JobsProcessed  int64                  `json:"jobs_processed"`
	JobsSucceeded  int64                  `json:"jobs_succeeded"`
	JobsFailed     int64                  `json:"jobs_failed"`
	AverageJobTime time.Duration          `json:"average_job_time"`
	HealthScore    float64                `json:"health_score"`
	Metadata       map[string]interface{} `json:"metadata"`

	// Internal fields
	queue      JobQueue
	manager    *repository.Manager
	ctx        context.Context
	cancel     context.CancelFunc
	wg         *sync.WaitGroup
	mu         sync.RWMutex
	heartbeat  chan struct{}
	errorCount int
	lastError  error
	maxErrors  int
}

// WorkerPool manages a pool of workers
type WorkerPool struct {
	workers    map[string]*Worker
	queue      JobQueue
	manager    *repository.Manager
	config     *WorkerPoolConfig
	ctx        context.Context
	cancel     context.CancelFunc
	wg         sync.WaitGroup
	mu         sync.RWMutex
	metrics    *WorkerPoolMetrics
	autoScaler *AutoScaler
}

// WorkerPoolConfig contains configuration for the worker pool
type WorkerPoolConfig struct {
	MinWorkers          int           `json:"min_workers"`
	MaxWorkers          int           `json:"max_workers"`
	InitialWorkers      int           `json:"initial_workers"`
	MaxJobsPerWorker    int64         `json:"max_jobs_per_worker"`
	WorkerTimeout       time.Duration `json:"worker_timeout"`
	HealthCheckInterval time.Duration `json:"health_check_interval"`
	MaxWorkerErrors     int           `json:"max_worker_errors"`
	AutoScaling         bool          `json:"auto_scaling"`
	ScaleUpThreshold    float64       `json:"scale_up_threshold"`
	ScaleDownThreshold  float64       `json:"scale_down_threshold"`
	ScaleCheckInterval  time.Duration `json:"scale_check_interval"`
}

// DefaultWorkerPoolConfig returns default configuration
func DefaultWorkerPoolConfig() *WorkerPoolConfig {
	return &WorkerPoolConfig{
		MinWorkers:          1,
		MaxWorkers:          runtime.NumCPU() * 2,
		InitialWorkers:      runtime.NumCPU(),
		MaxJobsPerWorker:    1000,
		WorkerTimeout:       30 * time.Minute,
		HealthCheckInterval: 30 * time.Second,
		MaxWorkerErrors:     5,
		AutoScaling:         true,
		ScaleUpThreshold:    0.8,
		ScaleDownThreshold:  0.3,
		ScaleCheckInterval:  1 * time.Minute,
	}
}

// WorkerPoolMetrics contains metrics for the worker pool
type WorkerPoolMetrics struct {
	TotalWorkers       int           `json:"total_workers"`
	ActiveWorkers      int           `json:"active_workers"`
	IdleWorkers        int           `json:"idle_workers"`
	BusyWorkers        int           `json:"busy_workers"`
	ErrorWorkers       int           `json:"error_workers"`
	TotalJobsProcessed int64         `json:"total_jobs_processed"`
	JobsPerSecond      float64       `json:"jobs_per_second"`
	AverageJobTime     time.Duration `json:"average_job_time"`
	QueueUtilization   float64       `json:"queue_utilization"`
	WorkerUtilization  float64       `json:"worker_utilization"`
	LastUpdated        time.Time     `json:"last_updated"`
}

// AutoScaler handles automatic scaling of workers
type AutoScaler struct {
	pool            *WorkerPool
	config          *WorkerPoolConfig
	mu              sync.RWMutex
	lastScaleAction time.Time
	cooldownPeriod  time.Duration
}

// NewWorkerPool creates a new worker pool
func NewWorkerPool(queue JobQueue, manager *repository.Manager, config *WorkerPoolConfig) *WorkerPool {
	if config == nil {
		config = DefaultWorkerPoolConfig()
	}

	ctx, cancel := context.WithCancel(context.Background())

	pool := &WorkerPool{
		workers: make(map[string]*Worker),
		queue:   queue,
		manager: manager,
		config:  config,
		ctx:     ctx,
		cancel:  cancel,
		metrics: &WorkerPoolMetrics{},
	}

	if config.AutoScaling {
		pool.autoScaler = &AutoScaler{
			pool:           pool,
			config:         config,
			cooldownPeriod: 2 * time.Minute,
		}
	}

	return pool
}

// Start starts the worker pool
func (wp *WorkerPool) Start() error {
	log.Printf("Starting worker pool with %d initial workers", wp.config.InitialWorkers)

	// Start initial workers
	for i := 0; i < wp.config.InitialWorkers; i++ {
		if err := wp.AddWorker(); err != nil {
			return fmt.Errorf("failed to start initial worker %d: %w", i, err)
		}
	}

	// Start health checker
	wp.wg.Add(1)
	go wp.healthChecker()

	// Start metrics updater
	wp.wg.Add(1)
	go wp.metricsUpdater()

	// Start auto-scaler if enabled
	if wp.autoScaler != nil {
		wp.wg.Add(1)
		go wp.autoScaler.run()
	}

	log.Printf("Worker pool started successfully")
	return nil
}

// Stop stops the worker pool
func (wp *WorkerPool) Stop() error {
	log.Printf("Stopping worker pool...")

	wp.cancel()
	wp.wg.Wait()

	// Stop all workers
	wp.mu.Lock()
	for _, worker := range wp.workers {
		worker.Stop()
	}
	wp.workers = make(map[string]*Worker)
	wp.mu.Unlock()

	log.Printf("Worker pool stopped")
	return nil
}

// AddWorker adds a new worker to the pool
func (wp *WorkerPool) AddWorker() error {
	wp.mu.Lock()
	defer wp.mu.Unlock()

	if len(wp.workers) >= wp.config.MaxWorkers {
		return fmt.Errorf("maximum number of workers (%d) reached", wp.config.MaxWorkers)
	}

	worker := wp.createWorker()
	wp.workers[worker.ID] = worker

	if err := worker.Start(); err != nil {
		delete(wp.workers, worker.ID)
		return fmt.Errorf("failed to start worker: %w", err)
	}

	log.Printf("Worker %s added to pool (total: %d)", worker.ID, len(wp.workers))
	return nil
}

// RemoveWorker removes a worker from the pool
func (wp *WorkerPool) RemoveWorker(workerID string) error {
	wp.mu.Lock()
	defer wp.mu.Unlock()

	worker, exists := wp.workers[workerID]
	if !exists {
		return fmt.Errorf("worker %s not found", workerID)
	}

	if len(wp.workers) <= wp.config.MinWorkers {
		return fmt.Errorf("minimum number of workers (%d) reached", wp.config.MinWorkers)
	}

	worker.Stop()
	delete(wp.workers, workerID)

	log.Printf("Worker %s removed from pool (total: %d)", workerID, len(wp.workers))
	return nil
}

// GetWorkers returns a copy of all workers
func (wp *WorkerPool) GetWorkers() map[string]*Worker {
	wp.mu.RLock()
	defer wp.mu.RUnlock()

	workers := make(map[string]*Worker)
	for id, worker := range wp.workers {
		workers[id] = worker
	}
	return workers
}

// GetMetrics returns current worker pool metrics
func (wp *WorkerPool) GetMetrics() *WorkerPoolMetrics {
	wp.mu.RLock()
	defer wp.mu.RUnlock()

	// Create a copy of metrics
	metrics := *wp.metrics
	return &metrics
}

// createWorker creates a new worker instance
func (wp *WorkerPool) createWorker() *Worker {
	workerID := uuid.New().String()[:8]
	ctx, cancel := context.WithCancel(wp.ctx)

	return &Worker{
		ID:           workerID,
		Status:       WorkerStatusIdle,
		StartedAt:    time.Now(),
		LastActivity: time.Now(),
		HealthScore:  1.0,
		Metadata:     make(map[string]interface{}),
		queue:        wp.queue,
		manager:      wp.manager,
		ctx:          ctx,
		cancel:       cancel,
		wg:           &sync.WaitGroup{},
		heartbeat:    make(chan struct{}, 1),
		maxErrors:    wp.config.MaxWorkerErrors,
	}
}

// healthChecker monitors worker health
func (wp *WorkerPool) healthChecker() {
	defer wp.wg.Done()

	ticker := time.NewTicker(wp.config.HealthCheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-wp.ctx.Done():
			return
		case <-ticker.C:
			wp.checkWorkerHealth()
		}
	}
}

// checkWorkerHealth checks the health of all workers
func (wp *WorkerPool) checkWorkerHealth() {
	wp.mu.Lock()
	defer wp.mu.Unlock()

	var unhealthyWorkers []string

	for workerID, worker := range wp.workers {
		worker.mu.RLock()
		lastActivity := worker.LastActivity
		errorCount := worker.errorCount
		status := worker.Status
		worker.mu.RUnlock()

		// Check if worker is unresponsive
		if time.Since(lastActivity) > wp.config.WorkerTimeout {
			log.Printf("Worker %s is unresponsive (last activity: %v)", workerID, lastActivity)
			unhealthyWorkers = append(unhealthyWorkers, workerID)
			continue
		}

		// Check if worker has too many errors
		if errorCount >= wp.config.MaxWorkerErrors {
			log.Printf("Worker %s has too many errors (%d)", workerID, errorCount)
			unhealthyWorkers = append(unhealthyWorkers, workerID)
			continue
		}

		// Check if worker is in error state
		if status == WorkerStatusError {
			log.Printf("Worker %s is in error state", workerID)
			unhealthyWorkers = append(unhealthyWorkers, workerID)
			continue
		}

		// Update health score
		worker.updateHealthScore()
	}

	// Remove unhealthy workers and replace them
	for _, workerID := range unhealthyWorkers {
		worker := wp.workers[workerID]
		worker.Stop()
		delete(wp.workers, workerID)

		// Add replacement worker if below minimum
		if len(wp.workers) < wp.config.MinWorkers {
			newWorker := wp.createWorker()
			wp.workers[newWorker.ID] = newWorker
			if err := newWorker.Start(); err != nil {
				log.Printf("Failed to start replacement worker: %v", err)
				delete(wp.workers, newWorker.ID)
			}
		}
	}
}

// metricsUpdater updates worker pool metrics
func (wp *WorkerPool) metricsUpdater() {
	defer wp.wg.Done()

	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-wp.ctx.Done():
			return
		case <-ticker.C:
			wp.updateMetrics()
		}
	}
}

// updateMetrics calculates and updates worker pool metrics
func (wp *WorkerPool) updateMetrics() {
	wp.mu.Lock()
	defer wp.mu.Unlock()

	metrics := &WorkerPoolMetrics{
		TotalWorkers: len(wp.workers),
		LastUpdated:  time.Now(),
	}

	var totalJobsProcessed int64
	var totalJobTime time.Duration
	var jobTimeCount int

	for _, worker := range wp.workers {
		worker.mu.RLock()
		status := worker.Status
		jobsProcessed := worker.JobsProcessed
		avgJobTime := worker.AverageJobTime
		worker.mu.RUnlock()

		totalJobsProcessed += jobsProcessed

		if avgJobTime > 0 {
			totalJobTime += avgJobTime
			jobTimeCount++
		}

		switch status {
		case WorkerStatusIdle:
			metrics.IdleWorkers++
			metrics.ActiveWorkers++
		case WorkerStatusBusy:
			metrics.BusyWorkers++
			metrics.ActiveWorkers++
		case WorkerStatusError:
			metrics.ErrorWorkers++
		}
	}

	metrics.TotalJobsProcessed = totalJobsProcessed

	if jobTimeCount > 0 {
		metrics.AverageJobTime = totalJobTime / time.Duration(jobTimeCount)
	}

	// Calculate utilization
	if metrics.TotalWorkers > 0 {
		metrics.WorkerUtilization = float64(metrics.BusyWorkers) / float64(metrics.TotalWorkers)
	}

	// Get queue stats for queue utilization
	if queueStats, err := wp.queue.GetQueueStats(context.Background()); err == nil {
		totalJobs := queueStats.PendingJobs + queueStats.RunningJobs
		if totalJobs > 0 {
			metrics.QueueUtilization = float64(queueStats.RunningJobs) / float64(totalJobs)
		}
	}

	// Calculate jobs per second (simple approximation)
	if wp.metrics != nil && wp.metrics.LastUpdated.Before(metrics.LastUpdated) {
		timeDiff := metrics.LastUpdated.Sub(wp.metrics.LastUpdated).Seconds()
		jobDiff := totalJobsProcessed - wp.metrics.TotalJobsProcessed
		if timeDiff > 0 {
			metrics.JobsPerSecond = float64(jobDiff) / timeDiff
		}
	}

	wp.metrics = metrics
}

// Start starts the worker
func (w *Worker) Start() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.Status != WorkerStatusIdle {
		return fmt.Errorf("worker %s is not in idle state", w.ID)
	}

	w.wg.Add(1)
	go w.run()

	log.Printf("Worker %s started", w.ID)
	return nil
}

// Stop stops the worker
func (w *Worker) Stop() {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.Status == WorkerStatusStopped {
		return
	}

	w.Status = WorkerStatusStopped
	w.cancel()
	w.wg.Wait()

	log.Printf("Worker %s stopped", w.ID)
}

// run is the main worker loop
func (w *Worker) run() {
	defer w.wg.Done()

	log.Printf("Worker %s starting job processing loop", w.ID)

	for {
		select {
		case <-w.ctx.Done():
			return
		default:
			if err := w.processNextJob(); err != nil {
				w.handleError(err)
			}

			// Small delay to prevent busy waiting
			time.Sleep(100 * time.Millisecond)
		}
	}
}

// processNextJob processes the next job from the queue
func (w *Worker) processNextJob() error {
	w.updateLastActivity()

	// Get next job from queue
	job, err := w.queue.Dequeue(w.ctx, w.ID)
	if err != nil {
		return fmt.Errorf("failed to dequeue job: %w", err)
	}

	if job == nil {
		// No jobs available, stay idle
		w.setStatus(WorkerStatusIdle)
		return nil
	}

	// Process the job
	return w.executeJob(job)
}

// executeJob executes a scan job
func (w *Worker) executeJob(job *ScanJob) error {
	w.setStatus(WorkerStatusBusy)
	w.setCurrentJob(job)

	startTime := time.Now()
	log.Printf("Worker %s executing job %s (type: %s, platform: %s)", w.ID, job.ID, job.Type, job.Platform)

	defer func() {
		duration := time.Since(startTime)
		w.updateJobStats(duration)
		w.setCurrentJob(nil)
		w.setStatus(WorkerStatusIdle)
		log.Printf("Worker %s completed job %s in %v", w.ID, job.ID, duration)
	}()

	// Execute the actual scan based on job type
	var result map[string]interface{}
	var err error

	switch job.Type {
	case "repository":
		result, err = w.scanRepository(job)
	case "organization":
		result, err = w.scanOrganization(job)
	case "bulk":
		result, err = w.scanBulk(job)
	default:
		err = fmt.Errorf("unknown job type: %s", job.Type)
	}

	// Update job status based on result
	if err != nil {
		w.incrementJobsFailed()
		if updateErr := w.queue.UpdateStatus(w.ctx, job.ID, JobStatusFailed, err.Error()); updateErr != nil {
			log.Printf("Failed to update job status: %v", updateErr)
		}
		return fmt.Errorf("job execution failed: %w", err)
	}

	w.incrementJobsSucceeded()
	job.Result = result
	if updateErr := w.queue.UpdateStatus(w.ctx, job.ID, JobStatusCompleted, ""); updateErr != nil {
		log.Printf("Failed to update job status: %v", updateErr)
	}

	return nil
}

// scanRepository scans a single repository
func (w *Worker) scanRepository(job *ScanJob) (map[string]interface{}, error) {
	// Get connector for the platform
	connector, err := w.manager.GetConnector(job.Platform)
	if err != nil {
		return nil, fmt.Errorf("failed to get connector for platform %s: %w", job.Platform, err)
	}

	// Parse repository information from target
	owner, repo, err := w.parseRepositoryTarget(job.Target)
	if err != nil {
		return nil, fmt.Errorf("failed to parse repository target: %w", err)
	}

	// Get repository details
	repoInfo, err := connector.GetRepository(w.ctx, owner, repo)
	if err != nil {
		return nil, fmt.Errorf("failed to get repository: %w", err)
	}

	// Create scan request for the repository manager
	scanRequest := &repository.ScanRequest{
		ScanID:     job.ID,
		Repository: repoInfo,
		Options: repository.ScanOptions{
			DeepScan:               job.Options != nil && job.Options["deep_scan"] == "true",
			IncludeDev:             true,
			Timeout:                30 * time.Minute,
			MaxFileSize:            100 * 1024 * 1024, // 100MB
			ExcludePatterns:        []string{},
			CustomRules:            []string{},
			OutputFormats:          []string{"json"},
			DeepAnalysis:           job.Options != nil && job.Options["deep_scan"] == "true",
			IncludeDevDependencies: true,
			SimilarityThreshold:    0.8,
			ExcludePackages:        []string{},
			CheckVulnerabilities:   true,
		},
	}

	// Execute the repository scan using the manager
	scanResult, err := w.manager.ScanRepositoryWithResult(w.ctx, scanRequest)
	if err != nil {
		return nil, fmt.Errorf("failed to scan repository %s/%s: %w", owner, repo, err)
	}

	// Convert scan result to job result format
	result := map[string]interface{}{
		"repository":       repoInfo,
		"scan_id":          scanResult.ScanID,
		"scan_time":        scanResult.StartTime,
		"completion_time":  scanResult.EndTime,
		"duration":         scanResult.Duration.String(),
		"status":           scanResult.Status,
		"analysis_result":  scanResult.AnalysisResult,
		"dependency_files": scanResult.DependencyFiles,
		"metadata":         scanResult.Metadata,
	}

	// Add error information if scan failed
	if scanResult.Error != "" {
		result["error"] = scanResult.Error
	}

	// Add message if available
	if scanResult.Message != "" {
		result["message"] = scanResult.Message
	}

	return result, nil
}

// scanOrganization scans all repositories in an organization
func (w *Worker) scanOrganization(job *ScanJob) (map[string]interface{}, error) {
	// Get connector for the platform
	connector, err := w.manager.GetConnector(job.Platform)
	if err != nil {
		return nil, fmt.Errorf("failed to get connector for platform %s: %w", job.Platform, err)
	}

	// Create repository filter with sensible defaults
	filter := &repository.RepositoryFilter{
		IncludeArchived:   false,
		IncludeForks:      false,
		IncludePrivate:    true,
		HasPackageManager: true,
		MinStars:          0,
		MaxSize:           500 * 1024 * 1024, // 500MB max
	}

	// Parse additional filter options from job options
	if options, ok := job.Options["include_forks"]; ok && options == "true" {
		filter.IncludeForks = true
	}
	if options, ok := job.Options["include_archived"]; ok && options == "true" {
		filter.IncludeArchived = true
	}
	if options, ok := job.Options["min_stars"]; ok {
		// Simple string to int conversion for demo
		if options == "1" {
			filter.MinStars = 1
		} else if options == "5" {
			filter.MinStars = 5
		} else if options == "10" {
			filter.MinStars = 10
		}
	}

	// List repositories in the organization
	repos, err := connector.ListOrgRepositories(w.ctx, job.Target, filter)
	if err != nil {
		return nil, fmt.Errorf("failed to list repositories for organization %s: %w", job.Target, err)
	}

	// Create scan requests for each repository
	var scanRequests []*repository.ScanRequest
	for _, repo := range repos {
		scanRequest := &repository.ScanRequest{
			ScanID:     fmt.Sprintf("%s-%s", job.ID, repo.Name),
			Repository: repo,
			Options: repository.ScanOptions{
				DeepScan:               job.Options != nil && job.Options["deep_scan"] == "true",
				IncludeDev:             true,
				Timeout:                15 * time.Minute, // Shorter timeout for org scans
				MaxFileSize:            50 * 1024 * 1024, // 50MB for org scans
				ExcludePatterns:        []string{},
				CustomRules:            []string{},
				OutputFormats:          []string{"json"},
				DeepAnalysis:           false, // Disable deep analysis for org scans
				IncludeDevDependencies: true,
				SimilarityThreshold:    0.8,
				ExcludePackages:        []string{},
				CheckVulnerabilities:   true,
			},
		}
		scanRequests = append(scanRequests, scanRequest)
	}

	// Execute bulk scan using the repository manager
	scanResults, err := w.manager.ScanRepositoriesWithResults(w.ctx, scanRequests)
	if err != nil {
		return nil, fmt.Errorf("failed to scan repositories for organization %s: %w", job.Target, err)
	}

	// Aggregate results
	var successCount, failureCount int
	var totalPackages, totalThreats int
	var repositoryResults []map[string]interface{}

	for i, result := range scanResults {
		if result.Status == "completed" {
			successCount++
		} else {
			failureCount++
		}

		// Extract metrics from analysis result
		if result.AnalysisResult != nil {
			if analysisMap, ok := result.AnalysisResult.(map[string]interface{}); ok {
				if packages, ok := analysisMap["packages"].(int); ok {
					totalPackages += packages
				}
				if findings, ok := analysisMap["findings"].(int); ok {
					totalThreats += findings
				}
			}
		}

		// Create repository result summary
		repoResult := map[string]interface{}{
			"repository": repos[i].FullName,
			"status":     result.Status,
			"duration":   result.Duration.String(),
			"scan_id":    result.ScanID,
		}

		if result.Error != "" {
			repoResult["error"] = result.Error
		}

		if result.AnalysisResult != nil {
			repoResult["analysis"] = result.AnalysisResult
		}

		repositoryResults = append(repositoryResults, repoResult)
	}

	// Build comprehensive result
	result := map[string]interface{}{
		"organization":       job.Target,
		"total_repositories": len(repos),
		"successful_scans":   successCount,
		"failed_scans":       failureCount,
		"total_packages":     totalPackages,
		"total_threats":      totalThreats,
		"scan_time":          time.Now(),
		"status":             "completed",
		"repository_results": repositoryResults,
		"summary": map[string]interface{}{
			"success_rate": float64(successCount) / float64(len(repos)) * 100,
			"avg_packages_per_repo": func() float64 {
				if len(repos) > 0 {
					return float64(totalPackages) / float64(len(repos))
				}
				return 0
			}(),
			"avg_threats_per_repo": func() float64 {
				if len(repos) > 0 {
					return float64(totalThreats) / float64(len(repos))
				}
				return 0
			}(),
		},
	}

	return result, nil
}

// scanBulk scans multiple targets in bulk
func (w *Worker) scanBulk(job *ScanJob) (map[string]interface{}, error) {
	// Parse bulk targets from job target (comma-separated)
	targets := strings.Split(job.Target, ",")
	if len(targets) == 0 {
		return nil, fmt.Errorf("no targets specified for bulk scan")
	}

	// Get connector for the platform
	connector, err := w.manager.GetConnector(job.Platform)
	if err != nil {
		return nil, fmt.Errorf("failed to get connector for platform %s: %w", job.Platform, err)
	}

	// Create scan requests for each target
	var scanRequests []*repository.ScanRequest
	var targetResults []map[string]interface{}

	for _, target := range targets {
		target = strings.TrimSpace(target)
		if target == "" {
			continue
		}

		// Check if target is organization or repository
		if strings.Contains(target, "/") {
			// Repository target (owner/repo format)
			owner, repo, err := w.parseRepositoryTarget(target)
			if err != nil {
				targetResults = append(targetResults, map[string]interface{}{
					"target": target,
					"type":   "repository",
					"status": "failed",
					"error":  fmt.Sprintf("failed to parse repository target: %v", err),
				})
				continue
			}

			// Get repository details
			repoInfo, err := connector.GetRepository(w.ctx, owner, repo)
			if err != nil {
				targetResults = append(targetResults, map[string]interface{}{
					"target": target,
					"type":   "repository",
					"status": "failed",
					"error":  fmt.Sprintf("failed to get repository: %v", err),
				})
				continue
			}

			// Create scan request for repository
			scanRequest := &repository.ScanRequest{
				ScanID:     fmt.Sprintf("%s-%s", job.ID, strings.ReplaceAll(target, "/", "-")),
				Repository: repoInfo,
				Options: repository.ScanOptions{
					DeepScan:               job.Options != nil && job.Options["deep_scan"] == "true",
					IncludeDev:             true,
					Timeout:                20 * time.Minute,
					MaxFileSize:            75 * 1024 * 1024, // 75MB for bulk scans
					ExcludePatterns:        []string{},
					CustomRules:            []string{},
					OutputFormats:          []string{"json"},
					DeepAnalysis:           false, // Disable deep analysis for bulk scans
					IncludeDevDependencies: true,
					SimilarityThreshold:    0.8,
					ExcludePackages:        []string{},
					CheckVulnerabilities:   true,
				},
			}
			scanRequests = append(scanRequests, scanRequest)

			targetResults = append(targetResults, map[string]interface{}{
				"target": target,
				"type":   "repository",
				"status": "queued",
			})

		} else {
			// Organization target
			filter := &repository.RepositoryFilter{
				IncludeArchived:   false,
				IncludeForks:      false,
				IncludePrivate:    true,
				HasPackageManager: true,
				MinStars:          0,
				MaxSize:           200 * 1024 * 1024, // 200MB max for bulk org scans
			}

			// List repositories in the organization
			repos, err := connector.ListOrgRepositories(w.ctx, target, filter)
			if err != nil {
				targetResults = append(targetResults, map[string]interface{}{
					"target": target,
					"type":   "organization",
					"status": "failed",
					"error":  fmt.Sprintf("failed to list repositories: %v", err),
				})
				continue
			}

			// Create scan requests for each repository in the organization
			for _, repo := range repos {
				scanRequest := &repository.ScanRequest{
					ScanID:     fmt.Sprintf("%s-%s-%s", job.ID, target, repo.Name),
					Repository: repo,
					Options: repository.ScanOptions{
						DeepScan:               false, // Disable deep scan for bulk org scans
						IncludeDev:             true,
						Timeout:                10 * time.Minute, // Shorter timeout for bulk
						MaxFileSize:            25 * 1024 * 1024, // 25MB for bulk org scans
						ExcludePatterns:        []string{},
						CustomRules:            []string{},
						OutputFormats:          []string{"json"},
						DeepAnalysis:           false,
						IncludeDevDependencies: true,
						SimilarityThreshold:    0.8,
						ExcludePackages:        []string{},
						CheckVulnerabilities:   true,
					},
				}
				scanRequests = append(scanRequests, scanRequest)
			}

			targetResults = append(targetResults, map[string]interface{}{
				"target":       target,
				"type":         "organization",
				"status":       "queued",
				"repositories": len(repos),
			})
		}
	}

	// Execute bulk scan using the repository manager
	scanResults, err := w.manager.ScanRepositoriesWithResults(w.ctx, scanRequests)
	if err != nil {
		return nil, fmt.Errorf("failed to execute bulk scan: %w", err)
	}

	// Aggregate results
	var successCount, failureCount int
	var totalPackages, totalThreats int
	var scanResultDetails []map[string]interface{}

	for _, result := range scanResults {
		if result.Status == "completed" {
			successCount++
		} else {
			failureCount++
		}

		// Extract metrics from analysis result
		if result.AnalysisResult != nil {
			if analysisMap, ok := result.AnalysisResult.(map[string]interface{}); ok {
				if packages, ok := analysisMap["packages"].(int); ok {
					totalPackages += packages
				}
				if findings, ok := analysisMap["findings"].(int); ok {
					totalThreats += findings
				}
			}
		}

		// Create scan result summary
		scanDetail := map[string]interface{}{
			"repository": result.Repository.FullName,
			"scan_id":    result.ScanID,
			"status":     result.Status,
			"duration":   result.Duration.String(),
		}

		if result.Error != "" {
			scanDetail["error"] = result.Error
		}

		if result.AnalysisResult != nil {
			scanDetail["analysis"] = result.AnalysisResult
		}

		scanResultDetails = append(scanResultDetails, scanDetail)
	}

	// Build comprehensive bulk scan result
	result := map[string]interface{}{
		"bulk_scan":          true,
		"targets":            targets,
		"total_targets":      len(targets),
		"total_repositories": len(scanRequests),
		"successful_scans":   successCount,
		"failed_scans":       failureCount,
		"total_packages":     totalPackages,
		"total_threats":      totalThreats,
		"scan_time":          time.Now(),
		"status":             "completed",
		"target_results":     targetResults,
		"scan_results":       scanResultDetails,
		"summary": map[string]interface{}{
			"success_rate": func() float64 {
				if len(scanRequests) > 0 {
					return float64(successCount) / float64(len(scanRequests)) * 100
				}
				return 0
			}(),
			"avg_packages_per_repo": func() float64 {
				if len(scanRequests) > 0 {
					return float64(totalPackages) / float64(len(scanRequests))
				}
				return 0
			}(),
			"avg_threats_per_repo": func() float64 {
				if len(scanRequests) > 0 {
					return float64(totalThreats) / float64(len(scanRequests))
				}
				return 0
			}(),
		},
	}

	return result, nil
}

// parseRepositoryTarget parses owner/repo from target string
func (w *Worker) parseRepositoryTarget(target string) (string, string, error) {
	// Simple parsing - in real implementation, this would be more robust
	parts := strings.Split(target, "/")
	if len(parts) != 2 {
		return "", "", fmt.Errorf("invalid repository target format: %s", target)
	}
	return parts[0], parts[1], nil
}

// Helper methods for worker state management

func (w *Worker) setStatus(status WorkerStatus) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.Status = status
	w.LastActivity = time.Now()
}

func (w *Worker) setCurrentJob(job *ScanJob) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.CurrentJob = job
}

func (w *Worker) updateLastActivity() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.LastActivity = time.Now()
}

func (w *Worker) incrementJobsSucceeded() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.JobsProcessed++
	w.JobsSucceeded++
}

func (w *Worker) incrementJobsFailed() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.JobsProcessed++
	w.JobsFailed++
}

func (w *Worker) updateJobStats(duration time.Duration) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.JobsProcessed == 1 {
		w.AverageJobTime = duration
	} else {
		// Calculate running average
		w.AverageJobTime = (w.AverageJobTime*time.Duration(w.JobsProcessed-1) + duration) / time.Duration(w.JobsProcessed)
	}
}

func (w *Worker) handleError(err error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	w.errorCount++
	w.lastError = err

	log.Printf("Worker %s error (count: %d): %v", w.ID, w.errorCount, err)

	if w.errorCount >= w.maxErrors {
		w.Status = WorkerStatusError
		log.Printf("Worker %s marked as error due to too many failures", w.ID)
	}
}

func (w *Worker) updateHealthScore() {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.JobsProcessed == 0 {
		w.HealthScore = 1.0
		return
	}

	// Calculate health score based on success rate and error count
	successRate := float64(w.JobsSucceeded) / float64(w.JobsProcessed)
	errorPenalty := float64(w.errorCount) * 0.1

	w.HealthScore = successRate - errorPenalty
	if w.HealthScore < 0 {
		w.HealthScore = 0
	}
	if w.HealthScore > 1 {
		w.HealthScore = 1
	}
}

// AutoScaler methods

func (as *AutoScaler) run() {
	defer as.pool.wg.Done()

	ticker := time.NewTicker(as.config.ScaleCheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-as.pool.ctx.Done():
			return
		case <-ticker.C:
			as.checkAndScale()
		}
	}
}

func (as *AutoScaler) checkAndScale() {
	as.mu.Lock()
	defer as.mu.Unlock()

	// Cooldown period to prevent rapid scaling
	if time.Since(as.lastScaleAction) < as.cooldownPeriod {
		return
	}

	metrics := as.pool.GetMetrics()

	// Scale up if utilization is high
	if metrics.WorkerUtilization > as.config.ScaleUpThreshold {
		if metrics.TotalWorkers < as.config.MaxWorkers {
			log.Printf("Auto-scaling up: utilization %.2f > threshold %.2f",
				metrics.WorkerUtilization, as.config.ScaleUpThreshold)

			if err := as.pool.AddWorker(); err != nil {
				log.Printf("Failed to scale up: %v", err)
			} else {
				as.lastScaleAction = time.Now()
			}
		}
	}

	// Scale down if utilization is low
	if metrics.WorkerUtilization < as.config.ScaleDownThreshold {
		if metrics.TotalWorkers > as.config.MinWorkers {
			log.Printf("Auto-scaling down: utilization %.2f < threshold %.2f",
				metrics.WorkerUtilization, as.config.ScaleDownThreshold)

			// Find an idle worker to remove
			workers := as.pool.GetWorkers()
			for workerID, worker := range workers {
				worker.mu.RLock()
				status := worker.Status
				worker.mu.RUnlock()

				if status == WorkerStatusIdle {
					if err := as.pool.RemoveWorker(workerID); err != nil {
						log.Printf("Failed to scale down: %v", err)
					} else {
						as.lastScaleAction = time.Now()
					}
					break
				}
			}
		}
	}
}
