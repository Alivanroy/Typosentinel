package batch

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/go-redis/redis/v8"

	"github.com/typosentinel/typosentinel/internal/database"
	"github.com/typosentinel/typosentinel/internal/queue"
	"github.com/typosentinel/typosentinel/internal/scanner"
	"github.com/typosentinel/typosentinel/internal/events"
	"github.com/typosentinel/typosentinel/pkg/types"
	"github.com/typosentinel/typosentinel/pkg/metrics"
)

// BatchStatus represents the status of a batch job
type BatchStatus string

const (
	BatchStatusPending    BatchStatus = "pending"
	BatchStatusRunning    BatchStatus = "running"
	BatchStatusCompleted  BatchStatus = "completed"
	BatchStatusFailed     BatchStatus = "failed"
	BatchStatusCancelled  BatchStatus = "cancelled"
	BatchStatusPaused     BatchStatus = "paused"
)

// BatchConfiguration holds configuration for batch processing
type BatchConfiguration struct {
	Concurrency       int           `json:"concurrency"`
	BatchSize         int           `json:"batch_size"`
	Timeout           time.Duration `json:"timeout"`
	RetryAttempts     int           `json:"retry_attempts"`
	Priority          queue.Priority `json:"priority"`
	NotifyOnComplete  bool          `json:"notify_on_complete"`
	NotifyOnFailure   bool          `json:"notify_on_failure"`
	StopOnFirstError  bool          `json:"stop_on_first_error"`
	IncludeMetadata   bool          `json:"include_metadata"`
	OutputFormat      string        `json:"output_format"`
	Filters           BatchFilters  `json:"filters"`
}

// BatchFilters defines filters for batch processing
type BatchFilters struct {
	Registries      []string `json:"registries,omitempty"`
	PackagePatterns []string `json:"package_patterns,omitempty"`
	ExcludePatterns []string `json:"exclude_patterns,omitempty"`
	MinVersion      string   `json:"min_version,omitempty"`
	MaxVersion      string   `json:"max_version,omitempty"`
	DateRange       *DateRange `json:"date_range,omitempty"`
}

// DateRange represents a date range filter
type DateRange struct {
	From time.Time `json:"from"`
	To   time.Time `json:"to"`
}

// BatchPackage represents a package in a batch job
type BatchPackage struct {
	ID         string                 `json:"id"`
	BatchID    string                 `json:"batch_id"`
	PackageName string                `json:"package_name"`
	Registry   string                 `json:"registry"`
	Version    string                 `json:"version"`
	Status     string                 `json:"status"` // pending, processing, completed, failed, skipped
	ScanResult *types.ScanResult      `json:"scan_result,omitempty"`
	Error      string                 `json:"error,omitempty"`
	StartedAt  *time.Time             `json:"started_at,omitempty"`
	CompletedAt *time.Time            `json:"completed_at,omitempty"`
	Metadata   map[string]interface{} `json:"metadata,omitempty"`
}

type BatchProcessor struct {
	db          *database.DB
	queue       *queue.ScannerQueue
	scanner     *scanner.Scanner
	eventBus    *events.EventBus
	redis       *redis.Client
	metrics     *metrics.Metrics
	concurrency int
	batchSize   int
	timeout     time.Duration
	ctx         context.Context
	cancel      context.CancelFunc
	mu          sync.RWMutex
	activeBatches map[string]*types.BatchJob
}

// BatchProcessorConfig holds configuration for the batch processor
type BatchProcessorConfig struct {
	Concurrency int
	BatchSize   int
	Timeout     time.Duration
}

// NewBatchProcessor creates a new batch processor instance
func NewBatchProcessor(
	db *database.DB,
	queue *queue.ScannerQueue,
	scanner *scanner.Scanner,
	eventBus *events.EventBus,
	redis *redis.Client,
	config BatchProcessorConfig,
) *BatchProcessor {
	ctx, cancel := context.WithCancel(context.Background())

	return &BatchProcessor{
		db:            db,
		queue:         queue,
		scanner:       scanner,
		eventBus:      eventBus,
		redis:         redis,
		metrics:       metrics.GetInstance(),
		concurrency:   config.Concurrency,
		batchSize:     config.BatchSize,
		timeout:       config.Timeout,
		ctx:           ctx,
		cancel:        cancel,
		activeBatches: make(map[string]*types.BatchJob),
	}
}

// CreateBatchJob creates a new batch job
func (bp *BatchProcessor) CreateBatchJob(
	organizationID string,
	name string,
	description string,
	packages []string,
	createdBy string,
	config BatchConfiguration,
) (*types.BatchJob, error) {
	// Validate input
	if len(packages) == 0 {
		return nil, fmt.Errorf("no packages provided for batch job")
	}

	if len(packages) > 10000 {
		return nil, fmt.Errorf("batch job too large: maximum 10,000 packages allowed")
	}

	// Set default configuration values
	if config.Concurrency == 0 {
		config.Concurrency = bp.concurrency
	}
	if config.BatchSize == 0 {
		config.BatchSize = bp.batchSize
	}
	if config.Timeout == 0 {
		config.Timeout = bp.timeout
	}
	if config.Priority == "" {
		config.Priority = queue.PriorityNormal
	}

	// Create batch job
	batch := &types.BatchJob{
		ID:             uuid.New().String(),
		OrganizationID: organizationID,
		Name:           name,
		Description:    description,
		Status:         string(BatchStatusPending),
		TotalPackages:  len(packages),
		CreatedAt:      time.Now(),
		UpdatedAt:      time.Now(),
		CreatedBy:      createdBy,
		Metadata:       make(map[string]interface{}),
	}

	// Store batch job in database
	if err := bp.db.CreateBatchJob(batch); err != nil {
		return nil, fmt.Errorf("failed to create batch job: %w", err)
	}

	// Create batch packages
	if err := bp.createBatchPackages(batch.ID, packages); err != nil {
		return nil, fmt.Errorf("failed to create batch packages: %w", err)
	}

	// Update metrics
	bp.metrics.BatchJobsTotal.WithLabelValues("created").Inc()
	bp.metrics.BatchPackagesTotal.WithLabelValues("pending").Add(float64(len(packages)))

	log.Printf("Created batch job %s with %d packages for organization %s", batch.ID, len(packages), organizationID)
	return batch, nil
}

// StartBatchJob starts processing a batch job
func (bp *BatchProcessor) StartBatchJob(batchID string) error {
	batch, err := bp.db.GetBatchJob(batchID)
	if err != nil {
		return fmt.Errorf("failed to get batch job: %w", err)
	}

	if batch.Status != string(BatchStatusPending) {
		return fmt.Errorf("batch job %s is not in pending status (current: %s)", batchID, batch.Status)
	}

	// Update batch status to running
	now := time.Now()
	batch.Status = string(BatchStatusRunning)
	batch.StartedAt = &now
	batch.UpdatedAt = now

	if err := bp.db.UpdateBatchJob(batch); err != nil {
		return fmt.Errorf("failed to update batch job status: %w", err)
	}

	// Add to active batches
	bp.mu.Lock()
	bp.activeBatches[batchID] = batch
	bp.mu.Unlock()

	// Start processing in background
	go bp.processBatchJob(batch)

	// Publish event
	bp.eventBus.Publish(&events.Event{
		Type: events.BatchStarted,
		Data: map[string]interface{}{
			"batch_id":        batchID,
			"organization_id": batch.OrganizationID,
			"total_packages":  batch.TotalPackages,
		},
	})

	// Update metrics
	bp.metrics.BatchJobsTotal.WithLabelValues("started").Inc()
	bp.metrics.ActiveBatchJobs.Inc()

	log.Printf("Started batch job %s", batchID)
	return nil
}

// ProcessPackageList creates and starts a batch job (legacy method for compatibility)
func (bp *BatchProcessor) ProcessPackageList(packages []string, orgID string) error {
	config := BatchConfiguration{
		Concurrency:      bp.concurrency,
		BatchSize:        bp.batchSize,
		Timeout:          bp.timeout,
		Priority:         queue.PriorityNormal,
		NotifyOnComplete: true,
		StopOnFirstError: false,
	}

	batch, err := bp.CreateBatchJob(orgID, "Legacy Batch", "Auto-created batch job", packages, "system", config)
	if err != nil {
		return err
	}

	return bp.StartBatchJob(batch.ID)
}

// processBatchJob processes all packages in a batch job
func (bp *BatchProcessor) processBatchJob(batch *types.BatchJob) {
	defer func() {
		// Remove from active batches
		bp.mu.Lock()
		delete(bp.activeBatches, batch.ID)
		bp.mu.Unlock()

		// Update metrics
		bp.metrics.ActiveBatchJobs.Dec()
	}()

	log.Printf("Processing batch job %s with %d packages", batch.ID, batch.TotalPackages)

	// Get batch packages
	packages, err := bp.db.GetBatchPackages(batch.ID)
	if err != nil {
		log.Printf("Failed to get batch packages for %s: %v", batch.ID, err)
		bp.failBatchJob(batch, fmt.Sprintf("Failed to get batch packages: %v", err))
		return
	}

	// Create semaphore for concurrency control
	sem := make(chan struct{}, bp.concurrency)
	var wg sync.WaitGroup
	var mu sync.Mutex

	// Process packages in chunks
	for i := 0; i < len(packages); i += bp.batchSize {
		end := i + bp.batchSize
		if end > len(packages) {
			end = len(packages)
		}

		chunk := packages[i:end]

		// Process chunk
		for _, pkg := range chunk {
			// Check if batch should be stopped
			if bp.shouldStopBatch(batch.ID) {
				log.Printf("Stopping batch job %s as requested", batch.ID)
				return
			}

			wg.Add(1)
			go func(batchPkg *BatchPackage) {
				defer wg.Done()

				// Acquire semaphore
				sem <- struct{}{}
				defer func() { <-sem }()

				// Process package
				bp.processBatchPackage(batch, batchPkg)

				// Update progress
				mu.Lock()
				batch.ProcessedCount++
				batch.Progress = float64(batch.ProcessedCount) / float64(batch.TotalPackages) * 100
				mu.Unlock()

				// Update batch progress periodically
				if batch.ProcessedCount%10 == 0 || batch.ProcessedCount == batch.TotalPackages {
					bp.updateBatchProgress(batch)
				}
			}(pkg)
		}

		// Wait for chunk to complete before processing next chunk
		wg.Wait()
	}

	// Complete the batch job
	bp.completeBatchJob(batch)
}

// processBatchPackage processes a single package in a batch
func (bp *BatchProcessor) processBatchPackage(batch *types.BatchJob, batchPkg *BatchPackage) {
	startTime := time.Now()
	batchPkg.StartedAt = &startTime
	batchPkg.Status = "processing"

	// Update package status
	bp.db.UpdateBatchPackage(batchPkg)

	log.Printf("Processing package %s in batch %s", batchPkg.PackageName, batch.ID)

	// Create package object
	pkg := &types.Package{
		ID:       batchPkg.ID,
		Name:     batchPkg.PackageName,
		Registry: batchPkg.Registry,
		Version:  batchPkg.Version,
		Metadata: batchPkg.Metadata,
	}

	// Perform scan
	scanResult, err := bp.scanner.Scan(bp.ctx, pkg)
	processingTime := time.Since(startTime)

	// Update package with result
	completedAt := time.Now()
	batchPkg.CompletedAt = &completedAt

	if err != nil {
		batchPkg.Status = "failed"
		batchPkg.Error = err.Error()
		batch.FailureCount++
		log.Printf("Failed to scan package %s in batch %s: %v", batchPkg.PackageName, batch.ID, err)

		// Update metrics
		bp.metrics.BatchPackagesTotal.WithLabelValues("failed").Inc()
	} else {
		batchPkg.Status = "completed"
		batchPkg.ScanResult = scanResult
		batch.SuccessCount++
		log.Printf("Successfully scanned package %s in batch %s", batchPkg.PackageName, batch.ID)

		// Update metrics
		bp.metrics.BatchPackagesTotal.WithLabelValues("completed").Inc()
		bp.metrics.BatchScanDuration.Observe(processingTime.Seconds())
	}

	// Update package in database
	bp.db.UpdateBatchPackage(batchPkg)
}

// updateBatchProgress updates the batch job progress
func (bp *BatchProcessor) updateBatchProgress(batch *types.BatchJob) {
	batch.UpdatedAt = time.Now()

	if err := bp.db.UpdateBatchJob(batch); err != nil {
		log.Printf("Failed to update batch job progress: %v", err)
		return
	}

	// Publish progress event
	bp.eventBus.Publish(&events.Event{
		Type: events.BatchProgress,
		Data: map[string]interface{}{
			"batch_id":        batch.ID,
			"organization_id": batch.OrganizationID,
			"progress":        batch.Progress,
			"processed":       batch.ProcessedCount,
			"total":           batch.TotalPackages,
			"successful":      batch.SuccessCount,
			"failed":          batch.FailureCount,
		},
	})

	log.Printf("Batch %s progress: %.2f%% (%d/%d)", batch.ID, batch.Progress, batch.ProcessedCount, batch.TotalPackages)
}

// completeBatchJob marks a batch job as completed
func (bp *BatchProcessor) completeBatchJob(batch *types.BatchJob) {
	now := time.Now()
	batch.Status = string(BatchStatusCompleted)
	batch.CompletedAt = &now
	batch.UpdatedAt = now
	batch.Progress = 100.0

	if err := bp.db.UpdateBatchJob(batch); err != nil {
		log.Printf("Failed to update completed batch job: %v", err)
		return
	}

	// Publish completion event
	bp.eventBus.Publish(&events.Event{
		Type: events.BatchCompleted,
		Data: map[string]interface{}{
			"batch_id":        batch.ID,
			"organization_id": batch.OrganizationID,
			"total_packages":  batch.TotalPackages,
			"successful":      batch.SuccessCount,
			"failed":          batch.FailureCount,
			"duration":        batch.CompletedAt.Sub(*batch.StartedAt).Seconds(),
		},
	})

	// Update metrics
	bp.metrics.BatchJobsTotal.WithLabelValues("completed").Inc()
	bp.metrics.BatchJobDuration.Observe(batch.CompletedAt.Sub(*batch.StartedAt).Seconds())

	log.Printf("Completed batch job %s: %d successful, %d failed out of %d total",
		batch.ID, batch.SuccessCount, batch.FailureCount, batch.TotalPackages)
}

// failBatchJob marks a batch job as failed
func (bp *BatchProcessor) failBatchJob(batch *types.BatchJob, errorMessage string) {
	now := time.Now()
	batch.Status = string(BatchStatusFailed)
	batch.CompletedAt = &now
	batch.UpdatedAt = now
	batch.ErrorMessage = errorMessage

	if err := bp.db.UpdateBatchJob(batch); err != nil {
		log.Printf("Failed to update failed batch job: %v", err)
		return
	}

	// Publish failure event
	bp.eventBus.Publish(&events.Event{
		Type: events.BatchFailed,
		Data: map[string]interface{}{
			"batch_id":        batch.ID,
			"organization_id": batch.OrganizationID,
			"error":           errorMessage,
			"processed":       batch.ProcessedCount,
			"total":           batch.TotalPackages,
		},
	})

	// Update metrics
	bp.metrics.BatchJobsTotal.WithLabelValues("failed").Inc()

	log.Printf("Failed batch job %s: %s", batch.ID, errorMessage)
}

// createBatchPackages creates batch package records
func (bp *BatchProcessor) createBatchPackages(batchID string, packages []string) error {
	batchPackages := make([]*BatchPackage, len(packages))

	for i, packageName := range packages {
		// Parse package name to extract registry and version if needed
		registry, name, version := bp.parsePackageName(packageName)

		batchPackages[i] = &BatchPackage{
			ID:          uuid.New().String(),
			BatchID:     batchID,
			PackageName: name,
			Registry:    registry,
			Version:     version,
			Status:      "pending",
			Metadata:    make(map[string]interface{}),
		}
	}

	return bp.db.CreateBatchPackages(batchPackages)
}

// parsePackageName parses a package name to extract registry, name, and version
func (bp *BatchProcessor) parsePackageName(packageName string) (registry, name, version string) {
	// Default registry
	registry = "npm"
	name = packageName
	version = "latest"

	// TODO: Implement more sophisticated parsing logic
	// This could parse package URLs, handle different registries, etc.

	return registry, name, version
}

// shouldStopBatch checks if a batch should be stopped
func (bp *BatchProcessor) shouldStopBatch(batchID string) bool {
	// Check Redis for stop signal
	stopKey := fmt.Sprintf("batch:stop:%s", batchID)
	result, err := bp.redis.Get(bp.ctx, stopKey).Result()
	if err == nil && result == "true" {
		return true
	}

	// Check context cancellation
	select {
	case <-bp.ctx.Done():
		return true
	default:
		return false
	}
}

// CancelBatchJob cancels a running batch job
func (bp *BatchProcessor) CancelBatchJob(batchID string) error {
	batch, err := bp.db.GetBatchJob(batchID)
	if err != nil {
		return fmt.Errorf("failed to get batch job: %w", err)
	}

	if batch.Status != string(BatchStatusRunning) {
		return fmt.Errorf("batch job %s is not running (current: %s)", batchID, batch.Status)
	}

	// Set stop signal in Redis
	stopKey := fmt.Sprintf("batch:stop:%s", batchID)
	bp.redis.Set(bp.ctx, stopKey, "true", time.Hour)

	// Update batch status
	now := time.Now()
	batch.Status = string(BatchStatusCancelled)
	batch.CompletedAt = &now
	batch.UpdatedAt = now

	if err := bp.db.UpdateBatchJob(batch); err != nil {
		return fmt.Errorf("failed to update batch job status: %w", err)
	}

	// Publish cancellation event
	bp.eventBus.Publish(&events.Event{
		Type: events.BatchCancelled,
		Data: map[string]interface{}{
			"batch_id":        batchID,
			"organization_id": batch.OrganizationID,
			"processed":       batch.ProcessedCount,
			"total":           batch.TotalPackages,
		},
	})

	// Update metrics
	bp.metrics.BatchJobsTotal.WithLabelValues("cancelled").Inc()

	log.Printf("Cancelled batch job %s", batchID)
	return nil
}

// GetBatchJob retrieves a batch job by ID
func (bp *BatchProcessor) GetBatchJob(batchID string) (*types.BatchJob, error) {
	return bp.db.GetBatchJob(batchID)
}

// GetBatchJobs retrieves batch jobs for an organization
func (bp *BatchProcessor) GetBatchJobs(organizationID string, limit, offset int) ([]*types.BatchJob, error) {
	return bp.db.GetBatchJobs(organizationID, limit, offset)
}

// GetActiveBatches returns currently active batch jobs
func (bp *BatchProcessor) GetActiveBatches() map[string]*types.BatchJob {
	bp.mu.RLock()
	defer bp.mu.RUnlock()

	active := make(map[string]*types.BatchJob)
	for id, batch := range bp.activeBatches {
		active[id] = batch
	}

	return active
}

// GetBatchStatus retrieves a batch job by ID (legacy method)
func (bp *BatchProcessor) GetBatchStatus(batchID string) (*types.BatchJob, error) {
	return bp.GetBatchJob(batchID)
}

// ListBatches retrieves batch jobs for an organization (legacy method)
func (bp *BatchProcessor) ListBatches(orgID string, limit, offset int) ([]*types.BatchJob, error) {
	return bp.GetBatchJobs(orgID, limit, offset)
}

// Shutdown gracefully shuts down the batch processor
func (bp *BatchProcessor) Shutdown() error {
	log.Println("Shutting down batch processor...")

	// Cancel context to stop all processing
	bp.cancel()

	// Wait for active batches to complete or timeout
	timeout := time.NewTimer(30 * time.Second)
	defer timeout.Stop()

	for {
		bp.mu.RLock()
		activeCount := len(bp.activeBatches)
		bp.mu.RUnlock()

		if activeCount == 0 {
			break
		}

		select {
		case <-timeout.C:
			log.Printf("Timeout waiting for %d active batches to complete", activeCount)
			return fmt.Errorf("timeout waiting for active batches to complete")
		default:
			time.Sleep(100 * time.Millisecond)
		}
	}

	log.Println("Batch processor shutdown complete")
	return nil
}