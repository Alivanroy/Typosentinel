package queue

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/google/uuid"

	"github.com/typosentinel/typosentinel/internal/scanner"
	"github.com/typosentinel/typosentinel/pkg/types"
	"github.com/typosentinel/typosentinel/pkg/metrics"
)

// Priority defines the priority levels for scan requests
type Priority string

const (
	PriorityCritical Priority = "critical"
	PriorityHigh     Priority = "high"
	PriorityNormal   Priority = "normal"
	PriorityLow      Priority = "low"
)

// ScanRequest represents a package scan request in the queue
type ScanRequest struct {
	ID             string            `json:"id"`
	PackageID      string            `json:"package_id"`
	PackageName    string            `json:"package_name"`
	Registry       string            `json:"registry"`
	Version        string            `json:"version"`
	Priority       Priority          `json:"priority"`
	Metadata       map[string]string `json:"metadata"`
	RequestedBy    string            `json:"requested_by"`
	OrganizationID string            `json:"organization_id"`
	Timestamp      time.Time         `json:"timestamp"`
	RetryCount     int               `json:"retry_count"`
	MaxRetries     int               `json:"max_retries"`
	Timeout        time.Duration     `json:"timeout"`
}

// ScanResult represents the result of a scan operation
type ScanResult struct {
	RequestID      string            `json:"request_id"`
	PackageID      string            `json:"package_id"`
	Success        bool              `json:"success"`
	Error          string            `json:"error,omitempty"`
	Result         *types.ScanResult `json:"result,omitempty"`
	ProcessedAt    time.Time         `json:"processed_at"`
	ProcessingTime time.Duration     `json:"processing_time"`
	WorkerID       int               `json:"worker_id"`
}

// ScannerQueue manages the queue-based processing system for package scans
type ScannerQueue struct {
	redis             *redis.Client
	scanner           *scanner.Scanner
	workers           int
	maxRetries        int
	retryDelay       time.Duration
	visibilityTimeout time.Duration
	pollInterval      time.Duration
	deadLetterQueue   bool
	ctx               context.Context
	cancel            context.CancelFunc
	wg                sync.WaitGroup
	mu                sync.RWMutex
	running           bool
	resultHandlers    []ResultHandler
	metrics           *metrics.Metrics
}

// ResultHandler defines the interface for handling scan results
type ResultHandler interface {
	HandleResult(result *ScanResult) error
}

// QueueStats represents queue statistics
type QueueStats struct {
	CriticalQueue int64 `json:"critical_queue"`
	HighQueue     int64 `json:"high_queue"`
	NormalQueue   int64 `json:"normal_queue"`
	LowQueue      int64 `json:"low_queue"`
	Processing    int64 `json:"processing"`
	DeadLetter    int64 `json:"dead_letter"`
	TotalWorkers  int   `json:"total_workers"`
	ActiveWorkers int   `json:"active_workers"`
}

// QueueConfig holds queue configuration
type QueueConfig struct {
	Workers           int
	MaxRetries        int
	RetryDelay        time.Duration
	VisibilityTimeout time.Duration
	PollInterval      time.Duration
	DeadLetterQueue   bool
}

// NewScannerQueue creates a new scanner queue instance
func NewScannerQueue(redis *redis.Client, scanner *scanner.Scanner, config QueueConfig) *ScannerQueue {
	ctx, cancel := context.WithCancel(context.Background())

	return &ScannerQueue{
		redis:             redis,
		scanner:           scanner,
		workers:           config.Workers,
		maxRetries:        config.MaxRetries,
		retryDelay:        config.RetryDelay,
		visibilityTimeout: config.VisibilityTimeout,
		pollInterval:      config.PollInterval,
		deadLetterQueue:   config.DeadLetterQueue,
		ctx:               ctx,
		cancel:            cancel,
		resultHandlers:    make([]ResultHandler, 0),
		metrics:           metrics.GetInstance(),
	}
}

// EnqueueScan adds a scan request to the appropriate priority queue
func (sq *ScannerQueue) EnqueueScan(req *ScanRequest) error {
	if req.ID == "" {
		req.ID = uuid.New().String()
	}

	if req.Timestamp.IsZero() {
		req.Timestamp = time.Now()
	}

	if req.MaxRetries == 0 {
		req.MaxRetries = sq.maxRetries
	}

	// Validate request
	if err := sq.validateScanRequest(req); err != nil {
		return fmt.Errorf("invalid scan request: %w", err)
	}

	// Serialize request
	data, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("failed to marshal scan request: %w", err)
	}

	// Determine queue name based on priority
	queueName := fmt.Sprintf("scan_queue:%s", req.Priority)

	// Add to queue with score for priority ordering
	score := sq.calculatePriorityScore(req)
	err = sq.redis.ZAdd(sq.ctx, queueName, &redis.Z{
		Score:  score,
		Member: data,
	}).Err()

	if err != nil {
		return fmt.Errorf("failed to enqueue scan request: %w", err)
	}

	// Update metrics
	sq.metrics.QueueSize.WithLabelValues(string(req.Priority)).Inc()
	sq.metrics.PackageScansTotal.WithLabelValues("queued", req.Registry).Inc()

	log.Printf("Enqueued scan request %s for package %s with priority %s", req.ID, req.PackageName, req.Priority)
	return nil
}

// StartWorkers starts the specified number of worker goroutines
func (sq *ScannerQueue) StartWorkers() error {
	sq.mu.Lock()
	defer sq.mu.Unlock()

	if sq.running {
		return fmt.Errorf("workers are already running")
	}

	sq.running = true

	for i := 0; i < sq.workers; i++ {
		sq.wg.Add(1)
		go sq.worker(i)
	}

	// Start cleanup worker
	sq.StartCleanupWorker()

	log.Printf("Started %d scanner queue workers", sq.workers)
	return nil
}

// StopWorkers gracefully stops all worker goroutines
func (sq *ScannerQueue) StopWorkers() error {
	sq.mu.Lock()
	defer sq.mu.Unlock()

	if !sq.running {
		return fmt.Errorf("workers are not running")
	}

	sq.running = false
	sq.cancel()
	sq.wg.Wait()

	log.Println("Stopped all scanner queue workers")
	return nil
}

// worker is the main worker goroutine that processes scan requests
func (sq *ScannerQueue) worker(id int) {
	defer sq.wg.Done()

	log.Printf("Worker %d started", id)
	defer log.Printf("Worker %d stopped", id)

	// Priority order: critical > high > normal > low
	queues := []string{"scan_queue:critical", "scan_queue:high", "scan_queue:normal", "scan_queue:low"}

	for {
		select {
		case <-sq.ctx.Done():
			return
		default:
			// Try to get a request from priority queues
			req, err := sq.dequeueRequest(queues)
			if err != nil {
				if err == redis.Nil {
					// No requests available, wait before polling again
					time.Sleep(sq.pollInterval)
					continue
				}
				log.Printf("Worker %d: Queue error: %v", id, err)
				time.Sleep(sq.pollInterval)
				continue
			}

			if req == nil {
				time.Sleep(sq.pollInterval)
				continue
			}

			// Process the scan request
			sq.processScan(id, req)
		}
	}
}

// processScan processes a single scan request
func (sq *ScannerQueue) processScan(workerID int, req *ScanRequest) {
	startTime := time.Now()
	log.Printf("Worker %d: Processing scan request %s for package %s", workerID, req.ID, req.PackageName)

	// Create package object
	pkg := &types.Package{
		Name:     req.PackageName,
		Registry: req.Registry,
		Version:  req.Version,
		Metadata: &types.PackageMetadata{
			Name:     req.PackageName,
			Version:  req.Version,
			Registry: req.Registry,
			Metadata: make(map[string]interface{}),
		},
	}

	// Perform the scan
	scanResult, err := sq.scanner.ScanProject(pkg.Name)
	processingTime := time.Since(startTime)

	// Create result object
	result := &ScanResult{
		RequestID:      req.ID,
		PackageID:      req.PackageID,
		Success:        err == nil,
		Result:         scanResult,
		ProcessedAt:    time.Now(),
		ProcessingTime: processingTime,
		WorkerID:       workerID,
	}

	if err != nil {
		result.Error = err.Error()
		log.Printf("Worker %d: Scan failed for request %s: %v", workerID, req.ID, err)

		// Handle retry logic
		if req.RetryCount < req.MaxRetries {
			sq.retryRequest(req)
			sq.removeFromProcessing(req)
			return
		}

		// Move to dead letter queue if retries exhausted
		if sq.deadLetterQueue {
			sq.moveToDeadLetter(req, err)
		}

		// Update metrics
		sq.metrics.PackageScansTotal.WithLabelValues("failed", req.Registry).Inc()
	} else {
		log.Printf("Worker %d: Scan completed for request %s in %v", workerID, req.ID, processingTime)
		// Update metrics
		sq.metrics.PackageScansTotal.WithLabelValues("completed", req.Registry).Inc()
		sq.metrics.ScanDuration.WithLabelValues(req.Registry).Observe(processingTime.Seconds())
	}

	// Remove from processing queue
	sq.removeFromProcessing(req)

	// Handle the result
	sq.handleResult(result)
}

func (sq *ScannerQueue) Stop() {
	sq.cancel()
}