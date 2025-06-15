package worker

import (
	"context"
	"fmt"
	"log"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-redis/redis/v8"

	"github.com/typosentinel/typosentinel/internal/queue"
	"github.com/typosentinel/typosentinel/internal/scanner"
	"github.com/typosentinel/typosentinel/pkg/metrics"
	"github.com/typosentinel/typosentinel/pkg/types"
)

// WorkerStatus represents the status of a worker
type WorkerStatus int

const (
	WorkerIdle WorkerStatus = iota
	WorkerBusy
	WorkerStopping
	WorkerStopped
)

func (ws WorkerStatus) String() string {
	switch ws {
	case WorkerIdle:
		return "idle"
	case WorkerBusy:
		return "busy"
	case WorkerStopping:
		return "stopping"
	case WorkerStopped:
		return "stopped"
	default:
		return "unknown"
	}
}

// Worker represents a single worker in the pool
type Worker struct {
	ID           int                    `json:"id"`
	Status       WorkerStatus           `json:"status"`
	CurrentTask  *queue.ScanRequest     `json:"current_task,omitempty"`
	TasksProcessed int64                `json:"tasks_processed"`
	LastActivity time.Time              `json:"last_activity"`
	StartTime    time.Time              `json:"start_time"`
	ErrorCount   int64                  `json:"error_count"`
	ctx          context.Context        `json:"-"`
	cancel       context.CancelFunc     `json:"-"`
	mu           sync.RWMutex           `json:"-"`
}

// WorkerPool manages a pool of workers for processing scan requests
type WorkerPool struct {
	workers        []*Worker
	queue          *queue.ScannerQueue
	scanner        scanner.Scanner
	redis          *redis.Client
	metrics        *metrics.Metrics
	config         WorkerPoolConfig
	ctx            context.Context
	cancel         context.CancelFunc
	mu             sync.RWMutex
	running        bool
	wg             sync.WaitGroup
	totalProcessed int64
	totalErrors    int64
	startTime      time.Time
	healthChecker  *HealthChecker
}

// WorkerPoolConfig holds configuration for the worker pool
type WorkerPoolConfig struct {
	MinWorkers       int           `json:"min_workers"`
	MaxWorkers       int           `json:"max_workers"`
	InitialWorkers   int           `json:"initial_workers"`
	TaskTimeout      time.Duration `json:"task_timeout"`
	IdleTimeout      time.Duration `json:"idle_timeout"`
	HealthCheckInterval time.Duration `json:"health_check_interval"`
	MaxErrorRate     float64       `json:"max_error_rate"`
	ScaleUpThreshold float64       `json:"scale_up_threshold"`
	ScaleDownThreshold float64     `json:"scale_down_threshold"`
	AutoScale        bool          `json:"auto_scale"`
}

// HealthChecker monitors worker health
type HealthChecker struct {
	pool     *WorkerPool
	interval time.Duration
	ctx      context.Context
	cancel   context.CancelFunc
}

// WorkerStats provides statistics about worker performance
type WorkerStats struct {
	TotalWorkers     int                    `json:"total_workers"`
	ActiveWorkers    int                    `json:"active_workers"`
	IdleWorkers      int                    `json:"idle_workers"`
	BusyWorkers      int                    `json:"busy_workers"`
	TotalProcessed   int64                  `json:"total_processed"`
	TotalErrors      int64                  `json:"total_errors"`
	ErrorRate        float64                `json:"error_rate"`
	Uptime           time.Duration          `json:"uptime"`
	AverageTaskTime  time.Duration          `json:"average_task_time"`
	WorkerDetails    []WorkerDetail         `json:"worker_details"`
}

// WorkerDetail provides detailed information about a worker
type WorkerDetail struct {
	ID             int           `json:"id"`
	Status         string        `json:"status"`
	TasksProcessed int64         `json:"tasks_processed"`
	ErrorCount     int64         `json:"error_count"`
	Uptime         time.Duration `json:"uptime"`
	LastActivity   time.Time     `json:"last_activity"`
	CurrentTask    string        `json:"current_task,omitempty"`
}

// NewWorkerPool creates a new worker pool
func NewWorkerPool(config WorkerPoolConfig, queue *queue.ScannerQueue, scanner scanner.Scanner, redis *redis.Client) *WorkerPool {
	ctx, cancel := context.WithCancel(context.Background())

	// Set default values
	if config.MinWorkers == 0 {
		config.MinWorkers = 1
	}
	if config.MaxWorkers == 0 {
		config.MaxWorkers = runtime.NumCPU() * 2
	}
	if config.InitialWorkers == 0 {
		config.InitialWorkers = runtime.NumCPU()
	}
	if config.TaskTimeout == 0 {
		config.TaskTimeout = 5 * time.Minute
	}
	if config.IdleTimeout == 0 {
		config.IdleTimeout = 10 * time.Minute
	}
	if config.HealthCheckInterval == 0 {
		config.HealthCheckInterval = 30 * time.Second
	}
	if config.MaxErrorRate == 0 {
		config.MaxErrorRate = 0.1 // 10%
	}
	if config.ScaleUpThreshold == 0 {
		config.ScaleUpThreshold = 0.8 // 80% utilization
	}
	if config.ScaleDownThreshold == 0 {
		config.ScaleDownThreshold = 0.3 // 30% utilization
	}

	// Validate configuration
	if config.InitialWorkers < config.MinWorkers {
		config.InitialWorkers = config.MinWorkers
	}
	if config.InitialWorkers > config.MaxWorkers {
		config.InitialWorkers = config.MaxWorkers
	}

	pool := &WorkerPool{
		workers:   make([]*Worker, 0, config.MaxWorkers),
		queue:     queue,
		scanner:   scanner,
		redis:     redis,
		metrics:   metrics.GetInstance(),
		config:    config,
		ctx:       ctx,
		cancel:    cancel,
		startTime: time.Now(),
	}

	// Create health checker
	healthCtx, healthCancel := context.WithCancel(ctx)
	pool.healthChecker = &HealthChecker{
		pool:     pool,
		interval: config.HealthCheckInterval,
		ctx:      healthCtx,
		cancel:   healthCancel,
	}

	return pool
}

// Start starts the worker pool
func (wp *WorkerPool) Start() error {
	wp.mu.Lock()
	defer wp.mu.Unlock()

	if wp.running {
		return fmt.Errorf("worker pool is already running")
	}

	// Start initial workers
	for i := 0; i < wp.config.InitialWorkers; i++ {
		if err := wp.addWorkerUnsafe(); err != nil {
			log.Printf("Failed to start worker %d: %v", i, err)
			return err
		}
	}

	wp.running = true

	// Start health checker
	go wp.healthChecker.start()

	// Start auto-scaling if enabled
	if wp.config.AutoScale {
		go wp.autoScaleWorker()
	}

	log.Printf("Worker pool started with %d workers", len(wp.workers))
	return nil
}

// Stop gracefully stops the worker pool
func (wp *WorkerPool) Stop() error {
	wp.mu.Lock()
	defer wp.mu.Unlock()

	if !wp.running {
		return fmt.Errorf("worker pool is not running")
	}

	log.Println("Stopping worker pool...")

	// Stop health checker
	wp.healthChecker.cancel()

	// Cancel context to signal all workers to stop
	wp.cancel()

	// Wait for all workers to finish
	wp.wg.Wait()

	wp.running = false
	log.Printf("Worker pool stopped. Processed %d tasks with %d errors", wp.totalProcessed, wp.totalErrors)
	return nil
}

// addWorkerUnsafe adds a new worker (caller must hold lock)
func (wp *WorkerPool) addWorkerUnsafe() error {
	if len(wp.workers) >= wp.config.MaxWorkers {
		return fmt.Errorf("maximum number of workers (%d) reached", wp.config.MaxWorkers)
	}

	workerID := len(wp.workers) + 1
	workerCtx, workerCancel := context.WithCancel(wp.ctx)

	worker := &Worker{
		ID:        workerID,
		Status:    WorkerIdle,
		StartTime: time.Now(),
		LastActivity: time.Now(),
		ctx:       workerCtx,
		cancel:    workerCancel,
	}

	wp.workers = append(wp.workers, worker)
	wp.wg.Add(1)

	// Start worker goroutine
	go wp.runWorker(worker)

	log.Printf("Added worker %d (total: %d)", workerID, len(wp.workers))
	return nil
}

// AddWorker adds a new worker to the pool
func (wp *WorkerPool) AddWorker() error {
	wp.mu.Lock()
	defer wp.mu.Unlock()

	if !wp.running {
		return fmt.Errorf("worker pool is not running")
	}

	return wp.addWorkerUnsafe()
}

// RemoveWorker removes a worker from the pool
func (wp *WorkerPool) RemoveWorker() error {
	wp.mu.Lock()
	defer wp.mu.Unlock()

	if !wp.running {
		return fmt.Errorf("worker pool is not running")
	}

	if len(wp.workers) <= wp.config.MinWorkers {
		return fmt.Errorf("minimum number of workers (%d) reached", wp.config.MinWorkers)
	}

	// Find an idle worker to remove
	for i := len(wp.workers) - 1; i >= 0; i-- {
		worker := wp.workers[i]
		worker.mu.RLock()
		status := worker.Status
		worker.mu.RUnlock()

		if status == WorkerIdle {
			// Mark worker as stopping
			worker.mu.Lock()
			worker.Status = WorkerStopping
			worker.mu.Unlock()

			// Cancel worker context
			worker.cancel()

			// Remove from slice
			wp.workers = append(wp.workers[:i], wp.workers[i+1:]...)

			log.Printf("Removed worker %d (total: %d)", worker.ID, len(wp.workers))
			return nil
		}
	}

	return fmt.Errorf("no idle workers available for removal")
}

// runWorker runs a single worker
func (wp *WorkerPool) runWorker(worker *Worker) {
	defer wp.wg.Done()
	defer func() {
		worker.mu.Lock()
		worker.Status = WorkerStopped
		worker.mu.Unlock()
	}()

	log.Printf("Worker %d started", worker.ID)

	for {
		select {
		case <-worker.ctx.Done():
			log.Printf("Worker %d stopped", worker.ID)
			return
		default:
			// Try to get a task from the queue
			task, err := wp.queue.DequeueRequest(worker.ctx, 5*time.Second)
			if err != nil {
				if err == context.Canceled || err == context.DeadlineExceeded {
					continue
				}
				log.Printf("Worker %d failed to dequeue task: %v", worker.ID, err)
				continue
			}

			if task == nil {
				// No task available, continue polling
				continue
			}

			// Process the task
			wp.processTask(worker, task)
		}
	}
}

// processTask processes a single task
func (wp *WorkerPool) processTask(worker *Worker, task *queue.ScanRequest) {
	// Update worker status
	worker.mu.Lock()
	worker.Status = WorkerBusy
	worker.CurrentTask = task
	worker.LastActivity = time.Now()
	worker.mu.Unlock()

	// Update metrics
	wp.metrics.WorkerPoolActiveTasks.WithLabelValues("default").Inc()
	wp.metrics.WorkerPoolTasksTotal.WithLabelValues("started").Inc()

	start := time.Now()

	defer func() {
		// Update worker status
		worker.mu.Lock()
		worker.Status = WorkerIdle
		worker.CurrentTask = nil
		worker.TasksProcessed++
		worker.LastActivity = time.Now()
		worker.mu.Unlock()

		// Update metrics
		wp.metrics.WorkerPoolActiveTasks.WithLabelValues("default").Dec()
		wp.metrics.WorkerPoolTaskDuration.Observe(time.Since(start).Seconds())
		atomic.AddInt64(&wp.totalProcessed, 1)
	}()

	// Create task context with timeout
	_, taskCancel := context.WithTimeout(worker.ctx, wp.config.TaskTimeout)
	defer taskCancel()

	// Process the scan request
	result, err := wp.scanner.ScanProject(task.PackageName)
	if err != nil {
		log.Printf("Worker %d failed to scan package %s: %v", worker.ID, task.PackageName, err)
		
		// Update error counts
		worker.mu.Lock()
		worker.ErrorCount++
		worker.mu.Unlock()
		atomic.AddInt64(&wp.totalErrors, 1)

		// Update metrics
		wp.metrics.WorkerPoolTasksTotal.WithLabelValues("failed").Inc()
		wp.metrics.WorkerPoolErrors.WithLabelValues(worker.ctx.Value("worker_id").(string)).Inc()

		// Handle task failure (retry logic would be implemented here)
		wp.handleTaskFailure(task, err)
		return
	}

	// Update metrics for successful task
	wp.metrics.WorkerPoolTasksTotal.WithLabelValues("completed").Inc()

	// Handle successful result
	wp.handleTaskSuccess(task, result)

	log.Printf("Worker %d completed scan for package %s in %v", worker.ID, task.PackageName, time.Since(start))
}

// handleTaskSuccess handles a successful task completion
func (wp *WorkerPool) handleTaskSuccess(task *queue.ScanRequest, result *types.ScanResult) {
	// Store result in Redis
	resultKey := fmt.Sprintf("scan_result:%s:%s", task.PackageName, task.Version)
	resultData := map[string]interface{}{
		"package_name": task.PackageName,
		"version":      task.Version,
		"scan_time":    time.Now().Unix(),
		"summary":      result.Summary,
		"status":       result.Status,
		"target":       result.Target,
	}

	wp.redis.HMSet(wp.ctx, resultKey, resultData)
	wp.redis.Expire(wp.ctx, resultKey, 24*time.Hour) // Keep results for 24 hours

	// Publish result event
	eventData := map[string]interface{}{
		"type":           "scan_completed",
		"package_name":   task.PackageName,
		"version":        task.Version,
		"organization_id": task.OrganizationID,
		"result":         result,
		"timestamp":      time.Now().Unix(),
	}

	wp.redis.Publish(wp.ctx, "scan_events", eventData)
}

// handleTaskFailure handles a failed task
func (wp *WorkerPool) handleTaskFailure(task *queue.ScanRequest, err error) {
	// Store failure information
	failureKey := fmt.Sprintf("scan_failure:%s:%s", task.PackageName, task.Version)
	failureData := map[string]interface{}{
		"package_name":   task.PackageName,
		"version":        task.Version,
		"error":          err.Error(),
		"failure_time":   time.Now().Unix(),
		"retry_count":    task.RetryCount,
		"status":         "failed",
	}

	wp.redis.HMSet(wp.ctx, failureKey, failureData)
	wp.redis.Expire(wp.ctx, failureKey, 24*time.Hour)

	// Publish failure event
	eventData := map[string]interface{}{
		"type":           "scan_failed",
		"package_name":   task.PackageName,
		"version":        task.Version,
		"organization_id": task.OrganizationID,
		"error":          err.Error(),
		"timestamp":      time.Now().Unix(),
	}

	wp.redis.Publish(wp.ctx, "scan_events", eventData)

	// Implement retry logic if needed
	if task.RetryCount < task.MaxRetries {
		task.RetryCount++
		// Re-enqueue with delay
		go func() {
			time.Sleep(time.Duration(task.RetryCount) * time.Minute)
			wp.queue.EnqueueScan(task)
		}()
	}
}

// autoScaleWorker handles automatic scaling of workers
func (wp *WorkerPool) autoScaleWorker() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-wp.ctx.Done():
			return
		case <-ticker.C:
			wp.evaluateScaling()
		}
	}
}

// evaluateScaling evaluates whether to scale workers up or down
func (wp *WorkerPool) evaluateScaling() {
	stats := wp.GetStats()

	// Calculate utilization
	utilization := float64(stats.BusyWorkers) / float64(stats.TotalWorkers)

	// Scale up if utilization is high
	if utilization > wp.config.ScaleUpThreshold && stats.TotalWorkers < wp.config.MaxWorkers {
		if err := wp.AddWorker(); err != nil {
			log.Printf("Failed to scale up workers: %v", err)
		} else {
			log.Printf("Scaled up workers due to high utilization (%.2f%%)", utilization*100)
		}
	}

	// Scale down if utilization is low
	if utilization < wp.config.ScaleDownThreshold && stats.TotalWorkers > wp.config.MinWorkers {
		if err := wp.RemoveWorker(); err != nil {
			log.Printf("Failed to scale down workers: %v", err)
		} else {
			log.Printf("Scaled down workers due to low utilization (%.2f%%)", utilization*100)
		}
	}
}

// GetStats returns current worker pool statistics
func (wp *WorkerPool) GetStats() WorkerStats {
	wp.mu.RLock()
	defer wp.mu.RUnlock()

	stats := WorkerStats{
		TotalWorkers:   len(wp.workers),
		TotalProcessed: atomic.LoadInt64(&wp.totalProcessed),
		TotalErrors:    atomic.LoadInt64(&wp.totalErrors),
		Uptime:         time.Since(wp.startTime),
		WorkerDetails:  make([]WorkerDetail, 0, len(wp.workers)),
	}

	// Calculate error rate
	if stats.TotalProcessed > 0 {
		stats.ErrorRate = float64(stats.TotalErrors) / float64(stats.TotalProcessed)
	}

	// Collect worker details and count by status
	for _, worker := range wp.workers {
		worker.mu.RLock()
		status := worker.Status
		currentTask := ""
		if worker.CurrentTask != nil {
			currentTask = worker.CurrentTask.PackageName
		}

		detail := WorkerDetail{
			ID:             worker.ID,
			Status:         status.String(),
			TasksProcessed: worker.TasksProcessed,
			ErrorCount:     worker.ErrorCount,
			Uptime:         time.Since(worker.StartTime),
			LastActivity:   worker.LastActivity,
			CurrentTask:    currentTask,
		}
		stats.WorkerDetails = append(stats.WorkerDetails, detail)

		// Count by status
		switch status {
		case WorkerIdle:
			stats.IdleWorkers++
			stats.ActiveWorkers++
		case WorkerBusy:
			stats.BusyWorkers++
			stats.ActiveWorkers++
		}

		worker.mu.RUnlock()
	}

	return stats
}

// GetWorkerByID returns a worker by its ID
func (wp *WorkerPool) GetWorkerByID(id int) (*Worker, error) {
	wp.mu.RLock()
	defer wp.mu.RUnlock()

	for _, worker := range wp.workers {
		if worker.ID == id {
			return worker, nil
		}
	}

	return nil, fmt.Errorf("worker with ID %d not found", id)
}

// IsRunning returns whether the worker pool is running
func (wp *WorkerPool) IsRunning() bool {
	wp.mu.RLock()
	defer wp.mu.RUnlock()
	return wp.running
}

// start starts the health checker
func (hc *HealthChecker) start() {
	ticker := time.NewTicker(hc.interval)
	defer ticker.Stop()

	for {
		select {
		case <-hc.ctx.Done():
			return
		case <-ticker.C:
			hc.checkHealth()
		}
	}
}

// checkHealth performs health checks on workers
func (hc *HealthChecker) checkHealth() {
	hc.pool.mu.RLock()
	workers := make([]*Worker, len(hc.pool.workers))
	copy(workers, hc.pool.workers)
	hc.pool.mu.RUnlock()

	for _, worker := range workers {
		worker.mu.RLock()
		lastActivity := worker.LastActivity
		status := worker.Status
		worker.mu.RUnlock()

		// Check if worker has been idle too long
		if status == WorkerIdle && time.Since(lastActivity) > hc.pool.config.IdleTimeout {
			log.Printf("Worker %d has been idle for %v, considering for removal", worker.ID, time.Since(lastActivity))
			// Could implement idle worker removal here
		}

		// Check if worker is stuck
		if status == WorkerBusy && time.Since(lastActivity) > hc.pool.config.TaskTimeout*2 {
			log.Printf("Worker %d appears to be stuck, last activity: %v", worker.ID, lastActivity)
			// Could implement stuck worker recovery here
		}
	}

	// Update health metrics
	stats := hc.pool.GetStats()
	hc.pool.metrics.WorkerPoolWorkers.WithLabelValues("total").Set(float64(stats.TotalWorkers))
	hc.pool.metrics.WorkerPoolWorkers.WithLabelValues("active").Set(float64(stats.ActiveWorkers))
	hc.pool.metrics.WorkerPoolWorkers.WithLabelValues("idle").Set(float64(stats.IdleWorkers))
	hc.pool.metrics.WorkerPoolWorkers.WithLabelValues("busy").Set(float64(stats.BusyWorkers))
}