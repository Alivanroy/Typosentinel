package orchestrator

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/go-redis/redis/v8"
)

// JobStatus represents the status of a scan job
type JobStatus string

const (
	JobStatusPending   JobStatus = "pending"
	JobStatusRunning   JobStatus = "running"
	JobStatusCompleted JobStatus = "completed"
	JobStatusFailed    JobStatus = "failed"
	JobStatusCancelled JobStatus = "cancelled"
	JobStatusRetrying  JobStatus = "retrying"
)

// JobPriority represents the priority level of a scan job
type JobPriority int

const (
	PriorityLow      JobPriority = 1
	PriorityNormal   JobPriority = 5
	PriorityHigh     JobPriority = 10
	PriorityCritical JobPriority = 15
)

// ScanJob represents a repository scanning job
type ScanJob struct {
	ID          string                 `json:"id"`
	Type        string                 `json:"type"`     // "repository", "organization", "bulk"
	Platform    string                 `json:"platform"` // "github", "gitlab", "bitbucket", "azure_devops"
	Target      string                 `json:"target"`   // Repository URL or organization name
	Options     map[string]interface{} `json:"options"`
	Priority    JobPriority            `json:"priority"`
	Status      JobStatus              `json:"status"`
	CreatedAt   time.Time              `json:"created_at"`
	StartedAt   *time.Time             `json:"started_at,omitempty"`
	CompletedAt *time.Time             `json:"completed_at,omitempty"`
	RetryCount  int                    `json:"retry_count"`
	MaxRetries  int                    `json:"max_retries"`
	Error       string                 `json:"error,omitempty"`
	Result      map[string]interface{} `json:"result,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
	ScheduledBy string                 `json:"scheduled_by"`
	WorkerID    string                 `json:"worker_id,omitempty"`
}

// JobQueue interface defines the contract for job queue implementations
type JobQueue interface {
	// Enqueue adds a job to the queue
	Enqueue(ctx context.Context, job *ScanJob) error

	// Dequeue retrieves the next job from the queue
	Dequeue(ctx context.Context, workerID string) (*ScanJob, error)

	// UpdateStatus updates the status of a job
	UpdateStatus(ctx context.Context, jobID string, status JobStatus, error string) error

	// GetJob retrieves a job by ID
	GetJob(ctx context.Context, jobID string) (*ScanJob, error)

	// ListJobs lists jobs with optional filters
	ListJobs(ctx context.Context, filters map[string]interface{}) ([]*ScanJob, error)

	// DeleteJob removes a job from the queue
	DeleteJob(ctx context.Context, jobID string) error

	// GetQueueStats returns queue statistics
	GetQueueStats(ctx context.Context) (*QueueStats, error)

	// Close closes the queue connection
	Close() error
}

// QueueStats represents queue statistics
type QueueStats struct {
	PendingJobs        int64         `json:"pending_jobs"`
	RunningJobs        int64         `json:"running_jobs"`
	CompletedJobs      int64         `json:"completed_jobs"`
	FailedJobs         int64         `json:"failed_jobs"`
	TotalJobs          int64         `json:"total_jobs"`
	AverageWaitTime    time.Duration `json:"average_wait_time"`
	AverageProcessTime time.Duration `json:"average_process_time"`
}

// RedisJobQueue implements JobQueue using Redis
type RedisJobQueue struct {
	client    *redis.Client
	queueKey  string
	jobPrefix string
	mu        sync.RWMutex
}

// NewRedisJobQueue creates a new Redis-based job queue
func NewRedisJobQueue(redisURL, queueKey string) (*RedisJobQueue, error) {
	opts, err := redis.ParseURL(redisURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse Redis URL: %w", err)
	}

	client := redis.NewClient(opts)

	// Test connection
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := client.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("failed to connect to Redis: %w", err)
	}

	return &RedisJobQueue{
		client:    client,
		queueKey:  queueKey,
		jobPrefix: "job:",
	}, nil
}

// Enqueue adds a job to the Redis queue
func (q *RedisJobQueue) Enqueue(ctx context.Context, job *ScanJob) error {
	q.mu.Lock()
	defer q.mu.Unlock()

	// Serialize job
	jobData, err := json.Marshal(job)
	if err != nil {
		return fmt.Errorf("failed to marshal job: %w", err)
	}

	// Store job data
	jobKey := q.jobPrefix + job.ID
	if err := q.client.Set(ctx, jobKey, jobData, 24*time.Hour).Err(); err != nil {
		return fmt.Errorf("failed to store job: %w", err)
	}

	// Add to priority queue (using sorted set with priority as score)
	score := float64(job.Priority)*1000000 + float64(job.CreatedAt.Unix())
	if err := q.client.ZAdd(ctx, q.queueKey, &redis.Z{
		Score:  score,
		Member: job.ID,
	}).Err(); err != nil {
		return fmt.Errorf("failed to enqueue job: %w", err)
	}

	log.Printf("Job %s enqueued with priority %d", job.ID, job.Priority)
	return nil
}

// Dequeue retrieves the next job from the Redis queue
func (q *RedisJobQueue) Dequeue(ctx context.Context, workerID string) (*ScanJob, error) {
	q.mu.Lock()
	defer q.mu.Unlock()

	// Get highest priority job (ZPOPMAX)
	result := q.client.ZPopMax(ctx, q.queueKey, 1)
	if result.Err() != nil {
		if result.Err() == redis.Nil {
			return nil, nil // No jobs available
		}
		return nil, fmt.Errorf("failed to dequeue job: %w", result.Err())
	}

	if len(result.Val()) == 0 {
		return nil, nil // No jobs available
	}

	jobID := result.Val()[0].Member.(string)

	// Retrieve job data
	jobKey := q.jobPrefix + jobID
	jobData, err := q.client.Get(ctx, jobKey).Result()
	if err != nil {
		if err == redis.Nil {
			return nil, fmt.Errorf("job %s not found", jobID)
		}
		return nil, fmt.Errorf("failed to get job data: %w", err)
	}

	// Deserialize job
	var job ScanJob
	if err := json.Unmarshal([]byte(jobData), &job); err != nil {
		return nil, fmt.Errorf("failed to unmarshal job: %w", err)
	}

	// Update job status to running
	now := time.Now()
	job.Status = JobStatusRunning
	job.StartedAt = &now
	job.WorkerID = workerID

	// Save updated job
	updatedData, err := json.Marshal(&job)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal updated job: %w", err)
	}

	if err := q.client.Set(ctx, jobKey, updatedData, 24*time.Hour).Err(); err != nil {
		return nil, fmt.Errorf("failed to update job: %w", err)
	}

	log.Printf("Job %s dequeued by worker %s", jobID, workerID)
	return &job, nil
}

// UpdateStatus updates the status of a job
func (q *RedisJobQueue) UpdateStatus(ctx context.Context, jobID string, status JobStatus, errorMsg string) error {
	q.mu.Lock()
	defer q.mu.Unlock()

	jobKey := q.jobPrefix + jobID

	// Get current job
	jobData, err := q.client.Get(ctx, jobKey).Result()
	if err != nil {
		return fmt.Errorf("failed to get job: %w", err)
	}

	var job ScanJob
	if err := json.Unmarshal([]byte(jobData), &job); err != nil {
		return fmt.Errorf("failed to unmarshal job: %w", err)
	}

	// Update status
	job.Status = status
	if errorMsg != "" {
		job.Error = errorMsg
	}

	if status == JobStatusCompleted || status == JobStatusFailed || status == JobStatusCancelled {
		now := time.Now()
		job.CompletedAt = &now
	}

	// Save updated job
	updatedData, err := json.Marshal(&job)
	if err != nil {
		return fmt.Errorf("failed to marshal job: %w", err)
	}

	if err := q.client.Set(ctx, jobKey, updatedData, 24*time.Hour).Err(); err != nil {
		return fmt.Errorf("failed to update job: %w", err)
	}

	log.Printf("Job %s status updated to %s", jobID, status)
	return nil
}

// GetJob retrieves a job by ID
func (q *RedisJobQueue) GetJob(ctx context.Context, jobID string) (*ScanJob, error) {
	q.mu.RLock()
	defer q.mu.RUnlock()

	jobKey := q.jobPrefix + jobID
	jobData, err := q.client.Get(ctx, jobKey).Result()
	if err != nil {
		if err == redis.Nil {
			return nil, fmt.Errorf("job %s not found", jobID)
		}
		return nil, fmt.Errorf("failed to get job: %w", err)
	}

	var job ScanJob
	if err := json.Unmarshal([]byte(jobData), &job); err != nil {
		return nil, fmt.Errorf("failed to unmarshal job: %w", err)
	}

	return &job, nil
}

// ListJobs lists jobs with optional filters
func (q *RedisJobQueue) ListJobs(ctx context.Context, filters map[string]interface{}) ([]*ScanJob, error) {
	q.mu.RLock()
	defer q.mu.RUnlock()

	// Get all job keys
	keys, err := q.client.Keys(ctx, q.jobPrefix+"*").Result()
	if err != nil {
		return nil, fmt.Errorf("failed to get job keys: %w", err)
	}

	var jobs []*ScanJob
	for _, key := range keys {
		jobData, err := q.client.Get(ctx, key).Result()
		if err != nil {
			continue // Skip if job doesn't exist
		}

		var job ScanJob
		if err := json.Unmarshal([]byte(jobData), &job); err != nil {
			continue // Skip malformed jobs
		}

		// Apply filters
		if q.matchesFilters(&job, filters) {
			jobs = append(jobs, &job)
		}
	}

	return jobs, nil
}

// DeleteJob removes a job from the queue
func (q *RedisJobQueue) DeleteJob(ctx context.Context, jobID string) error {
	q.mu.Lock()
	defer q.mu.Unlock()

	jobKey := q.jobPrefix + jobID

	// Remove from queue
	q.client.ZRem(ctx, q.queueKey, jobID)

	// Delete job data
	if err := q.client.Del(ctx, jobKey).Err(); err != nil {
		return fmt.Errorf("failed to delete job: %w", err)
	}

	log.Printf("Job %s deleted", jobID)
	return nil
}

// GetQueueStats returns queue statistics
func (q *RedisJobQueue) GetQueueStats(ctx context.Context) (*QueueStats, error) {
	q.mu.RLock()
	defer q.mu.RUnlock()

	// Get pending jobs count
	pendingCount, err := q.client.ZCard(ctx, q.queueKey).Result()
	if err != nil {
		return nil, fmt.Errorf("failed to get pending jobs count: %w", err)
	}

	// Get all jobs for other statistics
	jobs, err := q.ListJobs(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to list jobs: %w", err)
	}

	stats := &QueueStats{
		PendingJobs: pendingCount,
		TotalJobs:   int64(len(jobs)),
	}

	// Calculate other statistics
	var totalWaitTime, totalProcessTime time.Duration
	var waitCount, processCount int

	for _, job := range jobs {
		switch job.Status {
		case JobStatusRunning:
			stats.RunningJobs++
		case JobStatusCompleted:
			stats.CompletedJobs++
			if job.StartedAt != nil {
				totalWaitTime += job.StartedAt.Sub(job.CreatedAt)
				waitCount++
			}
			if job.CompletedAt != nil && job.StartedAt != nil {
				totalProcessTime += job.CompletedAt.Sub(*job.StartedAt)
				processCount++
			}
		case JobStatusFailed, JobStatusCancelled:
			stats.FailedJobs++
		}
	}

	if waitCount > 0 {
		stats.AverageWaitTime = totalWaitTime / time.Duration(waitCount)
	}
	if processCount > 0 {
		stats.AverageProcessTime = totalProcessTime / time.Duration(processCount)
	}

	return stats, nil
}

// Close closes the Redis connection
func (q *RedisJobQueue) Close() error {
	return q.client.Close()
}

// matchesFilters checks if a job matches the given filters
func (q *RedisJobQueue) matchesFilters(job *ScanJob, filters map[string]interface{}) bool {
	if filters == nil {
		return true
	}

	for key, value := range filters {
		switch key {
		case "status":
			if statusValue, ok := value.(JobStatus); ok {
				if job.Status != statusValue {
					return false
				}
			} else if statusStr, ok := value.(string); ok {
				if job.Status != JobStatus(statusStr) {
					return false
				}
			} else {
				return false
			}
		case "platform":
			if job.Platform != value.(string) {
				return false
			}
		case "type":
			if job.Type != value.(string) {
				return false
			}
		case "scheduled_by":
			if job.ScheduledBy != value.(string) {
				return false
			}
		}
	}

	return true
}

// InMemoryJobQueue implements JobQueue using in-memory storage (for testing)
type InMemoryJobQueue struct {
	jobs  map[string]*ScanJob
	queue []*ScanJob
	mu    sync.RWMutex
}

// NewInMemoryJobQueue creates a new in-memory job queue
func NewInMemoryJobQueue() *InMemoryJobQueue {
	return &InMemoryJobQueue{
		jobs:  make(map[string]*ScanJob),
		queue: make([]*ScanJob, 0),
	}
}

// Enqueue adds a job to the in-memory queue
func (q *InMemoryJobQueue) Enqueue(ctx context.Context, job *ScanJob) error {
	q.mu.Lock()
	defer q.mu.Unlock()

	q.jobs[job.ID] = job
	q.queue = append(q.queue, job)

	// Sort by priority (higher priority first)
	for i := len(q.queue) - 1; i > 0; i-- {
		if q.queue[i].Priority > q.queue[i-1].Priority {
			q.queue[i], q.queue[i-1] = q.queue[i-1], q.queue[i]
		} else {
			break
		}
	}

	return nil
}

// Dequeue retrieves the next job from the in-memory queue
func (q *InMemoryJobQueue) Dequeue(ctx context.Context, workerID string) (*ScanJob, error) {
	q.mu.Lock()
	defer q.mu.Unlock()

	if len(q.queue) == 0 {
		return nil, nil
	}

	job := q.queue[0]
	q.queue = q.queue[1:]

	now := time.Now()
	job.Status = JobStatusRunning
	job.StartedAt = &now
	job.WorkerID = workerID

	return job, nil
}

// UpdateStatus updates the status of a job in memory
func (q *InMemoryJobQueue) UpdateStatus(ctx context.Context, jobID string, status JobStatus, errorMsg string) error {
	q.mu.Lock()
	defer q.mu.Unlock()

	job, exists := q.jobs[jobID]
	if !exists {
		return fmt.Errorf("job %s not found", jobID)
	}

	job.Status = status
	if errorMsg != "" {
		job.Error = errorMsg
	}

	if status == JobStatusCompleted || status == JobStatusFailed || status == JobStatusCancelled {
		now := time.Now()
		job.CompletedAt = &now
	}

	return nil
}

// GetJob retrieves a job by ID from memory
func (q *InMemoryJobQueue) GetJob(ctx context.Context, jobID string) (*ScanJob, error) {
	q.mu.RLock()
	defer q.mu.RUnlock()

	job, exists := q.jobs[jobID]
	if !exists {
		return nil, fmt.Errorf("job %s not found", jobID)
	}

	return job, nil
}

// ListJobs lists jobs from memory with optional filters
func (q *InMemoryJobQueue) ListJobs(ctx context.Context, filters map[string]interface{}) ([]*ScanJob, error) {
	q.mu.RLock()
	defer q.mu.RUnlock()

	var jobs []*ScanJob
	for _, job := range q.jobs {
		if q.matchesFiltersInMemory(job, filters) {
			jobs = append(jobs, job)
		}
	}

	return jobs, nil
}

// DeleteJob removes a job from memory
func (q *InMemoryJobQueue) DeleteJob(ctx context.Context, jobID string) error {
	q.mu.Lock()
	defer q.mu.Unlock()

	delete(q.jobs, jobID)

	// Remove from queue if still pending
	for i, job := range q.queue {
		if job.ID == jobID {
			q.queue = append(q.queue[:i], q.queue[i+1:]...)
			break
		}
	}

	return nil
}

// GetQueueStats returns queue statistics from memory
func (q *InMemoryJobQueue) GetQueueStats(ctx context.Context) (*QueueStats, error) {
	q.mu.RLock()
	defer q.mu.RUnlock()

	stats := &QueueStats{
		PendingJobs: int64(len(q.queue)),
		TotalJobs:   int64(len(q.jobs)),
	}

	var totalWaitTime, totalProcessTime time.Duration
	var waitCount, processCount int

	for _, job := range q.jobs {
		switch job.Status {
		case JobStatusRunning:
			stats.RunningJobs++
		case JobStatusCompleted:
			stats.CompletedJobs++
			if job.StartedAt != nil {
				totalWaitTime += job.StartedAt.Sub(job.CreatedAt)
				waitCount++
			}
			if job.CompletedAt != nil && job.StartedAt != nil {
				totalProcessTime += job.CompletedAt.Sub(*job.StartedAt)
				processCount++
			}
		case JobStatusFailed, JobStatusCancelled:
			stats.FailedJobs++
		}
	}

	if waitCount > 0 {
		stats.AverageWaitTime = totalWaitTime / time.Duration(waitCount)
	}
	if processCount > 0 {
		stats.AverageProcessTime = totalProcessTime / time.Duration(processCount)
	}

	return stats, nil
}

// Close is a no-op for in-memory queue
func (q *InMemoryJobQueue) Close() error {
	return nil
}

// matchesFiltersInMemory checks if a job matches the given filters (in-memory version)
func (q *InMemoryJobQueue) matchesFiltersInMemory(job *ScanJob, filters map[string]interface{}) bool {
	if filters == nil {
		return true
	}

	for key, value := range filters {
		switch key {
		case "status":
			if statusValue, ok := value.(JobStatus); ok {
				if job.Status != statusValue {
					return false
				}
			} else if statusStr, ok := value.(string); ok {
				if job.Status != JobStatus(statusStr) {
					return false
				}
			} else {
				return false
			}
		case "platform":
			if job.Platform != value.(string) {
				return false
			}
		case "type":
			if job.Type != value.(string) {
				return false
			}
		case "scheduled_by":
			if job.ScheduledBy != value.(string) {
				return false
			}
		}
	}

	return true
}
