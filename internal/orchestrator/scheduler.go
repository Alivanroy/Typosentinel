package orchestrator

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/Alivanroy/Typosentinel/internal/repository"
	"github.com/robfig/cron/v3"
)

// ScanScheduler manages scheduled repository scans
type ScanScheduler struct {
	cron       *cron.Cron
	queue      ScanQueue
	repository repository.RepositoryManager
	schedules  map[string]*ScheduledScan
	mu         sync.RWMutex
	running    bool
	logger     *log.Logger
	metrics    *SchedulerMetrics
}

// ScheduledScan represents a scheduled scan configuration
type ScheduledScan struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Schedule    string                 `json:"schedule"` // Cron expression
	Targets     []ScanTarget           `json:"targets"`
	Options     repository.ScanOptions `json:"options"`
	Output      []OutputConfig         `json:"output"`
	Policies    []PolicyConfig         `json:"policies"`
	Enabled     bool                   `json:"enabled"`
	CreatedAt   time.Time              `json:"created_at"`
	UpdatedAt   time.Time              `json:"updated_at"`
	LastRun     *time.Time             `json:"last_run,omitempty"`
	NextRun     *time.Time             `json:"next_run,omitempty"`
	RunCount    int64                  `json:"run_count"`
	CronID      cron.EntryID           `json:"-"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// ScanTarget represents a scan target configuration
type ScanTarget struct {
	Type         string                       `json:"type"` // github, gitlab, bitbucket, etc.
	Organization string                       `json:"organization,omitempty"`
	Group        string                       `json:"group,omitempty"`
	User         string                       `json:"user,omitempty"`
	Repositories []string                     `json:"repositories,omitempty"`
	IncludeAll   bool                         `json:"include_all"`
	Filter       *repository.RepositoryFilter `json:"filter,omitempty"`
	Branch       string                       `json:"branch,omitempty"`
	Metadata     map[string]interface{}       `json:"metadata"`
}

// OutputConfig represents output configuration
type OutputConfig struct {
	Format      string                 `json:"format"`
	Destination string                 `json:"destination"`
	Template    string                 `json:"template,omitempty"`
	Options     map[string]interface{} `json:"options,omitempty"`
}

// PolicyConfig represents policy configuration
type PolicyConfig struct {
	Name       string                 `json:"name"`
	Condition  string                 `json:"condition"`
	Action     string                 `json:"action"`
	Parameters map[string]interface{} `json:"parameters,omitempty"`
	Enabled    bool                   `json:"enabled"`
}

// SchedulerMetrics tracks scheduler performance
type SchedulerMetrics struct {
	TotalSchedules  int64         `json:"total_schedules"`
	ActiveSchedules int64         `json:"active_schedules"`
	TotalRuns       int64         `json:"total_runs"`
	SuccessfulRuns  int64         `json:"successful_runs"`
	FailedRuns      int64         `json:"failed_runs"`
	LastRunTime     time.Time     `json:"last_run_time"`
	AverageRunTime  time.Duration `json:"average_run_time"`
	QueueSize       int           `json:"queue_size"`
}

// ScanQueue interface for managing scan jobs
type ScanQueue interface {
	Enqueue(ctx context.Context, request *repository.ScanRequest) error
	Dequeue(ctx context.Context) (*repository.ScanRequest, error)
	Size(ctx context.Context) (int, error)
	Clear(ctx context.Context) error
	GetPending(ctx context.Context) ([]*repository.ScanRequest, error)
	GetInProgress(ctx context.Context) ([]*repository.ScanRequest, error)
	MarkCompleted(ctx context.Context, scanID string) error
	MarkFailed(ctx context.Context, scanID string, err error) error
}

// NewScanScheduler creates a new scan scheduler
func NewScanScheduler(queue ScanQueue, repoManager repository.RepositoryManager, logger *log.Logger) *ScanScheduler {
	c := cron.New(cron.WithSeconds())

	return &ScanScheduler{
		cron:       c,
		queue:      queue,
		repository: repoManager,
		schedules:  make(map[string]*ScheduledScan),
		logger:     logger,
		metrics:    &SchedulerMetrics{},
	}
}

// Start starts the scheduler
func (s *ScanScheduler) Start(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.running {
		return fmt.Errorf("scheduler is already running")
	}

	s.cron.Start()
	s.running = true
	s.logger.Println("Scan scheduler started")

	// Start metrics collection goroutine
	go s.collectMetrics(ctx)

	return nil
}

// Stop stops the scheduler
func (s *ScanScheduler) Stop() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.running {
		return fmt.Errorf("scheduler is not running")
	}

	ctx := s.cron.Stop()
	<-ctx.Done()
	s.running = false
	s.logger.Println("Scan scheduler stopped")

	return nil
}

// AddSchedule adds a new scheduled scan
func (s *ScanScheduler) AddSchedule(schedule *ScheduledScan) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.running {
		return fmt.Errorf("scheduler is not running")
	}

	if schedule.ID == "" {
		schedule.ID = generateScheduleID()
	}

	if schedule.CreatedAt.IsZero() {
		schedule.CreatedAt = time.Now()
	}
	schedule.UpdatedAt = time.Now()

	// Validate cron expression
	if _, err := cron.ParseStandard(schedule.Schedule); err != nil {
		return fmt.Errorf("invalid cron expression: %w", err)
	}

	// Add to cron scheduler
	entryID, err := s.cron.AddFunc(schedule.Schedule, func() {
		s.executeSchedule(schedule.ID)
	})
	if err != nil {
		return fmt.Errorf("failed to add schedule to cron: %w", err)
	}

	schedule.CronID = entryID
	s.schedules[schedule.ID] = schedule
	s.metrics.TotalSchedules++
	if schedule.Enabled {
		s.metrics.ActiveSchedules++
	}

	s.logger.Printf("Added scheduled scan: %s (%s)", schedule.Name, schedule.ID)
	return nil
}

// RemoveSchedule removes a scheduled scan
func (s *ScanScheduler) RemoveSchedule(scheduleID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	schedule, exists := s.schedules[scheduleID]
	if !exists {
		return fmt.Errorf("schedule not found: %s", scheduleID)
	}

	s.cron.Remove(schedule.CronID)
	delete(s.schedules, scheduleID)
	s.metrics.TotalSchedules--
	if schedule.Enabled {
		s.metrics.ActiveSchedules--
	}

	s.logger.Printf("Removed scheduled scan: %s (%s)", schedule.Name, scheduleID)
	return nil
}

// UpdateSchedule updates an existing scheduled scan
func (s *ScanScheduler) UpdateSchedule(schedule *ScheduledScan) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	existing, exists := s.schedules[schedule.ID]
	if !exists {
		return fmt.Errorf("schedule not found: %s", schedule.ID)
	}

	// Remove old cron job
	s.cron.Remove(existing.CronID)

	// Validate new cron expression
	if _, err := cron.ParseStandard(schedule.Schedule); err != nil {
		return fmt.Errorf("invalid cron expression: %w", err)
	}

	// Add new cron job
	entryID, err := s.cron.AddFunc(schedule.Schedule, func() {
		s.executeSchedule(schedule.ID)
	})
	if err != nil {
		return fmt.Errorf("failed to update schedule in cron: %w", err)
	}

	// Update metrics
	if existing.Enabled && !schedule.Enabled {
		s.metrics.ActiveSchedules--
	} else if !existing.Enabled && schedule.Enabled {
		s.metrics.ActiveSchedules++
	}

	schedule.CronID = entryID
	schedule.CreatedAt = existing.CreatedAt
	schedule.UpdatedAt = time.Now()
	schedule.RunCount = existing.RunCount
	s.schedules[schedule.ID] = schedule

	s.logger.Printf("Updated scheduled scan: %s (%s)", schedule.Name, schedule.ID)
	return nil
}

// GetSchedule gets a scheduled scan by ID
func (s *ScanScheduler) GetSchedule(scheduleID string) (*ScheduledScan, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	schedule, exists := s.schedules[scheduleID]
	if !exists {
		return nil, fmt.Errorf("schedule not found: %s", scheduleID)
	}

	// Create a copy to avoid race conditions
	scheduleCopy := *schedule
	return &scheduleCopy, nil
}

// ListSchedules lists all scheduled scans
func (s *ScanScheduler) ListSchedules() []*ScheduledScan {
	s.mu.RLock()
	defer s.mu.RUnlock()

	schedules := make([]*ScheduledScan, 0, len(s.schedules))
	for _, schedule := range s.schedules {
		// Create a copy to avoid race conditions
		scheduleCopy := *schedule
		schedules = append(schedules, &scheduleCopy)
	}

	return schedules
}

// EnableSchedule enables a scheduled scan
func (s *ScanScheduler) EnableSchedule(scheduleID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	schedule, exists := s.schedules[scheduleID]
	if !exists {
		return fmt.Errorf("schedule not found: %s", scheduleID)
	}

	if !schedule.Enabled {
		schedule.Enabled = true
		schedule.UpdatedAt = time.Now()
		s.metrics.ActiveSchedules++
		s.logger.Printf("Enabled scheduled scan: %s (%s)", schedule.Name, scheduleID)
	}

	return nil
}

// DisableSchedule disables a scheduled scan
func (s *ScanScheduler) DisableSchedule(scheduleID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	schedule, exists := s.schedules[scheduleID]
	if !exists {
		return fmt.Errorf("schedule not found: %s", scheduleID)
	}

	if schedule.Enabled {
		schedule.Enabled = false
		schedule.UpdatedAt = time.Now()
		s.metrics.ActiveSchedules--
		s.logger.Printf("Disabled scheduled scan: %s (%s)", schedule.Name, scheduleID)
	}

	return nil
}

// TriggerSchedule manually triggers a scheduled scan
func (s *ScanScheduler) TriggerSchedule(scheduleID string) error {
	s.mu.RLock()
	schedule, exists := s.schedules[scheduleID]
	s.mu.RUnlock()

	if !exists {
		return fmt.Errorf("schedule not found: %s", scheduleID)
	}

	go s.executeSchedule(scheduleID)
	s.logger.Printf("Manually triggered scheduled scan: %s (%s)", schedule.Name, scheduleID)
	return nil
}

// GetMetrics returns scheduler metrics
func (s *ScanScheduler) GetMetrics() *SchedulerMetrics {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Update queue size
	if queueSize, err := s.queue.Size(context.Background()); err == nil {
		s.metrics.QueueSize = queueSize
	}

	// Create a copy to avoid race conditions
	metricsCopy := *s.metrics
	return &metricsCopy
}

// executeSchedule executes a scheduled scan
func (s *ScanScheduler) executeSchedule(scheduleID string) {
	start := time.Now()
	ctx := context.Background()

	s.mu.RLock()
	schedule, exists := s.schedules[scheduleID]
	s.mu.RUnlock()

	if !exists {
		s.logger.Printf("Schedule not found during execution: %s", scheduleID)
		return
	}

	if !schedule.Enabled {
		s.logger.Printf("Schedule is disabled, skipping: %s", scheduleID)
		return
	}

	s.logger.Printf("Executing scheduled scan: %s (%s)", schedule.Name, scheduleID)

	// Update run statistics
	s.mu.Lock()
	schedule.RunCount++
	now := time.Now()
	schedule.LastRun = &now
	s.metrics.TotalRuns++
	s.mu.Unlock()

	// Discover repositories for each target
	var allRequests []*repository.ScanRequest
	for _, target := range schedule.Targets {
		repos, err := s.discoverRepositories(ctx, &target)
		if err != nil {
			s.logger.Printf("Failed to discover repositories for target %+v: %v", target, err)
			continue
		}

		// Create scan requests
		for _, repo := range repos {
			request := &repository.ScanRequest{
				Repository:  repo,
				Branch:      target.Branch,
				ScanID:      generateScanID(),
				RequestedBy: fmt.Sprintf("scheduler:%s", scheduleID),
				Priority:    1, // Normal priority for scheduled scans
				Options:     schedule.Options,
				CreatedAt:   time.Now(),
			}
			allRequests = append(allRequests, request)
		}
	}

	// Enqueue scan requests
	successCount := 0
	for _, request := range allRequests {
		if err := s.queue.Enqueue(ctx, request); err != nil {
			s.logger.Printf("Failed to enqueue scan request for %s: %v", request.Repository.FullName, err)
		} else {
			successCount++
		}
	}

	duration := time.Since(start)
	s.mu.Lock()
	if successCount > 0 {
		s.metrics.SuccessfulRuns++
	} else {
		s.metrics.FailedRuns++
	}
	s.metrics.LastRunTime = time.Now()
	// Update average run time (simple moving average)
	if s.metrics.AverageRunTime == 0 {
		s.metrics.AverageRunTime = duration
	} else {
		s.metrics.AverageRunTime = (s.metrics.AverageRunTime + duration) / 2
	}
	s.mu.Unlock()

	s.logger.Printf("Completed scheduled scan: %s (%s) - %d repositories queued in %v",
		schedule.Name, scheduleID, successCount, duration)
}

// discoverRepositories discovers repositories based on scan target
func (s *ScanScheduler) discoverRepositories(ctx context.Context, target *ScanTarget) ([]*repository.Repository, error) {
	connector, err := s.repository.GetConnector(target.Type)
	if err != nil {
		return nil, fmt.Errorf("failed to get connector for %s: %w", target.Type, err)
	}

	var repos []*repository.Repository

	if target.IncludeAll {
		// Discover all repositories for organization/group
		if target.Organization != "" {
			repos, err = connector.ListOrgRepositories(ctx, target.Organization, target.Filter)
		} else if target.Group != "" {
			repos, err = connector.ListOrgRepositories(ctx, target.Group, target.Filter)
		} else if target.User != "" {
			repos, err = connector.ListRepositories(ctx, target.User, target.Filter)
		} else {
			return nil, fmt.Errorf("no organization, group, or user specified for target")
		}
	} else if len(target.Repositories) > 0 {
		// Get specific repositories
		for _, repoName := range target.Repositories {
			var owner string
			if target.Organization != "" {
				owner = target.Organization
			} else if target.Group != "" {
				owner = target.Group
			} else if target.User != "" {
				owner = target.User
			} else {
				return nil, fmt.Errorf("no owner specified for repository %s", repoName)
			}

			repo, err := connector.GetRepository(ctx, owner, repoName)
			if err != nil {
				s.logger.Printf("Failed to get repository %s/%s: %v", owner, repoName, err)
				continue
			}
			repos = append(repos, repo)
		}
	} else {
		return nil, fmt.Errorf("no repositories specified in target")
	}

	if err != nil {
		return nil, fmt.Errorf("failed to discover repositories: %w", err)
	}

	return repos, nil
}

// collectMetrics periodically collects scheduler metrics
func (s *ScanScheduler) collectMetrics(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			// Update queue size
			if queueSize, err := s.queue.Size(ctx); err == nil {
				s.mu.Lock()
				s.metrics.QueueSize = queueSize
				s.mu.Unlock()
			}
		}
	}
}

// LoadSchedulesFromConfig loads schedules from configuration
func (s *ScanScheduler) LoadSchedulesFromConfig(configData []byte) error {
	var schedules []*ScheduledScan
	if err := json.Unmarshal(configData, &schedules); err != nil {
		return fmt.Errorf("failed to unmarshal schedules config: %w", err)
	}

	for _, schedule := range schedules {
		if err := s.AddSchedule(schedule); err != nil {
			s.logger.Printf("Failed to add schedule %s: %v", schedule.Name, err)
		}
	}

	return nil
}

// Helper functions

func generateScheduleID() string {
	return fmt.Sprintf("sched_%d", time.Now().UnixNano())
}

func generateScanID() string {
	return fmt.Sprintf("scan_%d", time.Now().UnixNano())
}
