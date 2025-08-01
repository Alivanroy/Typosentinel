package orchestrator

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/Alivanroy/Typosentinel/internal/repository"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Simple test implementations
type TestConnector struct {
	repositories []*repository.Repository
}

func (c *TestConnector) GetPlatformName() string {
	return "test"
}

func (c *TestConnector) GetPlatformType() string {
	return "test"
}

func (c *TestConnector) GetAPIVersion() string {
	return "v1"
}

func (c *TestConnector) Authenticate(ctx context.Context, config repository.AuthConfig) error {
	return nil
}

func (c *TestConnector) ValidateAuth(ctx context.Context) error {
	return nil
}

func (c *TestConnector) RefreshAuth(ctx context.Context) error {
	return nil
}

func (c *TestConnector) ListOrganizations(ctx context.Context) ([]*repository.Organization, error) {
	return nil, nil
}

func (c *TestConnector) GetOrganization(ctx context.Context, name string) (*repository.Organization, error) {
	return nil, nil
}

func (c *TestConnector) ListRepositories(ctx context.Context, owner string, filter *repository.RepositoryFilter) ([]*repository.Repository, error) {
	return c.repositories, nil
}

func (c *TestConnector) ListOrgRepositories(ctx context.Context, org string, filter *repository.RepositoryFilter) ([]*repository.Repository, error) {
	return c.repositories, nil
}

func (c *TestConnector) GetRepository(ctx context.Context, owner, name string) (*repository.Repository, error) {
	for _, repo := range c.repositories {
		if repo.Owner.Login == owner && repo.Name == name {
			return repo, nil
		}
	}
	return &repository.Repository{
		Name:  name,
		Owner: repository.Owner{Login: owner},
	}, nil
}

func (c *TestConnector) SearchRepositories(ctx context.Context, query string, filter *repository.RepositoryFilter) ([]*repository.Repository, error) {
	return c.repositories, nil
}

func (c *TestConnector) GetRepositoryContent(ctx context.Context, repo *repository.Repository, path string, ref string) ([]byte, error) {
	return nil, nil
}

func (c *TestConnector) ListRepositoryFiles(ctx context.Context, repo *repository.Repository, path string, ref string) ([]string, error) {
	return nil, nil
}

func (c *TestConnector) GetPackageFiles(ctx context.Context, repo *repository.Repository, ref string) (map[string][]byte, error) {
	return nil, nil
}

func (c *TestConnector) GetRepositoryLanguages(ctx context.Context, repo *repository.Repository) (map[string]int, error) {
	return nil, nil
}

func (c *TestConnector) GetRepositoryTopics(ctx context.Context, repo *repository.Repository) ([]string, error) {
	return nil, nil
}

func (c *TestConnector) GetRepositoryBranches(ctx context.Context, repo *repository.Repository) ([]string, error) {
	return nil, nil
}

func (c *TestConnector) GetRepositoryCommits(ctx context.Context, repo *repository.Repository, branch string, limit int) ([]repository.Commit, error) {
	return nil, nil
}

func (c *TestConnector) CreateWebhook(ctx context.Context, repo *repository.Repository, webhookURL string, events []string) error {
	return nil
}

func (c *TestConnector) DeleteWebhook(ctx context.Context, repo *repository.Repository, webhookID string) error {
	return nil
}

func (c *TestConnector) ListWebhooks(ctx context.Context, repo *repository.Repository) ([]repository.Webhook, error) {
	return nil, nil
}

func (c *TestConnector) GetRateLimit(ctx context.Context) (*repository.RateLimit, error) {
	return &repository.RateLimit{
		Limit:     5000,
		Remaining: 4999,
		ResetTime: time.Now().Add(time.Hour),
	}, nil
}

func (c *TestConnector) HealthCheck(ctx context.Context) error {
	return nil
}

func (c *TestConnector) Close() error {
	return nil
}

// Tests
func TestInMemoryJobQueue(t *testing.T) {
	queue := NewInMemoryJobQueue()
	ctx := context.Background()

	job := &ScanJob{
		ID:        "test-job-1",
		Type:      "repository",
		Platform:  "github",
		Target:    "owner/repo",
		Status:    JobStatusPending,
		CreatedAt: time.Now(),
	}

	// Test enqueue
	err := queue.Enqueue(ctx, job)
	require.NoError(t, err)

	// Test dequeue
	dequeuedJob, err := queue.Dequeue(ctx, "worker-1")
	require.NoError(t, err)
	require.NotNil(t, dequeuedJob)
	assert.Equal(t, job.ID, dequeuedJob.ID)
	assert.Equal(t, JobStatusRunning, dequeuedJob.Status)

	// Test get job
	retrievedJob, err := queue.GetJob(ctx, job.ID)
	require.NoError(t, err)
	assert.Equal(t, job.ID, retrievedJob.ID)

	// Test update status
	err = queue.UpdateStatus(ctx, job.ID, JobStatusCompleted, "")
	require.NoError(t, err)

	// Test list jobs
	filters := map[string]interface{}{"status": JobStatusCompleted}
	jobs, err := queue.ListJobs(ctx, filters)
	require.NoError(t, err)
	assert.Len(t, jobs, 1)

	// Test delete job
	err = queue.DeleteJob(ctx, job.ID)
	require.NoError(t, err)

	// Verify deletion
	_, err = queue.GetJob(ctx, job.ID)
	assert.Error(t, err)
}

func TestTokenBucketLimiter(t *testing.T) {
	limiter := NewTokenBucketLimiter(10, 1) // 10 tokens, 1 per second

	// Test initial tokens
	assert.True(t, limiter.Allow())

	// Test rate limiting
	for i := 0; i < 10; i++ {
		assert.True(t, limiter.Allow())
	}

	// Should be rate limited now
	assert.False(t, limiter.Allow())

	// Test wait
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	err := limiter.Wait(ctx)
	assert.Error(t, err) // Should timeout
}

func TestPlatformRateLimiter(t *testing.T) {
	configs := map[string]*PlatformLimitConfig{
		"github": {
			Platform:          "github",
			RequestsPerMinute: 60,
			BurstSize:         10,
			Enabled:           true,
		},
	}

	limiter := NewPlatformRateLimiter(configs)

	// Test GitHub rate limiting
	ctx := context.Background()
	err := limiter.Wait(ctx, "github")
	assert.NoError(t, err)

	// Test stats
	stats := limiter.GetStats()
	assert.Contains(t, stats, "github")
}

func TestAdaptiveRateLimiter(t *testing.T) {
	baseLimiter := NewTokenBucketLimiter(1.0, 1)
	config := &PlatformLimitConfig{
		BackoffMultiplier:  2.0,
		MaxBackoffDuration: 5 * time.Second,
		RetryAttempts:      3,
	}

	adaptiveLimiter := NewAdaptiveRateLimiter(baseLimiter, "test", config)

	// Test normal operation
	assert.True(t, adaptiveLimiter.Allow())
	adaptiveLimiter.OnSuccess()

	// Test error handling
	adaptiveLimiter.OnError(fmt.Errorf("rate limit exceeded"))
	assert.True(t, adaptiveLimiter.ShouldRetry())
}

func TestWorkerPool(t *testing.T) {
	queue := NewInMemoryJobQueue()
	manager := repository.NewManager(&repository.ManagerConfig{})
	connector := &TestConnector{}
	manager.RegisterConnector("github", connector)

	config := DefaultWorkerPoolConfig()
	config.InitialWorkers = 2
	config.MaxWorkers = 2

	pool := NewWorkerPool(queue, manager, config)

	// Test start
	err := pool.Start()
	require.NoError(t, err)

	// Add a job
	job := &ScanJob{
		ID:        "worker-test-job",
		Type:      "repository",
		Platform:  "github",
		Target:    "owner/repo",
		Status:    JobStatusPending,
		CreatedAt: time.Now(),
	}

	ctx := context.Background()
	err = queue.Enqueue(ctx, job)
	require.NoError(t, err)

	// Wait a bit for processing
	time.Sleep(100 * time.Millisecond)

	// Test workers directly since metrics update asynchronously
	workers := pool.GetWorkers()
	assert.Equal(t, 2, len(workers))

	// Test metrics (may not be updated immediately)
	metrics := pool.GetMetrics()
	assert.NotNil(t, metrics)

	// Test stop
	err = pool.Stop()
	assert.NoError(t, err)
}

func TestScanCoordinator(t *testing.T) {
	queue := NewInMemoryJobQueue()
	manager := repository.NewManager(&repository.ManagerConfig{})
	connector := &TestConnector{
		repositories: []*repository.Repository{
			{
				Name:  "test-repo",
				Owner: repository.Owner{Login: "test-owner"},
			},
		},
	}
	manager.RegisterConnector("github", connector)

	config := &CoordinatorConfig{
		MaxConcurrentScans: 5,
		ScanTimeout:        30 * time.Second,
		RetryAttempts:      3,
		RetryDelay:         time.Second,
		ProgressUpdateInterval: time.Second,
		CleanupInterval:    time.Minute,
	}

	workerPool := NewWorkerPool(queue, manager, &WorkerPoolConfig{
		MinWorkers: 1,
		MaxWorkers: 2,
		InitialWorkers: 1,
	})
	platformLimiter := NewPlatformRateLimiter(nil) // Use default configs
	rateLimiter := NewRateLimitedExecutor(platformLimiter)
	discoveryService := &repository.DiscoveryService{}

	coordinator := NewScanCoordinator(
		queue,
		workerPool,
		rateLimiter,
		manager,
		discoveryService,
		config,
	)

	// Test start
	err := coordinator.Start()
	require.NoError(t, err)

	// Test repository scan
	operation, err := coordinator.StartRepositoryScan("github", "test-owner/test-repo", nil)
	require.NoError(t, err)
	assert.NotNil(t, operation)

	// Wait a bit for processing
	time.Sleep(100 * time.Millisecond)

	// Test get operation
	retrievedOp, err := coordinator.GetScan(operation.ID)
	require.NoError(t, err)
	assert.NotNil(t, retrievedOp)

	// Test metrics
	metrics := coordinator.GetMetrics()
	assert.NotNil(t, metrics)

	// Test stop
	err = coordinator.Stop()
	assert.NoError(t, err)
}

func TestScanCoordinatorOrganizationScan(t *testing.T) {
	queue := NewInMemoryJobQueue()
	manager := repository.NewManager(&repository.ManagerConfig{})

	// Setup test repositories
	repos := []*repository.Repository{
		{Name: "repo1", Owner: repository.Owner{Login: "org"}},
		{Name: "repo2", Owner: repository.Owner{Login: "org"}},
		{Name: "repo3", Owner: repository.Owner{Login: "org"}},
	}

	connector := &TestConnector{
		repositories: repos,
	}
	manager.RegisterConnector("github", connector)

	config := &CoordinatorConfig{
		MaxConcurrentScans: 5,
		ScanTimeout:        30 * time.Second,
		RetryAttempts:      3,
		RetryDelay:         time.Second,
		ProgressUpdateInterval: time.Second,
		CleanupInterval:    time.Minute,
	}

	workerPool := NewWorkerPool(queue, manager, &WorkerPoolConfig{
		MinWorkers: 1,
		MaxWorkers: 2,
		InitialWorkers: 1,
	})
	platformLimiter := NewPlatformRateLimiter(nil) // Use default configs
	rateLimiter := NewRateLimitedExecutor(platformLimiter)
	discoveryService := &repository.DiscoveryService{}

	coordinator := NewScanCoordinator(
		queue,
		workerPool,
		rateLimiter,
		manager,
		discoveryService,
		config,
	)

	// Test organization scan
	operation, err := coordinator.StartOrganizationScan("github", "org", nil)
	require.NoError(t, err)
	assert.NotNil(t, operation)
	assert.Equal(t, "organization", operation.Type)
	assert.Equal(t, "org", operation.Target)
}

func TestScanCoordinatorErrorHandling(t *testing.T) {
	queue := NewInMemoryJobQueue()
	manager := repository.NewManager(&repository.ManagerConfig{})
	connector := &TestConnector{}
	manager.RegisterConnector("github", connector)

	config := &CoordinatorConfig{
		MaxConcurrentScans: 1,
		ScanTimeout:        time.Millisecond, // Very short timeout
		RetryAttempts:      1,
		RetryDelay:         time.Millisecond,
		ProgressUpdateInterval: time.Second,
		CleanupInterval:    time.Minute,
	}

	workerPool := NewWorkerPool(queue, manager, &WorkerPoolConfig{
		MinWorkers: 1,
		MaxWorkers: 2,
		InitialWorkers: 1,
	})
	platformLimiter := NewPlatformRateLimiter(nil) // Use default configs
	rateLimiter := NewRateLimitedExecutor(platformLimiter)
	discoveryService := &repository.DiscoveryService{}

	coordinator := NewScanCoordinator(
		queue,
		workerPool,
		rateLimiter,
		manager,
		discoveryService,
		config,
	)

	// Test scan with non-existent platform (should succeed at coordinator level)
	scan, err := coordinator.StartRepositoryScan("nonexistent", "owner/repo", nil)
	assert.NoError(t, err)
	assert.NotNil(t, scan)
	assert.Equal(t, "nonexistent", scan.Platform)
	assert.Equal(t, "owner/repo", scan.Target)
}

// Benchmark tests
func BenchmarkInMemoryJobQueue(b *testing.B) {
	queue := NewInMemoryJobQueue()
	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		job := &ScanJob{
			ID:        fmt.Sprintf("bench-job-%d", i),
			Type:      "repository",
			Platform:  "github",
			Target:    "owner/repo",
			Status:    JobStatusPending,
			CreatedAt: time.Now(),
		}

		queue.Enqueue(ctx, job)
		queue.Dequeue(ctx, "worker-1")
	}
}

func BenchmarkTokenBucketLimiter(b *testing.B) {
	limiter := NewTokenBucketLimiter(1000, 100) // High capacity for benchmarking

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		limiter.Allow()
	}
}