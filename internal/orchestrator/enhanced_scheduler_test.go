package orchestrator

import (
	"context"
	"testing"
	"time"

	"github.com/Alivanroy/Typosentinel/internal/config"
	"github.com/Alivanroy/Typosentinel/internal/repository"
)

// MockRepositoryManager implements RepositoryManager for testing
type MockRepositoryManager struct{}

func (m *MockRepositoryManager) AddConnector(name string, connector repository.Connector) error {
	return nil
}

func (m *MockRepositoryManager) RemoveConnector(name string) error {
	return nil
}

func (m *MockRepositoryManager) GetConnector(name string) (repository.Connector, error) {
	return nil, nil
}

func (m *MockRepositoryManager) ListConnectors() []string {
	return []string{}
}

func (m *MockRepositoryManager) DiscoverRepositories(ctx context.Context, platforms []string, filter *repository.RepositoryFilter) ([]*repository.Repository, error) {
	return []*repository.Repository{}, nil
}

func (m *MockRepositoryManager) ScanRepository(ctx context.Context, request *repository.ScanRequest) error {
	return nil
}

func (m *MockRepositoryManager) BulkScan(ctx context.Context, requests []*repository.ScanRequest) error {
	return nil
}

func (m *MockRepositoryManager) LoadConfig(configPath string) error {
	return nil
}

func (m *MockRepositoryManager) ValidateConfiguration() error {
	return nil
}

func (m *MockRepositoryManager) GetConfiguration() map[string]repository.PlatformConfig {
	return map[string]repository.PlatformConfig{}
}

func (m *MockRepositoryManager) HealthCheck(ctx context.Context) map[string]error {
	return map[string]error{}
}

func (m *MockRepositoryManager) GetMetrics(ctx context.Context) map[string]interface{} {
	return map[string]interface{}{}
}

// MockPolicyEngine implements PolicyEngine for testing
type MockPolicyEngine struct{}

func (m *MockPolicyEngine) EvaluateRepository(repo *repository.Repository) (*ScanPolicy, error) {
	return nil, nil
}

func (m *MockPolicyEngine) GetDefaultPolicy() *ScanPolicy {
	return nil
}

func (m *MockPolicyEngine) ValidatePolicy(policy *ScanPolicy) error {
	return nil
}

// MockNotificationManager implements NotificationManager for testing
type MockNotificationManager struct{}

func (m *MockNotificationManager) SendScanStarted(scan *ScheduledScan) error {
	return nil
}

func (m *MockNotificationManager) SendScanCompleted(scan *ScheduledScan, result *repository.ScanResult) error {
	return nil
}

func (m *MockNotificationManager) SendScanFailed(scan *ScheduledScan, err error) error {
	return nil
}

func (m *MockNotificationManager) SendDiscoveryCompleted(results []repository.DiscoveryResult) error {
	return nil
}

// MockMetricsCollector implements MetricsCollector for testing
type MockMetricsCollector struct{}

func (m *MockMetricsCollector) RecordScanDuration(platform string, duration time.Duration) {}
func (m *MockMetricsCollector) RecordScanResult(platform string, success bool) {}
func (m *MockMetricsCollector) IncrementScanCounter(platform string, scanType string) {}
func (m *MockMetricsCollector) RecordRepositoriesDiscovered(platform string, count int) {}
func (m *MockMetricsCollector) RecordPolicyViolations(platform string, count int) {}

// MockAuditLogger implements AuditLogger for testing
type MockAuditLogger struct{}

func (m *MockAuditLogger) LogScanScheduled(scan *ScheduledScan, user string) error {
	return nil
}
func (m *MockAuditLogger) LogScanStarted(scan *ScheduledScan) error {
	return nil
}
func (m *MockAuditLogger) LogScanCompleted(scan *ScheduledScan, result *repository.ScanResult) error {
	return nil
}
func (m *MockAuditLogger) LogPolicyViolation(repo *repository.Repository, policy *ScanPolicy, violation string) error {
	return nil
}
func (m *MockAuditLogger) LogDiscoveryEvent(platform string, repoCount int, duration time.Duration) error {
	return nil
}

// MockDiscoveryService implements a basic discovery service for testing
type MockDiscoveryService struct{}

func (m *MockDiscoveryService) Start(ctx context.Context) error {
	return nil
}

func (m *MockDiscoveryService) Stop() error {
	return nil
}

func (m *MockDiscoveryService) IsRunning() bool {
	return false
}

func (m *MockDiscoveryService) DiscoverOnce(ctx context.Context) ([]repository.DiscoveryResult, error) {
	return []repository.DiscoveryResult{
		{
			Platform: "github",
			Repositories: []*repository.Repository{
				{
					ID:       "test-repo-1",
					Name:     "test-repo",
					FullName: "test-org/test-repo",
					URL:      "https://github.com/test-org/test-repo",
					Platform: "github",
				},
			},
			Errors:    []error{},
			Duration:  time.Second,
			Timestamp: time.Now(),
			Stats: repository.DiscoveryStats{
				TotalFound:      1,
				NewRepositories: 1,
			},
		},
	}, nil
}

func TestNewEnhancedScanScheduler(t *testing.T) {
	// Create mock dependencies
	scheduler := &ScanScheduler{}
	discoveryService := &repository.DiscoveryService{}
	repoManager := &MockRepositoryManager{}
	repoConfig := &config.RepositoryConfig{}
	policyEngine := &MockPolicyEngine{}
	notificationMgr := &MockNotificationManager{}
	metrics := &MockMetricsCollector{}
	auditLogger := &MockAuditLogger{}

	// Create enhanced scheduler
	enhancedScheduler := NewEnhancedScanScheduler(
		scheduler,
		discoveryService,
		repoManager,
		repoConfig,
	)

	// Set optional components
	enhancedScheduler.SetPolicyEngine(policyEngine)
	enhancedScheduler.SetNotificationManager(notificationMgr)
	enhancedScheduler.SetMetricsCollector(metrics)
	enhancedScheduler.SetAuditLogger(auditLogger)

	if enhancedScheduler == nil {
		t.Fatal("Expected non-nil enhanced scheduler")
	}

	if enhancedScheduler.scheduler != scheduler {
		t.Error("Expected scheduler to be set correctly")
	}
}

func TestEnhancedScanScheduler_DiscoverAndSchedule(t *testing.T) {
	// Create enhanced scheduler with mocks
	scheduler := &ScanScheduler{}
	discoveryService := &repository.DiscoveryService{}
	repoManager := &MockRepositoryManager{}
	repoConfig := &config.RepositoryConfig{}

	enhancedScheduler := NewEnhancedScanScheduler(
		scheduler,
		discoveryService,
		repoManager,
		repoConfig,
	)

	ctx := context.Background()
	err := enhancedScheduler.DiscoverAndSchedule(ctx, []string{"github"})
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}
}

func TestEnhancedScanScheduler_GetEnhancedStats(t *testing.T) {
	// Create enhanced scheduler with mocks
	scheduler := &ScanScheduler{}
	discoveryService := &repository.DiscoveryService{}
	repoManager := &MockRepositoryManager{}
	repoConfig := &config.RepositoryConfig{}

	enhancedScheduler := NewEnhancedScanScheduler(
		scheduler,
		discoveryService,
		repoManager,
		repoConfig,
	)

	stats := enhancedScheduler.GetEnhancedStats()
	if stats == nil {
		t.Fatal("Expected non-nil stats")
	}

	// Check that stats contains expected keys
	expectedKeys := []string{"policies", "notifications", "discovery"}
	for _, key := range expectedKeys {
		if _, exists := stats[key]; !exists {
			t.Errorf("Expected stats to contain key: %s", key)
		}
	}
}