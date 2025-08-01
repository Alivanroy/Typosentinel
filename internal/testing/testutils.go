// Package testing provides testing utilities and helpers for Typosentinel
// This package implements comprehensive testing infrastructure for unit, integration, and performance tests
package testing

import (
	"context"
	"database/sql"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v8"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"

	"github.com/Alivanroy/Typosentinel/internal/config"
	"github.com/Alivanroy/Typosentinel/internal/container"
	"github.com/Alivanroy/Typosentinel/internal/errors"
	"github.com/Alivanroy/Typosentinel/internal/interfaces"
	"github.com/Alivanroy/Typosentinel/internal/logging"
)

// TestSuite provides a base test suite with common setup and teardown
type TestSuite struct {
	suite.Suite
	Config    *config.Config
	Logger    interfaces.Logger
	Metrics   interfaces.Metrics
	Container *container.Container
	TempDir   string
	Cleanup   []func() error
	mu        sync.Mutex
}

// SetupSuite runs before all tests in the suite
func (ts *TestSuite) SetupSuite() {
	// Create temporary directory
	tempDir, err := os.MkdirTemp("", "typosentinel-test-*")
	require.NoError(ts.T(), err)
	ts.TempDir = tempDir

	// Setup test configuration
	ts.Config = ts.createTestConfig()

	// Setup test logger
	ts.Logger = ts.createTestLogger()

	// Setup test metrics
	ts.Metrics = ts.createTestMetrics()

	// Setup dependency injection container
	ts.Container = ts.createTestContainer()

	// Initialize container
	ctx := context.Background()
	err = ts.Container.Initialize(ctx)
	require.NoError(ts.T(), err)
}

// TearDownSuite runs after all tests in the suite
func (ts *TestSuite) TearDownSuite() {
	// Run cleanup functions in reverse order
	ts.mu.Lock()
	cleanupFuncs := make([]func() error, len(ts.Cleanup))
	copy(cleanupFuncs, ts.Cleanup)
	ts.mu.Unlock()

	for i := len(cleanupFuncs) - 1; i >= 0; i-- {
		if err := cleanupFuncs[i](); err != nil {
			ts.T().Logf("Cleanup error: %v", err)
		}
	}

	// Shutdown container
	if ts.Container != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		ts.Container.Shutdown(ctx)
	}

	// Remove temporary directory
	if ts.TempDir != "" {
		os.RemoveAll(ts.TempDir)
	}
}

// AddCleanup adds a cleanup function to be called during teardown
func (ts *TestSuite) AddCleanup(cleanup func() error) {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	ts.Cleanup = append(ts.Cleanup, cleanup)
}

// createTestConfig creates a test configuration
func (ts *TestSuite) createTestConfig() *config.Config {
	return &config.Config{
		App: config.AppConfig{
			Name:        "Typosentinel-Test",
			Version:     "test",
			Environment: config.EnvTesting,
			Debug:       true,
			LogLevel:    "debug",
			DataDir:     filepath.Join(ts.TempDir, "data"),
			TempDir:     filepath.Join(ts.TempDir, "tmp"),
			MaxWorkers:  2,
		},
		Server: config.ServerConfig{
			Host:            "localhost",
			Port:            0, // Use random port for testing
			ReadTimeout:     5 * time.Second,
			WriteTimeout:    5 * time.Second,
			IdleTimeout:     10 * time.Second,
			ShutdownTimeout: 5 * time.Second,
		},
		Database: config.DatabaseConfig{
			Type:            "sqlite",
			Database:        filepath.Join(ts.TempDir, "test.db"),
			MaxOpenConns:    5,
			MaxIdleConns:    2,
			ConnMaxLifetime: 5 * time.Minute,
			MigrationsPath:  "./migrations",
		},
		Redis: config.RedisConfig{
			Enabled: false, // Disable Redis for most tests
		},
		Logging: config.LoggingConfig{
			Level:  "debug",
			Format: "json",
			Output: "stderr",
		},
		Metrics: config.MetricsConfig{
			Enabled: false, // Disable metrics for most tests
		},
		Security: config.SecurityConfig{
			JWT: config.JWTConfig{
				Enabled: false,
			},
			APIKeys: config.APIKeysConfig{
				Enabled: false,
			},
			Encryption: config.EncryptionConfig{
				Key:       "test-encryption-key-32-characters",
				Algorithm: "aes-256-gcm",
			},
		},
		ML: config.MLConfig{
			Enabled:   false,
			Threshold: 0.5,
			BatchSize: 10,
			Timeout:   5 * time.Second,
		},
		Scanner: &config.ScannerConfig{
			MaxConcurrency: 2,
			Timeout:        10 * time.Second,
			RetryAttempts:  1,
			RetryDelay:     1 * time.Second,
			UserAgent:      "Typosentinel-Test/1.0",
		},
		API: config.APIConfig{
			Prefix:  "/api",
			Version: "v1",
		},
		RateLimit: config.RateLimitConfig{
			Enabled: false,
		},
		Features: config.FeatureConfig{
			Caching:      false,
			MLScoring:    false,
			BulkScanning: true,
		},
	}
}

// createTestLogger creates a test logger
func (ts *TestSuite) createTestLogger() interfaces.Logger {
	logConfig := &config.LoggingConfig{
		Level:  "debug",
		Format: "text",
		Output: "stderr",
	}

	logger, err := logging.NewLogger(logConfig)
	require.NoError(ts.T(), err)

	return logger
}

// createTestMetrics creates a test metrics collector
func (ts *TestSuite) createTestMetrics() interfaces.Metrics {
	return NewMockMetrics()
}

// createTestContainer creates a test dependency injection container
func (ts *TestSuite) createTestContainer() *container.Container {
	c := container.NewContainer()
	c.SetLogger(ts.Logger)
	c.SetMetrics(ts.Metrics)

	// Register test services
	err := c.RegisterInstance("config", ts.Config)
	require.NoError(ts.T(), err)

	err = c.RegisterInstance("logger", ts.Logger)
	require.NoError(ts.T(), err)

	err = c.RegisterInstance("metrics", ts.Metrics)
	require.NoError(ts.T(), err)

	return c
}

// MockHTTPServer provides a mock HTTP server for testing
type MockHTTPServer struct {
	Server   *httptest.Server
	Requests []*http.Request
	mu       sync.Mutex
}

// NewMockHTTPServer creates a new mock HTTP server
func NewMockHTTPServer() *MockHTTPServer {
	mock := &MockHTTPServer{
		Requests: make([]*http.Request, 0),
	}

	mock.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mock.mu.Lock()
		mock.Requests = append(mock.Requests, r)
		mock.mu.Unlock()

		// Default response
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status": "ok"}`))
	}))

	return mock
}

// Close closes the mock server
func (m *MockHTTPServer) Close() {
	m.Server.Close()
}

// GetRequests returns all captured requests
func (m *MockHTTPServer) GetRequests() []*http.Request {
	m.mu.Lock()
	defer m.mu.Unlock()

	requests := make([]*http.Request, len(m.Requests))
	copy(requests, m.Requests)
	return requests
}

// ClearRequests clears all captured requests
func (m *MockHTTPServer) ClearRequests() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Requests = m.Requests[:0]
}

// MockDatabase provides a mock database for testing
type MockDatabase struct {
	DB       *sql.DB
	FilePath string
}

// NewMockDatabase creates a new mock SQLite database
func NewMockDatabase(t *testing.T) *MockDatabase {
	tempFile, err := os.CreateTemp("", "test-db-*.sqlite")
	require.NoError(t, err)
	tempFile.Close()

	db, err := sql.Open("sqlite3", tempFile.Name())
	require.NoError(t, err)

	return &MockDatabase{
		DB:       db,
		FilePath: tempFile.Name(),
	}
}

// Close closes the mock database
func (m *MockDatabase) Close() error {
	if m.DB != nil {
		m.DB.Close()
	}
	if m.FilePath != "" {
		os.Remove(m.FilePath)
	}
	return nil
}

// MockRedis provides a mock Redis client for testing
type MockRedis struct {
	Client *redis.Client
	data   map[string]string
	mu     sync.RWMutex
}

// NewMockRedis creates a new mock Redis client
func NewMockRedis() *MockRedis {
	return &MockRedis{
		data: make(map[string]string),
	}
}

// Set sets a key-value pair
func (m *MockRedis) Set(key, value string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.data[key] = value
}

// Get gets a value by key
func (m *MockRedis) Get(key string) (string, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	value, exists := m.data[key]
	return value, exists
}

// Delete deletes a key
func (m *MockRedis) Delete(key string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.data, key)
}

// Clear clears all data
func (m *MockRedis) Clear() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.data = make(map[string]string)
}

// TestHelper provides common test helper functions
type TestHelper struct {
	t *testing.T
}

// NewTestHelper creates a new test helper
func NewTestHelper(t *testing.T) *TestHelper {
	return &TestHelper{t: t}
}

// AssertNoError asserts that an error is nil
func (h *TestHelper) AssertNoError(err error, msgAndArgs ...interface{}) {
	assert.NoError(h.t, err, msgAndArgs...)
}

// AssertError asserts that an error is not nil
func (h *TestHelper) AssertError(err error, msgAndArgs ...interface{}) {
	assert.Error(h.t, err, msgAndArgs...)
}

// AssertErrorCode asserts that an error has a specific error code
func (h *TestHelper) AssertErrorCode(err error, expectedCode errors.ErrorCode, msgAndArgs ...interface{}) {
	if !assert.Error(h.t, err, msgAndArgs...) {
		return
	}

	appErr := errors.GetAppError(err)
	if !assert.NotNil(h.t, appErr, "Expected AppError, got %T", err) {
		return
	}

	assert.Equal(h.t, expectedCode, appErr.GetCode(), msgAndArgs...)
}

// AssertHTTPStatus asserts that an HTTP response has a specific status code
func (h *TestHelper) AssertHTTPStatus(response *httptest.ResponseRecorder, expectedStatus int, msgAndArgs ...interface{}) {
	assert.Equal(h.t, expectedStatus, response.Code, msgAndArgs...)
}

// AssertJSONResponse asserts that an HTTP response contains valid JSON
func (h *TestHelper) AssertJSONResponse(response *httptest.ResponseRecorder, msgAndArgs ...interface{}) {
	contentType := response.Header().Get("Content-Type")
	assert.Contains(h.t, contentType, "application/json", msgAndArgs...)

	body := response.Body.String()
	assert.True(h.t, strings.HasPrefix(body, "{") || strings.HasPrefix(body, "["), "Response body is not valid JSON: %s", body)
}

// AssertFileExists asserts that a file exists
func (h *TestHelper) AssertFileExists(filePath string, msgAndArgs ...interface{}) {
	_, err := os.Stat(filePath)
	assert.NoError(h.t, err, msgAndArgs...)
}

// AssertFileNotExists asserts that a file does not exist
func (h *TestHelper) AssertFileNotExists(filePath string, msgAndArgs ...interface{}) {
	_, err := os.Stat(filePath)
	assert.True(h.t, os.IsNotExist(err), "File should not exist: %s", filePath)
}

// AssertDuration asserts that a duration is within expected bounds
func (h *TestHelper) AssertDuration(actual, min, max time.Duration, msgAndArgs ...interface{}) {
	assert.True(h.t, actual >= min, "Duration %v should be >= %v", actual, min)
	assert.True(h.t, actual <= max, "Duration %v should be <= %v", actual, max)
}

// CreateTempFile creates a temporary file with content
func (h *TestHelper) CreateTempFile(content string, suffix string) string {
	tempFile, err := os.CreateTemp("", fmt.Sprintf("test-*%s", suffix))
	require.NoError(h.t, err)
	defer tempFile.Close()

	_, err = tempFile.WriteString(content)
	require.NoError(h.t, err)

	return tempFile.Name()
}

// CreateTempDir creates a temporary directory
func (h *TestHelper) CreateTempDir(prefix string) string {
	tempDir, err := os.MkdirTemp("", prefix)
	require.NoError(h.t, err)
	return tempDir
}

// PerformanceTest provides utilities for performance testing
type PerformanceTest struct {
	t         *testing.T
	StartTime time.Time
	EndTime   time.Time
}

// NewPerformanceTest creates a new performance test
func NewPerformanceTest(t *testing.T) *PerformanceTest {
	return &PerformanceTest{t: t}
}

// Start starts the performance measurement
func (p *PerformanceTest) Start() {
	p.StartTime = time.Now()
}

// Stop stops the performance measurement
func (p *PerformanceTest) Stop() {
	p.EndTime = time.Now()
}

// Duration returns the measured duration
func (p *PerformanceTest) Duration() time.Duration {
	if p.EndTime.IsZero() {
		return time.Since(p.StartTime)
	}
	return p.EndTime.Sub(p.StartTime)
}

// AssertMaxDuration asserts that the measured duration is below a threshold
func (p *PerformanceTest) AssertMaxDuration(maxDuration time.Duration, msgAndArgs ...interface{}) {
	duration := p.Duration()
	assert.True(p.t, duration <= maxDuration, "Duration %v should be <= %v", duration, maxDuration)
}

// AssertMinDuration asserts that the measured duration is above a threshold
func (p *PerformanceTest) AssertMinDuration(minDuration time.Duration, msgAndArgs ...interface{}) {
	duration := p.Duration()
	assert.True(p.t, duration >= minDuration, "Duration %v should be >= %v", duration, minDuration)
}

// BenchmarkHelper provides utilities for benchmark tests
type BenchmarkHelper struct {
	b *testing.B
}

// NewBenchmarkHelper creates a new benchmark helper
func NewBenchmarkHelper(b *testing.B) *BenchmarkHelper {
	return &BenchmarkHelper{b: b}
}

// TimeOperation measures the time of an operation
func (bh *BenchmarkHelper) TimeOperation(operation func()) time.Duration {
	start := time.Now()
	operation()
	return time.Since(start)
}

// RunParallel runs a benchmark in parallel
func (bh *BenchmarkHelper) RunParallel(operation func()) {
	bh.b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			operation()
		}
	})
}

// SetBytes sets the number of bytes processed per operation
func (bh *BenchmarkHelper) SetBytes(bytes int64) {
	bh.b.SetBytes(bytes)
}

// ReportAllocs enables allocation reporting
func (bh *BenchmarkHelper) ReportAllocs() {
	bh.b.ReportAllocs()
}

// IntegrationTestHelper provides utilities for integration tests
type IntegrationTestHelper struct {
	t      *testing.T
	server *gin.Engine
	config *config.Config
}

// NewIntegrationTestHelper creates a new integration test helper
func NewIntegrationTestHelper(t *testing.T, server *gin.Engine, config *config.Config) *IntegrationTestHelper {
	return &IntegrationTestHelper{
		t:      t,
		server: server,
		config: config,
	}
}

// MakeRequest makes an HTTP request to the test server
func (ith *IntegrationTestHelper) MakeRequest(method, path string, body io.Reader, headers map[string]string) *httptest.ResponseRecorder {
	req, err := http.NewRequest(method, path, body)
	require.NoError(ith.t, err)

	// Set headers
	for key, value := range headers {
		req.Header.Set(key, value)
	}

	// Set default content type if not provided
	if req.Header.Get("Content-Type") == "" && body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	w := httptest.NewRecorder()
	ith.server.ServeHTTP(w, req)

	return w
}

// MakeJSONRequest makes a JSON HTTP request
func (ith *IntegrationTestHelper) MakeJSONRequest(method, path string, payload interface{}) *httptest.ResponseRecorder {
	body := strings.NewReader("{}")
	if payload != nil {
		// In a real implementation, you'd marshal the payload to JSON
		body = strings.NewReader(fmt.Sprintf("%v", payload))
	}

	headers := map[string]string{
		"Content-Type": "application/json",
	}

	return ith.MakeRequest(method, path, body, headers)
}

// WaitForCondition waits for a condition to be true with timeout
func WaitForCondition(t *testing.T, condition func() bool, timeout time.Duration, message string) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			t.Fatalf("Timeout waiting for condition: %s", message)
		case <-ticker.C:
			if condition() {
				return
			}
		}
	}
}

// SkipIfShort skips the test if running in short mode
func SkipIfShort(t *testing.T, reason string) {
	if testing.Short() {
		t.Skipf("Skipping test in short mode: %s", reason)
	}
}

// RequireEnvironment skips the test if a required environment variable is not set
func RequireEnvironment(t *testing.T, envVar string) string {
	value := os.Getenv(envVar)
	if value == "" {
		t.Skipf("Skipping test: required environment variable %s not set", envVar)
	}
	return value
}

// CleanupTempFiles removes temporary files created during testing
func CleanupTempFiles(t *testing.T, files ...string) {
	t.Cleanup(func() {
		for _, file := range files {
			if err := os.Remove(file); err != nil && !os.IsNotExist(err) {
				t.Logf("Failed to remove temp file %s: %v", file, err)
			}
		}
	})
}

// CleanupTempDirs removes temporary directories created during testing
func CleanupTempDirs(t *testing.T, dirs ...string) {
	t.Cleanup(func() {
		for _, dir := range dirs {
			if err := os.RemoveAll(dir); err != nil {
				t.Logf("Failed to remove temp dir %s: %v", dir, err)
			}
		}
	})
}
