// Package testing provides mock implementations for testing
package testing

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/Alivanroy/Typosentinel/internal/errors"
	"github.com/Alivanroy/Typosentinel/internal/interfaces"
)

// MockRegistryClient provides a mock implementation of RegistryClient
type MockRegistryClient struct {
	mu       sync.RWMutex
	packages map[string]*interfaces.PackageInfo
	errors   map[string]error
	delay    time.Duration
	calls    []string
}

// NewMockRegistryClient creates a new mock registry client
func NewMockRegistryClient() *MockRegistryClient {
	return &MockRegistryClient{
		packages: make(map[string]*interfaces.PackageInfo),
		errors:   make(map[string]error),
		calls:    make([]string, 0),
	}
}

// GetPackageInfo returns package information
func (m *MockRegistryClient) GetPackageInfo(ctx context.Context, packageName string) (*interfaces.PackageInfo, error) {
	m.mu.Lock()
	m.calls = append(m.calls, fmt.Sprintf("GetPackageInfo:%s", packageName))
	m.mu.Unlock()

	if m.delay > 0 {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(m.delay):
		}
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	if err, exists := m.errors[packageName]; exists {
		return nil, err
	}

	if pkg, exists := m.packages[packageName]; exists {
		return pkg, nil
	}

	return nil, errors.New(
		errors.NOT_FOUND_ERROR,
		fmt.Sprintf("Package %s not found", packageName),
	).WithContext("package", packageName)
}

// SearchPackages searches for packages
func (m *MockRegistryClient) SearchPackages(ctx context.Context, query string, limit int) ([]*interfaces.PackageInfo, error) {
	m.mu.Lock()
	m.calls = append(m.calls, fmt.Sprintf("SearchPackages:%s:%d", query, limit))
	m.mu.Unlock()

	if m.delay > 0 {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(m.delay):
		}
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	results := make([]*interfaces.PackageInfo, 0)
	for name, pkg := range m.packages {
		if len(results) >= limit {
			break
		}
		if name == query || pkg.Name == query {
			results = append(results, pkg)
		}
	}

	return results, nil
}

// SetPackage sets a package for testing
func (m *MockRegistryClient) SetPackage(name string, pkg *interfaces.PackageInfo) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.packages[name] = pkg
}

// SetError sets an error for a specific package
func (m *MockRegistryClient) SetError(packageName string, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.errors[packageName] = err
}

// SetDelay sets a delay for all operations
func (m *MockRegistryClient) SetDelay(delay time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.delay = delay
}

// GetCalls returns all method calls made
func (m *MockRegistryClient) GetCalls() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	calls := make([]string, len(m.calls))
	copy(calls, m.calls)
	return calls
}

// ClearCalls clears all recorded calls
func (m *MockRegistryClient) ClearCalls() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls = m.calls[:0]
}

// MockThreatDatabase provides a mock implementation of ThreatDatabase
type MockThreatDatabase struct {
	mu      sync.RWMutex
	threats map[string]*interfaces.ThreatInfo
	errors  map[string]error
	delay   time.Duration
	calls   []string
}

// NewMockThreatDatabase creates a new mock threat database
func NewMockThreatDatabase() *MockThreatDatabase {
	return &MockThreatDatabase{
		threats: make(map[string]*interfaces.ThreatInfo),
		errors:  make(map[string]error),
		calls:   make([]string, 0),
	}
}

// CheckThreat checks if a package is a known threat
func (m *MockThreatDatabase) CheckThreat(ctx context.Context, packageName string) (*interfaces.ThreatInfo, error) {
	m.mu.Lock()
	m.calls = append(m.calls, fmt.Sprintf("CheckThreat:%s", packageName))
	m.mu.Unlock()

	if m.delay > 0 {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(m.delay):
		}
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	if err, exists := m.errors[packageName]; exists {
		return nil, err
	}

	if threat, exists := m.threats[packageName]; exists {
		return threat, nil
	}

	return nil, nil // No threat found
}

// UpdateThreat updates threat information
func (m *MockThreatDatabase) UpdateThreat(ctx context.Context, threat *interfaces.ThreatInfo) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls = append(m.calls, fmt.Sprintf("UpdateThreat:%s", threat.PackageName))
	m.threats[threat.PackageName] = threat
	return nil
}

// SetThreat sets a threat for testing
func (m *MockThreatDatabase) SetThreat(packageName string, threat *interfaces.ThreatInfo) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.threats[packageName] = threat
}

// SetError sets an error for a specific package
func (m *MockThreatDatabase) SetError(packageName string, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.errors[packageName] = err
}

// SetDelay sets a delay for all operations
func (m *MockThreatDatabase) SetDelay(delay time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.delay = delay
}

// GetCalls returns all method calls made
func (m *MockThreatDatabase) GetCalls() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	calls := make([]string, len(m.calls))
	copy(calls, m.calls)
	return calls
}

// MockMLScorer provides a mock implementation of MLScorer
type MockMLScorer struct {
	mu     sync.RWMutex
	scores map[string]float64
	errors map[string]error
	delay  time.Duration
	calls  []string
}

// NewMockMLScorer creates a new mock ML scorer
func NewMockMLScorer() *MockMLScorer {
	return &MockMLScorer{
		scores: make(map[string]float64),
		errors: make(map[string]error),
		calls:  make([]string, 0),
	}
}

// ScorePackage scores a package for suspiciousness
func (m *MockMLScorer) ScorePackage(ctx context.Context, pkg *interfaces.PackageInfo) (float64, error) {
	m.mu.Lock()
	m.calls = append(m.calls, fmt.Sprintf("ScorePackage:%s", pkg.Name))
	m.mu.Unlock()

	if m.delay > 0 {
		select {
		case <-ctx.Done():
			return 0, ctx.Err()
		case <-time.After(m.delay):
		}
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	if err, exists := m.errors[pkg.Name]; exists {
		return 0, err
	}

	if score, exists := m.scores[pkg.Name]; exists {
		return score, nil
	}

	// Default score based on package name length (for testing)
	return float64(len(pkg.Name)) / 100.0, nil
}

// BatchScore scores multiple packages
func (m *MockMLScorer) BatchScore(ctx context.Context, packages []*interfaces.PackageInfo) (map[string]float64, error) {
	m.mu.Lock()
	m.calls = append(m.calls, fmt.Sprintf("BatchScore:%d", len(packages)))
	m.mu.Unlock()

	results := make(map[string]float64)
	for _, pkg := range packages {
		score, err := m.ScorePackage(ctx, pkg)
		if err != nil {
			return nil, err
		}
		results[pkg.Name] = score
	}

	return results, nil
}

// SetScore sets a score for a specific package
func (m *MockMLScorer) SetScore(packageName string, score float64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.scores[packageName] = score
}

// SetError sets an error for a specific package
func (m *MockMLScorer) SetError(packageName string, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.errors[packageName] = err
}

// SetDelay sets a delay for all operations
func (m *MockMLScorer) SetDelay(delay time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.delay = delay
}

// GetCalls returns all method calls made
func (m *MockMLScorer) GetCalls() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	calls := make([]string, len(m.calls))
	copy(calls, m.calls)
	return calls
}

// MockCache provides a mock implementation of Cache
type MockCache struct {
	mu    sync.RWMutex
	data  map[string]interface{}
	ttls  map[string]time.Time
	calls []string
}

// NewMockCache creates a new mock cache
func NewMockCache() *MockCache {
	return &MockCache{
		data:  make(map[string]interface{}),
		ttls:  make(map[string]time.Time),
		calls: make([]string, 0),
	}
}

// Get retrieves a value from the cache
func (m *MockCache) Get(ctx context.Context, key string) (interface{}, error) {
	m.mu.Lock()
	m.calls = append(m.calls, fmt.Sprintf("Get:%s", key))
	m.mu.Unlock()

	m.mu.RLock()
	defer m.mu.RUnlock()

	// Check TTL
	if ttl, exists := m.ttls[key]; exists && time.Now().After(ttl) {
		delete(m.data, key)
		delete(m.ttls, key)
		return nil, errors.New(
			errors.NOT_FOUND_ERROR,
			"Key not found in cache",
		).WithContext("key", key)
	}

	if value, exists := m.data[key]; exists {
		return value, nil
	}

	return nil, errors.New(
		errors.NOT_FOUND_ERROR,
		"Key not found in cache",
	).WithContext("key", key)
}

// Set stores a value in the cache
func (m *MockCache) Set(ctx context.Context, key string, value interface{}, ttl time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls = append(m.calls, fmt.Sprintf("Set:%s:%v", key, ttl))
	m.data[key] = value
	if ttl > 0 {
		m.ttls[key] = time.Now().Add(ttl)
	}
	return nil
}

// Delete removes a value from the cache
func (m *MockCache) Delete(ctx context.Context, key string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls = append(m.calls, fmt.Sprintf("Delete:%s", key))
	delete(m.data, key)
	delete(m.ttls, key)
	return nil
}

// Clear removes all values from the cache
func (m *MockCache) Clear(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls = append(m.calls, "Clear")
	m.data = make(map[string]interface{})
	m.ttls = make(map[string]time.Time)
	return nil
}

// GetCalls returns all method calls made
func (m *MockCache) GetCalls() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	calls := make([]string, len(m.calls))
	copy(calls, m.calls)
	return calls
}

// MockValidator provides a mock implementation of Validator
type MockValidator struct {
	mu      sync.RWMutex
	results map[string]bool
	errors  map[string]error
	calls   []string
}

// NewMockValidator creates a new mock validator
func NewMockValidator() *MockValidator {
	return &MockValidator{
		results: make(map[string]bool),
		errors:  make(map[string]error),
		calls:   make([]string, 0),
	}
}

// ValidatePackageName validates a package name
func (m *MockValidator) ValidatePackageName(packageName string) error {
	m.mu.Lock()
	m.calls = append(m.calls, fmt.Sprintf("ValidatePackageName:%s", packageName))
	m.mu.Unlock()

	m.mu.RLock()
	defer m.mu.RUnlock()

	if err, exists := m.errors[packageName]; exists {
		return err
	}

	if valid, exists := m.results[packageName]; exists && !valid {
		return errors.New(
			errors.VALIDATION_ERROR,
			fmt.Sprintf("Invalid package name: %s", packageName),
		).WithContext("package", packageName)
	}

	return nil
}

// ValidateConfig validates configuration
func (m *MockValidator) ValidateConfig(config interface{}) error {
	m.mu.Lock()
	m.calls = append(m.calls, "ValidateConfig")
	m.mu.Unlock()
	return nil
}

// SetResult sets a validation result for a package
func (m *MockValidator) SetResult(packageName string, valid bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.results[packageName] = valid
}

// SetError sets an error for a specific package
func (m *MockValidator) SetError(packageName string, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.errors[packageName] = err
}

// GetCalls returns all method calls made
func (m *MockValidator) GetCalls() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	calls := make([]string, len(m.calls))
	copy(calls, m.calls)
	return calls
}

// MockConfigManager provides a mock implementation of ConfigManager
type MockConfigManager struct {
	mu     sync.RWMutex
	config map[string]interface{}
	calls  []string
}

// NewMockConfigManager creates a new mock config manager
func NewMockConfigManager() *MockConfigManager {
	return &MockConfigManager{
		config: make(map[string]interface{}),
		calls:  make([]string, 0),
	}
}

// Get retrieves a configuration value
func (m *MockConfigManager) Get(key string) interface{} {
	m.mu.Lock()
	m.calls = append(m.calls, fmt.Sprintf("Get:%s", key))
	m.mu.Unlock()

	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.config[key]
}

// Set stores a configuration value
func (m *MockConfigManager) Set(key string, value interface{}) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls = append(m.calls, fmt.Sprintf("Set:%s", key))
	m.config[key] = value
}

// GetString retrieves a string configuration value
func (m *MockConfigManager) GetString(key string) string {
	if value := m.Get(key); value != nil {
		if str, ok := value.(string); ok {
			return str
		}
	}
	return ""
}

// GetInt retrieves an integer configuration value
func (m *MockConfigManager) GetInt(key string) int {
	if value := m.Get(key); value != nil {
		if i, ok := value.(int); ok {
			return i
		}
	}
	return 0
}

// GetBool retrieves a boolean configuration value
func (m *MockConfigManager) GetBool(key string) bool {
	if value := m.Get(key); value != nil {
		if b, ok := value.(bool); ok {
			return b
		}
	}
	return false
}

// GetDuration retrieves a duration configuration value
func (m *MockConfigManager) GetDuration(key string) time.Duration {
	if value := m.Get(key); value != nil {
		if d, ok := value.(time.Duration); ok {
			return d
		}
	}
	return 0
}

// Reload reloads the configuration
func (m *MockConfigManager) Reload() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls = append(m.calls, "Reload")
	return nil
}

// GetCalls returns all method calls made
func (m *MockConfigManager) GetCalls() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	calls := make([]string, len(m.calls))
	copy(calls, m.calls)
	return calls
}

// MockLogger provides a mock implementation of Logger
type MockLogger struct {
	mu   sync.RWMutex
	logs []LogEntry
}

// LogEntry represents a log entry
type LogEntry struct {
	Level   string
	Message string
	Fields  map[string]interface{}
	Time    time.Time
}

// NewMockLogger creates a new mock logger
func NewMockLogger() *MockLogger {
	return &MockLogger{
		logs: make([]LogEntry, 0),
	}
}

// Debug logs a debug message
func (m *MockLogger) Debug(message string, fields ...interfaces.LogField) {
	m.addLog("debug", message, fields...)
}

// Info logs an info message
func (m *MockLogger) Info(message string, fields ...interfaces.LogField) {
	m.addLog("info", message, fields...)
}

// Warn logs a warning message
func (m *MockLogger) Warn(message string, fields ...interfaces.LogField) {
	m.addLog("warn", message, fields...)
}

// Error logs an error message
func (m *MockLogger) Error(message string, fields ...interfaces.LogField) {
	m.addLog("error", message, fields...)
}

// Fatal logs a fatal message
func (m *MockLogger) Fatal(message string, fields ...interfaces.LogField) {
	m.addLog("fatal", message, fields...)
}

// WithContext returns a logger with context
func (m *MockLogger) WithContext(ctx context.Context) interfaces.Logger {
	return m
}

// WithFields returns a logger with additional fields
func (m *MockLogger) WithFields(fields ...interfaces.LogField) interfaces.Logger {
	return m
}

// addLog adds a log entry
func (m *MockLogger) addLog(level, message string, fields ...interfaces.LogField) {
	m.mu.Lock()
	defer m.mu.Unlock()

	fieldMap := make(map[string]interface{})
	for _, field := range fields {
		fieldMap[field.Key] = field.Value
	}

	m.logs = append(m.logs, LogEntry{
		Level:   level,
		Message: message,
		Fields:  fieldMap,
		Time:    time.Now(),
	})
}

// GetLogs returns all logged entries
func (m *MockLogger) GetLogs() []LogEntry {
	m.mu.RLock()
	defer m.mu.RUnlock()
	logs := make([]LogEntry, len(m.logs))
	copy(logs, m.logs)
	return logs
}

// GetLogsByLevel returns logs filtered by level
func (m *MockLogger) GetLogsByLevel(level string) []LogEntry {
	m.mu.RLock()
	defer m.mu.RUnlock()

	filtered := make([]LogEntry, 0)
	for _, log := range m.logs {
		if log.Level == level {
			filtered = append(filtered, log)
		}
	}
	return filtered
}

// ClearLogs clears all logged entries
func (m *MockLogger) ClearLogs() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.logs = m.logs[:0]
}

// HasLog checks if a log with specific message exists
func (m *MockLogger) HasLog(level, message string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for _, log := range m.logs {
		if log.Level == level && log.Message == message {
			return true
		}
	}
	return false
}

// MockMetrics provides a mock implementation of Metrics
type MockMetrics struct {
	mu      sync.RWMutex
	metrics map[string]interface{}
	calls   []string
}

// NewMockMetrics creates a new mock metrics collector
func NewMockMetrics() *MockMetrics {
	return &MockMetrics{
		metrics: make(map[string]interface{}),
		calls:   make([]string, 0),
	}
}

// IncrementCounter increments a counter metric
func (m *MockMetrics) IncrementCounter(name string, labels map[string]string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls = append(m.calls, fmt.Sprintf("IncrementCounter:%s", name))
	if current, exists := m.metrics[name]; exists {
		if counter, ok := current.(int); ok {
			m.metrics[name] = counter + 1
			return
		}
	}
	m.metrics[name] = 1
}

// SetGauge sets a gauge metric
func (m *MockMetrics) SetGauge(name string, value float64, labels map[string]string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls = append(m.calls, fmt.Sprintf("SetGauge:%s:%f", name, value))
	m.metrics[name] = value
}

// RecordHistogram records a histogram metric
func (m *MockMetrics) RecordHistogram(name string, value float64, labels map[string]string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls = append(m.calls, fmt.Sprintf("RecordHistogram:%s:%f", name, value))
	m.metrics[name] = value
}

// Start starts the metrics collector
func (m *MockMetrics) Start(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls = append(m.calls, "Start")
	return nil
}

// Stop stops the metrics collector
func (m *MockMetrics) Stop() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls = append(m.calls, "Stop")
	return nil
}

// GetMetric returns a metric value
func (m *MockMetrics) GetMetric(name string) interface{} {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.metrics[name]
}

// GetCalls returns all method calls made
func (m *MockMetrics) GetCalls() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	calls := make([]string, len(m.calls))
	copy(calls, m.calls)
	return calls
}

// ClearMetrics clears all metrics
func (m *MockMetrics) ClearMetrics() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.metrics = make(map[string]interface{})
}
