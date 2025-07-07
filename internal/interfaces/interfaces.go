// Package interfaces defines core interfaces for dependency injection
// This enables better testability and modularity throughout the application
package interfaces

import (
	"context"
	"time"
)

// RegistryClient defines the interface for package registry interactions
type RegistryClient interface {
	// GetPackageInfo retrieves detailed information about a package
	GetPackageInfo(ctx context.Context, packageName string) (*PackageInfo, error)
	
	// SearchPackages searches for packages matching the query
	SearchPackages(ctx context.Context, query string, limit int) ([]*PackageInfo, error)
	
	// GetPackageVersions retrieves all versions of a package
	GetPackageVersions(ctx context.Context, name string) ([]*VersionInfo, error)
	
	// GetPackageMetadata retrieves metadata for a specific package version
	GetPackageMetadata(ctx context.Context, name, version string) (*PackageMetadata, error)
	
	// GetEcosystem returns the ecosystem this client handles (npm, pypi, etc.)
	GetEcosystem() string
}

// ThreatDatabase defines the interface for threat intelligence operations
type ThreatDatabase interface {
	// CheckThreat checks if a package is known to be malicious
	CheckThreat(ctx context.Context, packageName string) (*ThreatInfo, error)
	
	// UpdateThreat updates threat information
	UpdateThreat(ctx context.Context, threat *ThreatInfo) error
	
	// UpdateThreats updates the threat database with latest intelligence
	UpdateThreats(ctx context.Context) error
	
	// AddThreat adds a new threat to the database
	AddThreat(ctx context.Context, threat *ThreatInfo) error
	
	// GetThreatsByType retrieves threats by category
	GetThreatsByType(ctx context.Context, threatType string) ([]*ThreatInfo, error)
	
	// GetLastUpdate returns the timestamp of the last database update
	GetLastUpdate(ctx context.Context) (time.Time, error)
}

// MLScorer defines the interface for machine learning risk scoring
type MLScorer interface {
	// ScorePackage scores a package for suspiciousness
	ScorePackage(ctx context.Context, pkg *PackageInfo) (float64, error)
	
	// BatchScore scores multiple packages
	BatchScore(ctx context.Context, packages []*PackageInfo) (map[string]float64, error)
	
	// CalculateRisk calculates the risk score for a package
	CalculateRisk(ctx context.Context, pkg *Package) (float64, error)
	
	// Train trains the model with new data
	Train(ctx context.Context, data TrainingData) error
	
	// GetModelVersion returns the current model version
	GetModelVersion() string
	
	// GetFeatureImportance returns feature importance scores
	GetFeatureImportance() map[string]float64
	
	// Predict makes predictions using the trained model
	Predict(ctx context.Context, features map[string]interface{}) (float64, error)
}

// Cache defines the interface for caching operations
type Cache interface {
	// Get retrieves a value from cache
	Get(ctx context.Context, key string) (interface{}, error)
	
	// Set stores a value in cache with TTL
	Set(ctx context.Context, key string, value interface{}, ttl time.Duration) error
	
	// Delete removes a value from cache
	Delete(ctx context.Context, key string) error
	
	// Clear removes all values from cache
	Clear(ctx context.Context) error
	
	// Exists checks if a key exists in cache
	Exists(ctx context.Context, key string) (bool, error)
	
	// GetTTL returns the remaining TTL for a key
	GetTTL(ctx context.Context, key string) (time.Duration, error)
}

// Logger defines the interface for structured logging
type Logger interface {
	// Debug logs debug level messages
	Debug(msg string, fields ...LogField)
	
	// Info logs info level messages
	Info(msg string, fields ...LogField)
	
	// Warn logs warning level messages
	Warn(msg string, fields ...LogField)
	
	// Error logs error level messages
	Error(msg string, fields ...LogField)
	
	// Fatal logs fatal level messages and exits
	Fatal(msg string, fields ...LogField)
	
	// WithContext returns a logger with context
	WithContext(ctx context.Context) Logger
	
	// WithFields returns a logger with additional fields
	WithFields(fields ...LogField) Logger
}

// Metrics defines the interface for metrics collection
type Metrics interface {
	// IncrementCounter increments a counter metric
	IncrementCounter(name string, labels MetricTags)
	
	// SetGauge sets a gauge metric
	SetGauge(name string, value float64, labels MetricTags)
	
	// RecordHistogram records a histogram metric
	RecordHistogram(name string, value float64, labels MetricTags)
	
	// RecordDuration records a duration metric
	RecordDuration(name string, duration time.Duration, tags MetricTags)
	
	// Start starts the metrics collector
	Start(ctx context.Context) error
	
	// Stop stops the metrics collector
	Stop() error
	
	// Counter creates or retrieves a counter metric
	Counter(name string, tags MetricTags) Counter
	
	// Gauge creates or retrieves a gauge metric
	Gauge(name string, tags MetricTags) Gauge
	
	// Histogram creates or retrieves a histogram metric
	Histogram(name string, tags MetricTags) Histogram
	
	// Timer creates or retrieves a timer metric
	Timer(name string, tags MetricTags) Timer
}

// Counter defines a counter metric interface
type Counter interface {
	// Inc increments the counter by 1
	Inc()
	
	// Add adds the given value to the counter
	Add(value float64)
}

// Gauge defines a gauge metric interface
type Gauge interface {
	// Set sets the gauge to the given value
	Set(value float64)
	
	// Inc increments the gauge by 1
	Inc()
	
	// Dec decrements the gauge by 1
	Dec()
	
	// Add adds the given value to the gauge
	Add(value float64)
	
	// Sub subtracts the given value from the gauge
	Sub(value float64)
}

// Histogram defines a histogram metric interface
type Histogram interface {
	// Observe adds an observation to the histogram
	Observe(value float64)
}

// Timer defines a timer metric interface
type Timer interface {
	// Time returns a function to call when the operation is complete
	Time() func()
	
	// Record records a duration
	Record(duration time.Duration)
}

// Validator defines the interface for input validation
type Validator interface {
	// ValidatePackageName validates a package name
	ValidatePackageName(name string) error
	
	// ValidateVersion validates a package version
	ValidateVersion(version string) error
	
	// ValidateEcosystem validates an ecosystem name
	ValidateEcosystem(ecosystem string) error
	
	// SanitizeInput sanitizes user input
	SanitizeInput(input string) string
	
	// ValidateURL validates a URL
	ValidateURL(url string) error
}

// ConfigManager defines the interface for configuration management
type ConfigManager interface {
	// Get retrieves a configuration value
	Get(key string) interface{}
	
	// GetString retrieves a string configuration value
	GetString(key string) string
	
	// GetInt retrieves an integer configuration value
	GetInt(key string) int
	
	// GetBool retrieves a boolean configuration value
	GetBool(key string) bool
	
	// GetDuration retrieves a duration configuration value
	GetDuration(key string) time.Duration
	
	// Set sets a configuration value
	Set(key string, value interface{})
	
	// Reload reloads the configuration
	Reload() error
	
	// Watch watches for configuration changes
	Watch(callback func()) error
}

// Data structures used by interfaces

// PackageInfo represents package information
type PackageInfo struct {
	Name        string            `json:"name"`
	Version     string            `json:"version"`
	Ecosystem   string            `json:"ecosystem"`
	Description string            `json:"description"`
	Author      string            `json:"author"`
	License     string            `json:"license"`
	Homepage    string            `json:"homepage"`
	Repository  string            `json:"repository"`
	Downloads   int64             `json:"downloads"`
	CreatedAt   time.Time         `json:"created_at"`
	UpdatedAt   time.Time         `json:"updated_at"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// VersionInfo represents version information
type VersionInfo struct {
	Version   string    `json:"version"`
	CreatedAt time.Time `json:"created_at"`
	Yanked    bool      `json:"yanked"`
}

// PackageMetadata represents detailed package metadata
type PackageMetadata struct {
	Name         string            `json:"name"`
	Version      string            `json:"version"`
	Dependencies []string          `json:"dependencies"`
	DevDeps      []string          `json:"dev_dependencies"`
	Keywords     []string          `json:"keywords"`
	Maintainers  []string          `json:"maintainers"`
	Size         int64             `json:"size"`
	Files        []string          `json:"files"`
	Scripts      map[string]string `json:"scripts"`
	Engines      map[string]string `json:"engines"`
}

// Package represents a package being analyzed
type Package struct {
	Name      string            `json:"name"`
	Version   string            `json:"version"`
	Ecosystem string            `json:"ecosystem"`
	Metadata  *PackageMetadata  `json:"metadata"`
	Features  map[string]interface{} `json:"features"`
}

// ThreatInfo represents threat intelligence information
type ThreatInfo struct {
	ID          string            `json:"id"`
	PackageName string            `json:"package_name"`
	Ecosystem   string            `json:"ecosystem"`
	ThreatType  string            `json:"threat_type"`
	Severity    string            `json:"severity"`
	Description string            `json:"description"`
	Source      string            `json:"source"`
	CreatedAt   time.Time         `json:"created_at"`
	UpdatedAt   time.Time         `json:"updated_at"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// TrainingData represents ML training data
type TrainingData struct {
	Features []map[string]interface{} `json:"features"`
	Labels   []float64               `json:"labels"`
	Metadata map[string]interface{}  `json:"metadata"`
}

// Field represents a structured logging field
type Field struct {
	Key   string      `json:"key"`
	Value interface{} `json:"value"`
}

// LogField represents a logging field (alias for Field)
type LogField = Field

// LogFields represents a slice of logging fields
type LogFields []Field

// MetricTags represents tags for metrics
type MetricTags map[string]string

// NewField creates a new logging field
func NewField(key string, value interface{}) Field {
	return Field{Key: key, Value: value}
}

// String creates a string field
func String(key, value string) Field {
	return Field{Key: key, Value: value}
}

// Int creates an integer field
func Int(key string, value int) Field {
	return Field{Key: key, Value: value}
}

// Float64 creates a float64 field
func Float64(key string, value float64) Field {
	return Field{Key: key, Value: value}
}

// Bool creates a boolean field
func Bool(key string, value bool) Field {
	return Field{Key: key, Value: value}
}

// Duration creates a duration field
func Duration(key string, value time.Duration) Field {
	return Field{Key: key, Value: value}
}

// Error creates an error field
func Error(err error) Field {
	return Field{Key: "error", Value: err.Error()}
}