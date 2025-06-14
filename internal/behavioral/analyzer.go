package behavioral

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

// BehavioralAnalyzer monitors runtime behavior of packages
type BehavioralAnalyzer struct {
	config           *Config
	monitors         map[string]*Monitor
	mu               sync.RWMutex
	anomalyDetector  *AnomalyDetector
	patternMatcher   *PatternMatcher
}

// Config contains behavioral analyzer configuration
type Config struct {
	Enabled                bool          `yaml:"enabled"`
	MonitorNetworkActivity bool          `yaml:"monitor_network_activity"`
	MonitorFileActivity    bool          `yaml:"monitor_file_activity"`
	MonitorProcessActivity bool          `yaml:"monitor_process_activity"`
	MonitorRegistryActivity bool         `yaml:"monitor_registry_activity"`
	MonitorMemoryActivity  bool          `yaml:"monitor_memory_activity"`
	SamplingRate          float64       `yaml:"sampling_rate"`
	AnalysisWindow        time.Duration `yaml:"analysis_window"`
	AnomalyThreshold      float64       `yaml:"anomaly_threshold"`
	MaxEvents             int           `yaml:"max_events"`
	Timeout               time.Duration `yaml:"timeout"`
	Verbose               bool          `yaml:"verbose"`
}

// Monitor represents a behavioral monitor for a specific package
type Monitor struct {
	PackageName    string
	StartTime      time.Time
	Events         []Event
	NetworkEvents  []NetworkEvent
	FileEvents     []FileEvent
	ProcessEvents  []ProcessEvent
	RegistryEvents []RegistryEvent
	MemoryEvents   []MemoryEvent
	mu             sync.Mutex
}

// Event represents a generic behavioral event
type Event struct {
	Timestamp   time.Time              `json:"timestamp"`
	Type        string                 `json:"type"`
	Severity    string                 `json:"severity"`
	Description string                 `json:"description"`
	Metadata    map[string]interface{} `json:"metadata"`
	RiskScore   float64                `json:"risk_score"`
}

// NetworkEvent represents network-related behavioral events
type NetworkEvent struct {
	Timestamp     time.Time `json:"timestamp"`
	Protocol      string    `json:"protocol"`
	SourceIP      string    `json:"source_ip"`
	SourcePort    int       `json:"source_port"`
	DestinationIP string    `json:"destination_ip"`
	DestPort      int       `json:"dest_port"`
	DataSize      int64     `json:"data_size"`
	Direction     string    `json:"direction"`
	Suspicious    bool      `json:"suspicious"`
	Reason        string    `json:"reason"`
}

// FileEvent represents file system behavioral events
type FileEvent struct {
	Timestamp  time.Time `json:"timestamp"`
	Operation  string    `json:"operation"`
	FilePath   string    `json:"file_path"`
	FileSize   int64     `json:"file_size"`
	Permissions string   `json:"permissions"`
	Suspicious bool      `json:"suspicious"`
	Reason     string    `json:"reason"`
}

// ProcessEvent represents process-related behavioral events
type ProcessEvent struct {
	Timestamp   time.Time `json:"timestamp"`
	PID         int       `json:"pid"`
	ParentPID   int       `json:"parent_pid"`
	ProcessName string    `json:"process_name"`
	CommandLine string    `json:"command_line"`
	Operation   string    `json:"operation"`
	Suspicious  bool      `json:"suspicious"`
	Reason      string    `json:"reason"`
}

// RegistryEvent represents Windows registry behavioral events
type RegistryEvent struct {
	Timestamp  time.Time `json:"timestamp"`
	Operation  string    `json:"operation"`
	KeyPath    string    `json:"key_path"`
	ValueName  string    `json:"value_name"`
	ValueData  string    `json:"value_data"`
	Suspicious bool      `json:"suspicious"`
	Reason     string    `json:"reason"`
}

// MemoryEvent represents memory-related behavioral events
type MemoryEvent struct {
	Timestamp    time.Time `json:"timestamp"`
	Operation    string    `json:"operation"`
	Address      uint64    `json:"address"`
	Size         uint64    `json:"size"`
	Permissions  string    `json:"permissions"`
	ProcessName  string    `json:"process_name"`
	Suspicious   bool      `json:"suspicious"`
	Reason       string    `json:"reason"`
}

// BehavioralAnalysis represents the result of behavioral analysis
type BehavioralAnalysis struct {
	PackageName       string                 `json:"package_name"`
	AnalysisTimestamp time.Time              `json:"analysis_timestamp"`
	Duration          time.Duration          `json:"duration"`
	TotalEvents       int                    `json:"total_events"`
	SuspiciousEvents  int                    `json:"suspicious_events"`
	NetworkActivity   NetworkActivitySummary `json:"network_activity"`
	FileActivity      FileActivitySummary    `json:"file_activity"`
	ProcessActivity   ProcessActivitySummary `json:"process_activity"`
	Anomalies         []Anomaly              `json:"anomalies"`
	PatternMatches    []PatternMatch         `json:"pattern_matches"`
	RiskScore         float64                `json:"risk_score"`
	ThreatLevel       string                 `json:"threat_level"`
	Recommendations   []string               `json:"recommendations"`
}

// NetworkActivitySummary summarizes network activity
type NetworkActivitySummary struct {
	TotalConnections    int      `json:"total_connections"`
	UniqueDestinations  int      `json:"unique_destinations"`
	SuspiciousHosts     []string `json:"suspicious_hosts"`
	DataTransferred     int64    `json:"data_transferred"`
	ProtocolsUsed       []string `json:"protocols_used"`
	UnusualPorts        []int    `json:"unusual_ports"`
}

// FileActivitySummary summarizes file system activity
type FileActivitySummary struct {
	FilesCreated       int      `json:"files_created"`
	FilesModified      int      `json:"files_modified"`
	FilesDeleted       int      `json:"files_deleted"`
	SuspiciousLocations []string `json:"suspicious_locations"`
	PermissionChanges  int      `json:"permission_changes"`
	HiddenFiles        []string `json:"hidden_files"`
}

// ProcessActivitySummary summarizes process activity
type ProcessActivitySummary struct {
	ProcessesSpawned   int      `json:"processes_spawned"`
	SuspiciousCommands []string `json:"suspicious_commands"`
	PrivilegeEscalation bool    `json:"privilege_escalation"`
	CodeInjection      bool     `json:"code_injection"`
	AntiAnalysis       bool     `json:"anti_analysis"`
}

// Anomaly represents detected behavioral anomalies
type Anomaly struct {
	Type        string    `json:"type"`
	Description string    `json:"description"`
	Severity    string    `json:"severity"`
	Timestamp   time.Time `json:"timestamp"`
	Confidence  float64   `json:"confidence"`
	Evidence    []string  `json:"evidence"`
}

// PatternMatch represents matched behavioral patterns
type PatternMatch struct {
	PatternName string    `json:"pattern_name"`
	Description string    `json:"description"`
	Severity    string    `json:"severity"`
	Timestamp   time.Time `json:"timestamp"`
	Confidence  float64   `json:"confidence"`
	Matches     []string  `json:"matches"`
}

// AnomalyDetector detects behavioral anomalies
type AnomalyDetector struct {
	baseline map[string]float64
	mu       sync.RWMutex
}

// PatternMatcher matches behavioral patterns
type PatternMatcher struct {
	patterns []*BehavioralPattern
}

// BehavioralPattern represents a behavioral pattern to match
type BehavioralPattern struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	Severity    string         `json:"severity"`
	Conditions  []Condition    `json:"conditions"`
	TimeWindow  time.Duration  `json:"time_window"`
	Threshold   int           `json:"threshold"`
	Enabled     bool          `json:"enabled"`
}

// Condition represents a condition in a behavioral pattern
type Condition struct {
	Type     string      `json:"type"`
	Field    string      `json:"field"`
	Operator string      `json:"operator"`
	Value    interface{} `json:"value"`
	Regex    *regexp.Regexp `json:"-"`
}

// NewBehavioralAnalyzer creates a new behavioral analyzer
func NewBehavioralAnalyzer(config *Config) (*BehavioralAnalyzer, error) {
	if config == nil {
		config = DefaultConfig()
	}

	analyzer := &BehavioralAnalyzer{
		config:   config,
		monitors: make(map[string]*Monitor),
		anomalyDetector: &AnomalyDetector{
			baseline: make(map[string]float64),
		},
		patternMatcher: &PatternMatcher{
			patterns: loadBehavioralPatterns(),
		},
	}

	return analyzer, nil
}

// DefaultConfig returns default behavioral analyzer configuration
func DefaultConfig() *Config {
	return &Config{
		Enabled:                true,
		MonitorNetworkActivity: true,
		MonitorFileActivity:    true,
		MonitorProcessActivity: true,
		MonitorRegistryActivity: true,
		MonitorMemoryActivity:  true,
		SamplingRate:          1.0,
		AnalysisWindow:        5 * time.Minute,
		AnomalyThreshold:      0.8,
		MaxEvents:             10000,
		Timeout:               30 * time.Second,
		Verbose:               false,
	}
}

// StartMonitoring begins behavioral monitoring for a package
func (ba *BehavioralAnalyzer) StartMonitoring(packageName string) error {
	ba.mu.Lock()
	defer ba.mu.Unlock()

	monitor := &Monitor{
		PackageName:    packageName,
		StartTime:      time.Now(),
		Events:         make([]Event, 0),
		NetworkEvents:  make([]NetworkEvent, 0),
		FileEvents:     make([]FileEvent, 0),
		ProcessEvents:  make([]ProcessEvent, 0),
		RegistryEvents: make([]RegistryEvent, 0),
		MemoryEvents:   make([]MemoryEvent, 0),
	}

	ba.monitors[packageName] = monitor
	return nil
}

// StopMonitoring stops behavioral monitoring for a package
func (ba *BehavioralAnalyzer) StopMonitoring(packageName string) (*BehavioralAnalysis, error) {
	ba.mu.Lock()
	monitor, exists := ba.monitors[packageName]
	if !exists {
		ba.mu.Unlock()
		return nil, fmt.Errorf("no monitor found for package %s", packageName)
	}
	delete(ba.monitors, packageName)
	ba.mu.Unlock()

	return ba.analyzeMonitorData(monitor)
}

// analyzeMonitorData analyzes collected monitoring data
func (ba *BehavioralAnalyzer) analyzeMonitorData(monitor *Monitor) (*BehavioralAnalysis, error) {
	analysis := &BehavioralAnalysis{
		PackageName:       monitor.PackageName,
		AnalysisTimestamp: time.Now(),
		Duration:          time.Since(monitor.StartTime),
		TotalEvents:       len(monitor.Events),
		Anomalies:         make([]Anomaly, 0),
		PatternMatches:    make([]PatternMatch, 0),
		Recommendations:   make([]string, 0),
	}

	// Analyze network activity
	analysis.NetworkActivity = ba.analyzeNetworkActivity(monitor.NetworkEvents)

	// Analyze file activity
	analysis.FileActivity = ba.analyzeFileActivity(monitor.FileEvents)

	// Analyze process activity
	analysis.ProcessActivity = ba.analyzeProcessActivity(monitor.ProcessEvents)

	// Detect anomalies
	anomalies := ba.anomalyDetector.DetectAnomalies(monitor)
	analysis.Anomalies = append(analysis.Anomalies, anomalies...)

	// Match patterns
	patternMatches := ba.patternMatcher.MatchPatterns(monitor)
	analysis.PatternMatches = append(analysis.PatternMatches, patternMatches...)

	// Count suspicious events
	analysis.SuspiciousEvents = ba.countSuspiciousEvents(monitor)

	// Calculate risk score
	analysis.RiskScore = ba.calculateRiskScore(analysis)
	analysis.ThreatLevel = ba.determineThreatLevel(analysis.RiskScore)

	// Generate recommendations
	analysis.Recommendations = ba.generateRecommendations(analysis)

	return analysis, nil
}

// analyzeNetworkActivity analyzes network events
func (ba *BehavioralAnalyzer) analyzeNetworkActivity(events []NetworkEvent) NetworkActivitySummary {
	summary := NetworkActivitySummary{
		TotalConnections:   len(events),
		SuspiciousHosts:    make([]string, 0),
		ProtocolsUsed:      make([]string, 0),
		UnusualPorts:       make([]int, 0),
	}

	destinations := make(map[string]bool)
	protocols := make(map[string]bool)
	ports := make(map[int]int)

	for _, event := range events {
		destinations[event.DestinationIP] = true
		protocols[event.Protocol] = true
		ports[event.DestPort]++
		summary.DataTransferred += event.DataSize

		if event.Suspicious {
			summary.SuspiciousHosts = append(summary.SuspiciousHosts, event.DestinationIP)
		}
	}

	summary.UniqueDestinations = len(destinations)

	for protocol := range protocols {
		summary.ProtocolsUsed = append(summary.ProtocolsUsed, protocol)
	}

	// Identify unusual ports (ports used infrequently)
	for port, count := range ports {
		if count == 1 && !isCommonPort(port) {
			summary.UnusualPorts = append(summary.UnusualPorts, port)
		}
	}

	return summary
}

// analyzeFileActivity analyzes file system events
func (ba *BehavioralAnalyzer) analyzeFileActivity(events []FileEvent) FileActivitySummary {
	summary := FileActivitySummary{
		SuspiciousLocations: make([]string, 0),
		HiddenFiles:         make([]string, 0),
	}

	for _, event := range events {
		switch event.Operation {
		case "create":
			summary.FilesCreated++
		case "modify":
			summary.FilesModified++
		case "delete":
			summary.FilesDeleted++
		case "chmod":
			summary.PermissionChanges++
		}

		if event.Suspicious {
			summary.SuspiciousLocations = append(summary.SuspiciousLocations, event.FilePath)
		}

		if isHiddenFile(event.FilePath) {
			summary.HiddenFiles = append(summary.HiddenFiles, event.FilePath)
		}
	}

	return summary
}

// analyzeProcessActivity analyzes process events
func (ba *BehavioralAnalyzer) analyzeProcessActivity(events []ProcessEvent) ProcessActivitySummary {
	summary := ProcessActivitySummary{
		SuspiciousCommands: make([]string, 0),
	}

	for _, event := range events {
		if event.Operation == "create" {
			summary.ProcessesSpawned++
		}

		if event.Suspicious {
			summary.SuspiciousCommands = append(summary.SuspiciousCommands, event.CommandLine)
		}

		// Check for privilege escalation
		if strings.Contains(event.CommandLine, "sudo") || strings.Contains(event.CommandLine, "su ") {
			summary.PrivilegeEscalation = true
		}

		// Check for code injection
		if strings.Contains(event.CommandLine, "ptrace") || strings.Contains(event.CommandLine, "inject") {
			summary.CodeInjection = true
		}

		// Check for anti-analysis
		if strings.Contains(event.CommandLine, "debugger") || strings.Contains(event.CommandLine, "vm") {
			summary.AntiAnalysis = true
		}
	}

	return summary
}

// Helper functions
func isCommonPort(port int) bool {
	commonPorts := []int{21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995}
	for _, p := range commonPorts {
		if port == p {
			return true
		}
	}
	return false
}

func isHiddenFile(path string) bool {
	filename := filepath.Base(path)
	return strings.HasPrefix(filename, ".")
}

func (ba *BehavioralAnalyzer) countSuspiciousEvents(monitor *Monitor) int {
	count := 0
	for _, event := range monitor.NetworkEvents {
		if event.Suspicious {
			count++
		}
	}
	for _, event := range monitor.FileEvents {
		if event.Suspicious {
			count++
		}
	}
	for _, event := range monitor.ProcessEvents {
		if event.Suspicious {
			count++
		}
	}
	return count
}

func (ba *BehavioralAnalyzer) calculateRiskScore(analysis *BehavioralAnalysis) float64 {
	score := 0.0

	// Network activity risk
	score += float64(len(analysis.NetworkActivity.SuspiciousHosts)) * 0.2
	score += float64(len(analysis.NetworkActivity.UnusualPorts)) * 0.1

	// File activity risk
	score += float64(len(analysis.FileActivity.SuspiciousLocations)) * 0.3
	score += float64(len(analysis.FileActivity.HiddenFiles)) * 0.1

	// Process activity risk
	if analysis.ProcessActivity.PrivilegeEscalation {
		score += 0.5
	}
	if analysis.ProcessActivity.CodeInjection {
		score += 0.4
	}
	if analysis.ProcessActivity.AntiAnalysis {
		score += 0.3
	}

	// Anomalies and patterns
	score += float64(len(analysis.Anomalies)) * 0.2
	score += float64(len(analysis.PatternMatches)) * 0.3

	// Normalize to 0-1 range
	if score > 1.0 {
		score = 1.0
	}

	return score
}

func (ba *BehavioralAnalyzer) determineThreatLevel(riskScore float64) string {
	if riskScore >= 0.8 {
		return "critical"
	} else if riskScore >= 0.6 {
		return "high"
	} else if riskScore >= 0.4 {
		return "medium"
	} else if riskScore >= 0.2 {
		return "low"
	}
	return "minimal"
}

func (ba *BehavioralAnalyzer) generateRecommendations(analysis *BehavioralAnalysis) []string {
	recommendations := make([]string, 0)

	if analysis.RiskScore >= 0.8 {
		recommendations = append(recommendations, "Immediately quarantine this package")
		recommendations = append(recommendations, "Perform detailed forensic analysis")
	}

	if len(analysis.NetworkActivity.SuspiciousHosts) > 0 {
		recommendations = append(recommendations, "Block network access to suspicious hosts")
	}

	if analysis.ProcessActivity.PrivilegeEscalation {
		recommendations = append(recommendations, "Review privilege escalation attempts")
	}

	if len(analysis.FileActivity.SuspiciousLocations) > 0 {
		recommendations = append(recommendations, "Monitor file system changes in sensitive locations")
	}

	return recommendations
}

// DetectAnomalies detects behavioral anomalies
func (ad *AnomalyDetector) DetectAnomalies(monitor *Monitor) []Anomaly {
	anomalies := make([]Anomaly, 0)

	// Detect network anomalies
	if len(monitor.NetworkEvents) > 100 {
		anomalies = append(anomalies, Anomaly{
			Type:        "network",
			Description: "Excessive network activity detected",
			Severity:    "high",
			Timestamp:   time.Now(),
			Confidence:  0.9,
			Evidence:    []string{fmt.Sprintf("%d network events", len(monitor.NetworkEvents))},
		})
	}

	// Detect file anomalies
	if len(monitor.FileEvents) > 50 {
		anomalies = append(anomalies, Anomaly{
			Type:        "filesystem",
			Description: "Excessive file system activity detected",
			Severity:    "medium",
			Timestamp:   time.Now(),
			Confidence:  0.8,
			Evidence:    []string{fmt.Sprintf("%d file events", len(monitor.FileEvents))},
		})
	}

	return anomalies
}

// MatchPatterns matches behavioral patterns
func (pm *PatternMatcher) MatchPatterns(monitor *Monitor) []PatternMatch {
	matches := make([]PatternMatch, 0)

	for _, pattern := range pm.patterns {
		if !pattern.Enabled {
			continue
		}

		if pm.evaluatePattern(pattern, monitor) {
			matches = append(matches, PatternMatch{
				PatternName: pattern.Name,
				Description: pattern.Description,
				Severity:    pattern.Severity,
				Timestamp:   time.Now(),
				Confidence:  0.8,
				Matches:     []string{pattern.Name},
			})
		}
	}

	return matches
}

func (pm *PatternMatcher) evaluatePattern(pattern *BehavioralPattern, monitor *Monitor) bool {
	// Simple pattern matching logic
	// In a real implementation, this would be more sophisticated
	return len(monitor.Events) > pattern.Threshold
}

func loadBehavioralPatterns() []*BehavioralPattern {
	return []*BehavioralPattern{
		{
			Name:        "excessive_network_activity",
			Description: "Package making excessive network connections",
			Severity:    "high",
			Threshold:   50,
			Enabled:     true,
		},
		{
			Name:        "suspicious_file_operations",
			Description: "Package performing suspicious file operations",
			Severity:    "medium",
			Threshold:   20,
			Enabled:     true,
		},
	}
}