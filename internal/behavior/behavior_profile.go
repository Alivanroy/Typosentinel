// Package behavior provides dynamic behavior analysis for malicious package detection
// through sandbox execution and behavioral monitoring.
package behavior

import "context"

import (
	"fmt"
	"time"
)

// BehaviorProfile captures the runtime behavior of a package during sandbox analysis
type BehaviorProfile struct {
	PackageName      string                 `json:"package_name"`
	Version          string                 `json:"version"`
	Ecosystem        string                 `json:"ecosystem"`
	AnalysisID       string                 `json:"analysis_id"`
	StartTime        time.Time              `json:"start_time"`
	EndTime          time.Time              `json:"end_time"`
	Duration         time.Duration          `json:"duration"`
	Status           string                 `json:"status"` // running, completed, failed, timeout
	
	// Filesystem behavior
	FilesystemActions FilesystemProfile      `json:"filesystem_actions"`
	
	// Network behavior  
	NetworkActivity   NetworkProfile         `json:"network_activity"`
	
	// Suspicious patterns detected
	SuspiciousPatterns SuspiciousProfile     `json:"suspicious_patterns"`
	
	// Process behavior
	ProcessActivity   ProcessProfile         `json:"process_activity"`
	
	// Risk assessment
	RiskScore         float64                `json:"risk_score"`
	RiskLevel         string                 `json:"risk_level"` // low, medium, high, critical
	Confidence        float64                `json:"confidence"`
	
	// Raw behavioral data
	RawEvents         []BehaviorEvent        `json:"raw_events"`
	
	// Analysis metadata
	SandboxID         string                 `json:"sandbox_id"`
	ContainerImage    string                 `json:"container_image"`
	AnalysisVersion   string                 `json:"analysis_version"`
}

// FilesystemProfile captures file system interactions
type FilesystemProfile struct {
	FilesRead        []string          `json:"files_read"`
	FilesWritten     []string          `json:"files_written"`
	FilesDeleted     []string          `json:"files_deleted"`
	FilesCreated     []string          `json:"files_created"`
	DirectoriesRead  []string          `json:"directories_read"`
	DirectoriesCreated []string        `json:"directories_created"`
	SymlinksCreated  []string          `json:"symlinks_created"`
	PermissionsModified []string       `json:"permissions_modified"`
	HiddenFilesAccessed []string       `json:"hidden_files_accessed"`
	SystemFilesAccessed []string       `json:"system_files_accessed"`
	
	// Risk indicators
	SuspiciousPaths    []string          `json:"suspicious_paths"`
	WriteToSystemDirs  bool              `json:"write_to_system_dirs"`
	MassDeletionAttempts int             `json:"mass_deletion_attempts"`
	EncryptionAttempts   int             `json:"encryption_attempts"`
}

// NetworkProfile captures network activity
type NetworkProfile struct {
	DNSQueries       []DNSQuery          `json:"dns_queries"`
	HTTPRequests     []HTTPRequest       `json:"http_requests"`
	TCPConnections   []NetworkConnection `json:"tcp_connections"`
	UDPConnections   []NetworkConnection `json:"udp_connections"`
	ExternalIPs      []string            `json:"external_ips"`
	ExternalDomains  []string            `json:"external_domains"`
	PortsAccessed    []int               `json:"ports_accessed"`
	
	// Risk indicators
	SuspiciousDomains []string           `json:"suspicious_domains"`
	KnownBadIPs       []string           `json:"known_bad_ips"`
	DataExfiltrationAttempts int          `json:"data_exfiltration_attempts"`
	C2CommunicationAttempts int           `json:"c2_communication_attempts"`
	
	// Traffic analysis
	TotalBytesSent   int64               `json:"total_bytes_sent"`
	TotalBytesReceived int64             `json:"total_bytes_received"`
	PeakBandwidth    int64               `json:"peak_bandwidth"`
}

// DNSQuery represents a DNS query
type DNSQuery struct {
	Domain    string    `json:"domain"`
	QueryType string    `json:"query_type"`
	Timestamp time.Time `json:"timestamp"`
	Resolved  bool      `json:"resolved"`
	IPs       []string  `json:"ips"`
}

// HTTPRequest represents an HTTP request
type HTTPRequest struct {
	Method    string            `json:"method"`
	URL       string            `json:"url"`
	Headers   map[string]string `json:"headers"`
	BodySize  int64             `json:"body_size"`
	Timestamp time.Time         `json:"timestamp"`
	StatusCode int              `json:"status_code"`
}

// NetworkConnection represents a network connection
type NetworkConnection struct {
	Protocol  string    `json:"protocol"`
	LocalIP   string    `json:"local_ip"`
	LocalPort int       `json:"local_port"`
	RemoteIP  string    `json:"remote_ip"`
	RemotePort int      `json:"remote_port"`
	Direction string    `json:"direction"` // inbound, outbound
	Timestamp time.Time `json:"timestamp"`
	BytesSent int64     `json:"bytes_sent"`
	BytesReceived int64 `json:"bytes_received"`
}

// SuspiciousProfile captures suspicious behavioral patterns
type SuspiciousProfile struct {
	// Code execution patterns
	EvalUsage           int      `json:"eval_usage"`
	DynamicCodeLoading  int      `json:"dynamic_code_loading"`
	ProcessInjection    int      `json:"process_injection"`
	PrivilegeEscalation int      `json:"privilege_escalation"`
	
	// Cryptographic operations
	CryptoOperations    []CryptoOperation `json:"crypto_operations"`
	RansomwareIndicators []string         `json:"ransomware_indicators"`
	
	// System manipulation
	RegistryModifications int      `json:"registry_modifications"`
	ServiceManipulations  int      `json:"service_manipulations"`
	DriverInstallations   int      `json:"driver_installations"`
	
	// Data manipulation
	DataEncryptionAttempts int     `json:"data_encryption_attempts"`
	DataDeletionAttempts   int     `json:"data_deletion_attempts"`
	DataExfiltrationAttempts int   `json:"data_exfiltration_attempts"`
	
	// Shell and command execution
	ShellExecutions      []ShellExecution `json:"shell_executions"`
	CommandLineArguments []string         `json:"command_line_arguments"`
	
	// Suspicious strings and patterns
	SuspiciousStrings    []string `json:"suspicious_strings"`
	ObfuscatedCode       bool     `json:"obfuscated_code"`
	PackedBinaries       bool     `json:"packed_binaries"`
	
	// IoC matches
	IOCMatches          []string `json:"ioc_matches"`
	YaraMatches         []string `json:"yara_matches"`
	SigmaMatches        []string `json:"sigma_matches"`
}

// CryptoOperation represents a cryptographic operation
type CryptoOperation struct {
	Type      string    `json:"type"` // encrypt, decrypt, hash, sign
	Algorithm string    `json:"algorithm"`
	KeySize   int       `json:"key_size"`
	DataSize  int64     `json:"data_size"`
	Timestamp time.Time `json:"timestamp"`
}

// ShellExecution represents a shell command execution
type ShellExecution struct {
	Command   string    `json:"command"`
	Arguments []string  `json:"arguments"`
	Shell     string    `json:"shell"`
	Timestamp time.Time `json:"timestamp"`
	ExitCode  int       `json:"exit_code"`
}

// ProcessProfile captures process behavior
type ProcessProfile struct {
	ProcessesSpawned   int               `json:"processes_spawned"`
	ProcessesTerminated int               `json:"processes_terminated"`
	ChildProcesses      []ProcessInfo     `json:"child_processes"`
	MemoryUsage         MemoryProfile     `json:"memory_usage"`
	CPUUsage            CPUProfile        `json:"cpu_usage"`
}

// ProcessInfo represents process information
type ProcessInfo struct {
	PID         int       `json:"pid"`
	Name        string    `json:"name"`
	CommandLine string    `json:"command_line"`
	StartTime   time.Time `json:"start_time"`
	EndTime     time.Time `json:"end_time"`
	MemoryUsage int64     `json:"memory_usage"`
	CPUUsage    float64   `json:"cpu_usage"`
}

// MemoryProfile captures memory usage patterns
type MemoryProfile struct {
	PeakUsage       int64 `json:"peak_usage"`
	AverageUsage    int64 `json:"average_usage"`
	MemoryLeaks     int   `json:"memory_leaks"`
	BufferOverflows int   `json:"buffer_overflows"`
}

// CPUProfile captures CPU usage patterns  
type CPUProfile struct {
	PeakUsage    float64 `json:"peak_usage"`
	AverageUsage float64 `json:"average_usage"`
	CPUSpikes    int     `json:"cpu_spikes"`
}

// BehaviorEvent represents a raw behavioral event
type BehaviorEvent struct {
	EventType string                 `json:"event_type"`
	Timestamp time.Time              `json:"timestamp"`
	ProcessID int                    `json:"process_id"`
	ThreadID  int                    `json:"thread_id"`
	Data      map[string]interface{} `json:"data"`
}

// BehaviorAnalyzerInterface interface for behavior analysis implementations
type BehaviorAnalyzerInterface interface {
	AnalyzeBehavior(ctx context.Context, profile *BehaviorProfile) (*BehaviorAnalysis, error)
	CalculateRiskScore(profile *BehaviorProfile) (float64, error)
	GenerateReport(profile *BehaviorProfile) (string, error)
}

// BehaviorAnalysis contains the results of behavior analysis
type BehaviorAnalysis struct {
	PackageID       string           `json:"package_id"`
	AnalysisTime    time.Time        `json:"analysis_time"`
	RiskScore       float64          `json:"risk_score"`
	RiskLevel       string           `json:"risk_level"`
	ThreatsDetected []BehaviorThreat `json:"threats_detected"`
	BehaviorSummary *BehaviorSummary `json:"behavior_summary"`
}

// BehaviorThreat represents a detected behavioral threat
type BehaviorThreat struct {
	ID          string    `json:"id"`
	Type        string    `json:"type"`
	Severity    string    `json:"severity"`
	Description string    `json:"description"`
	Evidence    []string  `json:"evidence"`
	Confidence  float64   `json:"confidence"`
	Timestamp   time.Time `json:"timestamp"`
}

// BehaviorSummary provides a summary of behavior analysis
type BehaviorSummary struct {
	TotalActions    int      `json:"total_actions"`
	CriticalActions int      `json:"critical_actions"`
	RiskFactors     []string `json:"risk_factors"`
	Recommendations []string `json:"recommendations"`
	Confidence      float64  `json:"confidence"`
}

// NewBehaviorProfile creates a new behavior profile
func NewBehaviorProfile(packageName, version, ecosystem string) *BehaviorProfile {
	return &BehaviorProfile{
		PackageName:   packageName,
		Version:       version,
		Ecosystem:     ecosystem,
		AnalysisID:    generateAnalysisID(),
		StartTime:     time.Now(),
		Status:        "running",
		RawEvents:     []BehaviorEvent{},
		RiskScore:     0.0,
		RiskLevel:     "unknown",
		Confidence:    0.0,
	}
}

// Complete marks the behavior analysis as completed
func (bp *BehaviorProfile) Complete() {
	bp.EndTime = time.Now()
	bp.Duration = bp.EndTime.Sub(bp.StartTime)
	bp.Status = "completed"
}

// AddEvent adds a raw behavioral event
func (bp *BehaviorProfile) AddEvent(eventType string, data map[string]interface{}) {
	event := BehaviorEvent{
		EventType: eventType,
		Timestamp: time.Now(),
		Data:      data,
	}
	bp.RawEvents = append(bp.RawEvents, event)
}

// generateAnalysisID generates a unique analysis ID
func generateAnalysisID() string {
	return fmt.Sprintf("behavior_%d", time.Now().UnixNano())
}

// IsHighRisk determines if the behavior profile indicates high risk
func (bp *BehaviorProfile) IsHighRisk() bool {
	return bp.RiskScore >= 0.7 || bp.RiskLevel == "high" || bp.RiskLevel == "critical"
}

// GetSuspiciousActivities returns a summary of suspicious activities
func (bp *BehaviorProfile) GetSuspiciousActivities() []string {
	activities := []string{}
	
	// Check filesystem activities
	if bp.FilesystemActions.WriteToSystemDirs {
		activities = append(activities, "Write operations to system directories")
	}
	if bp.FilesystemActions.MassDeletionAttempts > 0 {
		activities = append(activities, fmt.Sprintf("Mass deletion attempts: %d", bp.FilesystemActions.MassDeletionAttempts))
	}
	if bp.FilesystemActions.EncryptionAttempts > 0 {
		activities = append(activities, fmt.Sprintf("Encryption attempts: %d", bp.FilesystemActions.EncryptionAttempts))
	}
	
	// Check network activities
	if len(bp.NetworkActivity.SuspiciousDomains) > 0 {
		activities = append(activities, fmt.Sprintf("Suspicious domains accessed: %d", len(bp.NetworkActivity.SuspiciousDomains)))
	}
	if len(bp.NetworkActivity.KnownBadIPs) > 0 {
		activities = append(activities, fmt.Sprintf("Known bad IPs contacted: %d", len(bp.NetworkActivity.KnownBadIPs)))
	}
	if bp.NetworkActivity.DataExfiltrationAttempts > 0 {
		activities = append(activities, "Data exfiltration attempts detected")
	}
	if bp.NetworkActivity.C2CommunicationAttempts > 0 {
		activities = append(activities, "Command & Control communication attempts detected")
	}
	
	// Check suspicious patterns
	if bp.SuspiciousPatterns.EvalUsage > 0 {
		activities = append(activities, fmt.Sprintf("Dynamic code execution (eval): %d", bp.SuspiciousPatterns.EvalUsage))
	}
	if bp.SuspiciousPatterns.DynamicCodeLoading > 0 {
		activities = append(activities, fmt.Sprintf("Dynamic code loading: %d", bp.SuspiciousPatterns.DynamicCodeLoading))
	}
	if bp.SuspiciousPatterns.ProcessInjection > 0 {
		activities = append(activities, fmt.Sprintf("Process injection attempts: %d", bp.SuspiciousPatterns.ProcessInjection))
	}
	if len(bp.SuspiciousPatterns.ShellExecutions) > 0 {
		activities = append(activities, fmt.Sprintf("Shell command executions: %d", len(bp.SuspiciousPatterns.ShellExecutions)))
	}
	
	return activities
}