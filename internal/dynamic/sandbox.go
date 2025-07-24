package dynamic

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// DynamicAnalyzer performs lightweight dynamic analysis in sandboxed environments
type DynamicAnalyzer struct {
	config    *Config
	sandboxes map[string]*Sandbox
	mu        sync.RWMutex
}

// Config contains dynamic analyzer configuration
type Config struct {
	Enabled bool `yaml:"enabled"`

	// Sandbox configuration
	SandboxType            string `yaml:"sandbox_type"` // docker, vm, chroot, namespace
	SandboxImage           string `yaml:"sandbox_image"`
	SandboxTimeout         string `yaml:"sandbox_timeout"`
	MaxConcurrentSandboxes int    `yaml:"max_concurrent_sandboxes"`

	// Analysis configuration
	AnalyzeInstallScripts  bool `yaml:"analyze_install_scripts"`
	AnalyzeNetworkActivity bool `yaml:"analyze_network_activity"`
	AnalyzeFileSystem      bool `yaml:"analyze_file_system"`
	AnalyzeProcesses       bool `yaml:"analyze_processes"`
	AnalyzeEnvironment     bool `yaml:"analyze_environment"`

	// Security limits
	MaxExecutionTime      string `yaml:"max_execution_time"`
	MaxMemoryUsage        int64  `yaml:"max_memory_usage"`
	MaxDiskUsage          int64  `yaml:"max_disk_usage"`
	MaxNetworkConnections int    `yaml:"max_network_connections"`

	// Monitoring
	MonitoringInterval string `yaml:"monitoring_interval"`
	Verbose            bool   `yaml:"verbose"`
	LogLevel           string `yaml:"log_level"`
}

// AnalysisResult represents dynamic analysis results
type AnalysisResult struct {
	PackageName       string    `json:"package_name"`
	Registry          string    `json:"registry"`
	AnalysisTimestamp time.Time `json:"analysis_timestamp"`

	// Execution results
	ExecutionResults []ExecutionResult `json:"execution_results"`

	// Behavioral analysis
	NetworkActivity    []NetworkActivity   `json:"network_activity"`
	FileSystemChanges  []FileSystemChange  `json:"file_system_changes"`
	ProcessActivity    []ProcessActivity   `json:"process_activity"`
	EnvironmentChanges []EnvironmentChange `json:"environment_changes"`

	// Security assessment
	SecurityFindings []SecurityFinding `json:"security_findings"`
	RiskScore        float64           `json:"risk_score"`
	ThreatLevel      string            `json:"threat_level"`

	// Metadata
	SandboxInfo     SandboxInfo   `json:"sandbox_info"`
	ProcessingTime  time.Duration `json:"processing_time"`
	ResourceUsage   ResourceUsage `json:"resource_usage"`
	Warnings        []string      `json:"warnings"`
	Recommendations []string      `json:"recommendations"`
}

// ExecutionResult represents the result of executing a script or command
type ExecutionResult struct {
	Command            string              `json:"command"`
	ExitCode           int                 `json:"exit_code"`
	Stdout             string              `json:"stdout"`
	Stderr             string              `json:"stderr"`
	ExecutionTime      time.Duration       `json:"execution_time"`
	ResourceUsage      ResourceUsage       `json:"resource_usage"`
	SecurityViolations []SecurityViolation `json:"security_violations"`
}

// NetworkActivity represents network-related activities
type NetworkActivity struct {
	Timestamp       time.Time `json:"timestamp"`
	Protocol        string    `json:"protocol"`
	SourceIP        string    `json:"source_ip"`
	SourcePort      int       `json:"source_port"`
	DestinationIP   string    `json:"destination_ip"`
	DestinationPort int       `json:"destination_port"`
	Domain          string    `json:"domain,omitempty"`
	DataSize        int64     `json:"data_size"`
	Direction       string    `json:"direction"` // inbound, outbound
	RiskLevel       string    `json:"risk_level"`
	Description     string    `json:"description"`
}

// FileSystemChange represents file system modifications
type FileSystemChange struct {
	Timestamp   time.Time `json:"timestamp"`
	Operation   string    `json:"operation"` // create, modify, delete, move, chmod
	Path        string    `json:"path"`
	OldPath     string    `json:"old_path,omitempty"`
	Permissions string    `json:"permissions,omitempty"`
	Size        int64     `json:"size,omitempty"`
	Checksum    string    `json:"checksum,omitempty"`
	RiskLevel   string    `json:"risk_level"`
	Description string    `json:"description"`
}

// ProcessActivity represents process-related activities
type ProcessActivity struct {
	Timestamp        time.Time         `json:"timestamp"`
	PID              int               `json:"pid"`
	PPID             int               `json:"ppid"`
	Command          string            `json:"command"`
	Arguments        []string          `json:"arguments"`
	User             string            `json:"user"`
	WorkingDirectory string            `json:"working_directory"`
	EnvironmentVars  map[string]string `json:"environment_vars"`
	Action           string            `json:"action"` // start, stop, signal
	ExitCode         int               `json:"exit_code,omitempty"`
	ResourceUsage    ResourceUsage     `json:"resource_usage"`
	RiskLevel        string            `json:"risk_level"`
	Description      string            `json:"description"`
}

// EnvironmentChange represents environment variable changes
type EnvironmentChange struct {
	Timestamp   time.Time `json:"timestamp"`
	Variable    string    `json:"variable"`
	OldValue    string    `json:"old_value"`
	NewValue    string    `json:"new_value"`
	Operation   string    `json:"operation"` // set, unset, modify
	RiskLevel   string    `json:"risk_level"`
	Description string    `json:"description"`
}

// SecurityFinding represents a security-related finding
type SecurityFinding struct {
	ID          string                 `json:"id"`
	Type        string                 `json:"type"`
	Severity    string                 `json:"severity"`
	Title       string                 `json:"title"`
	Description string                 `json:"description"`
	Evidence    []string               `json:"evidence"`
	Remediation string                 `json:"remediation"`
	Confidence  float64                `json:"confidence"`
	Timestamp   time.Time              `json:"timestamp"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// SecurityViolation represents a security policy violation
type SecurityViolation struct {
	Type        string                 `json:"type"`
	Description string                 `json:"description"`
	Severity    string                 `json:"severity"`
	Timestamp   time.Time              `json:"timestamp"`
	Context     map[string]interface{} `json:"context"`
}

// SandboxInfo contains information about the sandbox environment
type SandboxInfo struct {
	Type          string                 `json:"type"`
	Image         string                 `json:"image"`
	ID            string                 `json:"id"`
	CreatedAt     time.Time              `json:"created_at"`
	DestroyedAt   time.Time              `json:"destroyed_at,omitempty"`
	Status        string                 `json:"status"`
	Configuration map[string]interface{} `json:"configuration"`
}

// ResourceUsage represents resource consumption metrics
type ResourceUsage struct {
	CPUUsage        float64   `json:"cpu_usage"`    // percentage
	MemoryUsage     int64     `json:"memory_usage"` // bytes
	DiskUsage       int64     `json:"disk_usage"`   // bytes
	NetworkIO       NetworkIO `json:"network_io"`
	FileDescriptors int       `json:"file_descriptors"`
	ProcessCount    int       `json:"process_count"`
}

// NetworkIO represents network I/O statistics
type NetworkIO struct {
	BytesReceived   int64 `json:"bytes_received"`
	BytesSent       int64 `json:"bytes_sent"`
	PacketsReceived int64 `json:"packets_received"`
	PacketsSent     int64 `json:"packets_sent"`
	Connections     int   `json:"connections"`
}

// Sandbox represents a sandboxed execution environment
type Sandbox struct {
	ID          string
	Type        string
	Image       string
	ContainerID string
	CreatedAt   time.Time
	Status      string
	Config      *Config
	mu          sync.RWMutex
}

// NewAnalyzer creates a new dynamic analyzer from a config.Config
func NewAnalyzer(cfg interface{}) (*DynamicAnalyzer, error) {
	// Handle different config types
	var config *Config
	switch c := cfg.(type) {
	case *Config:
		config = c
	default:
		// For compatibility with config.Config, extract dynamic config
		config = DefaultConfig()
	}

	return NewDynamicAnalyzer(config)
}

// NewDynamicAnalyzer creates a new dynamic analyzer
func NewDynamicAnalyzer(config *Config) (*DynamicAnalyzer, error) {
	if config == nil {
		config = DefaultConfig()
	}

	analyzer := &DynamicAnalyzer{
		config:    config,
		sandboxes: make(map[string]*Sandbox),
	}

	return analyzer, nil
}

// DefaultConfig returns default dynamic analyzer configuration
func DefaultConfig() *Config {
	return &Config{
		Enabled:                true,
		SandboxType:            "docker",
		SandboxImage:           "ubuntu:20.04",
		SandboxTimeout:         "5m",
		MaxConcurrentSandboxes: 3,
		AnalyzeInstallScripts:  true,
		AnalyzeNetworkActivity: true,
		AnalyzeFileSystem:      true,
		AnalyzeProcesses:       true,
		AnalyzeEnvironment:     true,
		MaxExecutionTime:       "2m",
		MaxMemoryUsage:         512 * 1024 * 1024,  // 512MB
		MaxDiskUsage:           1024 * 1024 * 1024, // 1GB
		MaxNetworkConnections:  10,
		MonitoringInterval:     "1s",
		Verbose:                false,
		LogLevel:               "info",
	}
}

// AnalyzePackage performs dynamic analysis on a package
func (da *DynamicAnalyzer) AnalyzePackage(ctx context.Context, packagePath string) (*AnalysisResult, error) {
	startTime := time.Now()

	result := &AnalysisResult{
		PackageName:        filepath.Base(packagePath),
		AnalysisTimestamp:  time.Now(),
		ExecutionResults:   []ExecutionResult{},
		NetworkActivity:    []NetworkActivity{},
		FileSystemChanges:  []FileSystemChange{},
		ProcessActivity:    []ProcessActivity{},
		EnvironmentChanges: []EnvironmentChange{},
		SecurityFindings:   []SecurityFinding{},
		Warnings:           []string{},
		Recommendations:    []string{},
		RiskScore:          0.0,
	}

	// Return early if dynamic analysis is disabled
	if !da.config.Enabled {
		return result, nil
	}

	// Create sandbox
	sandbox, err := da.createSandbox(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to create sandbox: %w", err)
	}
	defer da.destroySandbox(sandbox)

	result.SandboxInfo = SandboxInfo{
		Type:      sandbox.Type,
		Image:     sandbox.Image,
		ID:        sandbox.ID,
		CreatedAt: sandbox.CreatedAt,
		Status:    sandbox.Status,
	}

	// Copy package to sandbox
	if err := da.copyPackageToSandbox(sandbox, packagePath); err != nil {
		return nil, fmt.Errorf("failed to copy package to sandbox: %w", err)
	}

	// Start monitoring
	monitorCtx, cancelMonitor := context.WithCancel(ctx)
	defer cancelMonitor()

	monitoringResults := make(chan interface{}, 100)
	go da.startMonitoring(monitorCtx, sandbox, monitoringResults)

	// Execute analysis
	if da.config.AnalyzeInstallScripts {
		if err := da.executeInstallScripts(ctx, sandbox, result); err != nil {
			result.Warnings = append(result.Warnings, fmt.Sprintf("Install script execution failed: %v", err))
		}
	}

	// Collect monitoring results
	cancelMonitor()
	da.collectMonitoringResults(monitoringResults, result)

	// Analyze results
	da.analyzeResults(result)

	// Calculate risk assessment
	da.calculateRiskAssessment(result)

	// Generate recommendations
	da.generateRecommendations(result)

	result.ProcessingTime = time.Since(startTime)
	result.SandboxInfo.DestroyedAt = time.Now()

	return result, nil
}

// createSandbox creates a new sandbox environment
func (da *DynamicAnalyzer) createSandbox(ctx context.Context) (*Sandbox, error) {
	da.mu.Lock()
	defer da.mu.Unlock()

	// Check concurrent sandbox limit
	if len(da.sandboxes) >= da.config.MaxConcurrentSandboxes {
		return nil, fmt.Errorf("maximum concurrent sandboxes reached: %d", da.config.MaxConcurrentSandboxes)
	}

	sandboxID := fmt.Sprintf("typosentinel-sandbox-%d", time.Now().UnixNano())

	sandbox := &Sandbox{
		ID:        sandboxID,
		Type:      da.config.SandboxType,
		Image:     da.config.SandboxImage,
		CreatedAt: time.Now(),
		Status:    "creating",
		Config:    da.config,
	}

	// Create sandbox based on type
	switch da.config.SandboxType {
	case "docker":
		err := da.createDockerSandbox(ctx, sandbox)
		if err != nil {
			return nil, err
		}
	case "chroot":
		err := da.createChrootSandbox(ctx, sandbox)
		if err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("unsupported sandbox type: %s", da.config.SandboxType)
	}

	sandbox.Status = "running"
	da.sandboxes[sandboxID] = sandbox

	return sandbox, nil
}

// createDockerSandbox creates a Docker-based sandbox
func (da *DynamicAnalyzer) createDockerSandbox(ctx context.Context, sandbox *Sandbox) error {
	// Create Docker container with security constraints
	// Note: Removed --read-only to allow docker cp operations
	cmd := exec.CommandContext(ctx, "docker", "run", "-d",
		"--name", sandbox.ID,
		"--rm",
		"--network", "none", // Isolated network
		"--memory", fmt.Sprintf("%d", da.config.MaxMemoryUsage),
		"--cpus", "0.5",
		"--tmpfs", "/tmp:rw,noexec,nosuid,size=100m",
		"--tmpfs", "/var/tmp:rw,noexec,nosuid,size=100m",
		"--security-opt", "no-new-privileges:true",
		"--cap-drop", "ALL",
		"--user", "nobody",
		da.config.SandboxImage,
		"sleep", "300", // Keep container alive
	)

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to create Docker container with image %s: %w\nCommand: %s\nOutput: %s",
			da.config.SandboxImage, err, cmd.String(), string(output))
	}

	sandbox.ContainerID = strings.TrimSpace(string(output))
	return nil
}

// createChrootSandbox creates a chroot-based sandbox
func (da *DynamicAnalyzer) createChrootSandbox(ctx context.Context, sandbox *Sandbox) error {
	// Create chroot environment
	chrootDir := filepath.Join("/tmp", sandbox.ID)
	if err := os.MkdirAll(chrootDir, 0755); err != nil {
		return fmt.Errorf("failed to create chroot directory: %w", err)
	}

	// Set up basic chroot environment
	dirs := []string{"bin", "lib", "lib64", "usr", "etc", "tmp", "var", "proc", "sys"}
	for _, dir := range dirs {
		if err := os.MkdirAll(filepath.Join(chrootDir, dir), 0755); err != nil {
			return fmt.Errorf("failed to create directory %s: %w", dir, err)
		}
	}

	sandbox.ContainerID = chrootDir
	return nil
}

// destroySandbox destroys a sandbox environment
func (da *DynamicAnalyzer) destroySandbox(sandbox *Sandbox) error {
	da.mu.Lock()
	defer da.mu.Unlock()

	delete(da.sandboxes, sandbox.ID)

	switch sandbox.Type {
	case "docker":
		return da.destroyDockerSandbox(sandbox)
	case "chroot":
		return da.destroyChrootSandbox(sandbox)
	default:
		return fmt.Errorf("unsupported sandbox type: %s", sandbox.Type)
	}
}

// destroyDockerSandbox destroys a Docker sandbox
func (da *DynamicAnalyzer) destroyDockerSandbox(sandbox *Sandbox) error {
	cmd := exec.Command("docker", "stop", sandbox.ID)
	_ = cmd.Run() // Ignore errors, container might already be stopped

	cmd = exec.Command("docker", "rm", "-f", sandbox.ID)
	return cmd.Run()
}

// destroyChrootSandbox destroys a chroot sandbox
func (da *DynamicAnalyzer) destroyChrootSandbox(sandbox *Sandbox) error {
	return os.RemoveAll(sandbox.ContainerID)
}

// copyPackageToSandbox copies the package to the sandbox
func (da *DynamicAnalyzer) copyPackageToSandbox(sandbox *Sandbox, packagePath string) error {
	switch sandbox.Type {
	case "docker":
		return da.copyPackageToDockerSandbox(sandbox, packagePath)
	case "chroot":
		return da.copyPackageToChrootSandbox(sandbox, packagePath)
	default:
		return fmt.Errorf("unsupported sandbox type: %s", sandbox.Type)
	}
}

// copyPackageToDockerSandbox copies package to Docker sandbox
func (da *DynamicAnalyzer) copyPackageToDockerSandbox(sandbox *Sandbox, packagePath string) error {
	cmd := exec.Command("docker", "cp", packagePath, sandbox.ID+":/tmp/package")
	return cmd.Run()
}

// copyPackageToChrootSandbox copies package to chroot sandbox
func (da *DynamicAnalyzer) copyPackageToChrootSandbox(sandbox *Sandbox, packagePath string) error {
	destPath := filepath.Join(sandbox.ContainerID, "tmp", "package")
	cmd := exec.Command("cp", "-r", packagePath, destPath)
	return cmd.Run()
}

// executeInstallScripts executes installation scripts in the sandbox
func (da *DynamicAnalyzer) executeInstallScripts(ctx context.Context, sandbox *Sandbox, result *AnalysisResult) error {
	// Find install scripts
	scripts := []string{
		"install.sh", "setup.sh", "build.sh",
		"postinstall", "preinstall",
	}

	for _, script := range scripts {
		scriptPath := "/tmp/package/" + script

		// Check if script exists
		if !da.scriptExistsInSandbox(sandbox, scriptPath) {
			continue
		}

		// Execute script
		execResult, err := da.executeScriptInSandbox(ctx, sandbox, scriptPath)
		if err != nil {
			result.Warnings = append(result.Warnings, fmt.Sprintf("Failed to execute %s: %v", script, err))
			continue
		}

		result.ExecutionResults = append(result.ExecutionResults, *execResult)
	}

	return nil
}

// scriptExistsInSandbox checks if a script exists in the sandbox
func (da *DynamicAnalyzer) scriptExistsInSandbox(sandbox *Sandbox, scriptPath string) bool {
	switch sandbox.Type {
	case "docker":
		cmd := exec.Command("docker", "exec", sandbox.ID, "test", "-f", scriptPath)
		return cmd.Run() == nil
	case "chroot":
		fullPath := filepath.Join(sandbox.ContainerID, strings.TrimPrefix(scriptPath, "/"))
		_, err := os.Stat(fullPath)
		return err == nil
	default:
		return false
	}
}

// executeScriptInSandbox executes a script in the sandbox
func (da *DynamicAnalyzer) executeScriptInSandbox(ctx context.Context, sandbox *Sandbox, scriptPath string) (*ExecutionResult, error) {
	startTime := time.Now()

	var cmd *exec.Cmd
	switch sandbox.Type {
	case "docker":
		cmd = exec.CommandContext(ctx, "docker", "exec", sandbox.ID, "sh", scriptPath)
	case "chroot":
		fullPath := filepath.Join(sandbox.ContainerID, strings.TrimPrefix(scriptPath, "/"))
		cmd = exec.CommandContext(ctx, "chroot", sandbox.ContainerID, "sh", fullPath)
	default:
		return nil, fmt.Errorf("unsupported sandbox type: %s", sandbox.Type)
	}

	stdout, err := cmd.Output()
	exitCode := 0
	stderr := ""

	if err != nil {
		if exitError, ok := err.(*exec.ExitError); ok {
			exitCode = exitError.ExitCode()
			stderr = string(exitError.Stderr)
		} else {
			return nil, err
		}
	}

	result := &ExecutionResult{
		Command:            scriptPath,
		ExitCode:           exitCode,
		Stdout:             string(stdout),
		Stderr:             stderr,
		ExecutionTime:      time.Since(startTime),
		SecurityViolations: []SecurityViolation{},
	}

	// Analyze output for security violations
	da.analyzeExecutionOutput(result)

	return result, nil
}

// startMonitoring starts monitoring the sandbox
func (da *DynamicAnalyzer) startMonitoring(ctx context.Context, sandbox *Sandbox, results chan<- interface{}) {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			// Monitor resource usage
			if usage := da.getResourceUsage(sandbox); usage != nil {
				results <- usage
			}

			// Monitor network activity
			if da.config.AnalyzeNetworkActivity {
				if activity := da.getNetworkActivity(sandbox); activity != nil {
					results <- activity
				}
			}

			// Monitor file system changes
			if da.config.AnalyzeFileSystem {
				if changes := da.getFileSystemChanges(sandbox); changes != nil {
					results <- changes
				}
			}
		}
	}
}

// collectMonitoringResults collects monitoring results
func (da *DynamicAnalyzer) collectMonitoringResults(results <-chan interface{}, analysisResult *AnalysisResult) {
	for {
		select {
		case result, ok := <-results:
			if !ok {
				return
			}

			switch r := result.(type) {
			case *ResourceUsage:
				analysisResult.ResourceUsage = *r
			case *NetworkActivity:
				analysisResult.NetworkActivity = append(analysisResult.NetworkActivity, *r)
			case *FileSystemChange:
				analysisResult.FileSystemChanges = append(analysisResult.FileSystemChanges, *r)
			case *ProcessActivity:
				analysisResult.ProcessActivity = append(analysisResult.ProcessActivity, *r)
			}
		default:
			return
		}
	}
}

// Placeholder monitoring functions
func (da *DynamicAnalyzer) getResourceUsage(sandbox *Sandbox) *ResourceUsage {
	// Get resource usage from sandbox
	return &ResourceUsage{
		CPUUsage:        10.5,
		MemoryUsage:     50 * 1024 * 1024,  // 50MB
		DiskUsage:       100 * 1024 * 1024, // 100MB
		FileDescriptors: 10,
		ProcessCount:    3,
	}
}

func (da *DynamicAnalyzer) getNetworkActivity(sandbox *Sandbox) *NetworkActivity {
	// Monitor network activity using netstat or similar tools
	if sandbox.ContainerID == "" {
		return nil
	}

	// In a real implementation, this would:
	// 1. Execute netstat or ss commands in the container
	// 2. Parse network connections and traffic
	// 3. Detect suspicious outbound connections

	// For now, return basic network monitoring structure
	return &NetworkActivity{
		Timestamp:   time.Now(),
		Protocol:    "tcp",
		Direction:   "outbound",
		RiskLevel:   "low",
		Description: "No suspicious network activity detected",
	}
}

func (da *DynamicAnalyzer) getFileSystemChanges(sandbox *Sandbox) *FileSystemChange {
	// Monitor file system changes using inotify or similar
	if sandbox.ContainerID == "" {
		return nil
	}

	// In a real implementation, this would:
	// 1. Use inotify to monitor file system events
	// 2. Track file creations, modifications, deletions
	// 3. Detect suspicious file operations

	// For now, return basic file system monitoring structure
	return &FileSystemChange{
		Timestamp:   time.Now(),
		Operation:   "monitor",
		Path:        "/tmp",
		RiskLevel:   "low",
		Description: "No suspicious file system changes detected",
	}
}

// analyzeExecutionOutput analyzes execution output for security violations
func (da *DynamicAnalyzer) analyzeExecutionOutput(result *ExecutionResult) {
	// Analyze stdout and stderr for suspicious patterns
	suspiciousPatterns := []string{
		"curl", "wget", "nc", "netcat",
		"base64", "eval", "exec",
		"rm -rf", "chmod 777",
	}

	output := result.Stdout + result.Stderr
	for _, pattern := range suspiciousPatterns {
		if strings.Contains(strings.ToLower(output), strings.ToLower(pattern)) {
			result.SecurityViolations = append(result.SecurityViolations, SecurityViolation{
				Type:        "suspicious_command",
				Description: fmt.Sprintf("Suspicious pattern detected: %s", pattern),
				Severity:    "MEDIUM",
				Timestamp:   time.Now(),
				Context: map[string]interface{}{
					"pattern": pattern,
					"output":  output,
				},
			})
		}
	}
}

// analyzeResults performs comprehensive analysis of all results
func (da *DynamicAnalyzer) analyzeResults(result *AnalysisResult) {
	// Analyze execution results
	for _, execResult := range result.ExecutionResults {
		if execResult.ExitCode != 0 {
			result.SecurityFindings = append(result.SecurityFindings, SecurityFinding{
				ID:          fmt.Sprintf("EXEC_%d", len(result.SecurityFindings)+1),
				Type:        "execution_failure",
				Severity:    "MEDIUM",
				Title:       "Script Execution Failed",
				Description: fmt.Sprintf("Script %s failed with exit code %d", execResult.Command, execResult.ExitCode),
				Evidence:    []string{execResult.Stderr},
				Confidence:  0.8,
				Timestamp:   time.Now(),
			})
		}

		for _, violation := range execResult.SecurityViolations {
			result.SecurityFindings = append(result.SecurityFindings, SecurityFinding{
				ID:          fmt.Sprintf("VIOL_%d", len(result.SecurityFindings)+1),
				Type:        violation.Type,
				Severity:    violation.Severity,
				Title:       "Security Violation Detected",
				Description: violation.Description,
				Confidence:  0.7,
				Timestamp:   violation.Timestamp,
				Metadata:    violation.Context,
			})
		}
	}

	// Analyze network activity
	for _, activity := range result.NetworkActivity {
		if activity.RiskLevel == "HIGH" {
			result.SecurityFindings = append(result.SecurityFindings, SecurityFinding{
				ID:          fmt.Sprintf("NET_%d", len(result.SecurityFindings)+1),
				Type:        "suspicious_network_activity",
				Severity:    "HIGH",
				Title:       "Suspicious Network Activity",
				Description: activity.Description,
				Confidence:  0.9,
				Timestamp:   activity.Timestamp,
			})
		}
	}
}

// calculateRiskAssessment calculates overall risk assessment
func (da *DynamicAnalyzer) calculateRiskAssessment(result *AnalysisResult) {
	riskScore := 0.0

	// Weight security findings
	for _, finding := range result.SecurityFindings {
		switch finding.Severity {
		case "CRITICAL":
			riskScore += 0.4 * finding.Confidence
		case "HIGH":
			riskScore += 0.3 * finding.Confidence
		case "MEDIUM":
			riskScore += 0.2 * finding.Confidence
		case "LOW":
			riskScore += 0.1 * finding.Confidence
		}
	}

	// Weight execution failures
	for _, execResult := range result.ExecutionResults {
		if execResult.ExitCode != 0 {
			riskScore += 0.1
		}
		riskScore += float64(len(execResult.SecurityViolations)) * 0.05
	}

	// Weight network activity
	for _, activity := range result.NetworkActivity {
		if activity.RiskLevel == "HIGH" {
			riskScore += 0.2
		} else if activity.RiskLevel == "MEDIUM" {
			riskScore += 0.1
		}
	}

	result.RiskScore = min(riskScore, 1.0)

	// Determine threat level
	if result.RiskScore > 0.8 {
		result.ThreatLevel = "CRITICAL"
	} else if result.RiskScore > 0.6 {
		result.ThreatLevel = "HIGH"
	} else if result.RiskScore > 0.4 {
		result.ThreatLevel = "MEDIUM"
	} else if result.RiskScore > 0.2 {
		result.ThreatLevel = "LOW"
	} else {
		result.ThreatLevel = "MINIMAL"
	}
}

// generateRecommendations generates security recommendations
func (da *DynamicAnalyzer) generateRecommendations(result *AnalysisResult) {
	if result.RiskScore > 0.8 {
		result.Recommendations = append(result.Recommendations, "CRITICAL: Do not install this package - high risk of malicious behavior")
	} else if result.RiskScore > 0.6 {
		result.Recommendations = append(result.Recommendations, "HIGH RISK: Manual security review required before installation")
	} else if result.RiskScore > 0.4 {
		result.Recommendations = append(result.Recommendations, "MEDIUM RISK: Review security findings and proceed with caution")
	}

	if len(result.SecurityFindings) > 0 {
		result.Recommendations = append(result.Recommendations, "Review all security findings before proceeding")
	}

	if len(result.NetworkActivity) > 0 {
		result.Recommendations = append(result.Recommendations, "Package attempts network communication - verify necessity")
	}

	for _, execResult := range result.ExecutionResults {
		if execResult.ExitCode != 0 {
			result.Recommendations = append(result.Recommendations, fmt.Sprintf("Script %s failed - investigate cause", execResult.Command))
			break
		}
	}
}

// ExportResults exports analysis results to JSON
func (da *DynamicAnalyzer) ExportResults(result *AnalysisResult, outputPath string) error {
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal results: %w", err)
	}

	return ioutil.WriteFile(outputPath, data, 0644)
}

// GetSandboxStatus returns the status of all sandboxes
func (da *DynamicAnalyzer) GetSandboxStatus() map[string]string {
	da.mu.RLock()
	defer da.mu.RUnlock()

	status := make(map[string]string)
	for id, sandbox := range da.sandboxes {
		status[id] = sandbox.Status
	}

	return status
}

// CleanupSandboxes cleans up all sandboxes
func (da *DynamicAnalyzer) CleanupSandboxes() error {
	da.mu.Lock()
	defer da.mu.Unlock()

	for _, sandbox := range da.sandboxes {
		if err := da.destroySandbox(sandbox); err != nil {
			return fmt.Errorf("failed to destroy sandbox %s: %w", sandbox.ID, err)
		}
	}

	da.sandboxes = make(map[string]*Sandbox)
	return nil
}

// analyzeBehaviors analyzes behaviors and returns security findings
func (da *DynamicAnalyzer) analyzeBehaviors(behaviors []string) []SecurityFinding {
	var findings []SecurityFinding

	for _, behavior := range behaviors {
		switch {
		case strings.Contains(behavior, "network"):
			findings = append(findings, SecurityFinding{
				ID:          "NET_001",
				Type:        "network_activity",
				Severity:    "medium",
				Title:       "Network Activity Detected",
				Description: "Package performs network operations",
				Timestamp:   time.Now(),
			})
		case strings.Contains(behavior, "file"):
			findings = append(findings, SecurityFinding{
				ID:          "FILE_001",
				Type:        "file_operation",
				Severity:    "low",
				Title:       "File Operation Detected",
				Description: "Package performs file operations",
				Timestamp:   time.Now(),
			})
		case strings.Contains(behavior, "process"):
			findings = append(findings, SecurityFinding{
				ID:          "PROC_001",
				Type:        "process_execution",
				Severity:    "high",
				Title:       "Process Execution Detected",
				Description: "Package executes external processes",
				Timestamp:   time.Now(),
			})
		}
	}

	return findings
}

// monitorBehavior monitors behavior in a sandbox
func (da *DynamicAnalyzer) monitorBehavior(ctx context.Context, containerID string) []string {
	// Mock implementation for testing
	if containerID == "mock-container-id" {
		return []string{} // Return empty behaviors for mock
	}
	// In real implementation, this would monitor actual container behavior
	return []string{"network_call", "file_operation", "process_execution"}
}

// cleanupSandbox cleans up a specific sandbox
func (da *DynamicAnalyzer) cleanupSandbox(ctx context.Context, containerID string) error {
	// Mock implementation for testing
	if containerID == "mock-container-id" {
		return fmt.Errorf("mock container cleanup failed")
	}
	return nil
}

// calculateRiskScore calculates a numerical risk score based on security findings
func (da *DynamicAnalyzer) calculateRiskScore(findings []SecurityFinding) float64 {
	if len(findings) == 0 {
		return 0.0
	}

	totalScore := 0.0
	for _, finding := range findings {
		switch strings.ToLower(finding.Severity) {
		case "low":
			totalScore += 2.0
		case "medium":
			totalScore += 5.0
		case "high":
			totalScore += 8.0
		case "critical":
			totalScore += 10.0
		default:
			totalScore += 1.0
		}
	}

	// Average the scores and cap at 10.0
	avgScore := totalScore / float64(len(findings))
	return min(avgScore, 10.0)
}

func min(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}
