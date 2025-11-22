package behavior

import (
	"context"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	pkglogger "github.com/Alivanroy/Typosentinel/pkg/logger"
)

// SandboxConfig holds configuration for sandbox analysis
type SandboxConfig struct {
	ContainerImage   string
	Timeout          time.Duration
	MemoryLimit      string
	CPUShares        int64
	NetworkMode      string
	EnableFilesystem bool
	EnableNetwork    bool
	EnableProcess    bool
	WorkingDir       string
	EnvironmentVars  map[string]string
}

// DefaultSandboxConfig returns default sandbox configuration
func DefaultSandboxConfig() *SandboxConfig {
	return &SandboxConfig{
		ContainerImage:   "node:18-alpine", // Default for npm packages
		Timeout:          5 * time.Minute,
		MemoryLimit:      "512m",
		CPUShares:        512,
		NetworkMode:      "none", // Disable network by default for safety
		EnableFilesystem: true,
		EnableNetwork:    false,
		EnableProcess:    true,
		WorkingDir:       "/app",
		EnvironmentVars:  map[string]string{},
	}
}

// SandboxAgent is the interface for sandbox analysis
type SandboxAgent interface {
	RunSandboxAnalysis(ctx context.Context, packageDescriptor *PackageDescriptor) (*BehaviorProfile, error)
	SetupSandbox() error
	CleanupSandbox() error
}

// PackageDescriptor describes a package for sandbox analysis
type PackageDescriptor struct {
	Name         string
	Version      string
	Ecosystem    string
	PackageURL   string
	Checksum     string
	Dependencies []string
	Metadata     map[string]interface{}
}

// DockerSandboxAgent implements sandbox analysis using Docker containers
type DockerSandboxAgent struct {
	config      *SandboxConfig
	logger      *pkglogger.Logger
	workingDir  string
	containerID string
}

// NewDockerSandboxAgent creates a new Docker-based sandbox agent
func NewDockerSandboxAgent(config *SandboxConfig, logger *pkglogger.Logger) (*DockerSandboxAgent, error) {
	if config == nil {
		config = DefaultSandboxConfig()
	}

	if logger == nil {
		// Create a simple logger - we'll fix this properly later
		logger = pkglogger.New()
	}

	return &DockerSandboxAgent{
		config: config,
		logger: logger,
	}, nil
}

// NewDockerSandboxAgentWithDefaults creates a new Docker-based sandbox agent with default configuration
func NewDockerSandboxAgentWithDefaults() (*DockerSandboxAgent, error) {
	return NewDockerSandboxAgent(nil, nil)
}

// RunSandboxAnalysis performs dynamic behavior analysis in a sandboxed environment
func (dsa *DockerSandboxAgent) RunSandboxAnalysis(ctx context.Context, packageDescriptor *PackageDescriptor) (*BehaviorProfile, error) {
	dsa.logger.Info("Starting sandbox analysis",
		map[string]interface{}{
			"package":   packageDescriptor.Name,
			"version":   packageDescriptor.Version,
			"ecosystem": packageDescriptor.Ecosystem,
		})

	// Create behavior profile
	profile := NewBehaviorProfile(
		packageDescriptor.Name,
		packageDescriptor.Version,
		packageDescriptor.Ecosystem,
	)
	profile.SandboxID = fmt.Sprintf("sandbox_%s_%s_%d",
		packageDescriptor.Name, packageDescriptor.Version, time.Now().Unix())
	profile.ContainerImage = dsa.config.ContainerImage

	// Setup working directory
	if err := dsa.setupWorkingDirectory(); err != nil {
		profile.Status = "failed"
		profile.Complete()
		return profile, fmt.Errorf("failed to setup working directory: %w", err)
	}
	defer dsa.cleanupWorkingDirectory()

	// Create and run container
	containerID, err := dsa.createContainer(packageDescriptor)
	if err != nil {
		profile.Status = "failed"
		profile.Complete()
		return profile, fmt.Errorf("failed to create container: %w", err)
	}
	dsa.containerID = containerID
	defer dsa.cleanupContainer()

	// Start container
	if err := dsa.startContainer(); err != nil {
		profile.Status = "failed"
		profile.Complete()
		return profile, fmt.Errorf("failed to start container: %w", err)
	}

	// Run behavior monitoring
	behaviorData, err := dsa.monitorBehavior(ctx, packageDescriptor)
	if err != nil {
		profile.Status = "failed"
		profile.Complete()
		return profile, fmt.Errorf("behavior monitoring failed: %w", err)
	}

	// Populate profile with behavior data
	dsa.populateProfile(profile, behaviorData)

	// Analyze behavior and calculate risk
	if err := dsa.analyzeBehavior(profile); err != nil {
		dsa.logger.Warn("Behavior analysis failed", map[string]interface{}{
			"error": err.Error(),
		})
	}

	profile.Status = "completed"
	profile.Complete()

	dsa.logger.Info("Sandbox analysis completed",
		map[string]interface{}{
			"package":    packageDescriptor.Name,
			"risk_score": profile.RiskScore,
			"risk_level": profile.RiskLevel,
			"duration":   profile.Duration,
			"threats":    len(profile.GetSuspiciousActivities()),
		})

	return profile, nil
}

// setupWorkingDirectory creates a temporary working directory
func (dsa *DockerSandboxAgent) setupWorkingDirectory() error {
	tempDir, err := ioutil.TempDir("", "typosentinel-sandbox-*")
	if err != nil {
		return fmt.Errorf("failed to create temp directory: %w", err)
	}
	dsa.workingDir = tempDir
	return nil
}

// HealthCheck performs a health check of the sandbox
func (dsa *DockerSandboxAgent) HealthCheck(ctx context.Context) error {
	// Check if Docker is available
	cmd := exec.CommandContext(ctx, "docker", "version")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("docker not available: %w", err)
	}
	return nil
}

// Close cleans up the sandbox resources
func (dsa *DockerSandboxAgent) Close() error {
	return dsa.CleanupSandbox()
}

// cleanupWorkingDirectory removes the temporary working directory
func (dsa *DockerSandboxAgent) cleanupWorkingDirectory() {
	if dsa.workingDir != "" {
		os.RemoveAll(dsa.workingDir)
	}
}

// createContainer creates a Docker container for sandbox analysis
func (dsa *DockerSandboxAgent) createContainer(packageDescriptor *PackageDescriptor) (string, error) {
	// Build container creation command
	args := []string{"create"}

	// Add security options
	args = append(args, "--security-opt", "no-new-privileges")
	args = append(args, "--cap-drop", "ALL")
	args = append(args, "--cap-add", "CHOWN", "--cap-add", "SETGID", "--cap-add", "SETUID")

	// Add resource limits
	args = append(args, "--memory", dsa.config.MemoryLimit)
	args = append(args, "--cpus", "1.0")
	args = append(args, "--cpu-shares", fmt.Sprintf("%d", dsa.config.CPUShares))

	// Network configuration
	if !dsa.config.EnableNetwork {
		args = append(args, "--network", "none")
	} else {
		args = append(args, "--network", dsa.config.NetworkMode)
	}

	// Volume mounts
	args = append(args, "-v", fmt.Sprintf("%s:%s", dsa.workingDir, dsa.config.WorkingDir))

	// Environment variables
	for key, value := range dsa.config.EnvironmentVars {
		args = append(args, "-e", fmt.Sprintf("%s=%s", key, value))
	}

	// Working directory
	args = append(args, "-w", dsa.config.WorkingDir)

	// Container name
	containerName := fmt.Sprintf("typosentinel-sandbox-%s-%d",
		packageDescriptor.Name, time.Now().Unix())
	args = append(args, "--name", containerName)

	// Image
	args = append(args, dsa.config.ContainerImage)

	// Command to run (will be overridden by analysis script)
	args = append(args, "sh", "-c", "sleep infinity")

	cmd := exec.CommandContext(context.Background(), "docker", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("failed to create container: %w, output: %s", err, string(output))
	}

	containerID := strings.TrimSpace(string(output))
	dsa.logger.Info("Container created", map[string]interface{}{
		"container_id": containerID,
	})

	return containerID, nil
}

// startContainer starts the Docker container
func (dsa *DockerSandboxAgent) startContainer() error {
	cmd := exec.Command("docker", "start", dsa.containerID)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to start container: %w, output: %s", err, string(output))
	}

	dsa.logger.Info("Container started", map[string]interface{}{
		"container_id": dsa.containerID,
	})
	return nil
}

// cleanupContainer removes the Docker container
func (dsa *DockerSandboxAgent) cleanupContainer() {
	if dsa.containerID != "" {
		// Stop container
		exec.Command("docker", "stop", dsa.containerID).Run()
		// Remove container
		exec.Command("docker", "rm", "-f", dsa.containerID).Run()
		dsa.logger.Info("Container cleaned up", map[string]interface{}{
			"container_id": dsa.containerID,
		})
	}
}

// monitorBehavior monitors package behavior during execution
func (dsa *DockerSandboxAgent) monitorBehavior(ctx context.Context, packageDescriptor *PackageDescriptor) (*BehaviorData, error) {
	behaviorData := &BehaviorData{
		FilesystemEvents: []FilesystemEvent{},
		NetworkEvents:    []NetworkEvent{},
		ProcessEvents:    []ProcessEvent{},
	}

	// Install and test the package based on ecosystem
	switch packageDescriptor.Ecosystem {
	case "npm":
		return dsa.monitorNPMPackage(ctx, packageDescriptor, behaviorData)
	case "pypi":
		return dsa.monitorPyPIPackage(ctx, packageDescriptor, behaviorData)
	case "maven":
		return dsa.monitorMavenPackage(ctx, packageDescriptor, behaviorData)
	default:
		return dsa.monitorGenericPackage(ctx, packageDescriptor, behaviorData)
	}
}

// monitorNPMPackage monitors NPM package behavior
func (dsa *DockerSandboxAgent) monitorNPMPackage(ctx context.Context, packageDescriptor *PackageDescriptor, behaviorData *BehaviorData) (*BehaviorData, error) {
	// Create test script
	testScript := fmt.Sprintf(`
#!/bin/sh
set -e

# Install package
npm install %s@%s --save

# Create simple test
node -e "
try {
  const pkg = require('%s');
  console.log('Package loaded successfully');
  
  // Try to call main function if exists
  if (typeof pkg === 'function') {
    pkg();
  } else if (pkg.default && typeof pkg.default === 'function') {
    pkg.default();
  }
  
  console.log('Package execution completed');
} catch (err) {
  console.error('Package execution failed:', err.message);
  process.exit(1);
}
"
`, packageDescriptor.Name, packageDescriptor.Version, packageDescriptor.Name)

	// Write test script to container
	scriptPath := filepath.Join(dsa.workingDir, "test_script.sh")
	if err := ioutil.WriteFile(scriptPath, []byte(testScript), 0755); err != nil {
		return behaviorData, fmt.Errorf("failed to write test script: %w", err)
	}

	// Run monitoring in parallel with test execution
	monitoringDone := make(chan error, 1)
	go func() {
		monitoringDone <- dsa.runBehaviorMonitoring(ctx, behaviorData)
	}()

	// Execute test script
	cmd := exec.CommandContext(ctx, "docker", "exec", dsa.containerID, "sh", "/app/test_script.sh")
	output, err := cmd.CombinedOutput()
	if err != nil {
		dsa.logger.Warn("Package execution failed", map[string]interface{}{
			"error":  err.Error(),
			"output": string(output),
		})
	}

	// Wait for monitoring to complete
	select {
	case <-ctx.Done():
		return behaviorData, ctx.Err()
	case err := <-monitoringDone:
		if err != nil {
			dsa.logger.Warn("Behavior monitoring failed", map[string]interface{}{
				"error": err.Error(),
			})
		}
	}

	return behaviorData, nil
}

// monitorPyPIPackage monitors PyPI package behavior
func (dsa *DockerSandboxAgent) monitorPyPIPackage(ctx context.Context, packageDescriptor *PackageDescriptor, behaviorData *BehaviorData) (*BehaviorData, error) {
	// Create test script for Python package
	testScript := fmt.Sprintf(`
#!/bin/sh
set -e

# Install package
pip install %s==%s

# Create simple test
python3 -c "
import %s
try:
    # Try to import and use the package
    print('Package imported successfully')
    
    # Try to access main functionality
    if hasattr(%s, '__version__'):
        print(f'Version: {%s.__version__}')
    
    print('Package execution completed')
except Exception as e:
    print(f'Package execution failed: {e}')
    exit(1)
"
`, packageDescriptor.Name, packageDescriptor.Version, packageDescriptor.Name,
		packageDescriptor.Name, packageDescriptor.Name)

	// Write and execute test script (similar to NPM monitoring)
	scriptPath := filepath.Join(dsa.workingDir, "test_script.sh")
	if err := ioutil.WriteFile(scriptPath, []byte(testScript), 0755); err != nil {
		return behaviorData, fmt.Errorf("failed to write test script: %w", err)
	}

	// Run monitoring and test execution
	monitoringDone := make(chan error, 1)
	go func() {
		monitoringDone <- dsa.runBehaviorMonitoring(ctx, behaviorData)
	}()

	cmd := exec.CommandContext(ctx, "docker", "exec", dsa.containerID, "sh", "/app/test_script.sh")
	output, err := cmd.CombinedOutput()
	if err != nil {
		dsa.logger.Warn("Package execution failed", map[string]interface{}{
			"error":  err.Error(),
			"output": string(output),
		})
	}

	select {
	case <-ctx.Done():
		return behaviorData, ctx.Err()
	case err := <-monitoringDone:
		if err != nil {
			dsa.logger.Warn("Behavior monitoring failed", map[string]interface{}{
				"error": err.Error(),
			})
		}
	}

	return behaviorData, nil
}

// monitorMavenPackage monitors Maven package behavior
func (dsa *DockerSandboxAgent) monitorMavenPackage(ctx context.Context, packageDescriptor *PackageDescriptor, behaviorData *BehaviorData) (*BehaviorData, error) {
	// Similar implementation for Maven packages
	dsa.logger.Info("Maven package monitoring not fully implemented yet", nil)
	return behaviorData, nil
}

// monitorGenericPackage monitors generic package behavior
func (dsa *DockerSandboxAgent) monitorGenericPackage(ctx context.Context, packageDescriptor *PackageDescriptor, behaviorData *BehaviorData) (*BehaviorData, error) {
	dsa.logger.Info("Generic package monitoring not fully implemented yet", nil)
	return behaviorData, nil
}

// runBehaviorMonitoring runs behavior monitoring during package execution
func (dsa *DockerSandboxAgent) runBehaviorMonitoring(ctx context.Context, behaviorData *BehaviorData) error {
	// This would implement actual behavior monitoring using:
	// - System call tracing (strace)
	// - File system monitoring (inotify)
	// - Network monitoring
	// - Process monitoring

	// For now, we'll simulate some basic monitoring
	dsa.logger.Info("Starting behavior monitoring", nil)

	// Monitor filesystem events
	if dsa.config.EnableFilesystem {
		dsa.simulateFilesystemMonitoring(behaviorData)
	}

	// Monitor network events
	if dsa.config.EnableNetwork {
		dsa.simulateNetworkMonitoring(behaviorData)
	}

	// Monitor process events
	if dsa.config.EnableProcess {
		dsa.simulateProcessMonitoring(behaviorData)
	}

	return nil
}

// simulateFilesystemMonitoring simulates filesystem event monitoring
func (dsa *DockerSandboxAgent) simulateFilesystemMonitoring(behaviorData *BehaviorData) {
	// This would normally use inotify or similar tools
	// For simulation, we'll add some basic events
	events := []FilesystemEvent{
		{Type: "read", Path: "/app/package.json", Timestamp: time.Now()},
		{Type: "write", Path: "/app/node_modules", Timestamp: time.Now()},
	}
	behaviorData.FilesystemEvents = append(behaviorData.FilesystemEvents, events...)
}

// simulateNetworkMonitoring simulates network event monitoring
func (dsa *DockerSandboxAgent) simulateNetworkMonitoring(behaviorData *BehaviorData) {
	// This would normally use network monitoring tools
	// For simulation, we'll add some basic events
	events := []NetworkEvent{
		{Type: "dns", Domain: "registry.npmjs.org", Timestamp: time.Now()},
		{Type: "http", URL: "https://registry.npmjs.org", Timestamp: time.Now()},
	}
	behaviorData.NetworkEvents = append(behaviorData.NetworkEvents, events...)
}

// simulateProcessMonitoring simulates process event monitoring
func (dsa *DockerSandboxAgent) simulateProcessMonitoring(behaviorData *BehaviorData) {
	// This would normally use process monitoring tools
	// For simulation, we'll add some basic events
	events := []ProcessEvent{
		{Type: "spawn", Command: "npm install", PID: 1234, Timestamp: time.Now()},
		{Type: "spawn", Command: "node test.js", PID: 1235, Timestamp: time.Now()},
	}
	behaviorData.ProcessEvents = append(behaviorData.ProcessEvents, events...)
}

// populateProfile populates the behavior profile with collected data
func (dsa *DockerSandboxAgent) populateProfile(profile *BehaviorProfile, behaviorData *BehaviorData) {
	// Populate filesystem actions
	for _, event := range behaviorData.FilesystemEvents {
		switch event.Type {
		case "read":
			profile.FilesystemActions.FilesRead = append(profile.FilesystemActions.FilesRead, event.Path)
		case "write":
			profile.FilesystemActions.FilesWritten = append(profile.FilesystemActions.FilesWritten, event.Path)
		case "delete":
			profile.FilesystemActions.FilesDeleted = append(profile.FilesystemActions.FilesDeleted, event.Path)
		case "create":
			profile.FilesystemActions.FilesCreated = append(profile.FilesystemActions.FilesCreated, event.Path)
		}
	}

	// Populate network activity
	for _, event := range behaviorData.NetworkEvents {
		switch event.Type {
		case "dns":
			query := DNSQuery{
				Domain:    event.Domain,
				Timestamp: event.Timestamp,
			}
			profile.NetworkActivity.DNSQueries = append(profile.NetworkActivity.DNSQueries, query)
		case "http":
			request := HTTPRequest{
				URL:       event.URL,
				Timestamp: event.Timestamp,
			}
			profile.NetworkActivity.HTTPRequests = append(profile.NetworkActivity.HTTPRequests, request)
		case "tcp":
			connection := NetworkConnection{
				Protocol:   "tcp",
				RemoteIP:   event.RemoteIP,
				RemotePort: event.RemotePort,
				Timestamp:  event.Timestamp,
			}
			profile.NetworkActivity.TCPConnections = append(profile.NetworkActivity.TCPConnections, connection)
		}
	}

	// Populate process activity
	for _, event := range behaviorData.ProcessEvents {
		processInfo := ProcessInfo{
			PID:         event.PID,
			Name:        event.Command,
			CommandLine: event.Command,
			StartTime:   event.Timestamp,
		}
		profile.ProcessActivity.ChildProcesses = append(profile.ProcessActivity.ChildProcesses, processInfo)
		profile.ProcessActivity.ProcessesSpawned++
	}
}

// analyzeBehavior analyzes the collected behavior data and calculates risk
func (dsa *DockerSandboxAgent) analyzeBehavior(profile *BehaviorProfile) error {
	analyzer := NewBehaviorAnalyzer()
	analysis := analyzer.AnalyzeBehavior(profile)

	// Update profile with analysis results
	profile.RiskScore = analysis.RiskScore
	profile.RiskLevel = analysis.RiskLevel
	profile.Confidence = 0.9 // High confidence for behavior analysis

	return nil
}

// SetupSandbox sets up the sandbox environment
func (dsa *DockerSandboxAgent) SetupSandbox() error {
	return dsa.setupWorkingDirectory()
}

// CleanupSandbox cleans up the sandbox environment
func (dsa *DockerSandboxAgent) CleanupSandbox() error {
	dsa.cleanupContainer()
	dsa.cleanupWorkingDirectory()
	return nil
}

// BehaviorData holds raw behavior data collected during analysis
type BehaviorData struct {
	FilesystemEvents []FilesystemEvent `json:"filesystem_events"`
	NetworkEvents    []NetworkEvent    `json:"network_events"`
	ProcessEvents    []ProcessEvent    `json:"process_events"`
}

// FilesystemEvent represents a filesystem event
type FilesystemEvent struct {
	Type      string    `json:"type"`
	Path      string    `json:"path"`
	Size      int64     `json:"size,omitempty"`
	Timestamp time.Time `json:"timestamp"`
}

// NetworkEvent represents a network event
type NetworkEvent struct {
	Type       string    `json:"type"`
	Domain     string    `json:"domain,omitempty"`
	URL        string    `json:"url,omitempty"`
	RemoteIP   string    `json:"remote_ip,omitempty"`
	RemotePort int       `json:"remote_port,omitempty"`
	Timestamp  time.Time `json:"timestamp"`
}

// ProcessEvent represents a process event
type ProcessEvent struct {
	Type      string    `json:"type"`
	PID       int       `json:"pid"`
	Command   string    `json:"command"`
	Timestamp time.Time `json:"timestamp"`
}
