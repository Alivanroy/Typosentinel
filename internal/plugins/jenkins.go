package plugins

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/Alivanroy/Typosentinel/pkg/types"
)

// JenkinsPlugin implements Plugin interface for Jenkins integration
type JenkinsPlugin struct {
	info     PluginInfo
	settings JenkinsSettings
	logger   Logger
	status   PluginStatus
}

// JenkinsSettings contains Jenkins specific configuration
type JenkinsSettings struct {
	JenkinsURL       string            `json:"jenkins_url"`
	JobName          string            `json:"job_name"`
	BuildNumber      string            `json:"build_number"`
	Workspace        string            `json:"workspace"`
	CredentialsID    string            `json:"credentials_id"`
	FailOnCritical   bool              `json:"fail_on_critical"`
	FailOnHigh       bool              `json:"fail_on_high"`
	PublishResults   bool              `json:"publish_results"`
	ArchiveReports   bool              `json:"archive_reports"`
	NotifyEmail      bool              `json:"notify_email"`
	EmailRecipients  []string          `json:"email_recipients"`
	CustomProperties map[string]string `json:"custom_properties"`
}

// JenkinsOutput represents the output structure for Jenkins
type JenkinsOutput struct {
	BuildResult      string                 `json:"build_result"`
	ExitCode         int                    `json:"exit_code"`
	Properties       map[string]string      `json:"properties"`
	Artifacts        []JenkinsArtifact      `json:"artifacts"`
	TestResults      JenkinsTestResults     `json:"test_results"`
	PublishedReports []JenkinsReport        `json:"published_reports"`
	Notifications    []JenkinsNotification  `json:"notifications"`
	Metrics          map[string]interface{} `json:"metrics"`
}

// JenkinsArtifact represents a Jenkins build artifact
type JenkinsArtifact struct {
	Name        string `json:"name"`
	Path        string `json:"path"`
	Size        int64  `json:"size"`
	Fingerprint string `json:"fingerprint,omitempty"`
}

// JenkinsTestResults represents Jenkins test results
type JenkinsTestResults struct {
	TotalTests   int `json:"total_tests"`
	PassedTests  int `json:"passed_tests"`
	FailedTests  int `json:"failed_tests"`
	SkippedTests int `json:"skipped_tests"`
}

// JenkinsReport represents a published report
type JenkinsReport struct {
	Type        string `json:"type"`
	Title       string `json:"title"`
	Path        string `json:"path"`
	Description string `json:"description"`
}

// JenkinsNotification represents a notification
type JenkinsNotification struct {
	Type       string   `json:"type"`
	Recipients []string `json:"recipients"`
	Subject    string   `json:"subject"`
	Message    string   `json:"message"`
	Sent       bool     `json:"sent"`
}

// NewJenkinsPlugin creates a new Jenkins plugin instance
func NewJenkinsPlugin(logger Logger) *JenkinsPlugin {
	return &JenkinsPlugin{
		info: PluginInfo{
			Name:        "jenkins",
			Version:     "1.0.0",
			Description: "Jenkins CI/CD integration for Typosentinel",
			Author:      "Typosentinel Team",
			Platform:    "jenkins",
			Capabilities: []string{
				"build_integration",
				"test_results",
				"artifact_publishing",
				"email_notifications",
				"report_publishing",
				"build_properties",
				"pipeline_integration",
			},
		},
		logger: logger,
	}
}

// GetInfo returns plugin information
func (p *JenkinsPlugin) GetInfo() PluginInfo {
	return p.info
}

// Initialize sets up the Jenkins plugin
func (p *JenkinsPlugin) Initialize(ctx context.Context, config map[string]interface{}) error {
	// Convert config to settings
	configBytes, err := json.Marshal(config)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	if err := json.Unmarshal(configBytes, &p.settings); err != nil {
		return fmt.Errorf("failed to unmarshal settings: %w", err)
	}

	// Set defaults from environment if not provided
	if p.settings.JenkinsURL == "" {
		p.settings.JenkinsURL = os.Getenv("JENKINS_URL")
	}
	if p.settings.JobName == "" {
		p.settings.JobName = os.Getenv("JOB_NAME")
	}
	if p.settings.BuildNumber == "" {
		p.settings.BuildNumber = os.Getenv("BUILD_NUMBER")
	}
	if p.settings.Workspace == "" {
		p.settings.Workspace = os.Getenv("WORKSPACE")
	}

	// Initialize custom properties
	if p.settings.CustomProperties == nil {
		p.settings.CustomProperties = make(map[string]string)
	}

	p.logger.Info("Jenkins plugin initialized", map[string]interface{}{
		"jenkins_url":  p.settings.JenkinsURL,
		"job_name":     p.settings.JobName,
		"build_number": p.settings.BuildNumber,
		"workspace":    p.settings.Workspace,
	})

	return nil
}

// Execute runs the Jenkins integration
func (p *JenkinsPlugin) Execute(ctx context.Context, result *types.ScanResult) (*PluginResult, error) {
	start := time.Now()
	// Get package info from first package if available
	var packageName string
	var totalThreats int
	if len(result.Packages) > 0 {
		packageName = result.Packages[0].Name
		for _, pkg := range result.Packages {
			totalThreats += len(pkg.Threats)
		}
	} else {
		packageName = result.Target
	}

	p.logger.Info("Executing Jenkins plugin", map[string]interface{}{
		"package": packageName,
		"risk":    "unknown", // Risk calculation moved to individual packages
	})

	output := &JenkinsOutput{
		BuildResult:      "SUCCESS",
		ExitCode:         0,
		Properties:       make(map[string]string),
		Artifacts:        []JenkinsArtifact{},
		TestResults:      JenkinsTestResults{},
		PublishedReports: []JenkinsReport{},
		Notifications:    []JenkinsNotification{},
		Metrics:          make(map[string]interface{}),
	}

	// Set Jenkins build properties
	p.setBuildProperties(output, result)

	// Generate test results
	p.generateTestResults(output, result)

	// Create artifacts
	p.createArtifacts(output, result)

	// Publish reports
	p.publishReports(output, result)

	// Handle severity-based actions
	actions := p.handleSeverityActions(result)

	// Handle notifications
	p.handleNotifications(output, result)

	// Determine build result and exit code
	if p.shouldFailBuild(result) {
		output.BuildResult = "FAILURE"
		output.ExitCode = 1
	} else if totalThreats > 0 {
		output.BuildResult = "UNSTABLE"
	}

	// Create metrics
	var packageVersion string
	if len(result.Packages) > 0 {
		packageVersion = result.Packages[0].Version
	} else {
		packageVersion = "unknown"
	}

	output.Metrics = map[string]interface{}{
		"scan_duration_ms": time.Since(start).Milliseconds(),
		"threats_detected": totalThreats,
		"risk_score":       0.0,       // Risk calculation moved to individual packages
		"overall_risk":     "unknown", // Risk calculation moved to individual packages
		"package_name":     packageName,
		"package_version":  packageVersion,
		"scan_timestamp":   time.Now().Unix(),
		"build_number":     p.settings.BuildNumber,
		"job_name":         p.settings.JobName,
	}

	return &PluginResult{
		Success: output.BuildResult == "SUCCESS",
		Message: p.generateSummaryMessage(result),
		Data:    map[string]interface{}{"jenkins_output": output},
		Actions: actions,
		Metadata: map[string]interface{}{
			"platform":     "jenkins",
			"jenkins_url":  p.settings.JenkinsURL,
			"job_name":     p.settings.JobName,
			"build_number": p.settings.BuildNumber,
			"build_result": output.BuildResult,
			"exit_code":    output.ExitCode,
		},
	}, nil
}

// setBuildProperties sets Jenkins build properties
func (p *JenkinsPlugin) setBuildProperties(output *JenkinsOutput, result *types.ScanResult) {
	// Get package info from first package if available
	var packageName, packageVersion string
	var totalThreats int
	if len(result.Packages) > 0 {
		packageName = result.Packages[0].Name
		packageVersion = result.Packages[0].Version
		for _, pkg := range result.Packages {
			totalThreats += len(pkg.Threats)
		}
	} else {
		packageName = result.Target
		packageVersion = "unknown"
	}

	output.Properties["TYPOSENTINEL_RISK_SCORE"] = "0.0"       // Risk calculation moved to individual packages
	output.Properties["TYPOSENTINEL_OVERALL_RISK"] = "unknown" // Risk calculation moved to individual packages
	output.Properties["TYPOSENTINEL_THREATS_COUNT"] = fmt.Sprintf("%d", totalThreats)
	output.Properties["TYPOSENTINEL_PACKAGE_NAME"] = packageName
	output.Properties["TYPOSENTINEL_PACKAGE_VERSION"] = packageVersion
	output.Properties["TYPOSENTINEL_SCAN_STATUS"] = "completed"
	output.Properties["TYPOSENTINEL_SCAN_TIMESTAMP"] = time.Now().Format(time.RFC3339)

	// Add custom properties
	for key, value := range p.settings.CustomProperties {
		output.Properties[key] = value
	}

	// Set threat-specific properties
	criticalCount := 0
	highCount := 0
	mediumCount := 0
	lowCount := 0

	for _, pkg := range result.Packages {
		for _, threat := range pkg.Threats {
			switch threat.Severity {
			case types.SeverityCritical:
				criticalCount++
			case types.SeverityHigh:
				highCount++
			case types.SeverityMedium:
				mediumCount++
			case types.SeverityLow:
				lowCount++
			}
		}
	}

	output.Properties["TYPOSENTINEL_CRITICAL_COUNT"] = fmt.Sprintf("%d", criticalCount)
	output.Properties["TYPOSENTINEL_HIGH_COUNT"] = fmt.Sprintf("%d", highCount)
	output.Properties["TYPOSENTINEL_MEDIUM_COUNT"] = fmt.Sprintf("%d", mediumCount)
	output.Properties["TYPOSENTINEL_LOW_COUNT"] = fmt.Sprintf("%d", lowCount)
}

// generateTestResults generates Jenkins test results format
func (p *JenkinsPlugin) generateTestResults(output *JenkinsOutput, result *types.ScanResult) {
	// Convert threats to test results format
	var totalThreats int
	for _, pkg := range result.Packages {
		totalThreats += len(pkg.Threats)
	}

	totalTests := totalThreats + 1 // +1 for overall package test
	passedTests := 1               // Package scan completed
	failedTests := 0

	for _, pkg := range result.Packages {
		for _, threat := range pkg.Threats {
			if threat.Severity == types.SeverityCritical || threat.Severity == types.SeverityHigh {
				failedTests++
			} else {
				passedTests++
			}
		}
	}

	output.TestResults = JenkinsTestResults{
		TotalTests:   totalTests,
		PassedTests:  passedTests,
		FailedTests:  failedTests,
		SkippedTests: 0,
	}
}

// createArtifacts creates Jenkins artifacts
func (p *JenkinsPlugin) createArtifacts(output *JenkinsOutput, result *types.ScanResult) {
	if !p.settings.ArchiveReports {
		return
	}

	// Create scan report artifact
	reportPath := fmt.Sprintf("typosentinel-report-%s.json", time.Now().Format("20060102-150405"))
	output.Artifacts = append(output.Artifacts, JenkinsArtifact{
		Name: "Typosentinel Scan Report",
		Path: reportPath,
		Size: 0, // Will be calculated when file is created
	})

	// Create detailed report artifact
	detailedReportPath := fmt.Sprintf("typosentinel-detailed-%s.html", time.Now().Format("20060102-150405"))
	output.Artifacts = append(output.Artifacts, JenkinsArtifact{
		Name: "Typosentinel Detailed Report",
		Path: detailedReportPath,
		Size: 0,
	})

	// Create metrics artifact if there are threats
	var totalThreats int
	for _, pkg := range result.Packages {
		totalThreats += len(pkg.Threats)
	}
	if totalThreats > 0 {
		metricsPath := fmt.Sprintf("typosentinel-metrics-%s.json", time.Now().Format("20060102-150405"))
		output.Artifacts = append(output.Artifacts, JenkinsArtifact{
			Name: "Typosentinel Metrics",
			Path: metricsPath,
			Size: 0,
		})
	}
}

// publishReports publishes Jenkins reports
func (p *JenkinsPlugin) publishReports(output *JenkinsOutput, result *types.ScanResult) {
	if !p.settings.PublishResults {
		return
	}

	// Get package info from first package if available
	var packageName, packageVersion string
	if len(result.Packages) > 0 {
		packageName = result.Packages[0].Name
		packageVersion = result.Packages[0].Version
	} else {
		packageName = result.Target
		packageVersion = "unknown"
	}

	// Publish security report
	output.PublishedReports = append(output.PublishedReports, JenkinsReport{
		Type:        "security",
		Title:       "Typosentinel Security Report",
		Path:        "typosentinel-security-report.html",
		Description: fmt.Sprintf("Security scan results for %s@%s", packageName, packageVersion),
	})

	// Publish test results report
	output.PublishedReports = append(output.PublishedReports, JenkinsReport{
		Type:        "test",
		Title:       "Typosentinel Test Results",
		Path:        "typosentinel-test-results.xml",
		Description: "Test results in JUnit format",
	})

	// Publish trend report if there are multiple builds
	output.PublishedReports = append(output.PublishedReports, JenkinsReport{
		Type:        "trend",
		Title:       "Typosentinel Trend Analysis",
		Path:        "typosentinel-trend.html",
		Description: "Security trend analysis across builds",
	})
}

// handleSeverityActions handles actions based on threat severity
func (p *JenkinsPlugin) handleSeverityActions(result *types.ScanResult) []PluginAction {
	actions := []PluginAction{}

	hasCritical := false
	hasHigh := false

	for _, pkg := range result.Packages {
		for _, threat := range pkg.Threats {
			if threat.Severity == types.SeverityCritical {
				hasCritical = true
			}
			if threat.Severity == types.SeverityHigh {
				hasHigh = true
			}
		}
	}

	if hasCritical || hasHigh {
		actions = append(actions, PluginAction{
			Type: "set_build_description",
			Data: map[string]interface{}{
				"description": p.generateBuildDescription(result),
			},
		})
	}

	if hasCritical {
		actions = append(actions, PluginAction{
			Type: "mark_build_unstable",
			Data: map[string]interface{}{
				"reason": "Critical security threats detected",
			},
		})
	}

	return actions
}

// handleNotifications handles email notifications
func (p *JenkinsPlugin) handleNotifications(output *JenkinsOutput, result *types.ScanResult) {
	if !p.settings.NotifyEmail || len(p.settings.EmailRecipients) == 0 {
		return
	}

	// Get package info from first package if available
	var packageName, packageVersion string
	if len(result.Packages) > 0 {
		packageName = result.Packages[0].Name
		packageVersion = result.Packages[0].Version
	} else {
		packageName = result.Target
		packageVersion = "unknown"
	}

	hasCriticalOrHigh := false
	for _, pkg := range result.Packages {
		for _, threat := range pkg.Threats {
			if threat.Severity == types.SeverityCritical || threat.Severity == types.SeverityHigh {
				hasCriticalOrHigh = true
				break
			}
		}
		if hasCriticalOrHigh {
			break
		}
	}

	if hasCriticalOrHigh {
		notification := JenkinsNotification{
			Type:       "email",
			Recipients: p.settings.EmailRecipients,
			Subject:    fmt.Sprintf("Security Alert: %s@%s - Build #%s", packageName, packageVersion, p.settings.BuildNumber),
			Message:    p.generateEmailMessage(result),
			Sent:       false, // Will be marked as sent by Jenkins
		}
		output.Notifications = append(output.Notifications, notification)
	}
}

// shouldFailBuild determines if the build should fail based on settings
func (p *JenkinsPlugin) shouldFailBuild(result *types.ScanResult) bool {
	for _, pkg := range result.Packages {
		for _, threat := range pkg.Threats {
			if threat.Severity == types.SeverityCritical && p.settings.FailOnCritical {
				return true
			}
			if threat.Severity == types.SeverityHigh && p.settings.FailOnHigh {
				return true
			}
		}
	}
	return false
}

// generateSummaryMessage generates a summary message for the build
func (p *JenkinsPlugin) generateSummaryMessage(result *types.ScanResult) string {
	// Get package info from first package if available
	var packageName, packageVersion string
	if len(result.Packages) > 0 {
		packageName = result.Packages[0].Name
		packageVersion = result.Packages[0].Version
	} else {
		packageName = result.Target
		packageVersion = "unknown"
	}

	// Calculate total threats
	totalThreats := 0
	for _, pkg := range result.Packages {
		totalThreats += len(pkg.Threats)
	}

	if totalThreats == 0 {
		return fmt.Sprintf("✅ No security threats detected in %s@%s", packageName, packageVersion)
	}

	criticalCount := 0
	highCount := 0
	mediumCount := 0
	lowCount := 0

	for _, pkg := range result.Packages {
		for _, threat := range pkg.Threats {
			switch threat.Severity {
			case types.SeverityCritical:
				criticalCount++
			case types.SeverityHigh:
				highCount++
			case types.SeverityMedium:
				mediumCount++
			case types.SeverityLow:
				lowCount++
			}
		}
	}

	return fmt.Sprintf("🚨 Security threats detected in %s@%s: %d critical, %d high, %d medium, %d low",
		packageName, packageVersion, criticalCount, highCount, mediumCount, lowCount)
}

// generateBuildDescription generates description for Jenkins build
func (p *JenkinsPlugin) generateBuildDescription(result *types.ScanResult) string {
	// Get package info from first package if available
	var packageName, packageVersion string
	if len(result.Packages) > 0 {
		packageName = result.Packages[0].Name
		packageVersion = result.Packages[0].Version
	} else {
		packageName = result.Target
		packageVersion = "unknown"
	}

	// Calculate total threats
	totalThreats := 0
	for _, pkg := range result.Packages {
		totalThreats += len(pkg.Threats)
	}

	description := fmt.Sprintf("Typosentinel scan: %s@%s - ", packageName, packageVersion)

	if totalThreats == 0 {
		description += "No threats detected ✅"
	} else {
		criticalCount := 0
		highCount := 0
		for _, pkg := range result.Packages {
			for _, threat := range pkg.Threats {
				if threat.Severity == types.SeverityCritical {
					criticalCount++
				} else if threat.Severity == types.SeverityHigh {
					highCount++
				}
			}
		}
		description += fmt.Sprintf("%d critical, %d high threats 🚨", criticalCount, highCount)
	}

	return description
}

// generateEmailMessage generates email message content
func (p *JenkinsPlugin) generateEmailMessage(result *types.ScanResult) string {
	// Get package info from first package if available
	var packageName, packageVersion string
	if len(result.Packages) > 0 {
		packageName = result.Packages[0].Name
		packageVersion = result.Packages[0].Version
	} else {
		packageName = result.Target
		packageVersion = "unknown"
	}

	// Calculate total threats
	totalThreats := 0
	for _, pkg := range result.Packages {
		totalThreats += len(pkg.Threats)
	}

	message := fmt.Sprintf("Security Alert - Typosentinel Scan Results\n\n")
	message += fmt.Sprintf("Job: %s\n", p.settings.JobName)
	message += fmt.Sprintf("Build: #%s\n", p.settings.BuildNumber)
	message += fmt.Sprintf("Package: %s@%s\n", packageName, packageVersion)
	// Risk information moved to individual packages
	message += "Risk Score: Not available at scan level\n"
	message += "Overall Risk: Not available at scan level\n\n"

	message += "Detected Threats:\n"
	threatIndex := 1
	for _, pkg := range result.Packages {
		for _, threat := range pkg.Threats {
			if threat.Severity == types.SeverityCritical || threat.Severity == types.SeverityHigh {
				message += fmt.Sprintf("%d. %s (%s): %s\n", threatIndex, threat.Type, strings.ToUpper(threat.Severity.String()), threat.Description)
				threatIndex++
			}
		}
	}

	// Recommendations not available in new structure
	message += "\nRecommendations: Not available at scan level\n"

	message += fmt.Sprintf("\nView full report: %s/job/%s/%s/\n", p.settings.JenkinsURL, p.settings.JobName, p.settings.BuildNumber)

	return message
}

// Validate checks if the plugin configuration is valid
func (p *JenkinsPlugin) Validate(ctx context.Context) error {
	if p.settings.JenkinsURL == "" {
		return fmt.Errorf("jenkins_url is required for Jenkins integration")
	}
	if p.settings.JobName == "" {
		return fmt.Errorf("job_name is required for Jenkins integration")
	}
	return nil
}

// GetStatus returns the current plugin status
func (p *JenkinsPlugin) GetStatus() PluginStatus {
	return p.status
}

// Cleanup performs any necessary cleanup
func (p *JenkinsPlugin) Cleanup(ctx context.Context) error {
	p.logger.Info("Jenkins plugin cleanup completed")
	return nil
}
