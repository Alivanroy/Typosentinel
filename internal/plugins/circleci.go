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

// CircleCIPlugin implements Plugin interface for CircleCI integration
type CircleCIPlugin struct {
	info     PluginInfo
	settings CircleCISettings
	logger   Logger
	status   PluginStatus
}

// CircleCISettings contains CircleCI specific configuration
type CircleCISettings struct {
	ProjectSlug      string            `json:"project_slug"`
	WorkflowID       string            `json:"workflow_id"`
	JobNumber        string            `json:"job_number"`
	BuildNumber      string            `json:"build_number"`
	APIToken         string            `json:"api_token"`
	FailOnCritical   bool              `json:"fail_on_critical"`
	FailOnHigh       bool              `json:"fail_on_high"`
	StoreArtifacts   bool              `json:"store_artifacts"`
	StoreTestResults bool              `json:"store_test_results"`
	NotifySlack      bool              `json:"notify_slack"`
	SlackWebhook     string            `json:"slack_webhook"`
	CustomEnvVars    map[string]string `json:"custom_env_vars"`
}

// CircleCIOutput represents the output structure for CircleCI
type CircleCIOutput struct {
	JobStatus       string                 `json:"job_status"`
	ExitCode        int                    `json:"exit_code"`
	EnvironmentVars map[string]string      `json:"environment_vars"`
	Artifacts       []CircleCIArtifact     `json:"artifacts"`
	TestResults     CircleCITestResults    `json:"test_results"`
	Steps           []CircleCIStep         `json:"steps"`
	Notifications   []CircleCINotification `json:"notifications"`
	Metrics         map[string]interface{} `json:"metrics"`
	Insights        CircleCIInsights       `json:"insights"`
}

// CircleCIArtifact represents a CircleCI artifact
type CircleCIArtifact struct {
	Path        string `json:"path"`
	Destination string `json:"destination"`
	Size        int64  `json:"size"`
	Type        string `json:"type"`
}

// CircleCITestResults represents CircleCI test results
type CircleCITestResults struct {
	Path         string             `json:"path"`
	Format       string             `json:"format"`
	TotalTests   int                `json:"total_tests"`
	PassedTests  int                `json:"passed_tests"`
	FailedTests  int                `json:"failed_tests"`
	SkippedTests int                `json:"skipped_tests"`
	TestCases    []CircleCITestCase `json:"test_cases"`
}

// CircleCITestCase represents a test case
type CircleCITestCase struct {
	Classname string  `json:"classname"`
	Name      string  `json:"name"`
	Time      float64 `json:"time"`
	Failure   string  `json:"failure,omitempty"`
	Error     string  `json:"error,omitempty"`
	SystemOut string  `json:"system-out,omitempty"`
	SystemErr string  `json:"system-err,omitempty"`
}

// CircleCIStep represents a CircleCI step
type CircleCIStep struct {
	Name     string                 `json:"name"`
	Command  string                 `json:"command"`
	ExitCode int                    `json:"exit_code"`
	Duration int64                  `json:"duration_ms"`
	Output   string                 `json:"output"`
	Status   string                 `json:"status"`
	Metadata map[string]interface{} `json:"metadata"`
}

// CircleCINotification represents a notification
type CircleCINotification struct {
	Type    string                 `json:"type"`
	Target  string                 `json:"target"`
	Message string                 `json:"message"`
	Data    map[string]interface{} `json:"data"`
	Sent    bool                   `json:"sent"`
}

// CircleCIInsights represents CircleCI insights data
type CircleCIInsights struct {
	SecurityScore   float64                `json:"security_score"`
	TrendData       []CircleCITrendPoint   `json:"trend_data"`
	Recommendations []string               `json:"recommendations"`
	Metrics         map[string]interface{} `json:"metrics"`
}

// CircleCITrendPoint represents a trend data point
type CircleCITrendPoint struct {
	Timestamp   time.Time `json:"timestamp"`
	RiskScore   float64   `json:"risk_score"`
	ThreatCount int       `json:"threat_count"`
	BuildNumber string    `json:"build_number"`
}

// NewCircleCIPlugin creates a new CircleCI plugin instance
func NewCircleCIPlugin(logger Logger) *CircleCIPlugin {
	return &CircleCIPlugin{
		info: PluginInfo{
			Name:        "circleci",
			Version:     "1.0.0",
			Description: "CircleCI integration for Typosentinel",
			Author:      "Typosentinel Team",
			Platform:    "circleci",
			Capabilities: []string{
				"workflow_integration",
				"artifact_storage",
				"test_results",
				"slack_notifications",
				"environment_variables",
				"insights_tracking",
				"step_execution",
			},
		},
		logger: logger,
	}
}

// GetInfo returns plugin information
func (p *CircleCIPlugin) GetInfo() PluginInfo {
	return p.info
}

// Initialize sets up the CircleCI plugin
func (p *CircleCIPlugin) Initialize(ctx context.Context, config map[string]interface{}) error {
	// Convert config to settings
	configBytes, err := json.Marshal(config)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	if err := json.Unmarshal(configBytes, &p.settings); err != nil {
		return fmt.Errorf("failed to unmarshal settings: %w", err)
	}

	// Set defaults from environment if not provided
	if p.settings.ProjectSlug == "" {
		p.settings.ProjectSlug = os.Getenv("CIRCLE_PROJECT_REPONAME")
		if org := os.Getenv("CIRCLE_PROJECT_USERNAME"); org != "" && p.settings.ProjectSlug != "" {
			p.settings.ProjectSlug = fmt.Sprintf("%s/%s", org, p.settings.ProjectSlug)
		}
	}
	if p.settings.WorkflowID == "" {
		p.settings.WorkflowID = os.Getenv("CIRCLE_WORKFLOW_ID")
	}
	if p.settings.JobNumber == "" {
		p.settings.JobNumber = os.Getenv("CIRCLE_BUILD_NUM")
	}
	if p.settings.BuildNumber == "" {
		p.settings.BuildNumber = os.Getenv("CIRCLE_BUILD_NUM")
	}
	if p.settings.APIToken == "" {
		p.settings.APIToken = os.Getenv("CIRCLE_TOKEN")
	}

	// Initialize custom environment variables
	if p.settings.CustomEnvVars == nil {
		p.settings.CustomEnvVars = make(map[string]string)
	}

	p.logger.Info("CircleCI plugin initialized", map[string]interface{}{
		"project_slug": p.settings.ProjectSlug,
		"workflow_id":  p.settings.WorkflowID,
		"job_number":   p.settings.JobNumber,
		"build_number": p.settings.BuildNumber,
	})

	return nil
}

// Execute runs the CircleCI integration
func (p *CircleCIPlugin) Execute(ctx context.Context, result *types.ScanResult) (*PluginResult, error) {
	start := time.Now()

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

	p.logger.Info("Executing CircleCI plugin", map[string]interface{}{
		"package": packageName,
		"risk":    "unknown", // Risk calculation moved to individual packages
	})

	output := &CircleCIOutput{
		JobStatus:       "success",
		ExitCode:        0,
		EnvironmentVars: make(map[string]string),
		Artifacts:       []CircleCIArtifact{},
		TestResults:     CircleCITestResults{},
		Steps:           []CircleCIStep{},
		Notifications:   []CircleCINotification{},
		Metrics:         make(map[string]interface{}),
		Insights:        CircleCIInsights{},
	}

	// Add scan step
	p.addStep(output, "typosentinel-scan", "Typosentinel Security Scan", start)

	// Set CircleCI environment variables
	p.setEnvironmentVars(output, result)

	// Generate test results
	p.generateTestResults(output, result)

	// Create artifacts
	p.createArtifacts(output, result)

	// Generate insights
	p.generateInsights(output, result)

	// Handle severity-based actions
	actions := p.handleSeverityActions(result)

	// Handle notifications
	p.handleNotifications(output, result)

	// Determine job status and exit code
	if p.shouldFailJob(result) {
		output.JobStatus = "failed"
		output.ExitCode = 1
	} else if totalThreats > 0 {
		output.JobStatus = "success_with_warnings"
	}

	// Create metrics
	output.Metrics = map[string]interface{}{
		"scan_duration_ms": time.Since(start).Milliseconds(),
		"threats_detected": totalThreats,
		"risk_score":       0.0,       // Risk calculation moved to individual packages
		"overall_risk":     "unknown", // Risk calculation moved to individual packages
		"package_name":     packageName,
		"package_version":  packageVersion,
		"scan_timestamp":   time.Now().Unix(),
		"workflow_id":      p.settings.WorkflowID,
		"job_number":       p.settings.JobNumber,
	}

	// Complete the scan step
	p.completeStep(output, "typosentinel-scan", start, output.JobStatus)

	return &PluginResult{
		Success: output.JobStatus == "success" || output.JobStatus == "success_with_warnings",
		Message: p.generateSummaryMessage(result),
		Data:    map[string]interface{}{"circleci_output": output},
		Actions: actions,
		Metadata: map[string]interface{}{
			"platform":     "circleci",
			"project_slug": p.settings.ProjectSlug,
			"workflow_id":  p.settings.WorkflowID,
			"job_number":   p.settings.JobNumber,
			"job_status":   output.JobStatus,
			"exit_code":    output.ExitCode,
		},
	}, nil
}

// addStep adds a step to the CircleCI output
func (p *CircleCIPlugin) addStep(output *CircleCIOutput, name, command string, start time.Time) {
	step := CircleCIStep{
		Name:     name,
		Command:  command,
		ExitCode: 0,
		Duration: 0, // Will be updated when completed
		Output:   "",
		Status:   "running",
		Metadata: map[string]interface{}{
			"start_time": start,
		},
	}
	output.Steps = append(output.Steps, step)
}

// completeStep completes a step in the CircleCI output
func (p *CircleCIPlugin) completeStep(output *CircleCIOutput, name string, start time.Time, status string) {
	for i := range output.Steps {
		if output.Steps[i].Name == name {
			output.Steps[i].Duration = time.Since(start).Milliseconds()
			output.Steps[i].Status = status
			if status == "failed" {
				output.Steps[i].ExitCode = 1
			}
			break
		}
	}
}

// setEnvironmentVars sets CircleCI environment variables
func (p *CircleCIPlugin) setEnvironmentVars(output *CircleCIOutput, result *types.ScanResult) {
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

	output.EnvironmentVars["TYPOSENTINEL_RISK_SCORE"] = "0.0"       // Risk calculation moved to individual packages
	output.EnvironmentVars["TYPOSENTINEL_OVERALL_RISK"] = "unknown" // Risk calculation moved to individual packages
	output.EnvironmentVars["TYPOSENTINEL_THREATS_COUNT"] = fmt.Sprintf("%d", totalThreats)
	output.EnvironmentVars["TYPOSENTINEL_PACKAGE_NAME"] = packageName
	output.EnvironmentVars["TYPOSENTINEL_PACKAGE_VERSION"] = packageVersion
	output.EnvironmentVars["TYPOSENTINEL_SCAN_STATUS"] = "completed"
	output.EnvironmentVars["TYPOSENTINEL_SCAN_TIMESTAMP"] = time.Now().Format(time.RFC3339)

	// Add custom environment variables
	for key, value := range p.settings.CustomEnvVars {
		output.EnvironmentVars[key] = value
	}

	// Set threat severity counts
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

	output.EnvironmentVars["TYPOSENTINEL_CRITICAL_COUNT"] = fmt.Sprintf("%d", criticalCount)
	output.EnvironmentVars["TYPOSENTINEL_HIGH_COUNT"] = fmt.Sprintf("%d", highCount)
	output.EnvironmentVars["TYPOSENTINEL_MEDIUM_COUNT"] = fmt.Sprintf("%d", mediumCount)
	output.EnvironmentVars["TYPOSENTINEL_LOW_COUNT"] = fmt.Sprintf("%d", lowCount)
}

// generateTestResults generates CircleCI test results
func (p *CircleCIPlugin) generateTestResults(output *CircleCIOutput, result *types.ScanResult) {
	if !p.settings.StoreTestResults {
		return
	}

	// Get package info from first package if available
	var packageName string
	if len(result.Packages) > 0 {
		packageName = result.Packages[0].Name
	} else {
		packageName = result.Target
	}

	// Calculate total threats
	totalThreats := 0
	for _, pkg := range result.Packages {
		totalThreats += len(pkg.Threats)
	}

	testCases := []CircleCITestCase{}
	passedTests := 0
	failedTests := 0

	// Create a test case for the overall package scan
	overallTest := CircleCITestCase{
		Classname: "typosentinel.security",
		Name:      fmt.Sprintf("package_scan_%s", strings.ReplaceAll(packageName, "/", "_")),
		Time:      1.0, // 1 second default
	}

	if totalThreats > 0 {
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
			overallTest.Failure = fmt.Sprintf("Critical or high severity threats detected: %d total threats", totalThreats)
			failedTests++
		} else {
			passedTests++
		}
	} else {
		passedTests++
	}

	testCases = append(testCases, overallTest)

	// Create individual test cases for each threat
	threatIndex := 1
	for _, pkg := range result.Packages {
		for _, threat := range pkg.Threats {
			testCase := CircleCITestCase{
				Classname: "typosentinel.threats",
				Name:      fmt.Sprintf("threat_%d_%s", threatIndex, strings.ReplaceAll(string(threat.Type), " ", "_")),
				Time:      0.1, // 100ms default
			}

			if threat.Severity == types.SeverityCritical || threat.Severity == types.SeverityHigh {
				testCase.Failure = threat.Description
				failedTests++
			} else {
				passedTests++
			}

			testCases = append(testCases, testCase)
			threatIndex++
		}
	}

	output.TestResults = CircleCITestResults{
		Path:         "test-results/typosentinel.xml",
		Format:       "junit",
		TotalTests:   len(testCases),
		PassedTests:  passedTests,
		FailedTests:  failedTests,
		SkippedTests: 0,
		TestCases:    testCases,
	}
}

// createArtifacts creates CircleCI artifacts
func (p *CircleCIPlugin) createArtifacts(output *CircleCIOutput, result *types.ScanResult) {
	if !p.settings.StoreArtifacts {
		return
	}

	// Calculate total threats
	totalThreats := 0
	for _, pkg := range result.Packages {
		totalThreats += len(pkg.Threats)
	}

	// Create scan report artifact
	reportArtifact := CircleCIArtifact{
		Path:        fmt.Sprintf("/tmp/artifacts/typosentinel-report-%s.json", time.Now().Format("20060102-150405")),
		Destination: "typosentinel-reports",
		Size:        0, // Will be calculated when stored
		Type:        "report",
	}
	output.Artifacts = append(output.Artifacts, reportArtifact)

	// Create detailed HTML report artifact
	htmlArtifact := CircleCIArtifact{
		Path:        fmt.Sprintf("/tmp/artifacts/typosentinel-report-%s.html", time.Now().Format("20060102-150405")),
		Destination: "typosentinel-reports",
		Size:        0,
		Type:        "html",
	}
	output.Artifacts = append(output.Artifacts, htmlArtifact)

	// Create metrics artifact if there are threats
	if totalThreats > 0 {
		metricsArtifact := CircleCIArtifact{
			Path:        fmt.Sprintf("/tmp/artifacts/typosentinel-metrics-%s.json", time.Now().Format("20060102-150405")),
			Destination: "typosentinel-metrics",
			Size:        0,
			Type:        "metrics",
		}
		output.Artifacts = append(output.Artifacts, metricsArtifact)
	}
}

// generateInsights generates CircleCI insights data
func (p *CircleCIPlugin) generateInsights(output *CircleCIOutput, result *types.ScanResult) {
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

	// Create trend point for current scan
	trendPoint := CircleCITrendPoint{
		Timestamp:   time.Now(),
		RiskScore:   0.0, // Risk calculation moved to individual packages
		ThreatCount: totalThreats,
		BuildNumber: p.settings.BuildNumber,
	}

	output.Insights = CircleCIInsights{
		SecurityScore:   100.0, // Risk calculation moved to individual packages
		TrendData:       []CircleCITrendPoint{trendPoint},
		Recommendations: []string{}, // Recommendations not available in new structure
		Metrics: map[string]interface{}{
			"package_name":        packageName,
			"package_version":     packageVersion,
			"scan_timestamp":      time.Now().Unix(),
			"threats_by_severity": p.getThreatsBySeverity(result),
		},
	}
}

// getThreatsBySeverity returns threats grouped by severity
func (p *CircleCIPlugin) getThreatsBySeverity(result *types.ScanResult) map[string]int {
	counts := map[string]int{
		"critical": 0,
		"high":     0,
		"medium":   0,
		"low":      0,
	}

	for _, pkg := range result.Packages {
		for _, threat := range pkg.Threats {
			if count, exists := counts[threat.Severity.String()]; exists {
				counts[threat.Severity.String()] = count + 1
			}
		}
	}

	return counts
}

// handleSeverityActions handles actions based on threat severity
func (p *CircleCIPlugin) handleSeverityActions(result *types.ScanResult) []PluginAction {
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
			Type: "set_env_var",
			Data: map[string]interface{}{
				"name":  "TYPOSENTINEL_SECURITY_ALERT",
				"value": "true",
			},
		})
	}

	return actions
}

// handleNotifications handles Slack notifications
func (p *CircleCIPlugin) handleNotifications(output *CircleCIOutput, result *types.ScanResult) {
	if !p.settings.NotifySlack || p.settings.SlackWebhook == "" {
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
		notification := CircleCINotification{
			Type:    "slack",
			Target:  p.settings.SlackWebhook,
			Message: p.generateSlackMessage(result),
			Data: map[string]interface{}{
				"channel":    "#security",
				"username":   "Typosentinel",
				"icon_emoji": ":warning:",
				"attachments": []map[string]interface{}{
					{
						"color":  "danger",
						"title":  fmt.Sprintf("Security Alert: %s@%s", packageName, packageVersion),
						"text":   p.generateSlackAttachmentText(result),
						"fields": p.generateSlackFields(result),
					},
				},
			},
			Sent: false,
		}
		output.Notifications = append(output.Notifications, notification)
	}
}

// shouldFailJob determines if the job should fail based on settings
func (p *CircleCIPlugin) shouldFailJob(result *types.ScanResult) bool {
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

// generateSummaryMessage generates a summary message for the job
func (p *CircleCIPlugin) generateSummaryMessage(result *types.ScanResult) string {
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

// generateSlackMessage generates Slack message content
func (p *CircleCIPlugin) generateSlackMessage(result *types.ScanResult) string {
	// Get package info from first package if available
	var packageName, packageVersion string
	if len(result.Packages) > 0 {
		packageName = result.Packages[0].Name
		packageVersion = result.Packages[0].Version
	} else {
		packageName = result.Target
		packageVersion = "unknown"
	}

	message := fmt.Sprintf("🚨 *Security Alert* - Typosentinel detected threats in `%s@%s`\n", packageName, packageVersion)
	message += "*Risk Score:* Not available at scan level | *Overall Risk:* Not available at scan level\n"
	message += fmt.Sprintf("*CircleCI Job:* <%s|#%s>\n", p.getJobURL(), p.settings.JobNumber)
	return message
}

// generateSlackAttachmentText generates Slack attachment text
func (p *CircleCIPlugin) generateSlackAttachmentText(result *types.ScanResult) string {
	text := "Detected security threats:\n"
	for _, pkg := range result.Packages {
		for _, threat := range pkg.Threats {
			if threat.Severity == types.SeverityCritical || threat.Severity == types.SeverityHigh {
				text += fmt.Sprintf("• *%s* (%s): %s\n", threat.Type, strings.ToUpper(threat.Severity.String()), threat.Description)
			}
		}
	}
	return text
}

// generateSlackFields generates Slack fields
func (p *CircleCIPlugin) generateSlackFields(result *types.ScanResult) []map[string]interface{} {
	fields := []map[string]interface{}{}

	threatCounts := p.getThreatsBySeverity(result)
	for severity, count := range threatCounts {
		if count > 0 {
			fields = append(fields, map[string]interface{}{
				"title": strings.Title(severity),
				"value": fmt.Sprintf("%d", count),
				"short": true,
			})
		}
	}

	fields = append(fields, map[string]interface{}{
		"title": "Workflow",
		"value": p.settings.WorkflowID,
		"short": true,
	})

	return fields
}

// getJobURL returns the CircleCI job URL
func (p *CircleCIPlugin) getJobURL() string {
	if p.settings.ProjectSlug != "" && p.settings.JobNumber != "" {
		return fmt.Sprintf("https://app.circleci.com/pipelines/github/%s/jobs/%s", p.settings.ProjectSlug, p.settings.JobNumber)
	}
	return "#"
}

// Validate checks if the plugin configuration is valid
func (p *CircleCIPlugin) Validate(ctx context.Context) error {
	if p.settings.ProjectSlug == "" {
		return fmt.Errorf("project_slug is required for CircleCI integration")
	}
	if p.settings.NotifySlack && p.settings.SlackWebhook == "" {
		return fmt.Errorf("slack_webhook is required when notify_slack is enabled")
	}
	return nil
}

// GetStatus returns the current plugin status
func (p *CircleCIPlugin) GetStatus() PluginStatus {
	return p.status
}

// Cleanup performs any necessary cleanup
func (p *CircleCIPlugin) Cleanup(ctx context.Context) error {
	p.logger.Info("CircleCI plugin cleanup completed")
	return nil
}
