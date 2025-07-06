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



// AzureDevOpsPlugin implements Plugin interface for Azure DevOps integration
type AzureDevOpsPlugin struct {
	info     PluginInfo
	settings AzureDevOpsSettings
	logger   Logger
	status   PluginStatus
}

// AzureDevOpsSettings contains Azure DevOps specific configuration
type AzureDevOpsSettings struct {
	Organization       string            `json:"organization"`
	Project            string            `json:"project"`
	Repository         string            `json:"repository"`
	BuildID            string            `json:"build_id"`
	PipelineID         string            `json:"pipeline_id"`
	AccessToken        string            `json:"access_token"`
	FailOnCritical     bool              `json:"fail_on_critical"`
	FailOnHigh         bool              `json:"fail_on_high"`
	CreateWorkItem     bool              `json:"create_work_item"`
	CommentPR          bool              `json:"comment_pr"`
	PublishTestResults bool              `json:"publish_test_results"`
	UploadArtifacts    bool              `json:"upload_artifacts"`
	CustomVariables    map[string]string `json:"custom_variables"`
}

// AzureDevOpsOutput represents the output structure for Azure DevOps
type AzureDevOpsOutput struct {
	TaskResult       string                    `json:"task_result"`
	ExitCode         int                       `json:"exit_code"`
	Variables        map[string]string         `json:"variables"`
	TestResults      AzureDevOpsTestResults    `json:"test_results"`
	Artifacts        []AzureDevOpsArtifact     `json:"artifacts"`
	WorkItems        []AzureDevOpsWorkItem     `json:"work_items"`
	PRComments       []AzureDevOpsPRComment    `json:"pr_comments"`
	Timeline         []AzureDevOpsTimelineEntry `json:"timeline"`
	Metrics          map[string]interface{}    `json:"metrics"`
	SecurityReport   AzureDevOpsSecurityReport `json:"security_report"`
}

// AzureDevOpsTestResults represents Azure DevOps test results
type AzureDevOpsTestResults struct {
	TestRun      string                   `json:"test_run"`
	TotalTests   int                      `json:"total_tests"`
	PassedTests  int                      `json:"passed_tests"`
	FailedTests  int                      `json:"failed_tests"`
	SkippedTests int                      `json:"skipped_tests"`
	TestCases    []AzureDevOpsTestCase    `json:"test_cases"`
}

// AzureDevOpsTestCase represents a test case
type AzureDevOpsTestCase struct {
	Name        string `json:"name"`
	Outcome     string `json:"outcome"`
	Duration    int64  `json:"duration_ms"`
	ErrorMessage string `json:"error_message,omitempty"`
	StackTrace   string `json:"stack_trace,omitempty"`
}

// AzureDevOpsArtifact represents a build artifact
type AzureDevOpsArtifact struct {
	Name         string `json:"name"`
	Type         string `json:"type"`
	Path         string `json:"path"`
	Size         int64  `json:"size"`
	ContainerID  string `json:"container_id,omitempty"`
}

// AzureDevOpsWorkItem represents a work item
type AzureDevOpsWorkItem struct {
	ID          int               `json:"id,omitempty"`
	Type        string            `json:"type"`
	Title       string            `json:"title"`
	Description string            `json:"description"`
	State       string            `json:"state"`
	Priority    string            `json:"priority"`
	Severity    string            `json:"severity"`
	Tags        []string          `json:"tags"`
	Fields      map[string]string `json:"fields"`
}

// AzureDevOpsPRComment represents a pull request comment
type AzureDevOpsPRComment struct {
	PRID       int    `json:"pr_id"`
	ThreadID   int    `json:"thread_id,omitempty"`
	Content    string `json:"content"`
	CommentType string `json:"comment_type"`
	Status     string `json:"status"`
}

// AzureDevOpsTimelineEntry represents a timeline entry
type AzureDevOpsTimelineEntry struct {
	Timestamp time.Time `json:"timestamp"`
	Event     string    `json:"event"`
	Message   string    `json:"message"`
	Level     string    `json:"level"`
}

// AzureDevOpsSecurityReport represents security report for Azure DevOps
type AzureDevOpsSecurityReport struct {
	Version         string                           `json:"version"`
	Vulnerabilities []AzureDevOpsVulnerability       `json:"vulnerabilities"`
	Summary         AzureDevOpsSecuritySummary       `json:"summary"`
}

// AzureDevOpsVulnerability represents a vulnerability
type AzureDevOpsVulnerability struct {
	ID          string                 `json:"id"`
	Category    string                 `json:"category"`
	Title       string                 `json:"title"`
	Description string                 `json:"description"`
	Severity    string                 `json:"severity"`
	Confidence  string                 `json:"confidence"`
	Location    map[string]interface{} `json:"location"`
	References  []string               `json:"references"`
}

// AzureDevOpsSecuritySummary represents security summary
type AzureDevOpsSecuritySummary struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Total    int `json:"total"`
}

// NewAzureDevOpsPlugin creates a new Azure DevOps plugin instance
func NewAzureDevOpsPlugin(logger Logger) *AzureDevOpsPlugin {
	return &AzureDevOpsPlugin{
		info: PluginInfo{
			Name:        "azure-devops",
			Version:     "1.0.0",
			Description: "Azure DevOps integration for Typosentinel",
			Author:      "Typosentinel Team",
			Platform:    "azure-devops",
			Capabilities: []string{
				"pipeline_integration",
				"test_results",
				"work_item_creation",
				"pr_comments",
				"artifact_upload",
				"security_reports",
				"custom_variables",
				"timeline_logging",
			},
		},
		logger: logger,
	}
}

// GetInfo returns plugin information
func (p *AzureDevOpsPlugin) GetInfo() PluginInfo {
	return p.info
}

// Initialize sets up the Azure DevOps plugin
func (p *AzureDevOpsPlugin) Initialize(ctx context.Context, config map[string]interface{}) error {
	// Convert config to settings
	configBytes, err := json.Marshal(config)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	if err := json.Unmarshal(configBytes, &p.settings); err != nil {
		return fmt.Errorf("failed to unmarshal settings: %w", err)
	}

	// Set defaults from environment if not provided
	if p.settings.Organization == "" {
		p.settings.Organization = os.Getenv("SYSTEM_TEAMFOUNDATIONCOLLECTIONURI")
		if p.settings.Organization != "" {
			// Extract organization from URI
			parts := strings.Split(p.settings.Organization, "/")
			if len(parts) > 3 {
				p.settings.Organization = parts[3]
			}
		}
	}
	if p.settings.Project == "" {
		p.settings.Project = os.Getenv("SYSTEM_TEAMPROJECT")
	}
	if p.settings.Repository == "" {
		p.settings.Repository = os.Getenv("BUILD_REPOSITORY_NAME")
	}
	if p.settings.BuildID == "" {
		p.settings.BuildID = os.Getenv("BUILD_BUILDID")
	}
	if p.settings.PipelineID == "" {
		p.settings.PipelineID = os.Getenv("SYSTEM_DEFINITIONID")
	}
	if p.settings.AccessToken == "" {
		p.settings.AccessToken = os.Getenv("SYSTEM_ACCESSTOKEN")
	}

	// Initialize custom variables
	if p.settings.CustomVariables == nil {
		p.settings.CustomVariables = make(map[string]string)
	}

	p.logger.Info("Azure DevOps plugin initialized", map[string]interface{}{
		"organization": p.settings.Organization,
		"project":      p.settings.Project,
		"repository":   p.settings.Repository,
		"build_id":     p.settings.BuildID,
		"pipeline_id":  p.settings.PipelineID,
	})

	return nil
}

// Execute runs the Azure DevOps integration
func (p *AzureDevOpsPlugin) Execute(ctx context.Context, result *types.ScanResult) (*PluginResult, error) {
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
	
	p.logger.Info("Executing Azure DevOps plugin", map[string]interface{}{
		"package": packageName,
		"risk":    "unknown", // Risk calculation moved to individual packages
	})

	output := &AzureDevOpsOutput{
		TaskResult:     "Succeeded",
		ExitCode:       0,
		Variables:      make(map[string]string),
		TestResults:    AzureDevOpsTestResults{},
		Artifacts:      []AzureDevOpsArtifact{},
		WorkItems:      []AzureDevOpsWorkItem{},
		PRComments:     []AzureDevOpsPRComment{},
		Timeline:       []AzureDevOpsTimelineEntry{},
		Metrics:        make(map[string]interface{}),
		SecurityReport: AzureDevOpsSecurityReport{},
	}

	// Add timeline entry for scan start
	p.addTimelineEntry(output, "info", "scan_started", "Typosentinel security scan started")

	// Set Azure DevOps variables
	p.setAzureDevOpsVariables(output, result)

	// Generate test results
	p.generateTestResults(output, result)

	// Create artifacts
	p.createArtifacts(output, result)

	// Generate security report
	p.generateSecurityReport(output, result)

	// Handle severity-based actions
	actions := p.handleSeverityActions(output, result)

	// Handle work item creation
	p.handleWorkItems(output, result)

	// Handle PR comments
	p.handlePRComments(output, result)

	// Determine task result and exit code
	if p.shouldFailTask(result) {
		output.TaskResult = "Failed"
		output.ExitCode = 1
		p.addTimelineEntry(output, "error", "scan_failed", "Typosentinel scan failed due to critical threats")
	} else if totalThreats > 0 {
		output.TaskResult = "SucceededWithIssues"
		p.addTimelineEntry(output, "warning", "scan_completed_with_issues", "Typosentinel scan completed with security issues")
	} else {
		p.addTimelineEntry(output, "info", "scan_completed", "Typosentinel scan completed successfully")
	}

	// Get package version
	var packageVersion string
	if len(result.Packages) > 0 {
		packageVersion = result.Packages[0].Version
	} else {
		packageVersion = "unknown"
	}

	// Create metrics
	output.Metrics = map[string]interface{}{
		"scan_duration_ms":    time.Since(start).Milliseconds(),
		"threats_detected":    totalThreats,
		"risk_score":          0.0, // Risk calculation moved to individual packages
		"overall_risk":        "unknown", // Risk calculation moved to individual packages
		"package_name":        packageName,
		"package_version":     packageVersion,
		"scan_timestamp":      time.Now().Unix(),
		"build_id":            p.settings.BuildID,
		"pipeline_id":         p.settings.PipelineID,
	}

	// Convert output to JSON
	return &PluginResult{
		Success:   output.TaskResult == "Succeeded" || output.TaskResult == "SucceededWithIssues",
		Message:   p.generateSummaryMessage(result),
		Data:      map[string]interface{}{"azure_devops_output": output},
		Actions:   actions,
		Metadata: map[string]interface{}{
			"platform":     "azure-devops",
			"organization": p.settings.Organization,
			"project":      p.settings.Project,
			"build_id":     p.settings.BuildID,
			"pipeline_id":  p.settings.PipelineID,
			"task_result":  output.TaskResult,
			"exit_code":    output.ExitCode,
		},
	}, nil
}

// addTimelineEntry adds an entry to the timeline
func (p *AzureDevOpsPlugin) addTimelineEntry(output *AzureDevOpsOutput, level, event, message string) {
	entry := AzureDevOpsTimelineEntry{
		Timestamp: time.Now(),
		Event:     event,
		Message:   message,
		Level:     level,
	}
	output.Timeline = append(output.Timeline, entry)
}

// setAzureDevOpsVariables sets Azure DevOps pipeline variables
func (p *AzureDevOpsPlugin) setAzureDevOpsVariables(output *AzureDevOpsOutput, result *types.ScanResult) {
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

	output.Variables["TYPOSENTINEL_RISK_SCORE"] = "0.0" // Risk calculation moved to individual packages
	output.Variables["TYPOSENTINEL_OVERALL_RISK"] = "unknown" // Risk calculation moved to individual packages
	output.Variables["TYPOSENTINEL_THREATS_COUNT"] = fmt.Sprintf("%d", totalThreats)
	output.Variables["TYPOSENTINEL_PACKAGE_NAME"] = packageName
	output.Variables["TYPOSENTINEL_PACKAGE_VERSION"] = packageVersion
	output.Variables["TYPOSENTINEL_SCAN_STATUS"] = "completed"
	output.Variables["TYPOSENTINEL_SCAN_TIMESTAMP"] = time.Now().Format(time.RFC3339)

	// Add custom variables
	for key, value := range p.settings.CustomVariables {
		output.Variables[key] = value
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

	output.Variables["TYPOSENTINEL_CRITICAL_COUNT"] = fmt.Sprintf("%d", criticalCount)
	output.Variables["TYPOSENTINEL_HIGH_COUNT"] = fmt.Sprintf("%d", highCount)
	output.Variables["TYPOSENTINEL_MEDIUM_COUNT"] = fmt.Sprintf("%d", mediumCount)
	output.Variables["TYPOSENTINEL_LOW_COUNT"] = fmt.Sprintf("%d", lowCount)
}

// generateTestResults generates Azure DevOps test results
func (p *AzureDevOpsPlugin) generateTestResults(output *AzureDevOpsOutput, result *types.ScanResult) {
	if !p.settings.PublishTestResults {
		return
	}

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

	testCases := []AzureDevOpsTestCase{}
	passedTests := 0
	failedTests := 0

	// Create a test case for the overall package scan
	overallTest := AzureDevOpsTestCase{
		Name:     fmt.Sprintf("Package Security Scan: %s@%s", packageName, packageVersion),
		Outcome:  "Passed",
		Duration: 1000, // 1 second default
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
			overallTest.Outcome = "Failed"
			overallTest.ErrorMessage = fmt.Sprintf("Critical or high severity threats detected: %d total threats", totalThreats)
			failedTests++
		} else {
			passedTests++
		}
	} else {
		passedTests++
	}

	testCases = append(testCases, overallTest)

	// Create individual test cases for each threat
	for _, pkg := range result.Packages {
		for _, threat := range pkg.Threats {
			testCase := AzureDevOpsTestCase{
				Name:     fmt.Sprintf("Threat Detection: %s", string(threat.Type)),
				Duration: 100, // 100ms default
			}

			if threat.Severity == types.SeverityCritical || threat.Severity == types.SeverityHigh {
				testCase.Outcome = "Failed"
				testCase.ErrorMessage = threat.Description
				failedTests++
			} else {
				testCase.Outcome = "Passed"
				passedTests++
			}

			testCases = append(testCases, testCase)
		}
	}

	output.TestResults = AzureDevOpsTestResults{
		TestRun:      fmt.Sprintf("Typosentinel-%s", time.Now().Format("20060102-150405")),
		TotalTests:   len(testCases),
		PassedTests:  passedTests,
		FailedTests:  failedTests,
		SkippedTests: 0,
		TestCases:    testCases,
	}
}

// createArtifacts creates Azure DevOps artifacts
func (p *AzureDevOpsPlugin) createArtifacts(output *AzureDevOpsOutput, result *types.ScanResult) {
	if !p.settings.UploadArtifacts {
		return
	}

	// Create scan report artifact
	reportArtifact := AzureDevOpsArtifact{
		Name: "Typosentinel-Report",
		Type: "container",
		Path: fmt.Sprintf("typosentinel-report-%s.json", time.Now().Format("20060102-150405")),
		Size: 0, // Will be calculated when uploaded
	}
	output.Artifacts = append(output.Artifacts, reportArtifact)

	// Create detailed HTML report artifact
	htmlArtifact := AzureDevOpsArtifact{
		Name: "Typosentinel-HTML-Report",
		Type: "container",
		Path: fmt.Sprintf("typosentinel-report-%s.html", time.Now().Format("20060102-150405")),
		Size: 0,
	}
	output.Artifacts = append(output.Artifacts, htmlArtifact)

	// Create security report artifact if there are threats
	totalThreats := 0
	for _, pkg := range result.Packages {
		totalThreats += len(pkg.Threats)
	}
	if totalThreats > 0 {
		securityArtifact := AzureDevOpsArtifact{
			Name: "Typosentinel-Security-Report",
			Type: "container",
			Path: fmt.Sprintf("typosentinel-security-%s.json", time.Now().Format("20060102-150405")),
			Size: 0,
		}
		output.Artifacts = append(output.Artifacts, securityArtifact)
	}
}

// generateSecurityReport generates Azure DevOps security report
func (p *AzureDevOpsPlugin) generateSecurityReport(output *AzureDevOpsOutput, result *types.ScanResult) {
	vulnerabilities := []AzureDevOpsVulnerability{}
	summary := AzureDevOpsSecuritySummary{}

	vulnID := 1
	for _, pkg := range result.Packages {
		for _, threat := range pkg.Threats {
			vuln := AzureDevOpsVulnerability{
				ID:          fmt.Sprintf("TYPOSENTINEL-%d", vulnID),
				Category:    "dependency_scanning",
				Title:       string(threat.Type),
				Description: threat.Description,
				Severity:    strings.ToUpper(threat.Severity.String()),
				Confidence:  "High",
				Location: map[string]interface{}{
					"package": pkg.Name,
					"version": pkg.Version,
				},
				References: []string{
					"https://github.com/your-org/typosentinel",
				},
			}

			vulnerabilities = append(vulnerabilities, vuln)
			vulnID++

			// Update summary counts
			switch threat.Severity {
			case types.SeverityCritical:
				summary.Critical++
			case types.SeverityHigh:
				summary.High++
			case types.SeverityMedium:
				summary.Medium++
			case types.SeverityLow:
				summary.Low++
			}
			summary.Total++
		}
	}

	output.SecurityReport = AzureDevOpsSecurityReport{
		Version:         "1.0.0",
		Vulnerabilities: vulnerabilities,
		Summary:         summary,
	}
}

// handleSeverityActions handles actions based on threat severity
func (p *AzureDevOpsPlugin) handleSeverityActions(output *AzureDevOpsOutput, result *types.ScanResult) []PluginAction {
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
			Type: "log_issue",
			Data: map[string]interface{}{
				"type":    "error",
				"message": p.generateIssueMessage(result),
			},
		})
	}

	return actions
}

// handleWorkItems handles work item creation
func (p *AzureDevOpsPlugin) handleWorkItems(output *AzureDevOpsOutput, result *types.ScanResult) {
	if !p.settings.CreateWorkItem {
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
		workItem := AzureDevOpsWorkItem{
			Type:        "Bug",
			Title:       fmt.Sprintf("Security Alert: %s@%s", packageName, packageVersion),
			Description: p.generateWorkItemDescription(result),
			State:       "New",
			Priority:    "1",
			Severity:    "1 - Critical",
			Tags:        []string{"security", "typosentinel", "dependency"},
			Fields: map[string]string{
				"System.AreaPath":     p.settings.Project,
				"System.IterationPath": p.settings.Project,
				"Microsoft.VSTS.Common.Priority": "1",
				"Microsoft.VSTS.Common.Severity": "1 - Critical",
			},
		}
		output.WorkItems = append(output.WorkItems, workItem)
	}
}

// handlePRComments handles pull request comments
func (p *AzureDevOpsPlugin) handlePRComments(output *AzureDevOpsOutput, result *types.ScanResult) {
	if !p.settings.CommentPR {
		return
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
		comment := AzureDevOpsPRComment{
			PRID:        0, // Will be set by Azure DevOps
			Content:     p.generatePRComment(result),
			CommentType: "system",
			Status:      "pending",
		}
		output.PRComments = append(output.PRComments, comment)
	}
}

// shouldFailTask determines if the task should fail based on settings
func (p *AzureDevOpsPlugin) shouldFailTask(result *types.ScanResult) bool {
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

// generateSummaryMessage generates a summary message for the task
func (p *AzureDevOpsPlugin) generateSummaryMessage(result *types.ScanResult) string {
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

// generateIssueMessage generates issue message for logging
func (p *AzureDevOpsPlugin) generateIssueMessage(result *types.ScanResult) string {
	// Get package info from first package if available
	var packageName, packageVersion string
	if len(result.Packages) > 0 {
		packageName = result.Packages[0].Name
		packageVersion = result.Packages[0].Version
	} else {
		packageName = result.Target
		packageVersion = "unknown"
	}

	message := fmt.Sprintf("Security threats detected in %s@%s:\n", packageName, packageVersion)
	for _, pkg := range result.Packages {
		for _, threat := range pkg.Threats {
			if threat.Severity == types.SeverityCritical || threat.Severity == types.SeverityHigh {
				message += fmt.Sprintf("- %s (%s): %s\n", string(threat.Type), strings.ToUpper(threat.Severity.String()), threat.Description)
			}
		}
	}
	return message
}

// generateWorkItemDescription generates description for work item
func (p *AzureDevOpsPlugin) generateWorkItemDescription(result *types.ScanResult) string {
	// Get package info from first package if available
	var packageName, packageVersion string
	if len(result.Packages) > 0 {
		packageName = result.Packages[0].Name
		packageVersion = result.Packages[0].Version
	} else {
		packageName = result.Target
		packageVersion = "unknown"
	}

	description := fmt.Sprintf("## Security Threat Detection Report\n\n")
	description += fmt.Sprintf("**Package:** %s@%s\n", packageName, packageVersion)
	// Risk information moved to individual packages
	description += "**Risk Score:** Not available at scan level\n"
	description += "**Overall Risk:** Not available at scan level\n\n"

	description += "### Detected Threats\n\n"
	threatNum := 1
	for _, pkg := range result.Packages {
		for _, threat := range pkg.Threats {
			description += fmt.Sprintf("%d. **%s** (%s)\n", threatNum, string(threat.Type), threat.Severity.String())
			description += fmt.Sprintf("   - %s\n\n", threat.Description)
			threatNum++
		}
	}

	description += "### Recommendations\n\n"
	// Note: ScanResult doesn't have Recommendations field, so we'll skip this section
	// for _, rec := range result.Recommendations {
	//	description += fmt.Sprintf("- %s\n", rec)
	// }

	description += fmt.Sprintf("\n### Build Information\n\n")
	description += fmt.Sprintf("- **Build ID:** %s\n", p.settings.BuildID)
	description += fmt.Sprintf("- **Pipeline ID:** %s\n", p.settings.PipelineID)
	description += fmt.Sprintf("- **Repository:** %s\n", p.settings.Repository)

	return description
}

// generatePRComment generates comment for pull request
func (p *AzureDevOpsPlugin) generatePRComment(result *types.ScanResult) string {
	// Get package info from first package if available
	var packageName, packageVersion string
	if len(result.Packages) > 0 {
		packageName = result.Packages[0].Name
		packageVersion = result.Packages[0].Version
	} else {
		packageName = result.Target
		packageVersion = "unknown"
	}

	comment := "## 🚨 Typosentinel Security Alert\n\n"
	comment += fmt.Sprintf("Security threats detected in **%s@%s**\n\n", packageName, packageVersion)

	for _, pkg := range result.Packages {
		for _, threat := range pkg.Threats {
			if threat.Severity == types.SeverityCritical || threat.Severity == types.SeverityHigh {
				comment += fmt.Sprintf("- ⚠️ **%s** (%s): %s\n", string(threat.Type), threat.Severity.String(), threat.Description)
			}
		}
	}

	comment += "\n**Please review and address these security concerns before merging.**\n\n"
	comment += "📊 **Risk Score:** Not available at scan level | **Overall Risk:** Not available at scan level\n"
	comment += fmt.Sprintf("🔗 **Build:** [#%s](https://dev.azure.com/%s/%s/_build/results?buildId=%s)",
		p.settings.BuildID, p.settings.Organization, p.settings.Project, p.settings.BuildID)

	return comment
}

// Validate checks if the plugin configuration is valid
func (p *AzureDevOpsPlugin) Validate(ctx context.Context) error {
	if p.settings.Organization == "" {
		return fmt.Errorf("organization is required for Azure DevOps integration")
	}
	if p.settings.Project == "" {
		return fmt.Errorf("project is required for Azure DevOps integration")
	}
	if p.settings.AccessToken == "" {
		return fmt.Errorf("access_token is required for Azure DevOps integration")
	}
	return nil
}

// GetStatus returns the current plugin status
func (p *AzureDevOpsPlugin) GetStatus() PluginStatus {
	return p.status
}

// Cleanup performs any necessary cleanup
func (p *AzureDevOpsPlugin) Cleanup(ctx context.Context) error {
	p.logger.Info("Azure DevOps plugin cleanup completed")
	return nil
}