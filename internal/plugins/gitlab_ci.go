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

// Logger interface removed - using shared interface

// GitLabCIPlugin implements Plugin interface for GitLab CI integration
type GitLabCIPlugin struct {
	info     PluginInfo
	settings GitLabCISettings
	logger   Logger
	status   PluginStatus
}

// GitLabCISettings contains GitLab CI specific configuration
type GitLabCISettings struct {
	ProjectID       string            `json:"project_id"`
	Token           string            `json:"token"`
	PipelineID      string            `json:"pipeline_id"`
	JobID           string            `json:"job_id"`
	Environment     string            `json:"environment"`
	FailOnCritical  bool              `json:"fail_on_critical"`
	FailOnHigh      bool              `json:"fail_on_high"`
	CreateIssue     bool              `json:"create_issue"`
	NotifyMR        bool              `json:"notify_mr"`
	CustomVariables map[string]string `json:"custom_variables"`
}

// GitLabCIOutput represents the output structure for GitLab CI
type GitLabCIOutput struct {
	JobStatus   string                 `json:"job_status"`
	ExitCode    int                    `json:"exit_code"`
	Variables   map[string]string      `json:"variables"`
	Artifacts   []string               `json:"artifacts"`
	Annotations []GitLabCIAnnotation   `json:"annotations"`
	Metrics     map[string]interface{} `json:"metrics"`
	Reports     GitLabCIReports        `json:"reports"`
}

// GitLabCIAnnotation represents a GitLab CI annotation
type GitLabCIAnnotation struct {
	Level       string `json:"level"`
	Message     string `json:"message"`
	Path        string `json:"path,omitempty"`
	StartLine   int    `json:"start_line,omitempty"`
	EndLine     int    `json:"end_line,omitempty"`
	StartColumn int    `json:"start_column,omitempty"`
	EndColumn   int    `json:"end_column,omitempty"`
}

// GitLabCIReports represents GitLab CI reports
type GitLabCIReports struct {
	SecurityReport map[string]interface{} `json:"security_report,omitempty"`
	CodeQuality    []interface{}          `json:"code_quality,omitempty"`
	Junit          string                 `json:"junit,omitempty"`
}

// NewGitLabCIPlugin creates a new GitLab CI plugin instance
func NewGitLabCIPlugin(logger Logger) *GitLabCIPlugin {
	return &GitLabCIPlugin{
		info: PluginInfo{
			Name:        "gitlab-ci",
			Version:     "1.0.0",
			Description: "GitLab CI integration for Typosentinel",
			Author:      "Typosentinel Team",
			Platform:    "gitlab-ci",
			Capabilities: []string{
				"pipeline_integration",
				"merge_request_comments",
				"issue_creation",
				"security_reports",
				"code_quality_reports",
				"custom_variables",
				"artifacts",
			},
		},
		logger: logger,
	}
}

// GetInfo returns plugin information
func (p *GitLabCIPlugin) GetInfo() PluginInfo {
	return p.info
}

// Initialize sets up the GitLab CI plugin
func (p *GitLabCIPlugin) Initialize(ctx context.Context, config map[string]interface{}) error {
	// Convert config to settings
	configBytes, err := json.Marshal(config)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	if err := json.Unmarshal(configBytes, &p.settings); err != nil {
		return fmt.Errorf("failed to unmarshal settings: %w", err)
	}

	// Set defaults from environment if not provided
	if p.settings.ProjectID == "" {
		p.settings.ProjectID = os.Getenv("CI_PROJECT_ID")
	}
	if p.settings.Token == "" {
		p.settings.Token = os.Getenv("CI_JOB_TOKEN")
	}
	if p.settings.PipelineID == "" {
		p.settings.PipelineID = os.Getenv("CI_PIPELINE_ID")
	}
	if p.settings.JobID == "" {
		p.settings.JobID = os.Getenv("CI_JOB_ID")
	}
	if p.settings.Environment == "" {
		p.settings.Environment = os.Getenv("CI_ENVIRONMENT_NAME")
	}

	// Initialize custom variables from CI environment
	if p.settings.CustomVariables == nil {
		p.settings.CustomVariables = make(map[string]string)
	}

	p.logger.Info("GitLab CI plugin initialized", map[string]interface{}{
		"project_id":  p.settings.ProjectID,
		"pipeline_id": p.settings.PipelineID,
		"job_id":      p.settings.JobID,
		"environment": p.settings.Environment,
	})

	return nil
}

// Execute runs the GitLab CI integration
func (p *GitLabCIPlugin) Execute(ctx context.Context, result *types.ScanResult) (*PluginResult, error) {
	start := time.Now()

	// Derive package information from first package or fallback to target
	packageName := result.Target
	packageVersion := "unknown"
	if len(result.Packages) > 0 {
		packageName = result.Packages[0].Name
		packageVersion = result.Packages[0].Version
	}

	// Calculate total threats across all packages
	totalThreats := 0
	for _, pkg := range result.Packages {
		totalThreats += len(pkg.Threats)
	}

	p.logger.Info("Executing GitLab CI plugin", map[string]interface{}{
		"package": packageName,
		"risk":    "unknown", // Risk calculation moved to individual packages
	})

	output := &GitLabCIOutput{
		JobStatus:   "success",
		ExitCode:    0,
		Variables:   make(map[string]string),
		Artifacts:   []string{},
		Annotations: []GitLabCIAnnotation{},
		Metrics:     make(map[string]interface{}),
		Reports: GitLabCIReports{
			SecurityReport: make(map[string]interface{}),
			CodeQuality:    []interface{}{},
		},
	}

	// Set GitLab CI variables
	p.setGitLabVariables(output, result)

	// Create annotations for findings
	p.createAnnotations(output, result)

	// Generate security report
	p.generateSecurityReport(output, result)

	// Handle severity-based actions
	actions := p.handleSeverityActions(result)

	// Determine job status and exit code
	if p.shouldFailJob(result) {
		output.JobStatus = "failed"
		output.ExitCode = 1
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
	}

	// Convert output to JSON
	outputData, err := json.Marshal(output)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal GitLab CI output: %w", err)
	}

	return &PluginResult{
		Success: output.JobStatus == "success",
		Message: p.generateSummaryMessage(result),
		Data:    map[string]interface{}{"gitlab_ci_output": string(outputData)},
		Actions: actions,
		Metadata: map[string]interface{}{
			"platform":    "gitlab-ci",
			"project_id":  p.settings.ProjectID,
			"pipeline_id": p.settings.PipelineID,
			"job_id":      p.settings.JobID,
			"exit_code":   output.ExitCode,
		},
	}, nil
}

// setGitLabVariables sets GitLab CI variables
func (p *GitLabCIPlugin) setGitLabVariables(output *GitLabCIOutput, result *types.ScanResult) {
	// Derive package information from first package or fallback to target
	packageName := result.Target
	packageVersion := "unknown"
	if len(result.Packages) > 0 {
		packageName = result.Packages[0].Name
		packageVersion = result.Packages[0].Version
	}

	// Calculate total threats across all packages
	totalThreats := 0
	for _, pkg := range result.Packages {
		totalThreats += len(pkg.Threats)
	}

	output.Variables["TYPOSENTINEL_RISK_SCORE"] = "0.0"       // Risk calculation moved to individual packages
	output.Variables["TYPOSENTINEL_OVERALL_RISK"] = "unknown" // Risk calculation moved to individual packages
	output.Variables["TYPOSENTINEL_THREATS_COUNT"] = fmt.Sprintf("%d", totalThreats)
	output.Variables["TYPOSENTINEL_PACKAGE_NAME"] = packageName
	output.Variables["TYPOSENTINEL_PACKAGE_VERSION"] = packageVersion
	output.Variables["TYPOSENTINEL_SCAN_STATUS"] = "completed"

	// Add custom variables
	for key, value := range p.settings.CustomVariables {
		output.Variables[key] = value
	}

	// Set threat-specific variables
	threatIndex := 0
	for _, pkg := range result.Packages {
		for _, threat := range pkg.Threats {
			threatIndex++
			prefix := fmt.Sprintf("TYPOSENTINEL_THREAT_%d", threatIndex)
			output.Variables[prefix+"_TYPE"] = string(threat.Type)
			output.Variables[prefix+"_SEVERITY"] = threat.Severity.String()
			output.Variables[prefix+"_DESCRIPTION"] = threat.Description
		}
	}
}

// createAnnotations creates GitLab CI annotations for findings
func (p *GitLabCIPlugin) createAnnotations(output *GitLabCIOutput, result *types.ScanResult) {
	for _, pkg := range result.Packages {
		for _, threat := range pkg.Threats {
			level := "info"
			switch threat.Severity {
			case types.SeverityCritical:
				level = "error"
			case types.SeverityHigh:
				level = "error"
			case types.SeverityMedium:
				level = "warning"
			case types.SeverityLow:
				level = "info"
			}

			annotation := GitLabCIAnnotation{
				Level:   level,
				Message: fmt.Sprintf("%s: %s", string(threat.Type), threat.Description),
			}

			output.Annotations = append(output.Annotations, annotation)
		}
	}
}

// generateSecurityReport generates GitLab security report format
func (p *GitLabCIPlugin) generateSecurityReport(output *GitLabCIOutput, result *types.ScanResult) {
	vulnerabilities := []map[string]interface{}{}

	for _, pkg := range result.Packages {
		for _, threat := range pkg.Threats {
			vuln := map[string]interface{}{
				"id":          fmt.Sprintf("typosentinel-%s-%d", string(threat.Type), len(vulnerabilities)),
				"category":    "dependency_scanning",
				"name":        string(threat.Type),
				"message":     threat.Description,
				"description": threat.Description,
				"severity":    strings.ToUpper(threat.Severity.String()),
				"confidence":  "High",
				"location": map[string]interface{}{
					"file": "package.json", // or requirements.txt, etc.
					"dependency": map[string]interface{}{
						"package": map[string]interface{}{
							"name": pkg.Name,
						},
						"version": pkg.Version,
					},
				},
				"identifiers": []map[string]interface{}{
					{
						"type":  "typosentinel",
						"name":  string(threat.Type),
						"value": string(threat.Type),
					},
				},
			}

			vulnerabilities = append(vulnerabilities, vuln)
		}
	}

	output.Reports.SecurityReport = map[string]interface{}{
		"version":         "15.0.0",
		"vulnerabilities": vulnerabilities,
		"dependency_files": []map[string]interface{}{
			{
				"path":            "package.json",
				"package_manager": "npm",
			},
		},
	}
}

// handleSeverityActions handles actions based on threat severity
func (p *GitLabCIPlugin) handleSeverityActions(result *types.ScanResult) []PluginAction {
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

	// Derive package name from first package or fallback to target
	packageName := result.Target
	if len(result.Packages) > 0 {
		packageName = result.Packages[0].Name
	}

	if hasCritical && p.settings.CreateIssue {
		actions = append(actions, PluginAction{
			Type: "create_issue",
			Data: map[string]interface{}{
				"title":       fmt.Sprintf("Critical security threat detected in %s", packageName),
				"description": p.generateIssueDescription(result),
				"labels":      []string{"security", "critical", "typosentinel"},
			},
		})
	}

	if (hasCritical || hasHigh) && p.settings.NotifyMR {
		actions = append(actions, PluginAction{
			Type: "comment_mr",
			Data: map[string]interface{}{
				"message": p.generateMRComment(result),
			},
		})
	}

	return actions
}

// shouldFailJob determines if the job should fail based on settings
func (p *GitLabCIPlugin) shouldFailJob(result *types.ScanResult) bool {
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

// generateSummaryMessage generates a summary message for the scan
func (p *GitLabCIPlugin) generateSummaryMessage(result *types.ScanResult) string {
	// Derive package information from first package or fallback to target
	packageName := result.Target
	packageVersion := "unknown"
	if len(result.Packages) > 0 {
		packageName = result.Packages[0].Name
		packageVersion = result.Packages[0].Version
	}

	// Calculate total threats across all packages
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

// generateIssueDescription generates description for GitLab issue
func (p *GitLabCIPlugin) generateIssueDescription(result *types.ScanResult) string {
	// Derive package information from first package or fallback to target
	packageName := result.Target
	packageVersion := "unknown"
	if len(result.Packages) > 0 {
		packageName = result.Packages[0].Name
		packageVersion = result.Packages[0].Version
	}

	description := fmt.Sprintf("## Security Threat Detection Report\n\n")
	description += fmt.Sprintf("**Package:** %s@%s\n", packageName, packageVersion)
	// Risk information moved to individual packages
	description += "**Risk Score:** Not available at scan level\n"
	description += "**Overall Risk:** Not available at scan level\n\n"

	description += "### Detected Threats\n\n"
	threatIndex := 0
	for _, pkg := range result.Packages {
		for _, threat := range pkg.Threats {
			threatIndex++
			description += fmt.Sprintf("%d. **%s** (%s)\n", threatIndex, string(threat.Type), threat.Severity.String())
			description += fmt.Sprintf("   - %s\n\n", threat.Description)
		}
	}

	description += "### Recommendations\n\n"
	// Recommendations not available in new structure
	description += "- Recommendations not available at scan level\n"

	return description
}

// generateMRComment generates comment for merge request
func (p *GitLabCIPlugin) generateMRComment(result *types.ScanResult) string {
	// Derive package information from first package or fallback to target
	packageName := result.Target
	packageVersion := "unknown"
	if len(result.Packages) > 0 {
		packageName = result.Packages[0].Name
		packageVersion = result.Packages[0].Version
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

	comment += "\n**Please review and address these security concerns before merging.**"
	return comment
}

// Validate checks if the plugin configuration is valid
func (p *GitLabCIPlugin) Validate(ctx context.Context) error {
	if p.settings.ProjectID == "" {
		return fmt.Errorf("project_id is required for GitLab CI integration")
	}
	if p.settings.Token == "" {
		return fmt.Errorf("token is required for GitLab CI integration")
	}
	return nil
}

// GetStatus returns the current plugin status
func (p *GitLabCIPlugin) GetStatus() PluginStatus {
	return p.status
}

// Cleanup performs any necessary cleanup
func (p *GitLabCIPlugin) Cleanup(ctx context.Context) error {
	p.logger.Info("GitLab CI plugin cleanup completed")
	return nil
}
