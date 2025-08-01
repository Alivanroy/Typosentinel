package plugins

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/Alivanroy/Typosentinel/pkg/types"
)

// GitHubActionsPlugin implements CI/CD integration for GitHub Actions
type GitHubActionsPlugin struct {
	config   map[string]interface{}
	logger   Logger
	status   PluginStatus
	settings GitHubActionsSettings
}

// GitHubActionsSettings contains GitHub Actions specific configuration
type GitHubActionsSettings struct {
	Token              string             `json:"token"`
	Repository         string             `json:"repository"`
	FailOnCritical     bool               `json:"fail_on_critical"`
	FailOnHigh         bool               `json:"fail_on_high"`
	CreateIssues       bool               `json:"create_issues"`
	CommentOnPR        bool               `json:"comment_on_pr"`
	BlockedPackages    []string           `json:"blocked_packages"`
	AllowedPackages    []string           `json:"allowed_packages"`
	NotificationUsers  []string           `json:"notification_users"`
	CustomLabels       []string           `json:"custom_labels"`
	SeverityThresholds map[string]float64 `json:"severity_thresholds"`
}

// GitHubActionsOutput represents the output format for GitHub Actions
type GitHubActionsOutput struct {
	Summary         string                 `json:"summary"`
	CriticalCount   int                    `json:"critical_count"`
	HighCount       int                    `json:"high_count"`
	MediumCount     int                    `json:"medium_count"`
	LowCount        int                    `json:"low_count"`
	TotalPackages   int                    `json:"total_packages"`
	BlockedPackages []string               `json:"blocked_packages"`
	Recommendations []string               `json:"recommendations"`
	Details         map[string]interface{} `json:"details"`
	ExitCode        int                    `json:"exit_code"`
}

// NewGitHubActionsPlugin creates a new GitHub Actions plugin
func NewGitHubActionsPlugin(config map[string]interface{}, logger Logger) *GitHubActionsPlugin {
	return &GitHubActionsPlugin{
		config: config,
		logger: logger,
		status: PluginStatus{
			State:       "inactive",
			HealthCheck: false,
		},
	}
}

// GetInfo returns plugin metadata
func (ga *GitHubActionsPlugin) GetInfo() PluginInfo {
	return PluginInfo{
		Name:        "GitHub Actions Integration",
		Version:     "1.0.0",
		Description: "Integrates Typosentinel with GitHub Actions workflows",
		Author:      "Typosentinel Team",
		Platform:    "github-actions",
		Capabilities: []string{
			"workflow_integration",
			"pr_comments",
			"issue_creation",
			"status_checks",
			"artifact_upload",
			"security_alerts",
		},
		Requirements: map[string]string{
			"GITHUB_TOKEN":      "GitHub token with appropriate permissions",
			"GITHUB_REPOSITORY": "Repository in format owner/repo",
		},
		ConfigSchema: map[string]interface{}{
			"token":               "string",
			"repository":          "string",
			"fail_on_critical":    "boolean",
			"fail_on_high":        "boolean",
			"create_issues":       "boolean",
			"comment_on_pr":       "boolean",
			"blocked_packages":    "array",
			"allowed_packages":    "array",
			"notification_users":  "array",
			"custom_labels":       "array",
			"severity_thresholds": "object",
		},
	}
}

// Initialize sets up the plugin
func (ga *GitHubActionsPlugin) Initialize(ctx context.Context, config map[string]interface{}) error {
	ga.logger.Debug("Initializing GitHub Actions plugin", map[string]interface{}{})

	// Parse configuration
	if err := ga.parseConfig(config); err != nil {
		return fmt.Errorf("failed to parse configuration: %w", err)
	}

	// Load environment variables
	ga.loadEnvironmentVariables()

	// Validate required settings
	if err := ga.validateSettings(); err != nil {
		return fmt.Errorf("configuration validation failed: %w", err)
	}

	ga.status.State = "active"
	ga.status.HealthCheck = true
	ga.logger.Info("GitHub Actions plugin initialized successfully", map[string]interface{}{})
	return nil
}

// Execute runs the plugin with scan results
func (ga *GitHubActionsPlugin) Execute(ctx context.Context, results *types.ScanResult) (*PluginResult, error) {
	start := time.Now()
	ga.logger.Debug("Executing GitHub Actions plugin", map[string]interface{}{})

	ga.status.RunCount++
	ga.status.LastRun = start

	pluginResult := &PluginResult{
		Success: true,
		Actions: []PluginAction{},
		Metrics: make(map[string]interface{}),
	}

	// Generate GitHub Actions output
	output := ga.generateOutput(results)

	// Set GitHub Actions outputs
	if err := ga.setGitHubOutputs(output); err != nil {
		ga.logger.Warn("Failed to set GitHub outputs", map[string]interface{}{"error": err})
	}

	// Create step summary
	if err := ga.createStepSummary(results, output); err != nil {
		ga.logger.Warn("Failed to create step summary", map[string]interface{}{"error": err})
	}

	// Handle critical/high severity findings
	actions := ga.handleSeverityActions(results, output)
	pluginResult.Actions = append(pluginResult.Actions, actions...)

	// Create issues if configured
	if ga.settings.CreateIssues {
		issueActions := ga.createSecurityIssues(ctx, results)
		pluginResult.Actions = append(pluginResult.Actions, issueActions...)
	}

	// Comment on PR if configured
	if ga.settings.CommentOnPR {
		prActions := ga.commentOnPullRequest(ctx, results, output)
		pluginResult.Actions = append(pluginResult.Actions, prActions...)
	}

	// Set exit code based on findings
	exitCode := ga.determineExitCode(output)
	if exitCode != 0 {
		ga.setWorkflowExitCode(exitCode)
	}

	// Add metrics
	pluginResult.Metrics["critical_count"] = output.CriticalCount
	pluginResult.Metrics["high_count"] = output.HighCount
	pluginResult.Metrics["total_packages"] = output.TotalPackages
	pluginResult.Metrics["exit_code"] = exitCode
	pluginResult.Metrics["blocked_packages"] = len(output.BlockedPackages)

	pluginResult.Message = fmt.Sprintf("Processed %d packages, found %d critical and %d high severity issues",
		output.TotalPackages, output.CriticalCount, output.HighCount)

	ga.logger.Info("GitHub Actions plugin execution completed", map[string]interface{}{
		"duration":       time.Since(start),
		"critical_count": output.CriticalCount,
		"high_count":     output.HighCount,
		"exit_code":      exitCode,
	})

	return pluginResult, nil
}

// Validate checks if the plugin can run in the current environment
func (ga *GitHubActionsPlugin) Validate(ctx context.Context) error {
	// Check if running in GitHub Actions environment
	if os.Getenv("GITHUB_ACTIONS") != "true" {
		return fmt.Errorf("not running in GitHub Actions environment")
	}

	// Validate required environment variables
	requiredEnvVars := []string{"GITHUB_TOKEN", "GITHUB_REPOSITORY"}
	for _, envVar := range requiredEnvVars {
		if os.Getenv(envVar) == "" {
			return fmt.Errorf("required environment variable %s is not set", envVar)
		}
	}

	// Test GitHub API access
	if err := ga.testGitHubAPIAccess(ctx); err != nil {
		return fmt.Errorf("GitHub API access test failed: %w", err)
	}

	ga.status.HealthCheck = true
	return nil
}

// Cleanup performs plugin cleanup
func (ga *GitHubActionsPlugin) Cleanup(ctx context.Context) error {
	ga.logger.Debug("Cleaning up GitHub Actions plugin", map[string]interface{}{})
	ga.status.State = "inactive"
	return nil
}

// GetStatus returns current plugin status
func (ga *GitHubActionsPlugin) GetStatus() PluginStatus {
	return ga.status
}

// Helper methods

func (ga *GitHubActionsPlugin) parseConfig(config map[string]interface{}) error {
	// Convert config map to settings struct
	configJSON, err := json.Marshal(config)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	if err := json.Unmarshal(configJSON, &ga.settings); err != nil {
		return fmt.Errorf("failed to unmarshal config: %w", err)
	}

	// Set default values
	if ga.settings.SeverityThresholds == nil {
		ga.settings.SeverityThresholds = map[string]float64{
			"critical": 0.9,
			"high":     0.7,
			"medium":   0.5,
			"low":      0.3,
		}
	}

	return nil
}

func (ga *GitHubActionsPlugin) loadEnvironmentVariables() {
	// Load from environment if not set in config
	if ga.settings.Token == "" {
		ga.settings.Token = os.Getenv("GITHUB_TOKEN")
	}
	if ga.settings.Repository == "" {
		ga.settings.Repository = os.Getenv("GITHUB_REPOSITORY")
	}
}

func (ga *GitHubActionsPlugin) validateSettings() error {
	if ga.settings.Token == "" {
		return fmt.Errorf("GitHub token is required")
	}
	if ga.settings.Repository == "" {
		return fmt.Errorf("GitHub repository is required")
	}
	return nil
}

func (ga *GitHubActionsPlugin) generateOutput(results *types.ScanResult) *GitHubActionsOutput {
	output := &GitHubActionsOutput{
		Details:         make(map[string]interface{}),
		BlockedPackages: []string{},
		Recommendations: []string{},
	}

	// Count threats by severity from packages
	for _, pkg := range results.Packages {
		for _, threat := range pkg.Threats {
			switch threat.Severity {
			case types.SeverityCritical:
				output.CriticalCount++
			case types.SeverityHigh:
				output.HighCount++
			case types.SeverityMedium:
				output.MediumCount++
			case types.SeverityLow:
				output.LowCount++
			}

			// Check if package should be blocked
			if ga.shouldBlockPackage(pkg, threat) {
				output.BlockedPackages = append(output.BlockedPackages, pkg.Name)
			}
		}
	}

	output.TotalPackages = len(results.Packages)

	// Generate summary
	output.Summary = ga.generateSummary(output)

	// Generate recommendations
	output.Recommendations = ga.generateRecommendations(results, output)

	return output
}

func (ga *GitHubActionsPlugin) setGitHubOutputs(output *GitHubActionsOutput) error {
	// Set GitHub Actions outputs
	outputs := map[string]string{
		"summary":          output.Summary,
		"critical-count":   strconv.Itoa(output.CriticalCount),
		"high-count":       strconv.Itoa(output.HighCount),
		"medium-count":     strconv.Itoa(output.MediumCount),
		"low-count":        strconv.Itoa(output.LowCount),
		"total-packages":   strconv.Itoa(output.TotalPackages),
		"blocked-packages": strings.Join(output.BlockedPackages, ","),
		"exit-code":        strconv.Itoa(output.ExitCode),
	}

	for key, value := range outputs {
		if err := ga.setGitHubOutput(key, value); err != nil {
			return fmt.Errorf("failed to set output %s: %w", key, err)
		}
	}

	return nil
}

func (ga *GitHubActionsPlugin) setGitHubOutput(name, value string) error {
	outputFile := os.Getenv("GITHUB_OUTPUT")
	if outputFile == "" {
		// Fallback to echo format for older runners
		fmt.Printf("::set-output name=%s::%s\n", name, value)
		return nil
	}

	// Use output file format
	f, err := os.OpenFile(outputFile, os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = fmt.Fprintf(f, "%s=%s\n", name, value)
	return err
}

func (ga *GitHubActionsPlugin) createStepSummary(results *types.ScanResult, output *GitHubActionsOutput) error {
	summaryFile := os.Getenv("GITHUB_STEP_SUMMARY")
	if summaryFile == "" {
		return nil // Step summary not supported
	}

	summaryContent := ga.generateMarkdownSummary(results, output)

	f, err := os.OpenFile(summaryFile, os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = f.WriteString(summaryContent)
	return err
}

func (ga *GitHubActionsPlugin) generateMarkdownSummary(results *types.ScanResult, output *GitHubActionsOutput) string {
	var summary strings.Builder

	summary.WriteString("# 🔒 Typosentinel Security Scan Results\n\n")

	// Overview table
	summary.WriteString("## 📊 Overview\n\n")
	summary.WriteString("| Severity | Count |\n")
	summary.WriteString("|----------|-------|\n")
	summary.WriteString(fmt.Sprintf("| 🔴 Critical | %d |\n", output.CriticalCount))
	summary.WriteString(fmt.Sprintf("| 🟠 High | %d |\n", output.HighCount))
	summary.WriteString(fmt.Sprintf("| 🟡 Medium | %d |\n", output.MediumCount))
	summary.WriteString(fmt.Sprintf("| 🟢 Low | %d |\n", output.LowCount))
	summary.WriteString(fmt.Sprintf("| 📦 Total Packages | %d |\n\n", output.TotalPackages))

	// Blocked packages
	if len(output.BlockedPackages) > 0 {
		summary.WriteString("## 🚫 Blocked Packages\n\n")
		for _, pkg := range output.BlockedPackages {
			summary.WriteString(fmt.Sprintf("- `%s`\n", pkg))
		}
		summary.WriteString("\n")
	}

	// Critical findings
	if output.CriticalCount > 0 {
		summary.WriteString("## 🔴 Critical Findings\n\n")
		for _, pkg := range results.Packages {
			for _, threat := range pkg.Threats {
				if threat.Severity == types.SeverityCritical {
					summary.WriteString(fmt.Sprintf("### %s\n", pkg.Name))
					summary.WriteString(fmt.Sprintf("- **Type**: %s\n", string(threat.Type)))
					summary.WriteString(fmt.Sprintf("- **Confidence**: %.2f\n", threat.Confidence))
					summary.WriteString(fmt.Sprintf("- **Description**: %s\n\n", threat.Description))
				}
			}
		}
	}

	// Recommendations
	if len(output.Recommendations) > 0 {
		summary.WriteString("## 💡 Recommendations\n\n")
		for _, rec := range output.Recommendations {
			summary.WriteString(fmt.Sprintf("- %s\n", rec))
		}
		summary.WriteString("\n")
	}

	return summary.String()
}

func (ga *GitHubActionsPlugin) handleSeverityActions(results *types.ScanResult, output *GitHubActionsOutput) []PluginAction {
	var actions []PluginAction

	// Handle critical findings
	if output.CriticalCount > 0 && ga.settings.FailOnCritical {
		actions = append(actions, PluginAction{
			Type:        "block",
			Target:      "workflow",
			Description: fmt.Sprintf("Workflow blocked due to %d critical security findings", output.CriticalCount),
			Metadata: map[string]interface{}{
				"severity": "critical",
				"count":    output.CriticalCount,
			},
			Timestamp: time.Now(),
		})
	}

	// Handle high findings
	if output.HighCount > 0 && ga.settings.FailOnHigh {
		actions = append(actions, PluginAction{
			Type:        "warn",
			Target:      "workflow",
			Description: fmt.Sprintf("Workflow warning due to %d high severity findings", output.HighCount),
			Metadata: map[string]interface{}{
				"severity": "high",
				"count":    output.HighCount,
			},
			Timestamp: time.Now(),
		})
	}

	return actions
}

func (ga *GitHubActionsPlugin) shouldBlockPackage(pkg *types.Package, threat types.Threat) bool {
	// Check if package is in blocked list
	for _, blocked := range ga.settings.BlockedPackages {
		if pkg.Name == blocked {
			return true
		}
	}

	// Check if package is in allowed list
	for _, allowed := range ga.settings.AllowedPackages {
		if pkg.Name == allowed {
			return false
		}
	}

	// Block based on severity and confidence
	if threat.Severity == types.SeverityCritical {
		return true
	}

	if threat.Severity == types.SeverityHigh && threat.Confidence >= ga.settings.SeverityThresholds["high"] {
		return true
	}

	return false
}

func (ga *GitHubActionsPlugin) generateSummary(output *GitHubActionsOutput) string {
	if output.CriticalCount > 0 {
		return fmt.Sprintf("🔴 CRITICAL: Found %d critical and %d high severity security issues in %d packages",
			output.CriticalCount, output.HighCount, output.TotalPackages)
	}

	if output.HighCount > 0 {
		return fmt.Sprintf("🟠 HIGH: Found %d high severity security issues in %d packages",
			output.HighCount, output.TotalPackages)
	}

	if output.MediumCount > 0 {
		return fmt.Sprintf("🟡 MEDIUM: Found %d medium severity issues in %d packages",
			output.MediumCount, output.TotalPackages)
	}

	return fmt.Sprintf("✅ CLEAN: No significant security issues found in %d packages", output.TotalPackages)
}

func (ga *GitHubActionsPlugin) generateRecommendations(results *types.ScanResult, output *GitHubActionsOutput) []string {
	var recommendations []string

	if output.CriticalCount > 0 {
		recommendations = append(recommendations, "Immediately review and remove critical security threats")
		recommendations = append(recommendations, "Do not deploy to production until critical issues are resolved")
	}

	if len(output.BlockedPackages) > 0 {
		recommendations = append(recommendations, "Remove or replace blocked packages before proceeding")
	}

	if output.HighCount > 0 {
		recommendations = append(recommendations, "Review high severity findings and consider alternatives")
	}

	recommendations = append(recommendations, "Regularly update dependencies to latest secure versions")
	recommendations = append(recommendations, "Consider using package-lock files to prevent dependency confusion")

	return recommendations
}

func (ga *GitHubActionsPlugin) determineExitCode(output *GitHubActionsOutput) int {
	if output.CriticalCount > 0 && ga.settings.FailOnCritical {
		return 2 // Critical failure
	}

	if output.HighCount > 0 && ga.settings.FailOnHigh {
		return 1 // High severity warning
	}

	return 0 // Success
}

func (ga *GitHubActionsPlugin) setWorkflowExitCode(exitCode int) {
	// Set exit code for the workflow
	os.Exit(exitCode)
}

func (ga *GitHubActionsPlugin) testGitHubAPIAccess(ctx context.Context) error {
	token := os.Getenv("GITHUB_TOKEN")
	if token == "" {
		return fmt.Errorf("GITHUB_TOKEN environment variable not set")
	}

	client := &http.Client{Timeout: 30 * time.Second}
	req, err := http.NewRequestWithContext(ctx, "GET", "https://api.github.com/user", nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "token "+token)
	req.Header.Set("Accept", "application/vnd.github.v3+json")
	req.Header.Set("User-Agent", "TypoSentinel/1.0")

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to test GitHub API access: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GitHub API access test failed with status %d", resp.StatusCode)
	}

	ga.logger.Info("GitHub API access test successful")
	return nil
}

func (ga *GitHubActionsPlugin) createSecurityIssues(ctx context.Context, results *types.ScanResult) []PluginAction {
	var actions []PluginAction

	token := os.Getenv("GITHUB_TOKEN")
	repo := os.Getenv("GITHUB_REPOSITORY")
	if token == "" || repo == "" {
		ga.logger.Warn("GitHub token or repository not configured for issue creation")
		return actions
	}

	client := &http.Client{Timeout: 30 * time.Second}

	// Create issues for critical and high severity findings
	for _, pkg := range results.Packages {
		for _, threat := range pkg.Threats {
			if threat.Severity == types.SeverityCritical || threat.Severity == types.SeverityHigh {
				if err := ga.createSecurityIssue(ctx, client, token, repo, pkg, threat); err != nil {
					ga.logger.Warn("Failed to create security issue", map[string]interface{}{
						"package": pkg.Name,
						"error":   err,
					})
					continue
				}

				actions = append(actions, PluginAction{
					Type:        "issue_created",
					Target:      "github",
					Description: fmt.Sprintf("Created security issue for %s", pkg.Name),
					Metadata: map[string]interface{}{
						"package":  pkg.Name,
						"severity": string(threat.Severity),
						"type":     string(threat.Type),
					},
					Timestamp: time.Now(),
				})
			}
		}
	}

	return actions
}

func (ga *GitHubActionsPlugin) createSecurityIssue(ctx context.Context, client *http.Client, token, repo string, pkg *types.Package, threat types.Threat) error {
	title := fmt.Sprintf("[SECURITY] %s vulnerability in %s", strings.ToUpper(string(threat.Severity)), pkg.Name)
	body := ga.formatSecurityIssueBody(pkg, threat)

	issue := map[string]interface{}{
		"title": title,
		"body":  body,
		"labels": []string{"security", "vulnerability", string(threat.Severity)},
	}

	payloadBytes, err := json.Marshal(issue)
	if err != nil {
		return fmt.Errorf("failed to marshal issue: %w", err)
	}

	url := fmt.Sprintf("https://api.github.com/repos/%s/issues", repo)
	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(payloadBytes))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "token "+token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/vnd.github.v3+json")
	req.Header.Set("User-Agent", "TypoSentinel/1.0")

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to create issue: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("GitHub API returned status %d", resp.StatusCode)
	}

	return nil
}

func (ga *GitHubActionsPlugin) formatSecurityIssueBody(pkg *types.Package, threat types.Threat) string {
	var body strings.Builder

	body.WriteString("## 🔒 Security Vulnerability Detected\n\n")
	body.WriteString(fmt.Sprintf("**Package:** `%s`\n", pkg.Name))
	body.WriteString(fmt.Sprintf("**Version:** `%s`\n", pkg.Version))
	body.WriteString(fmt.Sprintf("**Registry:** `%s`\n", pkg.Registry))
	body.WriteString(fmt.Sprintf("**Severity:** %s\n", strings.ToUpper(string(threat.Severity))))
	body.WriteString(fmt.Sprintf("**Threat Type:** %s\n", string(threat.Type)))
	body.WriteString(fmt.Sprintf("**Confidence:** %.2f\n\n", threat.Confidence))

	body.WriteString("## Description\n\n")
	body.WriteString(threat.Description)
	body.WriteString("\n\n")

	if len(threat.References) > 0 {
		body.WriteString("## References\n\n")
		for _, ref := range threat.References {
			body.WriteString(fmt.Sprintf("- %s\n", ref))
		}
		body.WriteString("\n")
	}

	body.WriteString("## Recommendations\n\n")
	body.WriteString("- Review and update the package to a secure version\n")
	body.WriteString("- Consider alternative packages if no secure version is available\n")
	body.WriteString("- Implement additional security measures if the package is critical\n\n")

	body.WriteString("---\n")
	body.WriteString("*This issue was automatically created by TypoSentinel*")

	return body.String()
}

func (ga *GitHubActionsPlugin) commentOnPullRequest(ctx context.Context, results *types.ScanResult, output *GitHubActionsOutput) []PluginAction {
	var actions []PluginAction

	token := os.Getenv("GITHUB_TOKEN")
	repo := os.Getenv("GITHUB_REPOSITORY")
	prNumber := os.Getenv("GITHUB_PR_NUMBER")

	if token == "" || repo == "" || prNumber == "" {
		ga.logger.Debug("GitHub PR commenting not configured or not in PR context")
		return actions
	}

	client := &http.Client{Timeout: 30 * time.Second}
	commentBody := ga.formatPRComment(results, output)

	comment := map[string]interface{}{
		"body": commentBody,
	}

	payloadBytes, err := json.Marshal(comment)
	if err != nil {
		ga.logger.Warn("Failed to marshal PR comment", map[string]interface{}{"error": err})
		return actions
	}

	url := fmt.Sprintf("https://api.github.com/repos/%s/issues/%s/comments", repo, prNumber)
	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(payloadBytes))
	if err != nil {
		ga.logger.Warn("Failed to create PR comment request", map[string]interface{}{"error": err})
		return actions
	}

	req.Header.Set("Authorization", "token "+token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/vnd.github.v3+json")
	req.Header.Set("User-Agent", "TypoSentinel/1.0")

	resp, err := client.Do(req)
	if err != nil {
		ga.logger.Warn("Failed to post PR comment", map[string]interface{}{"error": err})
		return actions
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		ga.logger.Warn("GitHub API returned error for PR comment", map[string]interface{}{
			"status": resp.StatusCode,
		})
		return actions
	}

	actions = append(actions, PluginAction{
		Type:        "pr_comment",
		Target:      "github",
		Description: "Posted security scan results to pull request",
		Metadata: map[string]interface{}{
			"pr_number":      prNumber,
			"critical_count": output.CriticalCount,
			"high_count":     output.HighCount,
			"total_packages": output.TotalPackages,
		},
		Timestamp: time.Now(),
	})

	return actions
}

func (ga *GitHubActionsPlugin) formatPRComment(results *types.ScanResult, output *GitHubActionsOutput) string {
	var comment strings.Builder

	comment.WriteString("## 🔒 TypoSentinel Security Scan Results\n\n")

	// Status badge
	if output.CriticalCount > 0 {
		comment.WriteString("![Status](https://img.shields.io/badge/Security-CRITICAL-red)\n\n")
	} else if output.HighCount > 0 {
		comment.WriteString("![Status](https://img.shields.io/badge/Security-HIGH-orange)\n\n")
	} else if output.MediumCount > 0 {
		comment.WriteString("![Status](https://img.shields.io/badge/Security-MEDIUM-yellow)\n\n")
	} else {
		comment.WriteString("![Status](https://img.shields.io/badge/Security-CLEAN-green)\n\n")
	}

	// Summary table
	comment.WriteString("### 📊 Summary\n\n")
	comment.WriteString("| Severity | Count |\n")
	comment.WriteString("|----------|-------|\n")
	comment.WriteString(fmt.Sprintf("| 🔴 Critical | %d |\n", output.CriticalCount))
	comment.WriteString(fmt.Sprintf("| 🟠 High | %d |\n", output.HighCount))
	comment.WriteString(fmt.Sprintf("| 🟡 Medium | %d |\n", output.MediumCount))
	comment.WriteString(fmt.Sprintf("| 🟢 Low | %d |\n", output.LowCount))
	comment.WriteString(fmt.Sprintf("| 📦 Total Packages | %d |\n\n", output.TotalPackages))

	// Critical findings details
	if output.CriticalCount > 0 {
		comment.WriteString("### 🔴 Critical Findings\n\n")
		for _, pkg := range results.Packages {
			for _, threat := range pkg.Threats {
				if threat.Severity == types.SeverityCritical {
					comment.WriteString(fmt.Sprintf("- **%s**: %s (Confidence: %.2f)\n", pkg.Name, threat.Description, threat.Confidence))
				}
			}
		}
		comment.WriteString("\n")
	}

	// High findings details
	if output.HighCount > 0 {
		comment.WriteString("### 🟠 High Severity Findings\n\n")
		for _, pkg := range results.Packages {
			for _, threat := range pkg.Threats {
				if threat.Severity == types.SeverityHigh {
					comment.WriteString(fmt.Sprintf("- **%s**: %s (Confidence: %.2f)\n", pkg.Name, threat.Description, threat.Confidence))
				}
			}
		}
		comment.WriteString("\n")
	}

	// Blocked packages
	if len(output.BlockedPackages) > 0 {
		comment.WriteString("### 🚫 Blocked Packages\n\n")
		for _, pkg := range output.BlockedPackages {
			comment.WriteString(fmt.Sprintf("- `%s`\n", pkg))
		}
		comment.WriteString("\n")
	}

	// Recommendations
	if len(output.Recommendations) > 0 {
		comment.WriteString("### 💡 Recommendations\n\n")
		for _, rec := range output.Recommendations {
			comment.WriteString(fmt.Sprintf("- %s\n", rec))
		}
		comment.WriteString("\n")
	}

	comment.WriteString("---\n")
	comment.WriteString("*Scan completed by [TypoSentinel](https://github.com/Alivanroy/Typosentinel)*")

	return comment.String()
}
