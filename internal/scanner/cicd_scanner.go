package scanner

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/Alivanroy/Typosentinel/pkg/types"
	"github.com/sirupsen/logrus"
	"gopkg.in/yaml.v3"
)

// CICDScanner scans CI/CD configuration files for vulnerabilities
type CICDScanner struct {
	projectPath string
}

// NewCICDScanner creates a new CI/CD scanner
func NewCICDScanner(projectPath string) *CICDScanner {
	return &CICDScanner{
		projectPath: projectPath,
	}
}

// ScanProject scans project for CI/CD vulnerabilities
func (cs *CICDScanner) ScanProject() ([]types.Threat, error) {
	var threats []types.Threat

	// Scan GitHub Actions workflows
	ghThreats, err := cs.scanGitHubActions()
	if err != nil {
		logrus.Debugf("[CICDScanner] Error scanning GitHub Actions: %v", err)
	}
	threats = append(threats, ghThreats...)

	// Scan GitLab CI pipelines
	glThreats, err := cs.scanGitLabCI()
	if err != nil {
		logrus.Debugf("[CICDScanner] Error scanning GitLab CI: %v", err)
	}
	threats = append(threats, glThreats...)

	logrus.Infof("[CICDScanner] Found %d CI/CD vulnerabilities", len(threats))
	return threats, nil
}

// scanGitHubActions scans .github/workflows for vulnerabilities
func (cs *CICDScanner) scanGitHubActions() ([]types.Threat, error) {
	var threats []types.Threat

	workflowDir := filepath.Join(cs.projectPath, ".github", "workflows")
	if _, err := os.Stat(workflowDir); os.IsNotExist(err) {
		return threats, nil
	}

	files, err := os.ReadDir(workflowDir)
	if err != nil {
		return threats, err
	}

	for _, file := range files {
		if file.IsDir() {
			continue
		}

		// Only scan YAML files
		ext := strings.ToLower(filepath.Ext(file.Name()))
		if ext != ".yml" && ext != ".yaml" {
			continue
		}

		filePath := filepath.Join(workflowDir, file.Name())
		fileThreats, err := cs.scanGitHubWorkflow(filePath, file.Name())
		if err != nil {
			logrus.Warnf("[CICDScanner] Error scanning %s: %v", file.Name(), err)
			continue
		}

		threats = append(threats, fileThreats...)
	}

	return threats, nil
}

// scanGitHubWorkflow scans a single GitHub Actions workflow file
func (cs *CICDScanner) scanGitHubWorkflow(filePath, fileName string) ([]types.Threat, error) {
	var threats []types.Threat

	content, err := os.ReadFile(filePath)
	if err != nil {
		return threats, err
	}

	contentStr := string(content)

	// Parse YAML
	var workflow map[string]interface{}
	if err := yaml.Unmarshal(content, &workflow); err != nil {
		logrus.Debugf("[CICDScanner] Failed to parse %s as YAML: %v", fileName, err)
		return threats, nil
	}

	// 1. Detect self-hosted runners (Shai-Hulud red flag)
	if cs.hasSelfHostedRunner(workflow) {
		threats = append(threats, cs.createSelfHostedRunnerThreat(fileName, filePath))
	}

	// 2. Detect injection vulnerabilities
	if injections := cs.detectInjectionVulnerabilities(contentStr); len(injections) > 0 {
		threats = append(threats, cs.createInjectionThreat(fileName, filePath, injections))
	}

	// 3. Detect C2 channel patterns (Discussion/Issue triggers)
	if cs.hasC2ChannelTrigger(workflow) {
		threats = append(threats, cs.createC2ChannelThreat(fileName, filePath))
	}

	return threats, nil
}

// hasSelfHostedRunner checks if workflow uses self-hosted runners
func (cs *CICDScanner) hasSelfHostedRunner(workflow map[string]interface{}) bool {
	jobs, ok := workflow["jobs"].(map[string]interface{})
	if !ok {
		return false
	}

	for _, job := range jobs {
		jobMap, ok := job.(map[string]interface{})
		if !ok {
			continue
		}

		runsOn, ok := jobMap["runs-on"]
		if !ok {
			continue
		}

		// Check if runs-on is "self-hosted" (string or array)
		switch v := runsOn.(type) {
		case string:
			if v == "self-hosted" || strings.Contains(v, "self-hosted") {
				return true
			}
		case []interface{}:
			for _, runner := range v {
				if runnerStr, ok := runner.(string); ok {
					if runnerStr == "self-hosted" || strings.Contains(runnerStr, "self-hosted") {
						return true
					}
				}
			}
		}
	}

	return false
}

// detectInjectionVulnerabilities detects code injection patterns
func (cs *CICDScanner) detectInjectionVulnerabilities(content string) []string {
	var injections []string

	// Dangerous injection patterns (Shai-Hulud used github.event.discussion.body)
	patterns := []struct {
		name    string
		pattern *regexp.Regexp
	}{
		{
			name:    "github.event.discussion.body",
			pattern: regexp.MustCompile(`\$\{\{\s*github\.event\.discussion\.body\s*\}\}`),
		},
		{
			name:    "github.event.issue.title",
			pattern: regexp.MustCompile(`\$\{\{\s*github\.event\.issue\.title\s*\}\}`),
		},
		{
			name:    "github.event.issue.body",
			pattern: regexp.MustCompile(`\$\{\{\s*github\.event\.issue\.body\s*\}\}`),
		},
		{
			name:    "github.event.comment.body",
			pattern: regexp.MustCompile(`\$\{\{\s*github\.event\.comment\.body\s*\}\}`),
		},
		{
			name:    "github.event.pull_request.title",
			pattern: regexp.MustCompile(`\$\{\{\s*github\.event\.pull_request\.title\s*\}\}`),
		},
		{
			name:    "github.event.pull_request.body",
			pattern: regexp.MustCompile(`\$\{\{\s*github\.event\.pull_request\.body\s*\}\}`),
		},
	}

	for _, p := range patterns {
		if p.pattern.MatchString(content) {
			injections = append(injections, p.name)
		}
	}

	return injections
}

// hasC2ChannelTrigger detects workflows triggered by Discussions/Issues (C2 red flag)
func (cs *CICDScanner) hasC2ChannelTrigger(workflow map[string]interface{}) bool {
	on, ok := workflow["on"]
	if !ok {
		return false
	}

	// "on" can be string, array, or map
	switch v := on.(type) {
	case string:
		return v == "discussion" || v == "issues" || v == "issue_comment"
	case []interface{}:
		for _, trigger := range v {
			if triggerStr, ok := trigger.(string); ok {
				if triggerStr == "discussion" || triggerStr == "issues" || triggerStr == "issue_comment" {
					return true
				}
			}
		}
	case map[string]interface{}:
		if _, hasDiscussion := v["discussion"]; hasDiscussion {
			return true
		}
		if _, hasIssues := v["issues"]; hasIssues {
			return true
		}
		if _, hasIssueComment := v["issue_comment"]; hasIssueComment {
			return true
		}
	}

	return false
}

// scanGitLabCI scans .gitlab-ci.yml for vulnerabilities
func (cs *CICDScanner) scanGitLabCI() ([]types.Threat, error) {
	var threats []types.Threat

	ciFilePath := filepath.Join(cs.projectPath, ".gitlab-ci.yml")
	if _, err := os.Stat(ciFilePath); os.IsNotExist(err) {
		return threats, nil
	}

	content, err := os.ReadFile(ciFilePath)
	if err != nil {
		return threats, err
	}

	contentStr := string(content)

	// Parse YAML
	var pipeline map[string]interface{}
	if err := yaml.Unmarshal(content, &pipeline); err != nil {
		logrus.Debugf("[CICDScanner] Failed to parse .gitlab-ci.yml: %v", err)
		return threats, nil
	}

	// 1. Detect custom Docker images from unknown registries
	if unknownImages := cs.detectUnknownDockerImages(pipeline); len(unknownImages) > 0 {
		threats = append(threats, cs.createUnknownImageThreat(unknownImages))
	}

	// 2. Detect secrets in variables
	if cs.hasSecretsInVariables(contentStr) {
		threats = append(threats, cs.createSecretsInVariablesThreat())
	}

	return threats, nil
}

// detectUnknownDockerImages detects custom Docker images from non-standard registries
func (cs *CICDScanner) detectUnknownDockerImages(pipeline map[string]interface{}) []string {
	var unknownImages []string
	knownRegistries := []string{"docker.io", "gcr.io", "ghcr.io", "registry.gitlab.com"}

	// Check global image
	if image, ok := pipeline["image"].(string); ok {
		if !cs.isKnownRegistry(image, knownRegistries) {
			unknownImages = append(unknownImages, image)
		}
	}

	// Check job-level images
	for key, value := range pipeline {
		if strings.HasPrefix(key, ".") || key == "stages" || key == "variables" {
			continue
		}

		if jobMap, ok := value.(map[string]interface{}); ok {
			if image, ok := jobMap["image"].(string); ok {
				if !cs.isKnownRegistry(image, knownRegistries) {
					unknownImages = append(unknownImages, image)
				}
			}
		}
	}

	return unknownImages
}

// isKnownRegistry checks if Docker image is from a known/trusted registry
func (cs *CICDScanner) isKnownRegistry(image string, knownRegistries []string) bool {
	// If no registry prefix, assume docker.io
	if !strings.Contains(image, "/") {
		return true
	}

	for _, registry := range knownRegistries {
		if strings.HasPrefix(image, registry) {
			return true
		}
	}

	return false
}

// hasSecretsInVariables detects hardcoded secrets in GitLab CI variables
func (cs *CICDScanner) hasSecretsInVariables(content string) bool {
	// Simple heuristic: look for common secret patterns in variables section
	secretPatterns := []string{
		"password:", "PASSWORD:",
		"secret:", "SECRET:",
		"token:", "TOKEN:",
		"api_key:", "API_KEY:",
	}

	for _, pattern := range secretPatterns {
		if strings.Contains(content, pattern) {
			return true
		}
	}

	return false
}

// Threat creation helpers

func (cs *CICDScanner) createSelfHostedRunnerThreat(fileName, filePath string) types.Threat {
	return types.Threat{
		Type:            types.ThreatTypeSelfHostedRunner,
		Severity:        types.SeverityHigh,
		Confidence:      0.9,
		Description:     fmt.Sprintf("Workflow '%s' uses self-hosted runners (Shai-Hulud attack vector)", fileName),
		DetectionMethod: "cicd_analysis",
		Recommendation:  "Self-hosted runners can be compromised to register backdoors. Review runner configuration and ensure it's legitimate. Consider using GitHub-hosted runners unless self-hosting is required.",
		Evidence: []types.Evidence{
			{
				Type:        "workflow_file",
				Description: "GitHub Actions workflow",
				Value:       fileName,
			},
			{
				Type:        "runner_type",
				Description: "Runner configuration",
				Value:       "self-hosted",
			},
		},
		Metadata: map[string]interface{}{
			"file_path": filePath,
			"file_name": fileName,
		},
		DetectedAt: time.Now(),
	}
}

func (cs *CICDScanner) createInjectionThreat(fileName, filePath string, injections []string) types.Threat {
	return types.Threat{
		Type:            types.ThreatTypeCICDInjection,
		Severity:        types.SeverityCritical,
		Confidence:      0.95,
		Description:     fmt.Sprintf("Workflow '%s' contains code injection vulnerabilities: %s", fileName, strings.Join(injections, ", ")),
		DetectionMethod: "cicd_analysis",
		Recommendation:  "CRITICAL: Code injection detected. Attackers can execute arbitrary commands via GitHub Discussions/Issues. Use ${{ toJSON(github.event) }} piped to a safe parser instead of using event fields directly in 'run' steps.",
		Evidence: []types.Evidence{
			{
				Type:        "workflow_file",
				Description: "GitHub Actions workflow",
				Value:       fileName,
			},
			{
				Type:        "injection_patterns",
				Description: "Vulnerable expressions",
				Value:       strings.Join(injections, "; "),
			},
		},
		Metadata: map[string]interface{}{
			"file_path":  filePath,
			"file_name":  fileName,
			"injections": injections,
		},
		DetectedAt: time.Now(),
	}
}

func (cs *CICDScanner) createC2ChannelThreat(fileName, filePath string) types.Threat {
	return types.Threat{
		Type:            types.ThreatTypeC2Channel,
		Severity:        types.SeverityHigh,
		Confidence:      0.8,
		Description:     fmt.Sprintf("Workflow '%s' is triggered by Discussions/Issues (potential C2 channel like Shai-Hulud)", fileName),
		DetectionMethod: "cicd_analysis",
		Recommendation:  "Workflows triggered by 'discussion' or 'issues' events can be used as command-and-control channels. Review workflow purpose and ensure it's legitimate.",
		Evidence: []types.Evidence{
			{
				Type:        "workflow_file",
				Description: "GitHub Actions workflow",
				Value:       fileName,
			},
			{
				Type:        "trigger_type",
				Description: "Workflow trigger",
				Value:       "discussion/issues",
			},
		},
		Metadata: map[string]interface{}{
			"file_path": filePath,
			"file_name": fileName,
		},
		DetectedAt: time.Now(),
	}
}

func (cs *CICDScanner) createUnknownImageThreat(images []string) types.Threat {
	return types.Threat{
		Type:            types.ThreatTypeSuspiciousPattern,
		Severity:        types.SeverityMedium,
		Confidence:      0.7,
		Description:     fmt.Sprintf("GitLab CI uses Docker images from unknown registries: %s", strings.Join(images, ", ")),
		DetectionMethod: "cicd_analysis",
		Recommendation:  "Verify Docker images are from trusted sources. Unknown registries may host malicious images.",
		Evidence: []types.Evidence{
			{
				Type:        "ci_file",
				Description: "GitLab CI configuration",
				Value:       ".gitlab-ci.yml",
			},
			{
				Type:        "docker_images",
				Description: "Unknown registry images",
				Value:       strings.Join(images, "; "),
			},
		},
		Metadata: map[string]interface{}{
			"images": images,
		},
		DetectedAt: time.Now(),
	}
}

func (cs *CICDScanner) createSecretsInVariablesThreat() types.Threat {
	return types.Threat{
		Type:            types.ThreatTypeEmbeddedSecret,
		Severity:        types.SeverityHigh,
		Confidence:      0.75,
		Description:     "GitLab CI configuration may contain hardcoded secrets in variables",
		DetectionMethod: "cicd_analysis",
		Recommendation:  "Use GitLab CI/CD variables with masking and protection enabled instead of hardcoding secrets in .gitlab-ci.yml.",
		Evidence: []types.Evidence{
			{
				Type:        "ci_file",
				Description: "GitLab CI configuration",
				Value:       ".gitlab-ci.yml",
			},
		},
		Metadata:   map[string]interface{}{},
		DetectedAt: time.Now(),
	}
}
