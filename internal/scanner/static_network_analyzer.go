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
)

// StaticNetworkAnalyzer analyzes code for network patterns without runtime execution
type StaticNetworkAnalyzer struct {
	projectPath string
}

// NewStaticNetworkAnalyzer creates a new static network analyzer
func NewStaticNetworkAnalyzer(projectPath string) *StaticNetworkAnalyzer {
	return &StaticNetworkAnalyzer{
		projectPath: projectPath,
	}
}

// ScanDirectory scans a directory for network threats
func (sna *StaticNetworkAnalyzer) ScanDirectory(root string) ([]types.Threat, error) {
	var files []string
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if !info.IsDir() {
			files = append(files, path)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return sna.AnalyzeProject(files)
}

// AnalyzeProject scans project files for network exfiltration patterns
func (sna *StaticNetworkAnalyzer) AnalyzeProject(files []string) ([]types.Threat, error) {
	var threats []types.Threat

	for _, file := range files {
		// Only analyze JavaScript/Python files
		ext := strings.ToLower(filepath.Ext(file))
		if ext != ".js" && ext != ".py" && ext != ".ts" {
			continue
		}

		content, err := os.ReadFile(file)
		if err != nil {
			continue
		}

		contentStr := string(content)
		relPath, _ := filepath.Rel(sna.projectPath, file)

		// Check for various network patterns
		if exfil := sna.detectExfiltrationPatterns(contentStr, relPath); exfil != nil {
			threats = append(threats, *exfil)
		}

		if envAware := sna.detectEnvironmentAwareness(contentStr, relPath); envAware != nil {
			threats = append(threats, *envAware)
		}

		if beacon := sna.detectBeaconPatterns(contentStr, relPath); beacon != nil {
			threats = append(threats, *beacon)
		}
	}

	logrus.Infof("[StaticNetworkAnalyzer] Found %d runtime behavior threats", len(threats))
	return threats, nil
}

// detectExfiltrationPatterns detects data exfiltration to external services
func (sna *StaticNetworkAnalyzer) detectExfiltrationPatterns(content, filePath string) *types.Threat {
	// Pattern 1: GitHub/GitLab API calls (Shai-Hulud pattern)
	githubAPIPattern := regexp.MustCompile(`https?://api\.github\.com`)
	gitlabAPIPattern := regexp.MustCompile(`https?://gitlab\.com/api`)

	// Pattern 2: POST requests with environment data
	envPostPattern := regexp.MustCompile(`(fetch|axios|request)\s*\([^)]*method\s*:\s*['"]POST['"]`)
	envDataPattern := regexp.MustCompile(`process\.env`)

	var indicators []string

	if githubAPIPattern.MatchString(content) {
		indicators = append(indicators, "GitHub API calls detected")
	}

	if gitlabAPIPattern.MatchString(content) {
		indicators = append(indicators, "GitLab API calls detected")
	}

	// Check for POST + environment data combination
	if envPostPattern.MatchString(content) && envDataPattern.MatchString(content) {
		indicators = append(indicators, "POST requests with environment data")
	}

	// Pattern 3: External domain connections
	suspiciousDomains := sna.extractSuspiciousDomains(content)
	if len(suspiciousDomains) > 0 {
		indicators = append(indicators, fmt.Sprintf("Connections to unknown domains: %s", strings.Join(suspiciousDomains, ", ")))
	}

	if len(indicators) == 0 {
		return nil
	}

	return &types.Threat{
		Type:            types.ThreatTypeRuntimeExfiltration,
		Severity:        types.SeverityHigh,
		Confidence:      0.8,
		Description:     fmt.Sprintf("File '%s' contains potential data exfiltration patterns", filepath.Base(filePath)),
		DetectionMethod: "static_network_analysis",
		Recommendation:  "Review network calls for unauthorized data exfiltration. Packages should not make external API calls during installation.",
		Evidence: []types.Evidence{
			{
				Type:        "network_patterns",
				Description: "Detected network indicators",
				Value:       strings.Join(indicators, "; "),
			},
			{
				Type:        "file",
				Description: "Source file",
				Value:       filepath.Base(filePath),
			},
		},
		Metadata: map[string]interface{}{
			"file_path":  filePath,
			"indicators": indicators,
		},
		DetectedAt: time.Now(),
	}
}

// detectEnvironmentAwareness detects CI/environment-aware behavior
func (sna *StaticNetworkAnalyzer) detectEnvironmentAwareness(content, filePath string) *types.Threat {
	// Patterns for CI environment checks
	patterns := map[string]*regexp.Regexp{
		"CI environment check":          regexp.MustCompile(`process\.env\.CI`),
		"GitHub Actions check":          regexp.MustCompile(`process\.env\.GITHUB_ACTIONS`),
		"GitLab CI check":               regexp.MustCompile(`process\.env\.GITLAB_CI`),
		"Jenkins check":                 regexp.MustCompile(`process\.env\.JENKINS_URL`),
		"Travis CI check":               regexp.MustCompile(`process\.env\.TRAVIS`),
		"Environment-based conditional": regexp.MustCompile(`if\s*\(\s*process\.env\.(CI|GITHUB_ACTIONS|GITLAB_CI)`),
	}

	var detectedPatterns []string
	for name, pattern := range patterns {
		if pattern.MatchString(content) {
			detectedPatterns = append(detectedPatterns, name)
		}
	}

	// Only flag if multiple CI checks (indicates targeted behavior)
	if len(detectedPatterns) < 2 {
		return nil
	}

	return &types.Threat{
		Type:            types.ThreatTypeEnvironmentAware,
		Severity:        types.SeverityMedium,
		Confidence:      0.75,
		Description:     fmt.Sprintf("File '%s' contains CI/environment-aware behavior (may only activate in specific environments)", filepath.Base(filePath)),
		DetectionMethod: "static_network_analysis",
		Recommendation:  "Malware that only activates in CI environments can evade local testing. Review all environment-based conditionals.",
		Evidence: []types.Evidence{
			{
				Type:        "environment_checks",
				Description: "Detected CI/environment checks",
				Value:       strings.Join(detectedPatterns, "; "),
			},
			{
				Type:        "file",
				Description: "Source file",
				Value:       filepath.Base(filePath),
			},
		},
		Metadata: map[string]interface{}{
			"file_path": filePath,
			"patterns":  detectedPatterns,
		},
		DetectedAt: time.Now(),
	}
}

// detectBeaconPatterns detects periodic network activity (C2 beacons)
func (sna *StaticNetworkAnalyzer) detectBeaconPatterns(content, filePath string) *types.Threat {
	// Pattern: setInterval with network calls
	intervalPattern := regexp.MustCompile(`setInterval\s*\(`)
	networkCallPattern := regexp.MustCompile(`(fetch|axios|http\.request|https\.request|XMLHttpRequest)`)

	// Must have both interval and network call
	if !intervalPattern.MatchString(content) || !networkCallPattern.MatchString(content) {
		return nil
	}

	return &types.Threat{
		Type:            types.ThreatTypeBeaconActivity,
		Severity:        types.SeverityHigh,
		Confidence:      0.7,
		Description:     fmt.Sprintf("File '%s' contains potential beacon/C2 pattern (periodic network activity)", filepath.Base(filePath)),
		DetectionMethod: "static_network_analysis",
		Recommendation:  "Packages should not make periodic network requests. This pattern is often used for command-and-control communication.",
		Evidence: []types.Evidence{
			{
				Type:        "beacon_pattern",
				Description: "setInterval + network calls",
				Value:       "Detected",
			},
			{
				Type:        "file",
				Description: "Source file",
				Value:       filepath.Base(filePath),
			},
		},
		Metadata: map[string]interface{}{
			"file_path": filePath,
		},
		DetectedAt: time.Now(),
	}
}

// extractSuspiciousDomains extracts external domains from HTTP calls
func (sna *StaticNetworkAnalyzer) extractSuspiciousDomains(content string) []string {
	// Extract URLs from fetch/axios calls
	urlPattern := regexp.MustCompile(`https?://([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})`)
	matches := urlPattern.FindAllStringSubmatch(content, -1)

	// Whitelist known-good domains
	whitelist := map[string]bool{
		"registry.npmjs.org": true,
		"pypi.org":           true,
		"pypi.python.org":    true,
		"api.github.com":     false, // Suspicious if used in install scripts
		"gitlab.com":         false, // Suspicious if used in install scripts
	}

	var suspicious []string
	seen := make(map[string]bool)

	for _, match := range matches {
		if len(match) < 2 {
			continue
		}

		domain := match[1]
		if seen[domain] {
			continue
		}
		seen[domain] = true

		// Check whitelist
		if isGood, exists := whitelist[domain]; exists {
			if !isGood {
				suspicious = append(suspicious, domain)
			}
			continue
		}

		// Any other external domain is suspicious
		suspicious = append(suspicious, domain)
	}

	return suspicious
}
