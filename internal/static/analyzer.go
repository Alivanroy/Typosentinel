package static

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// StaticAnalyzer performs static analysis on packages
type StaticAnalyzer struct {
	config         *Config
	yaraRules      []*YaraRule
	scriptPatterns []*ScriptPattern
}

// Config contains static analyzer configuration
type Config struct {
	Enabled               bool     `yaml:"enabled"`
	AnalyzeInstallScripts bool     `yaml:"analyze_install_scripts"`
	AnalyzeManifests      bool     `yaml:"analyze_manifests"`
	YaraRulesEnabled      bool     `yaml:"yara_rules_enabled"`
	YaraRulesPath         string   `yaml:"yara_rules_path"`
	SuspiciousCommands    []string `yaml:"suspicious_commands"`
	DangerousPermissions  []string `yaml:"dangerous_permissions"`
	MaxFileSize           int64    `yaml:"max_file_size"`
	Timeout               string   `yaml:"timeout"`
	Verbose               bool     `yaml:"verbose"`
}

// AnalysisResult represents static analysis results
type AnalysisResult struct {
	PackageName       string    `json:"package_name"`
	Registry          string    `json:"registry"`
	AnalysisTimestamp time.Time `json:"analysis_timestamp"`

	// Install script analysis
	InstallScripts []InstallScriptAnalysis `json:"install_scripts"`

	// Manifest analysis
	Manifests []ManifestAnalysis `json:"manifests"`

	// YARA rule matches
	YaraMatches []YaraMatch `json:"yara_matches"`

	// Overall assessment
	RiskScore       float64   `json:"risk_score"`
	ThreatLevel     string    `json:"threat_level"`
	Findings        []Finding `json:"findings"`
	Warnings        []string  `json:"warnings"`
	Recommendations []string  `json:"recommendations"`

	// Metadata
	ProcessingTime time.Duration `json:"processing_time"`
	FilesAnalyzed  int           `json:"files_analyzed"`
	TotalFileSize  int64         `json:"total_file_size"`
}

// InstallScriptAnalysis represents analysis of installation scripts
type InstallScriptAnalysis struct {
	FilePath           string              `json:"file_path"`
	ScriptType         string              `json:"script_type"`
	FileSize           int64               `json:"file_size"`
	SuspiciousCommands []SuspiciousCommand `json:"suspicious_commands"`
	NetworkCalls       []NetworkCall       `json:"network_calls"`
	FileOperations     []FileOperation     `json:"file_operations"`
	PermissionChanges  []PermissionChange  `json:"permission_changes"`
	EnvironmentAccess  []EnvironmentAccess `json:"environment_access"`
	RiskScore          float64             `json:"risk_score"`
	Recommendation     string              `json:"recommendation"`
}

// ManifestAnalysis represents analysis of package manifests
type ManifestAnalysis struct {
	FilePath         string               `json:"file_path"`
	ManifestType     string               `json:"manifest_type"`
	FileSize         int64                `json:"file_size"`
	Dependencies     []DependencyAnalysis `json:"dependencies"`
	Scripts          map[string]string    `json:"scripts"`
	SuspiciousFields []SuspiciousField    `json:"suspicious_fields"`
	MissingFields    []string             `json:"missing_fields"`
	VersionAnomalies []VersionAnomaly     `json:"version_anomalies"`
	LicenseIssues    []LicenseIssue       `json:"license_issues"`
	RiskScore        float64              `json:"risk_score"`
	Recommendation   string               `json:"recommendation"`
}

// SuspiciousCommand represents a suspicious command found in scripts
type SuspiciousCommand struct {
	Command     string  `json:"command"`
	LineNumber  int     `json:"line_number"`
	Context     string  `json:"context"`
	RiskLevel   string  `json:"risk_level"`
	Description string  `json:"description"`
	Confidence  float64 `json:"confidence"`
}

// NetworkCall represents network-related operations
type NetworkCall struct {
	URL         string  `json:"url"`
	Method      string  `json:"method"`
	LineNumber  int     `json:"line_number"`
	Context     string  `json:"context"`
	RiskLevel   string  `json:"risk_level"`
	Description string  `json:"description"`
	Confidence  float64 `json:"confidence"`
}

// FileOperation represents file system operations
type FileOperation struct {
	Operation   string  `json:"operation"`
	Path        string  `json:"path"`
	LineNumber  int     `json:"line_number"`
	Context     string  `json:"context"`
	RiskLevel   string  `json:"risk_level"`
	Description string  `json:"description"`
	Confidence  float64 `json:"confidence"`
}

// PermissionChange represents permission modifications
type PermissionChange struct {
	Path        string  `json:"path"`
	Permissions string  `json:"permissions"`
	LineNumber  int     `json:"line_number"`
	Context     string  `json:"context"`
	RiskLevel   string  `json:"risk_level"`
	Description string  `json:"description"`
	Confidence  float64 `json:"confidence"`
}

// EnvironmentAccess represents environment variable access
type EnvironmentAccess struct {
	Variable    string  `json:"variable"`
	Operation   string  `json:"operation"`
	LineNumber  int     `json:"line_number"`
	Context     string  `json:"context"`
	RiskLevel   string  `json:"risk_level"`
	Description string  `json:"description"`
	Confidence  float64 `json:"confidence"`
}

// DependencyAnalysis represents analysis of dependencies
type DependencyAnalysis struct {
	Name            string   `json:"name"`
	Version         string   `json:"version"`
	Type            string   `json:"type"`
	Source          string   `json:"source"`
	SuspiciousFlags []string `json:"suspicious_flags"`
	RiskScore       float64  `json:"risk_score"`
}

// SuspiciousField represents suspicious manifest fields
type SuspiciousField struct {
	Field      string  `json:"field"`
	Value      string  `json:"value"`
	Reason     string  `json:"reason"`
	RiskLevel  string  `json:"risk_level"`
	Confidence float64 `json:"confidence"`
}

// VersionAnomaly represents version-related anomalies
type VersionAnomaly struct {
	Type        string  `json:"type"`
	Description string  `json:"description"`
	RiskLevel   string  `json:"risk_level"`
	Confidence  float64 `json:"confidence"`
}

// LicenseIssue represents license-related issues
type LicenseIssue struct {
	Type        string  `json:"type"`
	Description string  `json:"description"`
	RiskLevel   string  `json:"risk_level"`
	Confidence  float64 `json:"confidence"`
}

// YaraMatch represents YARA rule matches
type YaraMatch struct {
	RuleName    string            `json:"rule_name"`
	FileName    string            `json:"file_name"`
	Matches     []YaraRuleMatch   `json:"matches"`
	Metadata    map[string]string `json:"metadata"`
	RiskLevel   string            `json:"risk_level"`
	Description string            `json:"description"`
}

// YaraRuleMatch represents individual YARA rule matches
type YaraRuleMatch struct {
	Offset  int64  `json:"offset"`
	Length  int    `json:"length"`
	Data    string `json:"data"`
	Context string `json:"context"`
}

// Finding represents a security finding
type Finding struct {
	ID          string            `json:"id"`
	Type        string            `json:"type"`
	Severity    string            `json:"severity"`
	Title       string            `json:"title"`
	Description string            `json:"description"`
	File        string            `json:"file"`
	Line        int               `json:"line,omitempty"`
	Evidence    string            `json:"evidence"`
	Remediation string            `json:"remediation"`
	Confidence  float64           `json:"confidence"`
	Metadata    map[string]string `json:"metadata"`
}

// YaraRule represents a YARA-like detection rule
type YaraRule struct {
	Name        string            `yaml:"name"`
	Description string            `yaml:"description"`
	Severity    string            `yaml:"severity"`
	Patterns    []string          `yaml:"patterns"`
	Condition   string            `yaml:"condition"`
	Metadata    map[string]string `yaml:"metadata"`
	Enabled     bool              `yaml:"enabled"`
}

// ScriptPattern represents patterns for script analysis
type ScriptPattern struct {
	Name        string  `yaml:"name"`
	Pattern     string  `yaml:"pattern"`
	Description string  `yaml:"description"`
	RiskLevel   string  `yaml:"risk_level"`
	Confidence  float64 `yaml:"confidence"`
	Enabled     bool    `yaml:"enabled"`
}

// NewStaticAnalyzer creates a new static analyzer
func NewStaticAnalyzer(config *Config) (*StaticAnalyzer, error) {
	if config == nil {
		config = DefaultConfig()
	}

	analyzer := &StaticAnalyzer{
		config: config,
	}

	// Load YARA rules
	if config.YaraRulesEnabled {
		if err := analyzer.loadYaraRules(); err != nil {
			return nil, fmt.Errorf("failed to load YARA rules: %w", err)
		}
	}

	// Load script patterns
	if err := analyzer.loadScriptPatterns(); err != nil {
		return nil, fmt.Errorf("failed to load script patterns: %w", err)
	}

	return analyzer, nil
}

// DefaultConfig returns default static analyzer configuration
func DefaultConfig() *Config {
	return &Config{
		Enabled:               true,
		AnalyzeInstallScripts: true,
		AnalyzeManifests:      true,
		YaraRulesEnabled:      true,
		YaraRulesPath:         "./rules",
		SuspiciousCommands: []string{
			"curl", "wget", "nc", "netcat", "telnet", "ssh", "scp",
			"rm -rf", "chmod 777", "sudo", "su", "passwd",
			"eval", "exec", "system", "shell_exec",
			"base64", "xxd", "hexdump",
		},
		DangerousPermissions: []string{
			"777", "666", "4755", "2755", "1755",
		},
		MaxFileSize: 10 * 1024 * 1024, // 10MB
		Timeout:     "30s",
		Verbose:     false,
	}
}

// AnalyzePackage performs static analysis on a package
func (sa *StaticAnalyzer) AnalyzePackage(ctx context.Context, packagePath string) (*AnalysisResult, error) {
	startTime := time.Now()

	result := &AnalysisResult{
		PackageName:       filepath.Base(packagePath),
		AnalysisTimestamp: time.Now(),
		InstallScripts:    []InstallScriptAnalysis{},
		Manifests:         []ManifestAnalysis{},
		YaraMatches:       []YaraMatch{},
		Findings:          []Finding{},
		Warnings:          []string{},
		Recommendations:   []string{},
	}

	// Walk through package files
	err := filepath.Walk(packagePath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Skip directories and large files
		if info.IsDir() || info.Size() > sa.config.MaxFileSize {
			return nil
		}

		result.FilesAnalyzed++
		result.TotalFileSize += info.Size()

		// Analyze install scripts
		if sa.config.AnalyzeInstallScripts && sa.isInstallScript(path) {
			scriptAnalysis, err := sa.analyzeInstallScript(path)
			if err != nil {
				result.Warnings = append(result.Warnings, fmt.Sprintf("Failed to analyze script %s: %v", path, err))
			} else {
				result.InstallScripts = append(result.InstallScripts, *scriptAnalysis)
			}
		}

		// Analyze manifests
		if sa.config.AnalyzeManifests && sa.isManifest(path) {
			manifestAnalysis, err := sa.analyzeManifest(path)
			if err != nil {
				result.Warnings = append(result.Warnings, fmt.Sprintf("Failed to analyze manifest %s: %v", path, err))
			} else {
				result.Manifests = append(result.Manifests, *manifestAnalysis)
			}
		}

		// Apply enhanced YARA rules
		if sa.config.YaraRulesEnabled {
			matches, err := sa.applyEnhancedYaraRules(path)
			if err != nil {
				result.Warnings = append(result.Warnings, fmt.Sprintf("Failed to apply YARA rules to %s: %v", path, err))
			} else {
				result.YaraMatches = append(result.YaraMatches, matches...)
			}
		}

		// Perform enhanced static analysis
		enhancedFindings, err := sa.performEnhancedAnalysis(path)
		if err != nil {
			result.Warnings = append(result.Warnings, fmt.Sprintf("Failed to perform enhanced analysis on %s: %v", path, err))
		} else {
			result.Findings = append(result.Findings, enhancedFindings...)
		}

		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to walk package directory: %w", err)
	}

	// Calculate enhanced risk assessment
	sa.calculateEnhancedRiskAssessment(result)

	// Generate findings
	sa.generateFindings(result)

	// Generate recommendations
	sa.generateRecommendations(result)

	result.ProcessingTime = time.Since(startTime)

	return result, nil
}

// isInstallScript checks if a file is an installation script
func (sa *StaticAnalyzer) isInstallScript(path string) bool {
	filename := filepath.Base(path)
	scriptNames := []string{
		"install.sh", "setup.sh", "build.sh", "configure.sh",
		"postinstall", "preinstall", "postuninstall", "preuninstall",
		"install.js", "postinstall.js", "preinstall.js",
		"install.py", "setup.py", "build.py",
	}

	for _, name := range scriptNames {
		if strings.EqualFold(filename, name) {
			return true
		}
	}

	// Check file extensions
	ext := filepath.Ext(path)
	scriptExts := []string{".sh", ".bash", ".zsh", ".fish", ".ps1", ".bat", ".cmd"}
	for _, scriptExt := range scriptExts {
		if strings.EqualFold(ext, scriptExt) {
			return true
		}
	}

	return false
}

// isManifest checks if a file is a package manifest
func (sa *StaticAnalyzer) isManifest(path string) bool {
	filename := filepath.Base(path)
	manifestNames := []string{
		"package.json", "package-lock.json", "yarn.lock",
		"requirements.txt", "setup.py", "pyproject.toml", "Pipfile",
		"go.mod", "go.sum",
		"Cargo.toml", "Cargo.lock",
		"pom.xml", "build.gradle", "build.gradle.kts",
		"Gemfile", "Gemfile.lock",
		"composer.json", "composer.lock",
	}

	for _, name := range manifestNames {
		if strings.EqualFold(filename, name) {
			return true
		}
	}

	return false
}

// analyzeInstallScript performs detailed analysis of installation scripts
func (sa *StaticAnalyzer) analyzeInstallScript(scriptPath string) (*InstallScriptAnalysis, error) {
	file, err := os.Open(scriptPath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		return nil, err
	}

	analysis := &InstallScriptAnalysis{
		FilePath:           scriptPath,
		ScriptType:         sa.detectScriptType(scriptPath),
		FileSize:           info.Size(),
		SuspiciousCommands: []SuspiciousCommand{},
		NetworkCalls:       []NetworkCall{},
		FileOperations:     []FileOperation{},
		PermissionChanges:  []PermissionChange{},
		EnvironmentAccess:  []EnvironmentAccess{},
	}

	scanner := bufio.NewScanner(file)
	lineNumber := 0

	for scanner.Scan() {
		lineNumber++
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Analyze for suspicious commands
		sa.analyzeSuspiciousCommands(line, lineNumber, analysis)

		// Analyze for network calls
		sa.analyzeNetworkCalls(line, lineNumber, analysis)

		// Analyze for file operations
		sa.analyzeFileOperations(line, lineNumber, analysis)

		// Analyze for permission changes
		sa.analyzePermissionChanges(line, lineNumber, analysis)

		// Analyze for environment access
		sa.analyzeEnvironmentAccess(line, lineNumber, analysis)
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	// Calculate risk score
	analysis.RiskScore = sa.calculateScriptRiskScore(analysis)
	analysis.Recommendation = sa.generateScriptRecommendation(analysis)

	return analysis, nil
}

// analyzeManifest performs detailed analysis of package manifests
func (sa *StaticAnalyzer) analyzeManifest(manifestPath string) (*ManifestAnalysis, error) {
	file, err := os.Open(manifestPath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		return nil, err
	}

	analysis := &ManifestAnalysis{
		FilePath:         manifestPath,
		ManifestType:     sa.detectManifestType(manifestPath),
		FileSize:         info.Size(),
		Dependencies:     []DependencyAnalysis{},
		Scripts:          make(map[string]string),
		SuspiciousFields: []SuspiciousField{},
		MissingFields:    []string{},
		VersionAnomalies: []VersionAnomaly{},
		LicenseIssues:    []LicenseIssue{},
	}

	// Parse manifest based on type
	switch analysis.ManifestType {
	case "package.json":
		err = sa.analyzePackageJSON(file, analysis)
	case "requirements.txt":
		err = sa.analyzeRequirementsTxt(file, analysis)
	case "go.mod":
		err = sa.analyzeGoMod(file, analysis)
	default:
		err = sa.analyzeGenericManifest(file, analysis)
	}

	if err != nil {
		return nil, err
	}

	// Calculate risk score
	analysis.RiskScore = sa.calculateManifestRiskScore(analysis)
	analysis.Recommendation = sa.generateManifestRecommendation(analysis)

	return analysis, nil
}

// detectScriptType detects the type of script
func (sa *StaticAnalyzer) detectScriptType(scriptPath string) string {
	ext := filepath.Ext(scriptPath)
	switch strings.ToLower(ext) {
	case ".sh", ".bash":
		return "bash"
	case ".zsh":
		return "zsh"
	case ".fish":
		return "fish"
	case ".ps1":
		return "powershell"
	case ".bat", ".cmd":
		return "batch"
	case ".js":
		return "javascript"
	case ".py":
		return "python"
	default:
		return "unknown"
	}
}

// detectManifestType detects the type of manifest
func (sa *StaticAnalyzer) detectManifestType(manifestPath string) string {
	filename := filepath.Base(manifestPath)
	switch strings.ToLower(filename) {
	case "package.json":
		return "package.json"
	case "requirements.txt":
		return "requirements.txt"
	case "go.mod":
		return "go.mod"
	case "cargo.toml":
		return "cargo.toml"
	case "pom.xml":
		return "pom.xml"
	case "gemfile":
		return "gemfile"
	case "composer.json":
		return "composer.json"
	default:
		return "unknown"
	}
}

// Enhanced detailed analysis functions for comprehensive security assessment

func (sa *StaticAnalyzer) analyzeSuspiciousCommands(line string, lineNumber int, analysis *InstallScriptAnalysis) {
	// Enhanced suspicious command detection with context analysis
	suspiciousPatterns := map[string]float64{
		"curl.*sh":           0.9, // Piping curl to shell
		"wget.*sh":           0.9, // Piping wget to shell
		"eval.*\\$":          0.8, // Dynamic code evaluation
		"base64.*decode":     0.7, // Base64 decoding
		"nc.*-l":            0.8, // Netcat listener
		"python.*-c":        0.6, // Python one-liner
		"perl.*-e":          0.6, // Perl one-liner
		"ruby.*-e":          0.6, // Ruby one-liner
		"bash.*-c":          0.5, // Bash command execution
		"sh.*-c":            0.5, // Shell command execution
		"sudo.*rm":          0.7, // Sudo with rm
		"rm.*-rf.*\\*":      0.8, // Recursive force delete with wildcard
		"dd.*if=":           0.6, // Disk operations
		"mkfifo":            0.7, // Named pipe creation
		"nohup":             0.5, // Background process
		"crontab":           0.6, // Cron job modification
		"systemctl":         0.6, // System service control
		"service":           0.6, // Service control
		"iptables":          0.7, // Firewall modification
		"ufw":               0.7, // Ubuntu firewall
		"passwd":            0.8, // Password modification
		"useradd":           0.7, // User creation
		"usermod":           0.7, // User modification
		"chown.*root":       0.6, // Change ownership to root
		"chmod.*777":        0.8, // World writable permissions
		"chmod.*\\+s":       0.9, // SUID/SGID permissions
	}

	for pattern, confidence := range suspiciousPatterns {
		if matched, _ := regexp.MatchString(pattern, strings.ToLower(line)); matched {
			riskLevel := "MEDIUM"
			if confidence >= 0.8 {
				riskLevel = "HIGH"
			} else if confidence >= 0.6 {
				riskLevel = "MEDIUM"
			} else {
				riskLevel = "LOW"
			}

			analysis.SuspiciousCommands = append(analysis.SuspiciousCommands, SuspiciousCommand{
				Command:     pattern,
				LineNumber:  lineNumber,
				Context:     line,
				RiskLevel:   riskLevel,
				Description: fmt.Sprintf("Suspicious pattern '%s' detected", pattern),
				Confidence:  confidence,
			})
		}
	}

	// Check against configured suspicious commands
	for _, cmd := range sa.config.SuspiciousCommands {
		if strings.Contains(strings.ToLower(line), strings.ToLower(cmd)) {
			analysis.SuspiciousCommands = append(analysis.SuspiciousCommands, SuspiciousCommand{
				Command:     cmd,
				LineNumber:  lineNumber,
				Context:     line,
				RiskLevel:   "HIGH",
				Description: fmt.Sprintf("Configured suspicious command '%s' detected", cmd),
				Confidence:  0.8,
			})
		}
	}
}

func (sa *StaticAnalyzer) analyzeNetworkCalls(line string, lineNumber int, analysis *InstallScriptAnalysis) {
	// Enhanced network call detection with URL extraction and risk assessment
	networkPatterns := map[string]struct {
		confidence float64
		method     string
		riskLevel  string
	}{
		`curl\s+.*https?://[^\s]+`:                    {0.8, "GET", "MEDIUM"},
		`wget\s+.*https?://[^\s]+`:                    {0.8, "GET", "MEDIUM"},
		`fetch\s+.*https?://[^\s]+`:                   {0.7, "GET", "MEDIUM"},
		`python.*urllib.*https?://[^\s]+`:             {0.7, "GET", "MEDIUM"},
		`python.*requests.*https?://[^\s]+`:           {0.7, "GET", "MEDIUM"},
		`node.*https?://[^\s]+`:                       {0.6, "GET", "MEDIUM"},
		`npm.*install.*https?://[^\s]+`:               {0.8, "GET", "HIGH"},
		`pip.*install.*https?://[^\s]+`:               {0.8, "GET", "HIGH"},
		`gem.*install.*https?://[^\s]+`:               {0.8, "GET", "HIGH"},
		`go.*get.*https?://[^\s]+`:                    {0.7, "GET", "MEDIUM"},
		`git.*clone.*https?://[^\s]+`:                 {0.6, "GET", "LOW"},
		`ssh.*[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+`:         {0.9, "SSH", "HIGH"},
		`telnet.*[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+`:      {0.9, "TELNET", "HIGH"},
		`nc.*[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+.*[0-9]+`:  {0.8, "NETCAT", "HIGH"},
		`socat.*[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+`:       {0.8, "SOCAT", "HIGH"},
		`ftp.*[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+`:         {0.7, "FTP", "MEDIUM"},
		`scp.*[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+`:         {0.7, "SCP", "MEDIUM"},
		`rsync.*[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+`:       {0.7, "RSYNC", "MEDIUM"},
	}

	for pattern, info := range networkPatterns {
		if matched, _ := regexp.MatchString(pattern, line); matched {
			// Extract URL if possible
			urlRegex := regexp.MustCompile(`https?://[^\s]+`)
			url := "detected"
			if matches := urlRegex.FindString(line); matches != "" {
				url = matches
			}

			// Check for suspicious domains
			suspiciousDomains := []string{
				"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
				"pastebin.com", "hastebin.com", "ghostbin.com",
				"raw.githubusercontent.com", "gist.githubusercontent.com",
			}

			riskLevel := info.riskLevel
			confidence := info.confidence

			for _, domain := range suspiciousDomains {
				if strings.Contains(url, domain) {
					riskLevel = "HIGH"
					confidence = 0.9
					break
				}
			}

			// Check for suspicious TLDs
			suspiciousTLDs := []string{".tk", ".ml", ".ga", ".cf", ".top", ".click", ".download"}
			for _, tld := range suspiciousTLDs {
				if strings.Contains(url, tld) {
					riskLevel = "HIGH"
					confidence = 0.8
					break
				}
			}

			analysis.NetworkCalls = append(analysis.NetworkCalls, NetworkCall{
				URL:         url,
				Method:      info.method,
				LineNumber:  lineNumber,
				Context:     line,
				RiskLevel:   riskLevel,
				Description: fmt.Sprintf("Network call detected: %s to %s", info.method, url),
				Confidence:  confidence,
			})
		}
	}

	// Check for DNS manipulation
	dnsPatterns := []string{
		`echo.*>.*\/etc\/hosts`,
		`echo.*>>.*\/etc\/hosts`,
		`sed.*\/etc\/hosts`,
		`awk.*\/etc\/hosts`,
	}

	for _, pattern := range dnsPatterns {
		if matched, _ := regexp.MatchString(pattern, line); matched {
			analysis.NetworkCalls = append(analysis.NetworkCalls, NetworkCall{
				URL:         "/etc/hosts",
				Method:      "DNS_MANIPULATION",
				LineNumber:  lineNumber,
				Context:     line,
				RiskLevel:   "HIGH",
				Description: "DNS manipulation detected - modifying /etc/hosts",
				Confidence:  0.9,
			})
		}
	}
}

func (sa *StaticAnalyzer) analyzeFileOperations(line string, lineNumber int, analysis *InstallScriptAnalysis) {
	// Enhanced file operation detection with path analysis and risk assessment
	filePatterns := map[string]struct {
		operation  string
		confidence float64
		riskLevel  string
	}{
		`rm\s+-rf\s+/`:                           {"delete", 0.9, "HIGH"},
		`rm\s+-rf\s+\*`:                          {"delete", 0.9, "HIGH"},
		`rm\s+-rf\s+~`:                           {"delete", 0.8, "HIGH"},
		`rm\s+-rf\s+\$HOME`:                      {"delete", 0.8, "HIGH"},
		`rm\s+-f\s+/etc/`:                        {"delete", 0.9, "HIGH"},
		`rm\s+-f\s+/usr/`:                        {"delete", 0.8, "HIGH"},
		`rm\s+-f\s+/var/`:                        {"delete", 0.7, "MEDIUM"},
		`cp\s+.*\s+/etc/`:                        {"copy", 0.7, "MEDIUM"},
		`cp\s+.*\s+/usr/bin/`:                    {"copy", 0.8, "HIGH"},
		`cp\s+.*\s+/usr/local/bin/`:              {"copy", 0.7, "MEDIUM"},
		`mv\s+.*\s+/etc/`:                        {"move", 0.7, "MEDIUM"},
		`mv\s+.*\s+/usr/bin/`:                    {"move", 0.8, "HIGH"},
		`mkdir\s+-p\s+/etc/`:                     {"create", 0.6, "MEDIUM"},
		`mkdir\s+-p\s+/usr/`:                     {"create", 0.7, "MEDIUM"},
		`touch\s+/etc/`:                          {"create", 0.6, "MEDIUM"},
		`ln\s+-s\s+.*\s+/usr/bin/`:               {"link", 0.7, "MEDIUM"},
		`ln\s+-sf\s+.*\s+/usr/bin/`:              {"link", 0.8, "HIGH"},
		`dd\s+if=.*\s+of=/dev/`:                  {"write", 0.9, "HIGH"},
		`dd\s+if=/dev/zero\s+of=`:                {"write", 0.7, "MEDIUM"},
		`tar\s+.*\s+/`:                           {"extract", 0.6, "MEDIUM"},
		`unzip\s+.*\s+-d\s+/`:                    {"extract", 0.6, "MEDIUM"},
		`find\s+/.*\s+-delete`:                   {"delete", 0.8, "HIGH"},
		`find\s+/.*\s+-exec\s+rm`:                {"delete", 0.8, "HIGH"},
		`shred\s+`:                               {"secure_delete", 0.8, "HIGH"},
		`wipe\s+`:                                {"secure_delete", 0.8, "HIGH"},
		`cat\s+.*>\s*/etc/`:                      {"write", 0.7, "MEDIUM"},
		`echo\s+.*>\s*/etc/`:                     {"write", 0.7, "MEDIUM"},
		`tee\s+.*\s*/etc/`:                       {"write", 0.7, "MEDIUM"},
		`rsync\s+.*\s+/`:                         {"sync", 0.5, "LOW"},
	}

	for pattern, info := range filePatterns {
		if matched, _ := regexp.MatchString(pattern, line); matched {
			// Extract path if possible
			pathRegex := regexp.MustCompile(`(/[^\s]+|~[^\s]*|\$[A-Z_][A-Z0-9_]*[^\s]*)`)
			path := "detected"
			if matches := pathRegex.FindString(line); matches != "" {
				path = matches
			}

			// Check for critical system paths
			criticalPaths := []string{
				"/etc/passwd", "/etc/shadow", "/etc/sudoers", "/etc/hosts",
				"/boot/", "/sys/", "/proc/", "/dev/",
				"/usr/bin/", "/usr/sbin/", "/sbin/", "/bin/",
				"/root/", "/home/", "~/.ssh/", "~/.bashrc", "~/.profile",
			}

			riskLevel := info.riskLevel
			confidence := info.confidence

			for _, criticalPath := range criticalPaths {
				if strings.Contains(path, criticalPath) {
					riskLevel = "HIGH"
					confidence = 0.9
					break
				}
			}

			// Check for hidden files/directories
			if strings.Contains(path, "/.") {
				confidence += 0.1
				if riskLevel == "LOW" {
					riskLevel = "MEDIUM"
				}
			}

			// Check for temporary directories (often used for malicious purposes)
			tempPaths := []string{"/tmp/", "/var/tmp/", "/dev/shm/"}
			for _, tempPath := range tempPaths {
				if strings.Contains(path, tempPath) {
					confidence += 0.1
					break
				}
			}

			analysis.FileOperations = append(analysis.FileOperations, FileOperation{
				Operation:   info.operation,
				Path:        path,
				LineNumber:  lineNumber,
				Context:     line,
				RiskLevel:   riskLevel,
				Description: fmt.Sprintf("File %s operation detected on %s", info.operation, path),
				Confidence:  confidence,
			})
		}
	}

	// Check for file hiding techniques
	hidingPatterns := []string{
		`mv\s+.*\s+\.[^/]*$`,        // Moving to hidden file
		`cp\s+.*\s+\.[^/]*$`,        // Copying to hidden file
		`touch\s+\.[^/]*$`,          // Creating hidden file
		`mkdir\s+\.[^/]*$`,          // Creating hidden directory
	}

	for _, pattern := range hidingPatterns {
		if matched, _ := regexp.MatchString(pattern, line); matched {
			analysis.FileOperations = append(analysis.FileOperations, FileOperation{
				Operation:   "hide",
				Path:        "hidden_file",
				LineNumber:  lineNumber,
				Context:     line,
				RiskLevel:   "HIGH",
				Description: "File hiding technique detected",
				Confidence:  0.8,
			})
		}
	}
}

func (sa *StaticAnalyzer) analyzePermissionChanges(line string, lineNumber int, analysis *InstallScriptAnalysis) {
	// Enhanced permission change detection with privilege escalation analysis
	permissionPatterns := map[string]struct {
		riskLevel  string
		confidence float64
		description string
	}{
		`chmod\s+777`:                    {"HIGH", 0.9, "World writable permissions (777)"},
		`chmod\s+\+x\s+.*\/bin\/`:        {"HIGH", 0.8, "Making binary executable in system path"},
		`chmod\s+\+s`:                    {"HIGH", 0.9, "Setting SUID/SGID bit"},
		`chmod\s+4755`:                   {"HIGH", 0.9, "Setting SUID permissions (4755)"},
		`chmod\s+2755`:                   {"HIGH", 0.9, "Setting SGID permissions (2755)"},
		`chmod\s+6755`:                   {"HIGH", 0.9, "Setting SUID+SGID permissions (6755)"},
		`chmod\s+u\+s`:                   {"HIGH", 0.9, "Setting SUID bit"},
		`chmod\s+g\+s`:                   {"HIGH", 0.9, "Setting SGID bit"},
		`chmod\s+\+t`:                    {"MEDIUM", 0.7, "Setting sticky bit"},
		`chmod\s+1755`:                   {"MEDIUM", 0.7, "Setting sticky bit permissions (1755)"},
		`chmod\s+755\s+.*\/bin\/`:        {"MEDIUM", 0.6, "Setting executable permissions in system path"},
		`chmod\s+644\s+\/etc\/`:          {"MEDIUM", 0.6, "Modifying system configuration file permissions"},
		`chmod\s+600\s+.*\.ssh\/`:        {"LOW", 0.4, "Setting SSH key permissions"},
		`chown\s+root`:                   {"HIGH", 0.8, "Changing ownership to root"},
		`chown\s+0:0`:                    {"HIGH", 0.8, "Changing ownership to root (numeric)"},
		`chgrp\s+root`:                   {"MEDIUM", 0.7, "Changing group to root"},
		`chgrp\s+0`:                      {"MEDIUM", 0.7, "Changing group to root (numeric)"},
		`chown\s+.*:.*\s+\/etc\/`:        {"HIGH", 0.8, "Changing ownership of system configuration"},
		`chown\s+.*:.*\s+\/usr\/bin\/`:   {"HIGH", 0.8, "Changing ownership of system binaries"},
		`chown\s+.*:.*\s+\/sbin\/`:       {"HIGH", 0.8, "Changing ownership of system binaries"},
		`chattr\s+\+i`:                   {"HIGH", 0.8, "Making file immutable"},
		`chattr\s+\+a`:                   {"MEDIUM", 0.7, "Making file append-only"},
		`setfacl`:                        {"MEDIUM", 0.6, "Modifying file ACLs"},
		`umask\s+000`:                    {"HIGH", 0.8, "Setting permissive umask"},
		`umask\s+002`:                    {"MEDIUM", 0.5, "Setting group-writable umask"},
	}

	for pattern, info := range permissionPatterns {
		if matched, _ := regexp.MatchString(pattern, line); matched {
			// Extract path if possible
			pathRegex := regexp.MustCompile(`(/[^\s]+|~[^\s]*|\.[^\s]*|\$[A-Z_][A-Z0-9_]*[^\s]*)`)
			path := "detected"
			if matches := pathRegex.FindString(line); matches != "" {
				path = matches
			}

			// Extract permission value
			permRegex := regexp.MustCompile(`\b[0-7]{3,4}\b|\+[rwxst]+|\-[rwxst]+`)
			permissions := "detected"
			if matches := permRegex.FindString(line); matches != "" {
				permissions = matches
			}

			analysis.PermissionChanges = append(analysis.PermissionChanges, PermissionChange{
				Path:        path,
				Permissions: permissions,
				LineNumber:  lineNumber,
				Context:     line,
				RiskLevel:   info.riskLevel,
				Description: info.description,
				Confidence:  info.confidence,
			})
		}
	}

	// Check against configured dangerous permissions
	if strings.Contains(line, "chmod") {
		for _, perm := range sa.config.DangerousPermissions {
			if strings.Contains(line, perm) {
				analysis.PermissionChanges = append(analysis.PermissionChanges, PermissionChange{
					Path:        "detected",
					Permissions: perm,
					LineNumber:  lineNumber,
					Context:     line,
					RiskLevel:   "HIGH",
					Description: fmt.Sprintf("Configured dangerous permission '%s' detected", perm),
					Confidence:  0.9,
				})
			}
		}
	}

	// Check for privilege escalation techniques
	privEscPatterns := []string{
		`sudo\s+su\s+-`,                  // Switching to root
		`sudo\s+bash`,                    // Getting root shell
		`sudo\s+sh`,                      // Getting root shell
		`su\s+-\s+root`,                  // Switching to root
		`sudo\s+.*NOPASSWD`,              // Passwordless sudo
		`echo.*sudoers`,                  // Modifying sudoers
		`visudo`,                         // Editing sudoers
		`passwd\s+root`,                  // Changing root password
		`usermod\s+.*sudo`,               // Adding user to sudo group
		`usermod\s+.*wheel`,              // Adding user to wheel group
		`gpasswd\s+.*sudo`,               // Adding user to sudo group
		`adduser\s+.*sudo`,               // Adding user to sudo group
	}

	for _, pattern := range privEscPatterns {
		if matched, _ := regexp.MatchString(pattern, line); matched {
			analysis.PermissionChanges = append(analysis.PermissionChanges, PermissionChange{
				Path:        "system",
				Permissions: "privilege_escalation",
				LineNumber:  lineNumber,
				Context:     line,
				RiskLevel:   "HIGH",
				Description: "Privilege escalation technique detected",
				Confidence:  0.9,
			})
		}
	}
}

func (sa *StaticAnalyzer) analyzeEnvironmentAccess(line string, lineNumber int, analysis *InstallScriptAnalysis) {
	// Enhanced environment variable access detection with sensitive data analysis
	
	// Sensitive environment variables that should raise alerts
	sensitiveEnvVars := map[string]struct {
		riskLevel  string
		confidence float64
		description string
	}{
		"PASSWORD":           {"HIGH", 0.9, "Password environment variable access"},
		"PASSWD":             {"HIGH", 0.9, "Password environment variable access"},
		"SECRET":             {"HIGH", 0.9, "Secret environment variable access"},
		"TOKEN":              {"HIGH", 0.9, "Token environment variable access"},
		"API_KEY":            {"HIGH", 0.9, "API key environment variable access"},
		"APIKEY":             {"HIGH", 0.9, "API key environment variable access"},
		"AUTH":               {"HIGH", 0.8, "Authentication environment variable access"},
		"PRIVATE_KEY":        {"HIGH", 0.9, "Private key environment variable access"},
		"PRIVATEKEY":         {"HIGH", 0.9, "Private key environment variable access"},
		"SSH_KEY":            {"HIGH", 0.9, "SSH key environment variable access"},
		"SSHKEY":             {"HIGH", 0.9, "SSH key environment variable access"},
		"DATABASE_URL":       {"MEDIUM", 0.7, "Database URL environment variable access"},
		"DB_PASSWORD":        {"HIGH", 0.9, "Database password environment variable access"},
		"DB_PASS":            {"HIGH", 0.9, "Database password environment variable access"},
		"MYSQL_PASSWORD":     {"HIGH", 0.9, "MySQL password environment variable access"},
		"POSTGRES_PASSWORD":  {"HIGH", 0.9, "PostgreSQL password environment variable access"},
		"REDIS_PASSWORD":     {"HIGH", 0.9, "Redis password environment variable access"},
		"AWS_SECRET":         {"HIGH", 0.9, "AWS secret environment variable access"},
		"AWS_ACCESS_KEY":     {"HIGH", 0.9, "AWS access key environment variable access"},
		"GITHUB_TOKEN":       {"HIGH", 0.9, "GitHub token environment variable access"},
		"GITLAB_TOKEN":       {"HIGH", 0.9, "GitLab token environment variable access"},
		"SLACK_TOKEN":        {"MEDIUM", 0.7, "Slack token environment variable access"},
		"DISCORD_TOKEN":      {"MEDIUM", 0.7, "Discord token environment variable access"},
		"WEBHOOK_URL":        {"MEDIUM", 0.6, "Webhook URL environment variable access"},
		"ENCRYPTION_KEY":     {"HIGH", 0.9, "Encryption key environment variable access"},
		"SIGNING_KEY":        {"HIGH", 0.9, "Signing key environment variable access"},
		"CERTIFICATE":        {"MEDIUM", 0.7, "Certificate environment variable access"},
		"CERT":               {"MEDIUM", 0.7, "Certificate environment variable access"},
		"HOME":               {"LOW", 0.3, "Home directory environment variable access"},
		"USER":               {"LOW", 0.3, "User environment variable access"},
		"PATH":               {"LOW", 0.2, "PATH environment variable access"},
		"SHELL":              {"LOW", 0.3, "Shell environment variable access"},
		"SUDO_USER":          {"MEDIUM", 0.6, "Sudo user environment variable access"},
		"SUDO_UID":           {"MEDIUM", 0.6, "Sudo UID environment variable access"},
		"SUDO_GID":           {"MEDIUM", 0.6, "Sudo GID environment variable access"},
	}

	// Detect environment variable access patterns
	envPatterns := []string{
		`\$[A-Z_][A-Z0-9_]*`,           // Standard env var access
		`\$\{[A-Z_][A-Z0-9_]*\}`,       // Braced env var access
		`export\s+[A-Z_][A-Z0-9_]*=`,   // Environment variable setting
		`env\s+[A-Z_][A-Z0-9_]*=`,      // Environment variable setting with env
		`printenv\s+[A-Z_][A-Z0-9_]*`,  // Environment variable reading
		`echo\s+\$[A-Z_][A-Z0-9_]*`,    // Environment variable echoing
	}

	for _, pattern := range envPatterns {
		if matched, _ := regexp.MatchString(pattern, line); matched {
			// Extract variable name
			varRegex := regexp.MustCompile(`[A-Z_][A-Z0-9_]*`)
			matches := varRegex.FindAllString(line, -1)
			
			for _, varName := range matches {
				// Skip common shell keywords
				if varName == "EXPORT" || varName == "ENV" || varName == "ECHO" || varName == "PRINTENV" {
					continue
				}

				riskLevel := "LOW"
				confidence := 0.3
				description := "Environment variable access detected"
				operation := "read"

				// Check if it's a sensitive variable
				for sensitiveVar, info := range sensitiveEnvVars {
					if strings.Contains(varName, sensitiveVar) {
						riskLevel = info.riskLevel
						confidence = info.confidence
						description = info.description
						break
					}
				}

				// Determine operation type
				if strings.Contains(line, "export") || strings.Contains(line, "=") {
					operation = "write"
					confidence += 0.1 // Writing is slightly more suspicious
				} else if strings.Contains(line, "unset") {
					operation = "delete"
					confidence += 0.2 // Deleting is more suspicious
				}

				analysis.EnvironmentAccess = append(analysis.EnvironmentAccess, EnvironmentAccess{
					Variable:    varName,
					Operation:   operation,
					LineNumber:  lineNumber,
					Context:     line,
					RiskLevel:   riskLevel,
					Description: description,
					Confidence:  confidence,
				})
			}
		}
	}

	// Check for environment variable exfiltration patterns
	exfiltrationPatterns := []string{
		`curl.*\$[A-Z_][A-Z0-9_]*`,      // Sending env vars via curl
		`wget.*\$[A-Z_][A-Z0-9_]*`,      // Sending env vars via wget
		`nc.*\$[A-Z_][A-Z0-9_]*`,        // Sending env vars via netcat
		`echo.*\$[A-Z_][A-Z0-9_]*.*>`,   // Redirecting env vars to files
		`cat.*\$[A-Z_][A-Z0-9_]*.*>`,    // Redirecting env vars to files
		`base64.*\$[A-Z_][A-Z0-9_]*`,    // Encoding env vars
	}

	for _, pattern := range exfiltrationPatterns {
		if matched, _ := regexp.MatchString(pattern, line); matched {
			analysis.EnvironmentAccess = append(analysis.EnvironmentAccess, EnvironmentAccess{
				Variable:    "detected",
				Operation:   "exfiltrate",
				LineNumber:  lineNumber,
				Context:     line,
				RiskLevel:   "HIGH",
				Description: "Environment variable exfiltration pattern detected",
				Confidence:  0.9,
			})
		}
	}

	// Check for environment variable manipulation
	manipulationPatterns := []string{
		`unset\s+[A-Z_][A-Z0-9_]*`,      // Unsetting environment variables
		`export\s+PATH=`,                // Modifying PATH
		`export\s+LD_PRELOAD=`,          // Library preloading
		`export\s+LD_LIBRARY_PATH=`,     // Library path modification
		`export\s+SHELL=`,               // Shell modification
		`export\s+HOME=`,                // Home directory modification
	}

	for _, pattern := range manipulationPatterns {
		if matched, _ := regexp.MatchString(pattern, line); matched {
			analysis.EnvironmentAccess = append(analysis.EnvironmentAccess, EnvironmentAccess{
				Variable:    "system",
				Operation:   "manipulate",
				LineNumber:  lineNumber,
				Context:     line,
				RiskLevel:   "HIGH",
				Description: "Environment variable manipulation detected",
				Confidence:  0.8,
			})
		}
	}
}

// Enhanced manifest analysis functions for comprehensive package security assessment
func (sa *StaticAnalyzer) analyzePackageJSON(file *os.File, analysis *ManifestAnalysis) error {
	// Parse package.json and analyze dependencies, scripts, etc.
	var packageData map[string]interface{}
	if err := json.NewDecoder(file).Decode(&packageData); err != nil {
		return err
	}

	// Analyze scripts
	if scripts, ok := packageData["scripts"].(map[string]interface{}); ok {
		for name, script := range scripts {
			if scriptStr, ok := script.(string); ok {
				analysis.Scripts[name] = scriptStr

				// Check for suspicious commands in scripts
				for _, cmd := range sa.config.SuspiciousCommands {
					if strings.Contains(strings.ToLower(scriptStr), strings.ToLower(cmd)) {
						analysis.SuspiciousFields = append(analysis.SuspiciousFields, SuspiciousField{
							Field:      fmt.Sprintf("scripts.%s", name),
							Value:      scriptStr,
							Reason:     fmt.Sprintf("Contains suspicious command: %s", cmd),
							RiskLevel:  "HIGH",
							Confidence: 0.8,
						})
						break // Only add one suspicious field per script
					}
				}
			}
		}
	}

	return nil
}

func (sa *StaticAnalyzer) analyzeRequirementsTxt(file *os.File, analysis *ManifestAnalysis) error {
	// Parse requirements.txt
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			// Parse dependency
			parts := strings.Split(line, "==")
			if len(parts) >= 1 {
				analysis.Dependencies = append(analysis.Dependencies, DependencyAnalysis{
					Name:      parts[0],
					Version:   "",
					Type:      "python",
					Source:    "pypi",
					RiskScore: 0.1,
				})
			}
		}
	}
	return scanner.Err()
}

func (sa *StaticAnalyzer) analyzeGoMod(file *os.File, analysis *ManifestAnalysis) error {
	// Parse go.mod
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "require") {
			// Parse Go dependencies
			parts := strings.Fields(line)
			if len(parts) >= 3 {
				analysis.Dependencies = append(analysis.Dependencies, DependencyAnalysis{
					Name:      parts[1],
					Version:   parts[2],
					Type:      "go",
					Source:    "go-modules",
					RiskScore: 0.1,
				})
			}
		}
	}
	return scanner.Err()
}

func (sa *StaticAnalyzer) analyzeGenericManifest(file *os.File, analysis *ManifestAnalysis) error {
	// Generic manifest analysis
	return nil
}

// Risk calculation and assessment functions
func (sa *StaticAnalyzer) calculateScriptRiskScore(analysis *InstallScriptAnalysis) float64 {
	score := 0.0

	// Weight different risk factors
	score += float64(len(analysis.SuspiciousCommands)) * 0.3
	score += float64(len(analysis.NetworkCalls)) * 0.2
	score += float64(len(analysis.PermissionChanges)) * 0.4
	score += float64(len(analysis.FileOperations)) * 0.1

	return min(score, 1.0)
}

func (sa *StaticAnalyzer) calculateManifestRiskScore(analysis *ManifestAnalysis) float64 {
	score := 0.0

	// Weight different risk factors
	score += float64(len(analysis.SuspiciousFields)) * 0.4
	score += float64(len(analysis.VersionAnomalies)) * 0.3
	score += float64(len(analysis.LicenseIssues)) * 0.2
	score += float64(len(analysis.MissingFields)) * 0.1

	return min(score, 1.0)
}

func (sa *StaticAnalyzer) calculateRiskAssessment(result *AnalysisResult) {
	totalRisk := 0.0
	count := 0

	// Average script risks
	for _, script := range result.InstallScripts {
		totalRisk += script.RiskScore
		count++
	}

	// Average manifest risks
	for _, manifest := range result.Manifests {
		totalRisk += manifest.RiskScore
		count++
	}

	// YARA matches increase risk
	totalRisk += float64(len(result.YaraMatches)) * 0.2

	if count > 0 {
		result.RiskScore = totalRisk / float64(count)
	} else {
		result.RiskScore = 0.0
	}

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

func (sa *StaticAnalyzer) calculateEnhancedRiskAssessment(result *AnalysisResult) {
	totalRisk := 0.0
	count := 0

	// Enhanced risk calculation with weighted factors
	for _, script := range result.InstallScripts {
		totalRisk += script.RiskScore * 1.2 // Scripts have higher weight
		count++
	}

	// Average manifest risks
	for _, manifest := range result.Manifests {
		totalRisk += manifest.RiskScore
		count++
	}

	// YARA matches increase risk significantly
	totalRisk += float64(len(result.YaraMatches)) * 0.3

	// Enhanced findings contribute to risk
	for _, finding := range result.Findings {
		switch finding.Severity {
		case "CRITICAL":
			totalRisk += 0.4
		case "HIGH":
			totalRisk += 0.3
		case "MEDIUM":
			totalRisk += 0.2
		case "LOW":
			totalRisk += 0.1
		}
	}

	if count > 0 {
		result.RiskScore = min(totalRisk/float64(count), 1.0)
	} else {
		result.RiskScore = 0.0
	}

	// Determine threat level with enhanced criteria
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

// Enhanced functions for loading rules and generating recommendations
func (sa *StaticAnalyzer) loadYaraRules() error {
	// Load YARA rules from files or embedded resources
	// In production, this would load .yar files and compile them
	
	// Define built-in YARA-like rules for common malware patterns
	// Note: In production, these would be loaded from .yar files
	if sa.config.YaraRulesEnabled {
		// Initialize the yaraRules slice if not already done
		sa.yaraRules = []*YaraRule{
			{
				Name:        "suspicious_downloader",
				Description: "Detects suspicious download patterns",
				Severity:    "HIGH",
				Patterns:    []string{"(curl|wget|fetch).*\\|\\s*(bash|sh|python|perl)"},
				Condition:   "any of them",
				Metadata:    map[string]string{"category": "downloader", "family": "execution"},
				Enabled:     true,
			},
			{
				Name:        "crypto_miner",
				Description: "Detects cryptocurrency mining patterns",
				Severity:    "HIGH",
				Patterns:    []string{"(xmrig|cpuminer|ccminer|sgminer|cgminer)"},
				Condition:   "any of them",
				Metadata:    map[string]string{"category": "cryptominer", "family": "malware"},
				Enabled:     true,
			},
			{
				Name:        "backdoor_creation",
				Description: "Detects backdoor creation attempts",
				Severity:    "CRITICAL",
				Patterns:    []string{"(nc\\s+-l|netcat.*-l|socat.*EXEC|/dev/tcp/)"},
				Condition:   "any of them",
				Metadata:    map[string]string{"category": "backdoor", "family": "network"},
				Enabled:     true,
			},
			{
				Name:        "credential_harvesting",
				Description: "Detects credential harvesting attempts",
				Severity:    "HIGH",
				Patterns:    []string{"(\\.ssh/|\\.aws/|\\.docker/|password|passwd|shadow|authorized_keys)"},
				Condition:   "any of them",
				Metadata:    map[string]string{"category": "credentials", "family": "data-theft"},
				Enabled:     true,
			},
			{
				Name:        "system_modification",
				Description: "Detects system file modifications",
				Severity:    "HIGH",
				Patterns:    []string{"(/etc/passwd|/etc/shadow|/etc/hosts|/etc/crontab|/etc/sudoers)"},
				Condition:   "any of them",
				Metadata:    map[string]string{"category": "system", "family": "persistence"},
				Enabled:     true,
			},
			{
				Name:        "obfuscated_code",
				Description: "Detects code obfuscation patterns",
				Severity:    "MEDIUM",
				Patterns:    []string{"(eval\\s*\\(|exec\\s*\\(|base64.*decode|rot13|\\\\x[0-9a-fA-F]{2})"},
				Condition:   "any of them",
				Metadata:    map[string]string{"category": "obfuscation", "family": "evasion"},
				Enabled:     true,
			},
			{
				Name:        "privilege_escalation",
				Description: "Detects privilege escalation attempts",
				Severity:    "HIGH",
				Patterns:    []string{"(sudo\\s+su|chmod\\s+[47]77|setuid|setgid|pkexec)"},
				Condition:   "any of them",
				Metadata:    map[string]string{"category": "privilege-escalation", "family": "security"},
				Enabled:     true,
			},
			{
				Name:        "data_exfiltration",
				Description: "Detects data exfiltration patterns",
				Severity:    "HIGH",
				Patterns:    []string{"(scp\\s+.*@|rsync\\s+.*@|tar.*\\|\\s*nc|zip.*\\|\\s*curl)"},
				Condition:   "any of them",
				Metadata:    map[string]string{"category": "exfiltration", "family": "data-theft"},
				Enabled:     true,
			},
		}
	}
	
	return nil
}

func (sa *StaticAnalyzer) loadScriptPatterns() error {
	// Load script analysis patterns
	// This would load regex patterns, command lists, etc.
	
	// Enhanced script patterns for comprehensive analysis
	sa.scriptPatterns = []*ScriptPattern{
		{
			Name:        "base64_decode",
			Pattern:     "base64.*(-d|--decode)",
			Description: "Base64 decoding operation detected",
			RiskLevel:   "MEDIUM",
			Confidence:  0.7,
			Enabled:     true,
		},
		{
			Name:        "remote_execution",
			Pattern:     "(curl|wget).*\\|\\s*(bash|sh|python|perl)",
			Description: "Remote script execution pattern detected",
			RiskLevel:   "HIGH",
			Confidence:  0.9,
			Enabled:     true,
		},
		{
			Name:        "eval_execution",
			Pattern:     "eval\\s*\\(",
			Description: "Dynamic code evaluation detected",
			RiskLevel:   "HIGH",
			Confidence:  0.8,
			Enabled:     true,
		},
		{
			Name:        "system_command",
			Pattern:     "(system|exec|popen)\\s*\\(",
			Description: "System command execution detected",
			RiskLevel:   "HIGH",
			Confidence:  0.8,
			Enabled:     true,
		},
		{
			Name:        "network_listener",
			Pattern:     "nc\\s+-l\\s+\\d+",
			Description: "Network listener setup detected",
			RiskLevel:   "HIGH",
			Confidence:  0.9,
			Enabled:     true,
		},
		{
			Name:        "file_deletion",
			Pattern:     "rm\\s+-rf\\s+/",
			Description: "Dangerous file deletion pattern detected",
			RiskLevel:   "CRITICAL",
			Confidence:  0.95,
			Enabled:     true,
		},
		{
			Name:        "permission_change",
			Pattern:     "chmod\\s+[47]77",
			Description: "Dangerous permission change detected",
			RiskLevel:   "HIGH",
			Confidence:  0.8,
			Enabled:     true,
		},
		{
			Name:        "privilege_escalation",
			Pattern:     "sudo\\s+(su|passwd|useradd)",
			Description: "Privilege escalation attempt detected",
			RiskLevel:   "HIGH",
			Confidence:  0.8,
			Enabled:     true,
		},
		{
			Name:        "cron_modification",
			Pattern:     "crontab\\s+-e",
			Description: "Cron job modification detected",
			RiskLevel:   "MEDIUM",
			Confidence:  0.7,
			Enabled:     true,
		},
		{
			Name:        "background_process",
			Pattern:     "(nohup|screen|tmux).*&",
			Description: "Background process creation detected",
			RiskLevel:   "MEDIUM",
			Confidence:  0.6,
			Enabled:     true,
		},
	}
	
	return nil
}

func (sa *StaticAnalyzer) applyYaraRules(filePath string) ([]YaraMatch, error) {
	// Apply YARA rules to file - this is the basic implementation
	// The enhanced version is implemented in applyEnhancedYaraRules
	return sa.applyEnhancedYaraRules(filePath)
}

func (sa *StaticAnalyzer) applyEnhancedYaraRules(filePath string) ([]YaraMatch, error) {
	var matches []YaraMatch
	
	// Read file content
	content, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}
	
	contentStr := string(content)
	
	// Apply each YARA rule
	for _, rule := range sa.yaraRules {
		if !rule.Enabled {
			continue
		}
		
		// Check patterns in the rule
		for _, pattern := range rule.Patterns {
			if matched, _ := regexp.MatchString(pattern, contentStr); matched {
				// Find all matches with context
				re, err := regexp.Compile(pattern)
				if err != nil {
					continue
				}
				
				allMatches := re.FindAllStringIndex(contentStr, -1)
				var ruleMatches []YaraRuleMatch
				
				for _, match := range allMatches {
					start := match[0]
					end := match[1]
					
					// Get context around the match
					contextStart := max(0, start-50)
					contextEnd := minInt(len(contentStr), end+50)
					context := contentStr[contextStart:contextEnd]
					
					ruleMatches = append(ruleMatches, YaraRuleMatch{
						Offset:  int64(start),
						Length:  end - start,
						Data:    contentStr[start:end],
						Context: context,
					})
				}
				
				if len(ruleMatches) > 0 {
					matches = append(matches, YaraMatch{
						RuleName:    rule.Name,
						FileName:    filePath,
						Matches:     ruleMatches,
						Metadata:    rule.Metadata,
						RiskLevel:   rule.Severity,
						Description: rule.Description,
					})
				}
			}
		}
	}
	
	return matches, nil
}

func (sa *StaticAnalyzer) performEnhancedAnalysis(filePath string) ([]Finding, error) {
	var findings []Finding
	
	// Read file content
	content, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}
	
	contentStr := string(content)
	lines := strings.Split(contentStr, "\n")
	
	// Enhanced pattern detection
	enhancedPatterns := map[string]struct {
		severity    string
		description string
		confidence  float64
	}{
		`eval\s*\(`:                    {"HIGH", "Dynamic code execution detected", 0.9},
		`exec\s*\(`:                    {"HIGH", "Command execution detected", 0.9},
		`system\s*\(`:                  {"HIGH", "System command execution detected", 0.9},
		`shell_exec\s*\(`:              {"HIGH", "Shell execution detected", 0.9},
		`base64_decode\s*\(`:           {"MEDIUM", "Base64 decoding detected", 0.7},
		`file_get_contents\s*\(.*http`: {"MEDIUM", "Remote file inclusion detected", 0.8},
		`curl_exec\s*\(`:               {"MEDIUM", "HTTP request execution detected", 0.7},
		`\$_GET\[.*\]`:                 {"MEDIUM", "User input handling detected", 0.6},
		`\$_POST\[.*\]`:                {"MEDIUM", "User input handling detected", 0.6},
		`\$_REQUEST\[.*\]`:             {"HIGH", "Unsafe user input handling detected", 0.8},
		`chmod\s+777`:                  {"HIGH", "Dangerous file permissions detected", 0.9},
		`rm\s+-rf\s+/`:                 {"CRITICAL", "Dangerous file deletion detected", 0.95},
		`wget.*\|.*sh`:                 {"HIGH", "Remote script execution detected", 0.9},
		`curl.*\|.*bash`:               {"HIGH", "Remote script execution detected", 0.9},
		`nc\s+-l`:                      {"HIGH", "Network listener detected", 0.8},
		`/dev/tcp/`:                    {"MEDIUM", "Network connection detected", 0.7},
		`python.*-c.*`:                 {"MEDIUM", "Inline Python execution detected", 0.6},
		`perl.*-e.*`:                   {"MEDIUM", "Inline Perl execution detected", 0.6},
		`awk.*system\(`:                {"HIGH", "AWK system call detected", 0.8},
		`find.*-exec`:                  {"MEDIUM", "Find with execution detected", 0.6},
		`xargs.*sh`:                    {"MEDIUM", "Xargs shell execution detected", 0.7},
		`sudo\s+.*`:                    {"MEDIUM", "Privilege escalation detected", 0.7},
		`su\s+-.*`:                     {"MEDIUM", "User switching detected", 0.7},
		`passwd\s+.*`:                  {"HIGH", "Password modification detected", 0.8},
		`crontab\s+-e`:                 {"MEDIUM", "Cron job modification detected", 0.7},
		`at\s+.*`:                      {"MEDIUM", "Scheduled task detected", 0.6},
		`nohup\s+.*&`:                  {"MEDIUM", "Background process detected", 0.6},
		`screen\s+-d`:                  {"MEDIUM", "Detached screen session detected", 0.6},
		`tmux\s+.*`:                    {"MEDIUM", "Terminal multiplexer detected", 0.6},
	}
	
	// Analyze each line
	for lineNum, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		
		// Check against enhanced patterns
		for pattern, info := range enhancedPatterns {
			if matched, _ := regexp.MatchString(pattern, line); matched {
				findings = append(findings, Finding{
					ID:          fmt.Sprintf("ENHANCED_%d", len(findings)+1),
					Type:        "enhanced_pattern",
					Severity:    info.severity,
					Title:       "Enhanced Pattern Detection",
					Description: info.description,
					File:        filePath,
					Line:        lineNum + 1,
					Evidence:    line,
					Remediation: "Review this code for potential security implications",
					Confidence:  info.confidence,
					Metadata: map[string]string{
						"pattern": pattern,
						"type":    "enhanced_detection",
					},
				})
			}
		}
		
		// Check for obfuscated code patterns
		if sa.detectObfuscation(line) {
			findings = append(findings, Finding{
				ID:          fmt.Sprintf("OBFUSCATION_%d", len(findings)+1),
				Type:        "obfuscation",
				Severity:    "HIGH",
				Title:       "Code Obfuscation Detected",
				Description: "Potentially obfuscated code detected",
				File:        filePath,
				Line:        lineNum + 1,
				Evidence:    line,
				Remediation: "Review obfuscated code for malicious intent",
				Confidence:  0.8,
				Metadata: map[string]string{
					"type": "obfuscation_detection",
				},
			})
		}
		
		// Check for suspicious URLs
		if sa.detectSuspiciousURLs(line) {
			findings = append(findings, Finding{
				ID:          fmt.Sprintf("SUSPICIOUS_URL_%d", len(findings)+1),
				Type:        "suspicious_url",
				Severity:    "MEDIUM",
				Title:       "Suspicious URL Detected",
				Description: "Potentially malicious URL detected",
				File:        filePath,
				Line:        lineNum + 1,
				Evidence:    line,
				Remediation: "Verify the legitimacy of the URL",
				Confidence:  0.7,
				Metadata: map[string]string{
					"type": "url_detection",
				},
			})
		}
	}
	
	return findings, nil
}

// Helper functions for enhanced analysis
func (sa *StaticAnalyzer) detectObfuscation(line string) bool {
	// Detect various obfuscation techniques
	obfuscationPatterns := []string{
		`[a-zA-Z0-9+/]{50,}={0,2}`, // Base64-like strings
		`\\x[0-9a-fA-F]{2}`,        // Hex encoding
		`\\[0-7]{3}`,               // Octal encoding
		`\$\{[^}]{20,}\}`,          // Long variable substitutions
		`[a-zA-Z_][a-zA-Z0-9_]*\[['\"][^'\"]{20,}['\"]\]`, // Long array indices
	}
	
	for _, pattern := range obfuscationPatterns {
		if matched, _ := regexp.MatchString(pattern, line); matched {
			return true
		}
	}
	
	// Check for excessive string concatenation (potential obfuscation)
	if strings.Count(line, "+") > 10 || strings.Count(line, ".") > 15 {
		return true
	}
	
	return false
}

func (sa *StaticAnalyzer) detectSuspiciousURLs(line string) bool {
	// Extract URLs from the line
	urlPattern := `https?://[^\s'"<>]+`
	re := regexp.MustCompile(urlPattern)
	urls := re.FindAllString(line, -1)
	
	for _, url := range urls {
		// Check for suspicious URL characteristics
		if sa.isSuspiciousURL(url) {
			return true
		}
	}
	
	return false
}

func (sa *StaticAnalyzer) isSuspiciousURL(url string) bool {
	// Check for various suspicious URL patterns
	suspiciousPatterns := []string{
		`\d+\.\d+\.\d+\.\d+`,           // IP addresses
		`[a-z0-9]{20,}\.com`,           // Long random domains
		`bit\.ly|tinyurl|t\.co|goo\.gl`, // URL shorteners
		`\.tk|\.ml|\.ga|\.cf`,          // Suspicious TLDs
		`[0-9]{4,}\.`,                  // Domains with many numbers
		`-{3,}`,                        // Multiple dashes
		`[a-z]{1,3}\.[a-z]{1,3}\.[a-z]{1,3}`, // Very short domain parts
	}
	
	for _, pattern := range suspiciousPatterns {
		if matched, _ := regexp.MatchString(pattern, url); matched {
			return true
		}
	}
	
	return false
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func (sa *StaticAnalyzer) generateFindings(result *AnalysisResult) {
	// Generate security findings based on analysis
	for _, script := range result.InstallScripts {
		for _, cmd := range script.SuspiciousCommands {
			result.Findings = append(result.Findings, Finding{
				ID:          fmt.Sprintf("SCRIPT_%d", len(result.Findings)+1),
				Type:        "suspicious_command",
				Severity:    cmd.RiskLevel,
				Title:       "Suspicious Command Detected",
				Description: cmd.Description,
				File:        script.FilePath,
				Line:        cmd.LineNumber,
				Evidence:    cmd.Context,
				Remediation: "Review the necessity of this command and ensure it's safe",
				Confidence:  cmd.Confidence,
			})
		}
	}
}

func (sa *StaticAnalyzer) generateRecommendations(result *AnalysisResult) {
	// Generate recommendations based on findings
	if result.RiskScore > 0.6 {
		result.Recommendations = append(result.Recommendations, "Manual security review recommended")
	}
	if len(result.InstallScripts) > 0 {
		result.Recommendations = append(result.Recommendations, "Review all installation scripts for malicious content")
	}
}

func (sa *StaticAnalyzer) generateScriptRecommendation(analysis *InstallScriptAnalysis) string {
	if analysis.RiskScore > 0.8 {
		return "HIGH RISK: Manual review required before execution"
	} else if analysis.RiskScore > 0.5 {
		return "MEDIUM RISK: Caution advised, review suspicious commands"
	}
	return "LOW RISK: Script appears safe"
}

func (sa *StaticAnalyzer) generateManifestRecommendation(analysis *ManifestAnalysis) string {
	if analysis.RiskScore > 0.8 {
		return "HIGH RISK: Manifest contains suspicious elements"
	} else if analysis.RiskScore > 0.5 {
		return "MEDIUM RISK: Review manifest for potential issues"
	}
	return "LOW RISK: Manifest appears normal"
}

func min(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}
