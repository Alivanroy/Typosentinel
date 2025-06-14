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
	config *Config
	yaraRules []*YaraRule
	scriptPatterns []*ScriptPattern
}

// Config contains static analyzer configuration
type Config struct {
	Enabled                bool     `yaml:"enabled"`
	AnalyzeInstallScripts  bool     `yaml:"analyze_install_scripts"`
	AnalyzeManifests       bool     `yaml:"analyze_manifests"`
	YaraRulesEnabled       bool     `yaml:"yara_rules_enabled"`
	YaraRulesPath          string   `yaml:"yara_rules_path"`
	SuspiciousCommands     []string `yaml:"suspicious_commands"`
	DangerousPermissions   []string `yaml:"dangerous_permissions"`
	MaxFileSize            int64    `yaml:"max_file_size"`
	Timeout                string   `yaml:"timeout"`
	Verbose                bool     `yaml:"verbose"`
}

// AnalysisResult represents static analysis results
type AnalysisResult struct {
	PackageName       string                 `json:"package_name"`
	Registry          string                 `json:"registry"`
	AnalysisTimestamp time.Time              `json:"analysis_timestamp"`
	
	// Install script analysis
	InstallScripts    []InstallScriptAnalysis `json:"install_scripts"`
	
	// Manifest analysis
	Manifests         []ManifestAnalysis      `json:"manifests"`
	
	// YARA rule matches
	YaraMatches       []YaraMatch             `json:"yara_matches"`
	
	// Overall assessment
	RiskScore         float64                 `json:"risk_score"`
	ThreatLevel       string                  `json:"threat_level"`
	Findings          []Finding               `json:"findings"`
	Warnings          []string                `json:"warnings"`
	Recommendations   []string                `json:"recommendations"`
	
	// Metadata
	ProcessingTime    time.Duration           `json:"processing_time"`
	FilesAnalyzed     int                     `json:"files_analyzed"`
	TotalFileSize     int64                   `json:"total_file_size"`
}

// InstallScriptAnalysis represents analysis of installation scripts
type InstallScriptAnalysis struct {
	FilePath          string              `json:"file_path"`
	ScriptType        string              `json:"script_type"`
	FileSize          int64               `json:"file_size"`
	SuspiciousCommands []SuspiciousCommand `json:"suspicious_commands"`
	NetworkCalls      []NetworkCall       `json:"network_calls"`
	FileOperations    []FileOperation     `json:"file_operations"`
	PermissionChanges []PermissionChange  `json:"permission_changes"`
	EnvironmentAccess []EnvironmentAccess `json:"environment_access"`
	RiskScore         float64             `json:"risk_score"`
	Recommendation    string              `json:"recommendation"`
}

// ManifestAnalysis represents analysis of package manifests
type ManifestAnalysis struct {
	FilePath           string                 `json:"file_path"`
	ManifestType       string                 `json:"manifest_type"`
	FileSize           int64                  `json:"file_size"`
	Dependencies       []DependencyAnalysis   `json:"dependencies"`
	Scripts            map[string]string      `json:"scripts"`
	SuspiciousFields   []SuspiciousField      `json:"suspicious_fields"`
	MissingFields      []string               `json:"missing_fields"`
	VersionAnomalies   []VersionAnomaly       `json:"version_anomalies"`
	LicenseIssues      []LicenseIssue         `json:"license_issues"`
	RiskScore          float64                `json:"risk_score"`
	Recommendation     string                 `json:"recommendation"`
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
	Field       string  `json:"field"`
	Value       string  `json:"value"`
	Reason      string  `json:"reason"`
	RiskLevel   string  `json:"risk_level"`
	Confidence  float64 `json:"confidence"`
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
		FilePath:          scriptPath,
		ScriptType:        sa.detectScriptType(scriptPath),
		FileSize:          info.Size(),
		SuspiciousCommands: []SuspiciousCommand{},
		NetworkCalls:      []NetworkCall{},
		FileOperations:    []FileOperation{},
		PermissionChanges: []PermissionChange{},
		EnvironmentAccess: []EnvironmentAccess{},
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

// Placeholder implementations for detailed analysis functions
// In production, these would contain comprehensive logic for each analysis type

func (sa *StaticAnalyzer) analyzeSuspiciousCommands(line string, lineNumber int, analysis *InstallScriptAnalysis) {
	for _, cmd := range sa.config.SuspiciousCommands {
		if strings.Contains(strings.ToLower(line), strings.ToLower(cmd)) {
			analysis.SuspiciousCommands = append(analysis.SuspiciousCommands, SuspiciousCommand{
				Command:     cmd,
				LineNumber:  lineNumber,
				Context:     line,
				RiskLevel:   "HIGH",
				Description: fmt.Sprintf("Suspicious command '%s' detected", cmd),
				Confidence:  0.8,
			})
		}
	}
}

func (sa *StaticAnalyzer) analyzeNetworkCalls(line string, lineNumber int, analysis *InstallScriptAnalysis) {
	// Detect network calls (curl, wget, etc.)
	networkPatterns := []string{
		`curl\s+.*https?://`,
		`wget\s+.*https?://`,
		`fetch\s+.*https?://`,
	}
	
	for _, pattern := range networkPatterns {
		if matched, _ := regexp.MatchString(pattern, line); matched {
			analysis.NetworkCalls = append(analysis.NetworkCalls, NetworkCall{
				URL:         "detected",
				Method:      "GET",
				LineNumber:  lineNumber,
				Context:     line,
				RiskLevel:   "MEDIUM",
				Description: "Network call detected",
				Confidence:  0.7,
			})
		}
	}
}

func (sa *StaticAnalyzer) analyzeFileOperations(line string, lineNumber int, analysis *InstallScriptAnalysis) {
	// Detect file operations
	filePatterns := []string{
		`rm\s+-rf`,
		`cp\s+.*`,
		`mv\s+.*`,
		`mkdir\s+.*`,
	}
	
	for _, pattern := range filePatterns {
		if matched, _ := regexp.MatchString(pattern, line); matched {
			analysis.FileOperations = append(analysis.FileOperations, FileOperation{
				Operation:   "file_operation",
				Path:        "detected",
				LineNumber:  lineNumber,
				Context:     line,
				RiskLevel:   "MEDIUM",
				Description: "File operation detected",
				Confidence:  0.6,
			})
		}
	}
}

func (sa *StaticAnalyzer) analyzePermissionChanges(line string, lineNumber int, analysis *InstallScriptAnalysis) {
	// Detect permission changes
	if strings.Contains(line, "chmod") {
		for _, perm := range sa.config.DangerousPermissions {
			if strings.Contains(line, perm) {
				analysis.PermissionChanges = append(analysis.PermissionChanges, PermissionChange{
					Path:        "detected",
					Permissions: perm,
					LineNumber:  lineNumber,
					Context:     line,
					RiskLevel:   "HIGH",
					Description: fmt.Sprintf("Dangerous permission '%s' detected", perm),
					Confidence:  0.9,
				})
			}
		}
	}
}

func (sa *StaticAnalyzer) analyzeEnvironmentAccess(line string, lineNumber int, analysis *InstallScriptAnalysis) {
	// Detect environment variable access
	envPattern := `\$[A-Z_][A-Z0-9_]*`
	if matched, _ := regexp.MatchString(envPattern, line); matched {
		analysis.EnvironmentAccess = append(analysis.EnvironmentAccess, EnvironmentAccess{
			Variable:    "detected",
			Operation:   "read",
			LineNumber:  lineNumber,
			Context:     line,
			RiskLevel:   "LOW",
			Description: "Environment variable access detected",
			Confidence:  0.5,
		})
	}
}

// Placeholder manifest analysis functions
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
		result.RiskScore = min(totalRisk / float64(count), 1.0)
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

// Placeholder functions for loading rules and generating recommendations
func (sa *StaticAnalyzer) loadYaraRules() error {
	// Load YARA rules from configuration
	sa.yaraRules = []*YaraRule{
		{
			Name:        "suspicious_download",
			Description: "Detects suspicious download patterns",
			Severity:    "HIGH",
			Patterns:    []string{"curl.*|.*wget.*"},
			Enabled:     true,
		},
	}
	return nil
}

func (sa *StaticAnalyzer) loadScriptPatterns() error {
	// Load script analysis patterns
	sa.scriptPatterns = []*ScriptPattern{
		{
			Name:        "base64_decode",
			Pattern:     "base64.*-d",
			Description: "Base64 decoding detected",
			RiskLevel:   "MEDIUM",
			Confidence:  0.7,
			Enabled:     true,
		},
	}
	return nil
}

func (sa *StaticAnalyzer) applyYaraRules(filePath string) ([]YaraMatch, error) {
	// Apply YARA rules to file
	return []YaraMatch{}, nil
}

func (sa *StaticAnalyzer) applyEnhancedYaraRules(filePath string) ([]YaraMatch, error) {
	// Apply enhanced YARA rules to file with improved detection
	return []YaraMatch{}, nil
}

func (sa *StaticAnalyzer) performEnhancedAnalysis(filePath string) ([]Finding, error) {
	// Perform enhanced static analysis on file
	return []Finding{}, nil
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