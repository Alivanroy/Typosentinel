package static

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/typosentinel/typosentinel/internal/types"
)

type Severity int

const (
	Low Severity = iota
	Medium
	High
	Critical
)

func (s Severity) String() string {
	switch s {
	case Low:
		return "low"
	case Medium:
		return "medium"
	case High:
		return "high"
	case Critical:
		return "critical"
	default:
		return "unknown"
	}
}

type Finding struct {
	Rule        string    `json:"rule"`
	Severity    Severity  `json:"severity"`
	Message     string    `json:"message"`
	Evidence    []string  `json:"evidence"`
	Confidence  float64   `json:"confidence"`
	Location    string    `json:"location,omitempty"`
	Remediation string    `json:"remediation,omitempty"`
	Timestamp   time.Time `json:"timestamp"`
}

type Rule interface {
	Name() string
	Description() string
	Severity() Severity
	Check(pkg *types.Package, code []byte) ([]*Finding, error)
}

type RuleEngine struct {
	rules []Rule
}

func NewRuleEngine() *RuleEngine {
	engine := &RuleEngine{
		rules: make([]Rule, 0),
	}

	// Register all built-in rules
	engine.RegisterRule(&SuspiciousNetworkRule{})
	engine.RegisterRule(&MaliciousCodePatternsRule{})
	engine.RegisterRule(&ObfuscatedCodeRule{})
	engine.RegisterRule(&SuspiciousFileOperationsRule{})
	engine.RegisterRule(&CryptocurrencyMiningRule{})
	engine.RegisterRule(&DataExfiltrationRule{})
	engine.RegisterRule(&PrivilegeEscalationRule{})
	engine.RegisterRule(&SuspiciousImportsRule{})
	engine.RegisterRule(&HardcodedCredentialsRule{})
	engine.RegisterRule(&SuspiciousMetadataRule{})
	engine.RegisterRule(&TyposquattingRule{})
	engine.RegisterRule(&SuspiciousInstallScriptsRule{})

	return engine
}

func (re *RuleEngine) RegisterRule(rule Rule) {
	re.rules = append(re.rules, rule)
}

func (re *RuleEngine) AnalyzePackage(pkg *types.Package, code []byte) ([]*Finding, error) {
	var allFindings []*Finding

	for _, rule := range re.rules {
		findings, err := rule.Check(pkg, code)
		if err != nil {
			// Log error but continue with other rules
			fmt.Printf("Rule %s failed: %v\n", rule.Name(), err)
			continue
		}
		allFindings = append(allFindings, findings...)
	}

	return allFindings, nil
}

// SuspiciousNetworkRule detects suspicious network calls
type SuspiciousNetworkRule struct{}

func (r *SuspiciousNetworkRule) Name() string {
	return "suspicious_network_calls"
}

func (r *SuspiciousNetworkRule) Description() string {
	return "Detects suspicious network requests to non-standard domains"
}

func (r *SuspiciousNetworkRule) Severity() Severity {
	return High
}

func (r *SuspiciousNetworkRule) Check(pkg *types.Package, code []byte) ([]*Finding, error) {
	suspiciousPatterns := []*regexp.Regexp{
		regexp.MustCompile(`requests\.get\(['"]https?://(?!pypi\.org|npmjs\.com|github\.com|githubusercontent\.com)[^'"]+['"]`),
		regexp.MustCompile(`urllib\.request\.urlopen\(['"]https?://(?!pypi\.org|npmjs\.com|github\.com)[^'"]+['"]`),
		regexp.MustCompile(`fetch\(['"]https?://(?!npmjs\.com|github\.com|unpkg\.com)[^'"]+['"]`),
		regexp.MustCompile(`XMLHttpRequest.*open\([^,]*['"]https?://(?!npmjs\.com|github\.com)[^'"]+['"]`),
		regexp.MustCompile(`axios\.[a-z]+\(['"]https?://(?!npmjs\.com|github\.com)[^'"]+['"]`),
	}

	var findings []*Finding
	codeStr := string(code)

	for _, pattern := range suspiciousPatterns {
		matches := pattern.FindAllString(codeStr, -1)
		if len(matches) > 0 {
			findings = append(findings, &Finding{
				Rule:        r.Name(),
				Severity:    r.Severity(),
				Message:     "Package makes suspicious network requests to external domains",
				Evidence:    matches,
				Confidence:  0.8,
				Remediation: "Review network requests and ensure they are legitimate",
				Timestamp:   time.Now(),
			})
			break
		}
	}

	return findings, nil
}

// MaliciousCodePatternsRule detects common malicious code patterns
type MaliciousCodePatternsRule struct{}

func (r *MaliciousCodePatternsRule) Name() string {
	return "malicious_code_patterns"
}

func (r *MaliciousCodePatternsRule) Description() string {
	return "Detects common malicious code patterns like eval, exec, and shell commands"
}

func (r *MaliciousCodePatternsRule) Severity() Severity {
	return Critical
}

func (r *MaliciousCodePatternsRule) Check(pkg *types.Package, code []byte) ([]*Finding, error) {
	maliciousPatterns := map[string]*regexp.Regexp{
		"eval_usage":       regexp.MustCompile(`\beval\s*\(`),
		"exec_usage":       regexp.MustCompile(`\bexec\s*\(`),
		"subprocess_shell": regexp.MustCompile(`subprocess\.[a-zA-Z]*\([^)]*shell\s*=\s*True`),
		"os_system":        regexp.MustCompile(`os\.system\s*\(`),
		"child_process":    regexp.MustCompile(`child_process\.(exec|spawn|fork)`),
		"vm_run":           regexp.MustCompile(`vm\.runInNewContext|vm\.runInThisContext`),
	}

	var findings []*Finding
	codeStr := string(code)

	for patternName, pattern := range maliciousPatterns {
		matches := pattern.FindAllString(codeStr, -1)
		if len(matches) > 0 {
			findings = append(findings, &Finding{
				Rule:        r.Name(),
				Severity:    r.Severity(),
				Message:     fmt.Sprintf("Detected potentially malicious pattern: %s", patternName),
				Evidence:    matches,
				Confidence:  0.9,
				Remediation: "Review code execution patterns and ensure they are safe",
				Timestamp:   time.Now(),
			})
		}
	}

	return findings, nil
}

// ObfuscatedCodeRule detects code obfuscation
type ObfuscatedCodeRule struct{}

func (r *ObfuscatedCodeRule) Name() string {
	return "obfuscated_code"
}

func (r *ObfuscatedCodeRule) Description() string {
	return "Detects obfuscated or encoded code patterns"
}

func (r *ObfuscatedCodeRule) Severity() Severity {
	return High
}

func (r *ObfuscatedCodeRule) Check(pkg *types.Package, code []byte) ([]*Finding, error) {
	obfuscationPatterns := []*regexp.Regexp{
		regexp.MustCompile(`base64\.b64decode`),
		regexp.MustCompile(`atob\s*\(`),
		regexp.MustCompile(`Buffer\.from\([^)]*,\s*['"]base64['"]`),
		regexp.MustCompile(`\\x[0-9a-fA-F]{2}`), // Hex encoded strings
		regexp.MustCompile(`\\u[0-9a-fA-F]{4}`), // Unicode encoded strings
		regexp.MustCompile(`String\.fromCharCode`),
		regexp.MustCompile(`chr\s*\(\s*[0-9]+\s*\)`), // Python chr() with numbers
	}

	var findings []*Finding
	codeStr := string(code)

	// Count obfuscation indicators
	obfuscationCount := 0
	var evidence []string

	for _, pattern := range obfuscationPatterns {
		matches := pattern.FindAllString(codeStr, -1)
		if len(matches) > 0 {
			obfuscationCount += len(matches)
			evidence = append(evidence, matches...)
		}
	}

	// Trigger if multiple obfuscation patterns found
	if obfuscationCount >= 3 {
		findings = append(findings, &Finding{
			Rule:        r.Name(),
			Severity:    r.Severity(),
			Message:     fmt.Sprintf("Code contains %d obfuscation patterns", obfuscationCount),
			Evidence:    evidence,
			Confidence:  0.85,
			Remediation: "Review obfuscated code sections for malicious intent",
			Timestamp:   time.Now(),
		})
	}

	return findings, nil
}

// SuspiciousFileOperationsRule detects suspicious file operations
type SuspiciousFileOperationsRule struct{}

func (r *SuspiciousFileOperationsRule) Name() string {
	return "suspicious_file_operations"
}

func (r *SuspiciousFileOperationsRule) Description() string {
	return "Detects suspicious file system operations"
}

func (r *SuspiciousFileOperationsRule) Severity() Severity {
	return Medium
}

func (r *SuspiciousFileOperationsRule) Check(pkg *types.Package, code []byte) ([]*Finding, error) {
	suspiciousPatterns := map[string]*regexp.Regexp{
		"file_deletion":     regexp.MustCompile(`(os\.remove|fs\.unlink|shutil\.rmtree|rm\s+-rf)`),
		"system_file_read": regexp.MustCompile(`(open|readFile)\s*\(['"]/(etc|proc|sys|root)/`),
		"temp_file_write":  regexp.MustCompile(`(open|writeFile)\s*\(['"]/(tmp|temp)/[^'"]*\.(sh|bat|exe|py|js)['"]`),
		"hidden_file":      regexp.MustCompile(`(open|writeFile)\s*\(['"][^'"]*\.[^'"]*\.[^'"]*['"]`), // Double extensions
	}

	var findings []*Finding
	codeStr := string(code)

	for patternName, pattern := range suspiciousPatterns {
		matches := pattern.FindAllString(codeStr, -1)
		if len(matches) > 0 {
			findings = append(findings, &Finding{
				Rule:        r.Name(),
				Severity:    r.Severity(),
				Message:     fmt.Sprintf("Suspicious file operation detected: %s", patternName),
				Evidence:    matches,
				Confidence:  0.7,
				Remediation: "Review file operations for legitimacy",
				Timestamp:   time.Now(),
			})
		}
	}

	return findings, nil
}

// CryptocurrencyMiningRule detects cryptocurrency mining code
type CryptocurrencyMiningRule struct{}

func (r *CryptocurrencyMiningRule) Name() string {
	return "cryptocurrency_mining"
}

func (r *CryptocurrencyMiningRule) Description() string {
	return "Detects cryptocurrency mining related code"
}

func (r *CryptocurrencyMiningRule) Severity() Severity {
	return High
}

func (r *CryptocurrencyMiningRule) Check(pkg *types.Package, code []byte) ([]*Finding, error) {
	miningPatterns := []*regexp.Regexp{
		regexp.MustCompile(`(?i)(mining|miner|hashrate|stratum)`),
		regexp.MustCompile(`(?i)(bitcoin|ethereum|monero|litecoin|dogecoin)`),
		regexp.MustCompile(`(?i)(pool\.(minergate|nanopool|ethermine))`),
		regexp.MustCompile(`(?i)(xmrig|cpuminer|cgminer)`),
		regexp.MustCompile(`(?i)(cryptonight|scrypt|sha256)`),
	}

	var findings []*Finding
	codeStr := string(code)
	miningIndicators := 0
	var evidence []string

	for _, pattern := range miningPatterns {
		matches := pattern.FindAllString(codeStr, -1)
		if len(matches) > 0 {
			miningIndicators++
			evidence = append(evidence, matches...)
		}
	}

	// Trigger if multiple mining indicators found
	if miningIndicators >= 2 {
		findings = append(findings, &Finding{
			Rule:        r.Name(),
			Severity:    r.Severity(),
			Message:     "Package contains cryptocurrency mining indicators",
			Evidence:    evidence,
			Confidence:  0.8,
			Remediation: "Verify if cryptocurrency mining is legitimate for this package",
			Timestamp:   time.Now(),
		})
	}

	return findings, nil
}

// DataExfiltrationRule detects data exfiltration patterns
type DataExfiltrationRule struct{}

func (r *DataExfiltrationRule) Name() string {
	return "data_exfiltration"
}

func (r *DataExfiltrationRule) Description() string {
	return "Detects potential data exfiltration patterns"
}

func (r *DataExfiltrationRule) Severity() Severity {
	return Critical
}

func (r *DataExfiltrationRule) Check(pkg *types.Package, code []byte) ([]*Finding, error) {
	exfiltrationPatterns := []*regexp.Regexp{
		regexp.MustCompile(`(?i)(password|passwd|credential|token|key|secret)`),
		regexp.MustCompile(`(?i)(ssh|ftp|sftp|scp).*upload`),
		regexp.MustCompile(`(?i)email.*send.*attachment`),
		regexp.MustCompile(`(?i)(zip|tar|compress).*upload`),
		regexp.MustCompile(`(?i)document.*exfil`),
	}

	var findings []*Finding
	codeStr := string(code)

	for _, pattern := range exfiltrationPatterns {
		matches := pattern.FindAllString(codeStr, -1)
		if len(matches) > 0 {
			findings = append(findings, &Finding{
				Rule:        r.Name(),
				Severity:    r.Severity(),
				Message:     "Potential data exfiltration pattern detected",
				Evidence:    matches,
				Confidence:  0.75,
				Remediation: "Review data handling and transmission code",
				Timestamp:   time.Now(),
			})
			break
		}
	}

	return findings, nil
}

// PrivilegeEscalationRule detects privilege escalation attempts
type PrivilegeEscalationRule struct{}

func (r *PrivilegeEscalationRule) Name() string {
	return "privilege_escalation"
}

func (r *PrivilegeEscalationRule) Description() string {
	return "Detects potential privilege escalation attempts"
}

func (r *PrivilegeEscalationRule) Severity() Severity {
	return Critical
}

func (r *PrivilegeEscalationRule) Check(pkg *types.Package, code []byte) ([]*Finding, error) {
	escalationPatterns := []*regexp.Regexp{
		regexp.MustCompile(`(?i)sudo\s+`),
		regexp.MustCompile(`(?i)setuid|seteuid|setgid|setegid`),
		regexp.MustCompile(`(?i)runas\s+administrator`),
		regexp.MustCompile(`(?i)elevate.*privilege`),
		regexp.MustCompile(`(?i)bypass.*uac`),
	}

	var findings []*Finding
	codeStr := string(code)

	for _, pattern := range escalationPatterns {
		matches := pattern.FindAllString(codeStr, -1)
		if len(matches) > 0 {
			findings = append(findings, &Finding{
				Rule:        r.Name(),
				Severity:    r.Severity(),
				Message:     "Potential privilege escalation attempt detected",
				Evidence:    matches,
				Confidence:  0.85,
				Remediation: "Review privilege-related operations",
				Timestamp:   time.Now(),
			})
			break
		}
	}

	return findings, nil
}

// SuspiciousImportsRule detects suspicious imports
type SuspiciousImportsRule struct{}

func (r *SuspiciousImportsRule) Name() string {
	return "suspicious_imports"
}

func (r *SuspiciousImportsRule) Description() string {
	return "Detects suspicious or uncommon imports"
}

func (r *SuspiciousImportsRule) Severity() Severity {
	return Medium
}

func (r *SuspiciousImportsRule) Check(pkg *types.Package, code []byte) ([]*Finding, error) {
	suspiciousImports := []*regexp.Regexp{
		regexp.MustCompile(`import\s+(ctypes|winreg|_winreg)`),
		regexp.MustCompile(`require\s*\(['"]child_process['"]\)`),
		regexp.MustCompile(`import\s+keyring`),
		regexp.MustCompile(`require\s*\(['"]keytar['"]\)`),
		regexp.MustCompile(`import\s+(win32api|win32con|win32security)`),
	}

	var findings []*Finding
	codeStr := string(code)

	for _, pattern := range suspiciousImports {
		matches := pattern.FindAllString(codeStr, -1)
		if len(matches) > 0 {
			findings = append(findings, &Finding{
				Rule:        r.Name(),
				Severity:    r.Severity(),
				Message:     "Suspicious import detected",
				Evidence:    matches,
				Confidence:  0.6,
				Remediation: "Review the necessity of these imports",
				Timestamp:   time.Now(),
			})
		}
	}

	return findings, nil
}

// HardcodedCredentialsRule detects hardcoded credentials
type HardcodedCredentialsRule struct{}

func (r *HardcodedCredentialsRule) Name() string {
	return "hardcoded_credentials"
}

func (r *HardcodedCredentialsRule) Description() string {
	return "Detects hardcoded credentials and secrets"
}

func (r *HardcodedCredentialsRule) Severity() Severity {
	return High
}

func (r *HardcodedCredentialsRule) Check(pkg *types.Package, code []byte) ([]*Finding, error) {
	credentialPatterns := []*regexp.Regexp{
		regexp.MustCompile(`(?i)(password|passwd)\s*[=:]\s*['"][^'"]{8,}['"]`),
		regexp.MustCompile(`(?i)(api[_-]?key|apikey)\s*[=:]\s*['"][^'"]{16,}['"]`),
		regexp.MustCompile(`(?i)(secret|token)\s*[=:]\s*['"][^'"]{16,}['"]`),
		regexp.MustCompile(`(?i)(aws[_-]?access[_-]?key|aws[_-]?secret)`),
		regexp.MustCompile(`(?i)(github[_-]?token|gh[_-]?token)`),
	}

	var findings []*Finding
	codeStr := string(code)

	for _, pattern := range credentialPatterns {
		matches := pattern.FindAllString(codeStr, -1)
		if len(matches) > 0 {
			// Mask sensitive data in evidence
			maskedEvidence := make([]string, len(matches))
			for i, match := range matches {
				maskedEvidence[i] = r.maskCredential(match)
			}

			findings = append(findings, &Finding{
				Rule:        r.Name(),
				Severity:    r.Severity(),
				Message:     "Hardcoded credentials detected",
				Evidence:    maskedEvidence,
				Confidence:  0.9,
				Remediation: "Remove hardcoded credentials and use environment variables",
				Timestamp:   time.Now(),
			})
		}
	}

	return findings, nil
}

func (r *HardcodedCredentialsRule) maskCredential(credential string) string {
	// Mask the credential value while keeping the structure visible
	if len(credential) > 20 {
		return credential[:10] + "***MASKED***" + credential[len(credential)-5:]
	}
	return credential[:5] + "***MASKED***"
}

// SuspiciousMetadataRule analyzes package metadata
type SuspiciousMetadataRule struct{}

func (r *SuspiciousMetadataRule) Name() string {
	return "suspicious_metadata"
}

func (r *SuspiciousMetadataRule) Description() string {
	return "Analyzes package metadata for suspicious patterns"
}

func (r *SuspiciousMetadataRule) Severity() Severity {
	return Medium
}

func (r *SuspiciousMetadataRule) Check(pkg *types.Package, code []byte) ([]*Finding, error) {
	var findings []*Finding
	var evidence []string

	// Check for minimal metadata
	if pkg.Description == "" {
		evidence = append(evidence, "Missing package description")
	}

	if pkg.Author == "" {
		evidence = append(evidence, "Missing author information")
	}

	if pkg.Homepage == "" && pkg.Repository == "" {
		evidence = append(evidence, "Missing homepage and repository links")
	}

	// Check for suspicious version patterns
	if strings.Contains(pkg.Version, "alpha") || strings.Contains(pkg.Version, "beta") {
		evidence = append(evidence, "Pre-release version")
	}

	// Check for suspicious keywords
	suspiciousKeywords := []string{"hack", "crack", "exploit", "bypass", "stealer"}
	for _, keyword := range suspiciousKeywords {
		if strings.Contains(strings.ToLower(pkg.Description), keyword) {
			evidence = append(evidence, fmt.Sprintf("Suspicious keyword in description: %s", keyword))
		}
	}

	if len(evidence) >= 2 {
		findings = append(findings, &Finding{
			Rule:        r.Name(),
			Severity:    r.Severity(),
			Message:     "Package metadata contains suspicious patterns",
			Evidence:    evidence,
			Confidence:  0.6,
			Remediation: "Review package metadata for completeness and legitimacy",
			Timestamp:   time.Now(),
		})
	}

	return findings, nil
}

// TyposquattingRule detects potential typosquatting
type TyposquattingRule struct{}

func (r *TyposquattingRule) Name() string {
	return "typosquatting_detection"
}

func (r *TyposquattingRule) Description() string {
	return "Detects potential typosquatting based on package name patterns"
}

func (r *TyposquattingRule) Severity() Severity {
	return High
}

func (r *TyposquattingRule) Check(pkg *types.Package, code []byte) ([]*Finding, error) {
	var findings []*Finding
	var evidence []string

	// Common typosquatting patterns
	typoPatterns := []*regexp.Regexp{
		regexp.MustCompile(`[0o]`),  // 0 and o confusion
		regexp.MustCompile(`[1il]`), // 1, i, l confusion
		regexp.MustCompile(`rn`),    // rn looks like m
		regexp.MustCompile(`vv`),    // vv looks like w
	}

	typoCount := 0
	for _, pattern := range typoPatterns {
		if pattern.MatchString(pkg.Name) {
			typoCount++
			evidence = append(evidence, fmt.Sprintf("Potential character confusion: %s", pattern.String()))
		}
	}

	// Check for common legitimate package name variations
	legitimatePackages := []string{
		"requests", "urllib3", "numpy", "pandas", "flask", "django",
		"express", "lodash", "moment", "axios", "react", "vue",
	}

	for _, legitPkg := range legitimatePackages {
		if r.isSimilar(pkg.Name, legitPkg) {
			evidence = append(evidence, fmt.Sprintf("Similar to legitimate package: %s", legitPkg))
			typoCount += 2 // Higher weight for similarity to known packages
		}
	}

	if typoCount >= 2 {
		findings = append(findings, &Finding{
			Rule:        r.Name(),
			Severity:    r.Severity(),
			Message:     "Potential typosquatting detected",
			Evidence:    evidence,
			Confidence:  0.8,
			Remediation: "Verify package name spelling and legitimacy",
			Timestamp:   time.Now(),
		})
	}

	return findings, nil
}

func (r *TyposquattingRule) isSimilar(name1, name2 string) bool {
	// Simple similarity check based on edit distance
	if len(name1) == 0 || len(name2) == 0 {
		return false
	}

	// Calculate Levenshtein distance
	distance := r.levenshteinDistance(name1, name2)
	maxLen := len(name1)
	if len(name2) > maxLen {
		maxLen = len(name2)
	}

	// Consider similar if edit distance is small relative to length
	similarity := 1.0 - float64(distance)/float64(maxLen)
	return similarity > 0.8 && distance <= 2
}

func (r *TyposquattingRule) levenshteinDistance(s1, s2 string) int {
	if len(s1) == 0 {
		return len(s2)
	}
	if len(s2) == 0 {
		return len(s1)
	}

	matrix := make([][]int, len(s1)+1)
	for i := range matrix {
		matrix[i] = make([]int, len(s2)+1)
		matrix[i][0] = i
	}
	for j := range matrix[0] {
		matrix[0][j] = j
	}

	for i := 1; i <= len(s1); i++ {
		for j := 1; j <= len(s2); j++ {
			cost := 0
			if s1[i-1] != s2[j-1] {
				cost = 1
			}
			matrix[i][j] = min(
				matrix[i-1][j]+1,      // deletion
				matrix[i][j-1]+1,      // insertion
				matrix[i-1][j-1]+cost, // substitution
			)
		}
	}

	return matrix[len(s1)][len(s2)]
}

func min(a, b, c int) int {
	if a < b {
		if a < c {
			return a
		}
		return c
	}
	if b < c {
		return b
	}
	return c
}

// SuspiciousInstallScriptsRule detects suspicious installation scripts
type SuspiciousInstallScriptsRule struct{}

func (r *SuspiciousInstallScriptsRule) Name() string {
	return "suspicious_install_scripts"
}

func (r *SuspiciousInstallScriptsRule) Description() string {
	return "Detects suspicious patterns in installation scripts"
}

func (r *SuspiciousInstallScriptsRule) Severity() Severity {
	return High
}

func (r *SuspiciousInstallScriptsRule) Check(pkg *types.Package, code []byte) ([]*Finding, error) {
	installPatterns := []*regexp.Regexp{
		regexp.MustCompile(`(?i)postinstall.*curl`),
		regexp.MustCompile(`(?i)postinstall.*wget`),
		regexp.MustCompile(`(?i)preinstall.*rm\s+-rf`),
		regexp.MustCompile(`(?i)(postinstall|preinstall).*chmod\s+\+x`),
		regexp.MustCompile(`(?i)(postinstall|preinstall).*\.(sh|bat|exe)`),
	}

	var findings []*Finding
	codeStr := string(code)

	for _, pattern := range installPatterns {
		matches := pattern.FindAllString(codeStr, -1)
		if len(matches) > 0 {
			findings = append(findings, &Finding{
				Rule:        r.Name(),
				Severity:    r.Severity(),
				Message:     "Suspicious installation script detected",
				Evidence:    matches,
				Confidence:  0.85,
				Remediation: "Review installation scripts for malicious behavior",
				Timestamp:   time.Now(),
			})
			break
		}
	}

	return findings, nil
}