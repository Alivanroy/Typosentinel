package scanner

import (
	"encoding/base64"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/Alivanroy/Typosentinel/pkg/types"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

// ContentScanner scans package contents for malicious patterns
type ContentScanner struct {
	maxFileSize       int64
	entropyThreshold  float64
	windowSize        int
	includeGlobs      []string
	excludeGlobs      []string
	suspiciousIPs     []string
	suspiciousDomains []string
}

// NewContentScanner creates a new content scanner
func NewContentScanner() *ContentScanner {
	// Configurable thresholds
	maxSize := viper.GetInt64("scanner.content.max_file_size")
	if maxSize <= 0 {
		maxSize = 1 * 1024 * 1024
	}
	entropy := viper.GetFloat64("scanner.content.entropy_threshold")
	if entropy <= 0 {
		entropy = 7.0
	}
	win := viper.GetInt("scanner.content.entropy_window")
	if win <= 0 {
		win = 256
	}
	inc := viper.GetStringSlice("scanner.content.include_globs")
	exc := viper.GetStringSlice("scanner.content.exclude_globs")

	return &ContentScanner{
		maxFileSize:      maxSize,
		entropyThreshold: entropy,
		windowSize:       win,
		includeGlobs:     inc,
		excludeGlobs:     exc,
		suspiciousIPs: []string{
			// Known malicious IPs (examples - in production, use threat intel feeds)
			"0.0.0.0",
		},
		suspiciousDomains: []string{
			// Suspicious TLDs and patterns
			".tk", ".ml", ".ga", ".cf", // Free TLDs often used by attackers
		},
	}
}

// ScanDirectory scans all files in a directory for malicious content
func (cs *ContentScanner) ScanDirectory(path string) ([]types.Threat, error) {
	var threats []types.Threat
	var scannedFiles int
	var suspiciousFiles []string

	err := filepath.Walk(path, func(filePath string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // Skip files with errors
		}

		// Skip directories
		if info.IsDir() {
			return nil
		}

		// Include/exclude filters
		rel, _ := filepath.Rel(path, filePath)
		if len(cs.includeGlobs) > 0 {
			matched := false
			for _, g := range cs.includeGlobs {
				if ok, _ := filepath.Match(g, rel); ok {
					matched = true
					break
				}
			}
			if !matched {
				return nil
			}
		}
		for _, g := range cs.excludeGlobs {
			if ok, _ := filepath.Match(g, rel); ok {
				return nil
			}
		}

		// Skip very large files
		if info.Size() > cs.maxFileSize {
			return nil
		}

		// Skip binary files (already handled by BinaryDetector)
		if cs.isBinaryFile(filePath) {
			return nil
		}

		// Scan text files for suspicious patterns
		fileThreats := cs.scanFile(filePath)
		if len(fileThreats) > 0 {
			threats = append(threats, fileThreats...)
			relPath, _ := filepath.Rel(path, filePath)
			suspiciousFiles = append(suspiciousFiles, relPath)
		}

		scannedFiles++
		return nil
	})

	if err != nil {
		return threats, err
	}

	logrus.Debugf("Content scanner: scanned %d files, found %d threats", scannedFiles, len(threats))
	return threats, nil
}

// scanFile scans a single file for malicious content
func (cs *ContentScanner) scanFile(filePath string) []types.Threat {
	content, err := os.ReadFile(filePath)
	if err != nil {
		return nil
	}

	contentStr := string(content)
	var threats []types.Threat

	// Check for high entropy (obfuscated/encrypted content) global and windowed
	if entropy := cs.calculateEntropy(contentStr); entropy > cs.entropyThreshold {
		threats = append(threats, cs.createEntropyThreat(filePath, entropy))
	}
	if spans := cs.detectHighEntropySpans(contentStr, cs.windowSize, cs.entropyThreshold); len(spans) > 0 {
		threats = append(threats, cs.createEntropySpanThreat(filePath, spans[0]))
	}

	// Check for suspicious patterns
	if patterns := cs.detectSuspiciousPatterns(contentStr); len(patterns) > 0 {
		threats = append(threats, cs.createPatternThreat(filePath, patterns))
	}

	// Check for embedded secrets/credentials
	if secrets := cs.detectEmbeddedSecrets(contentStr); len(secrets) > 0 {
		threats = append(threats, cs.createSecretThreat(filePath, secrets))
	}

	// Check for network indicators
	if networks := cs.detectNetworkIndicators(contentStr); len(networks) > 0 {
		threats = append(threats, cs.createNetworkThreat(filePath, networks))
	}

	return threats
}

// calculateEntropy calculates Shannon entropy of a string
func (cs *ContentScanner) calculateEntropy(data string) float64 {
	if len(data) == 0 {
		return 0.0
	}

	// Count character frequencies
	freq := make(map[rune]int)
	for _, char := range data {
		freq[char]++
	}

	// Calculate entropy
	var entropy float64
	length := float64(len(data))
	for _, count := range freq {
		if count > 0 {
			p := float64(count) / length
			entropy -= p * math.Log2(p)
		}
	}

	return entropy
}

type entropySpan struct {
	start int
	end   int
	score float64
}

func (cs *ContentScanner) detectHighEntropySpans(data string, window int, threshold float64) []entropySpan {
	var spans []entropySpan
	if window <= 0 || len(data) == 0 {
		return spans
	}
	w := window
	if w > len(data) {
		w = len(data)
	}
	step := w / 2
	if step <= 0 {
		step = w
	}
	for i := 0; i <= len(data)-w; i += step {
		seg := data[i : i+w]
		s := cs.calculateEntropy(seg)
		if s >= threshold {
			spans = append(spans, entropySpan{start: i, end: i + w, score: s})
		}
	}
	return spans
}

// detectSuspiciousPatterns detects obfuscation and suspicious code patterns
func (cs *ContentScanner) detectSuspiciousPatterns(content string) []string {
	var patterns []string

	// Eval chains
	if strings.Contains(content, "eval(") && strings.Count(content, "eval") > 3 {
		patterns = append(patterns, "Multiple eval calls (potential code injection)")
	}

	// Base64 encoded payloads
	base64Regex := regexp.MustCompile(`[A-Za-z0-9+/]{50,}={0,2}`)
	if matches := base64Regex.FindAllString(content, -1); len(matches) > 5 {
		// Try to decode to see if it's actual base64
		for _, match := range matches[:min(5, len(matches))] {
			if decoded, err := base64.StdEncoding.DecodeString(match); err == nil && len(decoded) > 20 {
				patterns = append(patterns, "Large base64 encoded strings detected")
				break
			}
		}
	}

	// Hex encoded strings
	hexRegex := regexp.MustCompile(`\\x[0-9a-fA-F]{2}`)
	if hexMatches := hexRegex.FindAllString(content, -1); len(hexMatches) > 20 {
		patterns = append(patterns, "Extensive hex encoding (potential obfuscation)")
	}

	// Unicode escapes
	unicodeRegex := regexp.MustCompile(`\\u[0-9a-fA-F]{4}`)
	if unicodeMatches := unicodeRegex.FindAllString(content, -1); len(unicodeMatches) > 20 {
		patterns = append(patterns, "Extensive unicode escaping (potential obfuscation)")
	}

	// Suspicious function chains
	suspiciousFuncs := []string{"fromCharCode", "unescape", "escape", "atob", "btoa"}
	count := 0
	for _, fn := range suspiciousFuncs {
		if strings.Contains(content, fn) {
			count++
		}
	}
	if count >= 3 {
		patterns = append(patterns, "Multiple encoding/decoding functions")
	}

	// Minified variables (single char names in excess)
	singleCharRegex := regexp.MustCompile(`\b[a-z]\s*=\s*`)
	if singleCharMatches := singleCharRegex.FindAllString(content, -1); len(singleCharMatches) > 30 {
		patterns = append(patterns, "Excessive single-character variables (minification or obfuscation)")
	}

	return patterns
}

// detectEmbeddedSecrets detects embedded API keys, tokens, and credentials
func (cs *ContentScanner) detectEmbeddedSecrets(content string) []string {
	var secrets []string

	// API Key patterns
	patterns := map[string]*regexp.Regexp{
		"Generic API Key":    regexp.MustCompile(`(?i)(api[_-]?key|apikey)["\s:=]+[a-zA-Z0-9]{20,}`),
		"AWS Key":            regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
		"GitHub Token":       regexp.MustCompile(`ghp_[a-zA-Z0-9]{36}`),
		"Generic Secret":     regexp.MustCompile(`(?i)(secret|password|passwd|pwd)["\s:=]+[^\s"']{8,}`),
		"Private Key Header": regexp.MustCompile(`-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----`),
		"JWT Token":          regexp.MustCompile(`eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*`),
	}

	for secretType, pattern := range patterns {
		if pattern.MatchString(content) {
			secrets = append(secrets, secretType)
		}
	}

	return secrets
}

// detectNetworkIndicators detects suspicious IPs and domains
func (cs *ContentScanner) detectNetworkIndicators(content string) []string {
	var indicators []string

	// IP address pattern
	ipRegex := regexp.MustCompile(`\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b`)
	ips := ipRegex.FindAllString(content, -1)

	// Filter out common safe IPs (localhost, private networks)
	safeIPPrefixes := []string{"127.", "192.168.", "10.", "172.16."}
	for _, ip := range ips {
		isSafe := false
		for _, prefix := range safeIPPrefixes {
			if strings.HasPrefix(ip, prefix) {
				isSafe = true
				break
			}
		}
		if !isSafe {
			indicators = append(indicators, fmt.Sprintf("External IP: %s", ip))
		}
	}

	// Check for suspicious TLDs
	for _, domain := range cs.suspiciousDomains {
		if strings.Contains(content, domain) {
			indicators = append(indicators, fmt.Sprintf("Suspicious TLD: %s", domain))
		}
	}

	// Check for HTTP/HTTPS requests to external domains
	urlRegex := regexp.MustCompile(`https?://[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`)
	urls := urlRegex.FindAllString(content, -1)
	if len(urls) > 5 {
		indicators = append(indicators, fmt.Sprintf("Multiple external URLs (%d found)", len(urls)))
	}

	return indicators
}

// Threat creation helpers

func (cs *ContentScanner) createEntropyThreat(filePath string, entropy float64) types.Threat {
	relPath := filepath.Base(filePath)
	return types.Threat{
		Type:            types.ThreatTypeObfuscatedCode,
		Severity:        types.SeverityHigh,
		Confidence:      0.8,
		Description:     fmt.Sprintf("File '%s' has high entropy (%.2f), indicating potential obfuscation or encryption", relPath, entropy),
		DetectionMethod: "entropy_analysis",
		Recommendation:  "Review file contents for obfuscated or encrypted code. High entropy often indicates malicious obfuscation techniques.",
		Evidence: []types.Evidence{
			{
				Type:        "entropy",
				Description: "Shannon entropy score",
				Value:       fmt.Sprintf("%.2f", entropy),
			},
			{
				Type:        "file",
				Description: "Suspicious file",
				Value:       relPath,
			},
		},
		DetectedAt: time.Now(),
	}
}

func (cs *ContentScanner) createEntropySpanThreat(filePath string, span entropySpan) types.Threat {
	relPath := filepath.Base(filePath)
	return types.Threat{
		Type:            types.ThreatTypeObfuscatedCode,
		Severity:        types.SeverityHigh,
		Confidence:      0.8,
		Description:     fmt.Sprintf("File '%s' has high-entropy span (%.2f)", relPath, span.score),
		DetectionMethod: "entropy_window_analysis",
		Recommendation:  "Review high-entropy segments for obfuscated payloads.",
		Evidence: []types.Evidence{
			{Type: "entropy_span", Description: "start", Value: span.start},
			{Type: "entropy_span", Description: "end", Value: span.end},
			{Type: "entropy", Description: "score", Value: fmt.Sprintf("%.2f", span.score)},
			{Type: "file", Description: "Suspicious file", Value: relPath},
		},
		DetectedAt: time.Now(),
	}
}

func (cs *ContentScanner) createPatternThreat(filePath string, patterns []string) types.Threat {
	relPath := filepath.Base(filePath)
	return types.Threat{
		Type:            types.ThreatTypeSuspiciousPattern,
		Severity:        types.SeverityHigh,
		Confidence:      0.85,
		Description:     fmt.Sprintf("File '%s' contains suspicious code patterns: %s", relPath, strings.Join(patterns, ", ")),
		DetectionMethod: "pattern_analysis",
		Recommendation:  "Review detected patterns. Multiple obfuscation techniques often indicate malicious intent.",
		Evidence: []types.Evidence{
			{
				Type:        "patterns",
				Description: "Detected patterns",
				Value:       strings.Join(patterns, "; "),
			},
			{
				Type:        "file",
				Description: "Suspicious file",
				Value:       relPath,
			},
		},
		DetectedAt: time.Now(),
	}
}

func (cs *ContentScanner) createSecretThreat(filePath string, secrets []string) types.Threat {
	relPath := filepath.Base(filePath)
	return types.Threat{
		Type:            types.ThreatTypeEmbeddedSecret,
		Severity:        types.SeverityCritical,
		Confidence:      0.9,
		Description:     fmt.Sprintf("File '%s' contains embedded secrets or credentials: %s", relPath, strings.Join(secrets, ", ")),
		DetectionMethod: "secret_scanning",
		Recommendation:  "CRITICAL: Embedded secrets detected. This package may contain leaked credentials or be designed to steal secrets. Do not install.",
		Evidence: []types.Evidence{
			{
				Type:        "secrets",
				Description: "Types of secrets found",
				Value:       strings.Join(secrets, "; "),
			},
			{
				Type:        "file",
				Description: "File containing secrets",
				Value:       relPath,
			},
		},
		DetectedAt: time.Now(),
	}
}

func (cs *ContentScanner) createNetworkThreat(filePath string, indicators []string) types.Threat {
	relPath := filepath.Base(filePath)
	return types.Threat{
		Type:            types.ThreatTypeSuspiciousPattern,
		Severity:        types.SeverityMedium,
		Confidence:      0.7,
		Description:     fmt.Sprintf("File '%s' contains network indicators: %s", relPath, strings.Join(indicators[:min(3, len(indicators))], ", ")),
		DetectionMethod: "network_indicator_analysis",
		Recommendation:  "Review network connections. Legitimate packages rarely make external requests during installation.",
		Evidence: []types.Evidence{
			{
				Type:        "network_indicators",
				Description: "Detected network activity",
				Value:       strings.Join(indicators, "; "),
			},
			{
				Type:        "file",
				Description: "File with network code",
				Value:       relPath,
			},
		},
		DetectedAt: time.Now(),
	}
}

// Helper functions

func (cs *ContentScanner) isBinaryFile(filePath string) bool {
	// Simple heuristic: check extension
	ext := strings.ToLower(filepath.Ext(filePath))
	binaryExts := []string{".exe", ".dll", ".so", ".dylib", ".node", ".bin", ".dat", ".pyc", ".pyo"}
	for _, binExt := range binaryExts {
		if ext == binExt {
			return true
		}
	}

	// Check file header for binary indicators
	file, err := os.Open(filePath)
	if err != nil {
		return false
	}
	defer file.Close()

	header := make([]byte, 512)
	n, err := file.Read(header)
	if err != nil {
		return false
	}

	// Check for null bytes (common in binary files)
	for i := 0; i < n; i++ {
		if header[i] == 0 {
			return true
		}
	}

	return false
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
