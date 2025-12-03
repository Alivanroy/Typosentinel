package scanner

import (
	"encoding/base64"
	"fmt"
	"math"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
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
	whitelistExt      []string
	maxFiles          int
	maxWorkers        int
	allowCIDRs        []string
	denyCIDRs         []string
	asnSources        []string
	asnMergeMode      string
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
	wl := viper.GetStringSlice("scanner.content.whitelist_extensions")
	mf := viper.GetInt("scanner.content.max_files")
	mw := viper.GetInt("scanner.content.max_workers")
	allow := viper.GetStringSlice("scanner.content.allowlist_cidrs")
	deny := viper.GetStringSlice("scanner.content.denylist_cidrs")
	asnSrc := viper.GetStringSlice("scanner.content.asn_sources")
	asnMode := viper.GetString("scanner.content.asn_merge_mode")

	return &ContentScanner{
		maxFileSize:      maxSize,
		entropyThreshold: entropy,
		windowSize:       win,
		includeGlobs:     inc,
		excludeGlobs:     exc,
		whitelistExt:     wl,
		maxFiles:         mf,
		maxWorkers:       mw,
		allowCIDRs:       allow,
		denyCIDRs:        deny,
		asnSources:       asnSrc,
		asnMergeMode:     strings.ToLower(asnMode),
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

	// Merge ASN sources into CIDR lists
	cs.loadASNFromSources()

	var files []string
	err := filepath.Walk(path, func(filePath string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() {
			return nil
		}
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
		if cs.maxFiles > 0 && scannedFiles >= cs.maxFiles {
			return nil
		}
		if len(cs.whitelistExt) > 0 {
			ok := false
			ext := strings.ToLower(filepath.Ext(filePath))
			for _, e := range cs.whitelistExt {
				if strings.EqualFold(e, ext) {
					ok = true
					break
				}
			}
			if !ok {
				return nil
			}
		}
		if info.Size() > cs.maxFileSize {
			return nil
		}
		if cs.isBinaryFile(filePath) {
			return nil
		}
		files = append(files, filePath)
		scannedFiles++
		return nil
	})

	if err != nil {
		return threats, err
	}

	workers := cs.maxWorkers
	if workers <= 0 {
		workers = 4
	}
	ch := make(chan string)
	var wg sync.WaitGroup
	var mu sync.Mutex
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for file := range ch {
				ts := cs.scanFile(file)
				if len(ts) > 0 {
					mu.Lock()
					threats = append(threats, ts...)
					relPath, _ := filepath.Rel(path, file)
					suspiciousFiles = append(suspiciousFiles, relPath)
					mu.Unlock()
				}
			}
		}()
	}
	for _, f := range files {
		ch <- f
	}
	close(ch)
	wg.Wait()

	logrus.Debugf("Content scanner: scanned %d files, found %d threats", scannedFiles, len(threats))
	return threats, nil
}

// scanFile scans a single file for malicious content
func (cs *ContentScanner) scanFile(filePath string) []types.Threat {
	// For memory efficiency, stream large files in chunks
	info, _ := os.Stat(filePath)
	if info != nil && info.Size() > int64(256*1024) {
		return cs.scanFileStream(filePath)
	}
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

// scanFileStream performs chunk-based scanning to reduce memory usage
func (cs *ContentScanner) scanFileStream(filePath string) []types.Threat {
	f, err := os.Open(filePath)
	if err != nil {
		return nil
	}
	defer f.Close()
	buf := make([]byte, 64*1024)
	carry := ""
	var threats []types.Threat
	var spansAll []entropySpan
	pattSet := map[string]struct{}{}
	secSet := map[string]struct{}{}
	netSet := map[string]struct{}{}
	previewSet := map[string]struct{}{}
	for {
		n, er := f.Read(buf)
		if n > 0 {
			segment := carry + string(buf[:n])
			if spans := cs.detectHighEntropySpans(segment, cs.windowSize, cs.entropyThreshold); len(spans) > 0 {
				spansAll = append(spansAll, spans...)
			}
			if pats := cs.detectSuspiciousPatterns(segment); len(pats) > 0 {
				for _, p := range pats {
					pattSet[p] = struct{}{}
				}
			}
			if secs := cs.detectEmbeddedSecrets(segment); len(secs) > 0 {
				for _, s := range secs {
					secSet[s] = struct{}{}
				}
			}
			if nets := cs.detectNetworkIndicators(segment); len(nets) > 0 {
				for _, v := range nets {
					netSet[v] = struct{}{}
				}
			}
			if prev := cs.detectBase64Previews(segment); len(prev) > 0 {
				for _, pv := range prev {
					previewSet[pv] = struct{}{}
				}
			}
			if len(segment) > cs.windowSize {
				carry = segment[len(segment)-cs.windowSize:]
			} else {
				carry = segment
			}
		}
		if er != nil {
			break
		}
	}
	if len(spansAll) > 0 {
		threats = append(threats, cs.createAggregatedEntropyThreat(filePath, spansAll))
	}
	if len(pattSet) > 0 {
		var patterns []string
		for p := range pattSet {
			patterns = append(patterns, p)
		}
		var previews []string
		for pv := range previewSet {
			previews = append(previews, pv)
		}
		if len(previews) > 0 {
			threats = append(threats, cs.createPatternThreatWithPreviews(filePath, patterns, previews))
		} else {
			threats = append(threats, cs.createPatternThreat(filePath, patterns))
		}
	}
	if len(secSet) > 0 {
		var secrets []string
		for s := range secSet {
			secrets = append(secrets, s)
		}
		threats = append(threats, cs.createSecretThreat(filePath, secrets))
	}
	if len(netSet) > 0 {
		var nets []string
		for v := range netSet {
			nets = append(nets, v)
		}
		threats = append(threats, cs.createNetworkThreat(filePath, nets))
	}
	return threats
}

// loadASNFromSources merges ASN source CIDRs into allow/deny lists
func (cs *ContentScanner) loadASNFromSources() {
	if len(cs.asnSources) == 0 {
		return
	}
	for _, src := range cs.asnSources {
		// Only support local files for safety; format: "ASNNUM,CIDR" per line
		if _, err := os.Stat(src); err != nil {
			continue
		}
		data, err := os.ReadFile(src)
		if err != nil {
			continue
		}
		lines := strings.Split(string(data), "\n")
		for _, ln := range lines {
			parts := strings.Split(strings.TrimSpace(ln), ",")
			if len(parts) < 2 {
				continue
			}
			cidr := strings.TrimSpace(parts[1])
			// Merge according to mode; default deny
			if cs.asnMergeMode == "allow" {
				cs.allowCIDRs = append(cs.allowCIDRs, cidr)
			} else {
				cs.denyCIDRs = append(cs.denyCIDRs, cidr)
			}
		}
	}
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

	// Phase 1: Dormancy Detection (SUNBURST-style time delays)
	// Detect long setTimeout/setInterval (> 7 days in milliseconds = 604800000)
	timeoutRegex := regexp.MustCompile(`setTimeout\s*\(\s*[^,]+,\s*(\d+)\s*\)`)
	intervalRegex := regexp.MustCompile(`setInterval\s*\(\s*[^,]+,\s*(\d+)\s*\)`)

	for _, match := range timeoutRegex.FindAllStringSubmatch(content, -1) {
		if len(match) > 1 {
			if delay := match[1]; len(delay) > 0 {
				// Simple check: if delay > 7 days (in ms)
				if len(delay) > 8 || (len(delay) == 8 && delay[0] >= '6') {
					patterns = append(patterns, fmt.Sprintf("Suspicious long setTimeout delay (potential dormancy: %s ms, >7 days)", delay))
				}
			}
		}
	}

	for _, match := range intervalRegex.FindAllStringSubmatch(content, -1) {
		if len(match) > 1 {
			if delay := match[1]; len(delay) > 0 {
				if len(delay) > 8 || (len(delay) == 8 && delay[0] >= '6') {
					patterns = append(patterns, fmt.Sprintf("Suspicious long setInterval delay (potential dormancy: %s ms, >7 days)", delay))
				}
			}
		}
	}

	// Detect date-based activation conditionals
	dateCheckRegex := regexp.MustCompile(`(new\s+Date\(\)|Date\.now\(\))\s*[><=]+`)
	if dateCheckRegex.MatchString(content) {
		// Count occurrences
		if len(dateCheckRegex.FindAllString(content, -1)) > 2 {
			patterns = append(patterns, "Multiple date-based conditionals (potential time-delayed activation)")
		}
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
			if cs.inCIDRs(ip, cs.denyCIDRs) && !cs.inCIDRs(ip, cs.allowCIDRs) {
				indicators = append(indicators, fmt.Sprintf("External IP: %s", ip))
			}
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

func (cs *ContentScanner) inCIDRs(ipStr string, cidrs []string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	for _, c := range cidrs {
		_, n, err := net.ParseCIDR(strings.TrimSpace(c))
		if err == nil && n.Contains(ip) {
			return true
		}
	}
	return false
}

func (cs *ContentScanner) detectBase64Previews(content string) []string {
	var previews []string
	re := regexp.MustCompile(`[A-Za-z0-9+/]{50,}={0,2}`)
	matches := re.FindAllString(content, -1)
	max := min(3, len(matches))
	for i := 0; i < max; i++ {
		m := matches[i]
		if dec, err := base64.StdEncoding.DecodeString(m); err == nil {
			if len(dec) > 16 {
				previews = append(previews, string(dec[:16]))
			}
		}
	}
	return previews
}

func (cs *ContentScanner) createAggregatedEntropyThreat(filePath string, spans []entropySpan) types.Threat {
	relPath := filepath.Base(filePath)
	var ev []types.Evidence
	for i := 0; i < min(5, len(spans)); i++ {
		sp := spans[i]
		ev = append(ev, types.Evidence{Type: "entropy_span", Description: "range", Value: map[string]interface{}{"start": sp.start, "end": sp.end, "score": sp.score}})
	}
	ev = append(ev, types.Evidence{Type: "file", Description: "Suspicious file", Value: map[string]interface{}{"relative": relPath, "path": filePath}})
	return types.Threat{
		Type:            types.ThreatTypeObfuscatedCode,
		Severity:        types.SeverityHigh,
		Confidence:      0.8,
		Description:     fmt.Sprintf("File '%s' has multiple high-entropy spans", relPath),
		DetectionMethod: "entropy_window_analysis",
		Recommendation:  "Review high-entropy segments for obfuscated payloads.",
		Evidence:        ev,
		Metadata:        map[string]interface{}{"file_path": filePath, "relative_path": relPath},
		DetectedAt:      time.Now(),
	}
}

func (cs *ContentScanner) createPatternThreatWithPreviews(filePath string, patterns []string, previews []string) types.Threat {
	relPath := filepath.Base(filePath)
	ev := []types.Evidence{
		{Type: "patterns", Description: "Detected patterns", Value: strings.Join(patterns, "; ")},
		{Type: "file", Description: "Suspicious file", Value: map[string]interface{}{"relative": relPath, "path": filePath}},
	}
	if len(previews) > 0 {
		ev = append(ev, types.Evidence{Type: "preview", Description: "decoded_base64", Value: map[string]interface{}{"contentType": "base64", "previews": previews}})
	}
	return types.Threat{
		Type:            types.ThreatTypeSuspiciousPattern,
		Severity:        types.SeverityHigh,
		Confidence:      0.85,
		Description:     fmt.Sprintf("File '%s' contains suspicious code patterns", relPath),
		DetectionMethod: "pattern_analysis",
		Recommendation:  "Review detected patterns and decoded previews.",
		Evidence:        ev,
		Metadata:        map[string]interface{}{"file_path": filePath, "relative_path": relPath},
		DetectedAt:      time.Now(),
	}
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
				Value:       map[string]interface{}{"relative": relPath, "path": filePath},
			},
		},
		Metadata:   map[string]interface{}{"file_path": filePath, "relative_path": relPath},
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
			{Type: "entropy_span", Description: "range", Value: map[string]interface{}{"start": span.start, "end": span.end, "score": span.score}},
			{Type: "file", Description: "Suspicious file", Value: map[string]interface{}{"relative": relPath, "path": filePath}},
		},
		Metadata:   map[string]interface{}{"file_path": filePath, "relative_path": relPath},
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
				Value:       map[string]interface{}{"relative": relPath, "path": filePath},
			},
		},
		Metadata:   map[string]interface{}{"file_path": filePath, "relative_path": relPath},
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
				Value:       map[string]interface{}{"relative": relPath, "path": filePath},
			},
		},
		Metadata:   map[string]interface{}{"file_path": filePath, "relative_path": relPath},
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
				Value:       map[string]interface{}{"relative": relPath, "path": filePath},
			},
		},
		Metadata:   map[string]interface{}{"file_path": filePath, "relative_path": relPath},
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
