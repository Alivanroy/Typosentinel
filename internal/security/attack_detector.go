package security

import (
	"regexp"
	"strings"
	"sync"
	"time"
)

// AttackDetector detects various attack patterns
type AttackDetector struct {
	patterns         map[string]*regexp.Regexp
	advancedPatterns map[string]*AdvancedPattern
	sequenceDetector *SequenceDetector
	behaviorAnalyzer *BehaviorAnalyzer
	thresholds       map[string]int
	detectionHistory map[string][]DetectionEvent
	mu               sync.RWMutex
}

// AdvancedPattern represents an advanced attack detection pattern
type AdvancedPattern struct {
	Pattern           *regexp.Regexp
	Severity          string
	Category          string
	Description       string
	Mitigation        string
	FalsePositiveRate float64
	ContextualRules   []ContextualRule
}

// ContextualRule represents a contextual rule for pattern matching
type ContextualRule struct {
	Condition  string
	Action     string
	Parameters map[string]interface{}
}

// DetectionEvent represents a detection event
type DetectionEvent struct {
	Timestamp   time.Time
	AttackType  string
	Severity    string
	Description string
	ClientID    string
	Blocked     bool
}

// RequestAnalyzer analyzes HTTP requests for security threats
type RequestAnalyzer struct {
	attackDetector *AttackDetector
	mu             sync.RWMutex
}

// ResponseFilter filters HTTP responses for security
type ResponseFilter struct {
	config *ResponseFilterConfig
	mu     sync.RWMutex
}

// ResponseFilterConfig configures response filtering
type ResponseFilterConfig struct {
	Enabled            bool
	RemoveHeaders      []string
	AddSecurityHeaders bool
	SanitizeContent    bool
}

// NewAttackDetector creates a new attack detector
func NewAttackDetector() *AttackDetector {
	return &AttackDetector{
		patterns:         initializeAttackPatterns(),
		advancedPatterns: initializeAdvancedPatterns(),
		sequenceDetector: NewSequenceDetector(),
		behaviorAnalyzer: NewBehaviorAnalyzer(),
		thresholds:       getDefaultThresholds(),
		detectionHistory: make(map[string][]DetectionEvent),
	}
}

// DetectInString detects attack patterns in a string
func (ad *AttackDetector) DetectInString(input string) (bool, string) {
	ad.mu.RLock()
	defer ad.mu.RUnlock()

	// Check basic patterns
	for attackType, pattern := range ad.patterns {
		if pattern.MatchString(input) {
			return true, attackType
		}
	}

	// Check advanced patterns
	for attackType, advPattern := range ad.advancedPatterns {
		if advPattern.Pattern.MatchString(input) {
			// Apply contextual rules
			if ad.evaluateContextualRules(input, advPattern.ContextualRules) {
				return true, attackType
			}
		}
	}

	return false, ""
}

// evaluateContextualRules evaluates contextual rules for pattern matching
func (ad *AttackDetector) evaluateContextualRules(input string, rules []ContextualRule) bool {
	for _, rule := range rules {
		switch rule.Condition {
		case "length_check":
			if maxLen, ok := rule.Parameters["max_length"].(int); ok {
				if len(input) > maxLen {
					return false
				}
			}
		case "context_check":
			if context, ok := rule.Parameters["context"].(string); ok {
				if !strings.Contains(input, context) {
					return false
				}
			}
		}
	}
	return true
}

// initializeAttackPatterns initializes basic attack detection patterns
func initializeAttackPatterns() map[string]*regexp.Regexp {
	patterns := make(map[string]*regexp.Regexp)

	// SQL Injection patterns
	patterns["sql_injection"] = regexp.MustCompile(`(?i)(union\s+select|drop\s+table|insert\s+into|delete\s+from|update\s+set|exec\s*\(|sp_|xp_)`)
	patterns["sql_injection_advanced"] = regexp.MustCompile(`(?i)('\s*(or|and)\s*'|'\s*;|--\s*$|/\*.*\*/|\bchar\s*\(|\bcast\s*\()`)

	// XSS patterns
	patterns["xss"] = regexp.MustCompile(`(?i)(<script|javascript:|on\w+\s*=|<iframe|<object|<embed)`)
	patterns["xss_advanced"] = regexp.MustCompile(`(?i)(eval\s*\(|expression\s*\(|vbscript:|data:text/html)`)

	// Command injection patterns
	patterns["command_injection"] = regexp.MustCompile(`(?i)(;\s*(cat|ls|pwd|whoami|id|uname)|\|\s*(cat|ls|pwd)|\$\(.*\)|` + "`" + `.*` + "`" + `)`)
	patterns["command_injection_advanced"] = regexp.MustCompile(`(?i)(\&\&\s*(cat|ls|pwd)|\|\|\s*(cat|ls|pwd)|\bexec\s*\(|\bsystem\s*\(|\bshell_exec\s*\()`)

	// Path traversal patterns
	patterns["path_traversal"] = regexp.MustCompile(`(?i)(\.\./|\.\.\\\\/|%2e%2e%2f|%2e%2e%5c)`)
	patterns["path_traversal_advanced"] = regexp.MustCompile(`(?i)(\.\.%252f|\.\.%255c|%c0%ae%c0%ae%c0%af|%uff0e%uff0e%uff0f)`)

	// LDAP injection patterns
	patterns["ldap_injection"] = regexp.MustCompile(`(?i)(\*\)|\(\*|\)\(|\*\(|\&\(|\|\()`)

	// NoSQL injection patterns
	patterns["nosql_injection"] = regexp.MustCompile(`(?i)(\$ne\s*:|\$gt\s*:|\$lt\s*:|\$where\s*:|\$regex\s*:|\$or\s*:)`)

	// XXE patterns
	patterns["xxe"] = regexp.MustCompile(`(?i)(<!entity|<!\[cdata\[|system\s+["']|public\s+["'])`)

	// SSRF patterns
	patterns["ssrf"] = regexp.MustCompile(`(?i)(localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\]|file://|gopher://|dict://)`)

	// Template injection patterns
	patterns["template_injection"] = regexp.MustCompile(`(?i)(\{\{.*\}\}|\{%.*%\}|\$\{.*\}|<%.*%>)`)

	return patterns
}

// initializeAdvancedPatterns initializes advanced attack detection patterns
func initializeAdvancedPatterns() map[string]*AdvancedPattern {
	patterns := make(map[string]*AdvancedPattern)

	patterns["advanced_sql_injection"] = &AdvancedPattern{
		Pattern:           regexp.MustCompile(`(?i)('\s*(union|select|insert|update|delete|drop|create|alter)\s+|'\s*;\s*(union|select|insert|update|delete|drop|create|alter)\s+)`),
		Severity:          "high",
		Category:          "injection",
		Description:       "Advanced SQL injection attempt detected",
		Mitigation:        "Block request and log incident",
		FalsePositiveRate: 0.05,
		ContextualRules: []ContextualRule{
			{
				Condition: "length_check",
				Action:    "validate",
				Parameters: map[string]interface{}{
					"max_length": 1000,
				},
			},
		},
	}

	patterns["advanced_xss"] = &AdvancedPattern{
		Pattern:           regexp.MustCompile(`(?i)(<script[^>]*>.*</script>|javascript:\s*[a-zA-Z0-9_$]+\s*\(|on[a-zA-Z]+\s*=\s*["'][^"']*["'])`),
		Severity:          "high",
		Category:          "xss",
		Description:       "Advanced XSS attempt detected",
		Mitigation:        "Sanitize input and block request",
		FalsePositiveRate: 0.03,
		ContextualRules: []ContextualRule{
			{
				Condition: "context_check",
				Action:    "validate",
				Parameters: map[string]interface{}{
					"context": "html",
				},
			},
		},
	}

	patterns["polyglot_injection"] = &AdvancedPattern{
		Pattern:           regexp.MustCompile(`(?i)(javascript:|data:text/html|<script|'\s*(union|select)|\$\{.*\}|\{\{.*\}\})`),
		Severity:          "critical",
		Category:          "polyglot",
		Description:       "Polyglot injection attempt detected",
		Mitigation:        "Block request immediately",
		FalsePositiveRate: 0.02,
		ContextualRules:   []ContextualRule{},
	}

	return patterns
}

// getDefaultThresholds returns default detection thresholds
func getDefaultThresholds() map[string]int {
	return map[string]int{
		"sql_injection":      3,
		"xss":                5,
		"command_injection":  2,
		"path_traversal":     3,
		"ldap_injection":     2,
		"nosql_injection":    3,
		"xxe":                1,
		"ssrf":               2,
		"template_injection": 2,
	}
}

// SequenceDetector detects attack sequences
type SequenceDetector struct {
	sequences map[string][]string
	mu        sync.RWMutex
}

// NewSequenceDetector creates a new sequence detector
func NewSequenceDetector() *SequenceDetector {
	return &SequenceDetector{
		sequences: make(map[string][]string),
	}
}

// DetectSequence detects attack sequences
func (sd *SequenceDetector) DetectSequence(clientID string, pattern string) bool {
	sd.mu.Lock()
	defer sd.mu.Unlock()

	if _, exists := sd.sequences[clientID]; !exists {
		sd.sequences[clientID] = make([]string, 0)
	}

	sd.sequences[clientID] = append(sd.sequences[clientID], pattern)

	// Keep only last 10 patterns
	if len(sd.sequences[clientID]) > 10 {
		sd.sequences[clientID] = sd.sequences[clientID][1:]
	}

	// Check for suspicious sequences
	return sd.isSequenceSuspicious(sd.sequences[clientID])
}

// isSequenceSuspicious checks if a sequence is suspicious
func (sd *SequenceDetector) isSequenceSuspicious(sequence []string) bool {
	// Simple heuristic: if we see multiple different attack types in sequence
	attackTypes := make(map[string]bool)
	for _, pattern := range sequence {
		attackTypes[pattern] = true
	}

	return len(attackTypes) >= 3
}

// BehaviorAnalyzer analyzes client behavior patterns
type BehaviorAnalyzer struct {
	behaviorProfiles map[string]*BehaviorProfile
	mu               sync.RWMutex
}

// BehaviorProfile represents a client's behavior profile
type BehaviorProfile struct {
	ClientID        string
	RequestCount    int
	ErrorCount      int
	LastSeen        time.Time
	SuspiciousCount int
	RiskScore       float64
}

// NewBehaviorAnalyzer creates a new behavior analyzer
func NewBehaviorAnalyzer() *BehaviorAnalyzer {
	return &BehaviorAnalyzer{
		behaviorProfiles: make(map[string]*BehaviorProfile),
	}
}

// AnalyzeBehavior analyzes client behavior
func (ba *BehaviorAnalyzer) AnalyzeBehavior(clientID string, suspicious bool) float64 {
	ba.mu.Lock()
	defer ba.mu.Unlock()

	if _, exists := ba.behaviorProfiles[clientID]; !exists {
		ba.behaviorProfiles[clientID] = &BehaviorProfile{
			ClientID: clientID,
			LastSeen: time.Now(),
		}
	}

	profile := ba.behaviorProfiles[clientID]
	profile.RequestCount++
	profile.LastSeen = time.Now()

	if suspicious {
		profile.SuspiciousCount++
	}

	// Calculate risk score
	if profile.RequestCount > 0 {
		profile.RiskScore = float64(profile.SuspiciousCount) / float64(profile.RequestCount)
	}

	return profile.RiskScore
}
