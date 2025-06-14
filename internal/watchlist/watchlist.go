package watchlist

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// WatchlistConfig represents the watchlist configuration
type WatchlistConfig struct {
	// Protected package names (literal strings)
	ProtectedPackages []string `yaml:"protected_packages"`
	
	// Fuzzy matching patterns with configurable edit distance
	FuzzyPatterns []FuzzyPattern `yaml:"fuzzy_patterns"`
	
	// Private namespaces/scopes for dependency confusion checks
	PrivateNamespaces []PrivateNamespace `yaml:"private_namespaces"`
	
	// Threat feeds configuration
	ThreatFeeds ThreatFeeds `yaml:"threat_feeds"`
	
	// Global settings
	Settings WatchlistSettings `yaml:"settings"`
}

// FuzzyPattern defines fuzzy matching rules
type FuzzyPattern struct {
	Pattern         string `yaml:"pattern"`
	MaxEditDistance int    `yaml:"max_edit_distance"`
	Enabled         bool   `yaml:"enabled"`
	Description     string `yaml:"description"`
}

// PrivateNamespace defines private namespace protection
type PrivateNamespace struct {
	Namespace   string   `yaml:"namespace"`
	Prefixes    []string `yaml:"prefixes"`
	Scopes      []string `yaml:"scopes"`
	Registries  []string `yaml:"registries"`
	Enabled     bool     `yaml:"enabled"`
	Description string   `yaml:"description"`
}

// ThreatFeeds contains threat intelligence configuration
type ThreatFeeds struct {
	// Banned entities
	BannedAuthors   []BannedEntity `yaml:"banned_authors"`
	BannedDomains   []BannedEntity `yaml:"banned_domains"`
	BannedEmails    []BannedEntity `yaml:"banned_emails"`
	
	// Known malicious indicators
	MaliciousChecksums []MaliciousIndicator `yaml:"malicious_checksums"`
	MaliciousSignatures []MaliciousIndicator `yaml:"malicious_signatures"`
	
	// External threat feeds
	ExternalFeeds []ExternalFeed `yaml:"external_feeds"`
	
	// MISP integration
	MISP MISPConfig `yaml:"misp"`
}

// BannedEntity represents a banned author/domain/email
type BannedEntity struct {
	Value       string `yaml:"value"`
	Pattern     string `yaml:"pattern,omitempty"`
	Reason      string `yaml:"reason"`
	Severity    string `yaml:"severity"`
	Enabled     bool   `yaml:"enabled"`
	DateAdded   string `yaml:"date_added"`
}

// MaliciousIndicator represents known malicious package indicators
type MaliciousIndicator struct {
	Value       string            `yaml:"value"`
	Type        string            `yaml:"type"` // checksum, signature, etc.
	PackageName string            `yaml:"package_name,omitempty"`
	Registry    string            `yaml:"registry,omitempty"`
	Metadata    map[string]string `yaml:"metadata,omitempty"`
	Reason      string            `yaml:"reason"`
	Severity    string            `yaml:"severity"`
	Enabled     bool              `yaml:"enabled"`
	DateAdded   string            `yaml:"date_added"`
}

// ExternalFeed represents external threat feed configuration
type ExternalFeed struct {
	Name        string            `yaml:"name"`
	URL         string            `yaml:"url"`
	Type        string            `yaml:"type"` // json, csv, xml, etc.
	Format      string            `yaml:"format"`
	Headers     map[string]string `yaml:"headers,omitempty"`
	UpdateInterval string         `yaml:"update_interval"`
	Enabled     bool              `yaml:"enabled"`
	LastUpdate  string            `yaml:"last_update,omitempty"`
}

// MISPConfig represents MISP threat intelligence platform configuration
type MISPConfig struct {
	Enabled    bool   `yaml:"enabled"`
	URL        string `yaml:"url"`
	APIKey     string `yaml:"api_key"`
	VerifyTLS  bool   `yaml:"verify_tls"`
	EventTypes []string `yaml:"event_types"`
	Tags       []string `yaml:"tags"`
	UpdateInterval string `yaml:"update_interval"`
}

// WatchlistSettings contains global watchlist settings
type WatchlistSettings struct {
	Enabled             bool    `yaml:"enabled"`
	DefaultEditDistance int     `yaml:"default_edit_distance"`
	CaseSensitive       bool    `yaml:"case_sensitive"`
	UpdateInterval      string  `yaml:"update_interval"`
	CacheEnabled        bool    `yaml:"cache_enabled"`
	CacheTTL            string  `yaml:"cache_ttl"`
	LogLevel            string  `yaml:"log_level"`
}

// Watchlist manages the watchlist functionality
type Watchlist struct {
	config *WatchlistConfig
	regexCache map[string]*regexp.Regexp
}

// NewWatchlist creates a new watchlist instance
func NewWatchlist(configPath string) (*Watchlist, error) {
	config, err := LoadWatchlistConfig(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load watchlist config: %w", err)
	}
	
	return &Watchlist{
		config: config,
		regexCache: make(map[string]*regexp.Regexp),
	}, nil
}

// LoadWatchlistConfig loads watchlist configuration from file
func LoadWatchlistConfig(configPath string) (*WatchlistConfig, error) {
	if configPath == "" {
		// Try default locations
		homeDir, _ := os.UserHomeDir()
		defaultPaths := []string{
			"./watchlist.yaml",
			filepath.Join(homeDir, ".typosentinel", "watchlist.yaml"),
			"/etc/typosentinel/watchlist.yaml",
		}
		
		for _, path := range defaultPaths {
			if _, err := os.Stat(path); err == nil {
				configPath = path
				break
			}
		}
		
		if configPath == "" {
			return GetDefaultWatchlistConfig(), nil
		}
	}
	
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read watchlist config: %w", err)
	}
	
	var config WatchlistConfig
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse watchlist config: %w", err)
	}
	
	return &config, nil
}

// GetDefaultWatchlistConfig returns a default watchlist configuration
func GetDefaultWatchlistConfig() *WatchlistConfig {
	return &WatchlistConfig{
		ProtectedPackages: []string{
			// Popular npm packages
			"express", "lodash", "react", "vue", "angular", "jquery", "bootstrap",
			"axios", "moment", "underscore", "chalk", "commander", "debug",
			// Popular Python packages
			"requests", "numpy", "pandas", "flask", "django", "tensorflow",
			"scikit-learn", "matplotlib", "pillow", "beautifulsoup4",
			// Popular Go packages
			"gin", "echo", "fiber", "gorilla", "cobra", "viper",
			// Popular Java packages
			"spring-boot", "junit", "mockito", "jackson", "slf4j",
		},
		FuzzyPatterns: []FuzzyPattern{
			{
				Pattern:         "*express*",
				MaxEditDistance: 2,
				Enabled:         true,
				Description:     "Express.js framework variations",
			},
			{
				Pattern:         "*react*",
				MaxEditDistance: 2,
				Enabled:         true,
				Description:     "React library variations",
			},
		},
		PrivateNamespaces: []PrivateNamespace{
			{
				Namespace:   "@mycorp",
				Prefixes:    []string{"internal-", "private-", "corp-"},
				Scopes:      []string{"@mycorp", "@internal"},
				Registries:  []string{"npm"},
				Enabled:     true,
				Description: "Corporate private packages",
			},
		},
		ThreatFeeds: ThreatFeeds{
			BannedAuthors: []BannedEntity{},
			BannedDomains: []BannedEntity{},
			BannedEmails:  []BannedEntity{},
			MaliciousChecksums: []MaliciousIndicator{},
			MaliciousSignatures: []MaliciousIndicator{},
			ExternalFeeds: []ExternalFeed{},
			MISP: MISPConfig{
				Enabled: false,
			},
		},
		Settings: WatchlistSettings{
			Enabled:             true,
			DefaultEditDistance: 2,
			CaseSensitive:       false,
			UpdateInterval:      "24h",
			CacheEnabled:        true,
			CacheTTL:            "1h",
			LogLevel:            "info",
		},
	}
}

// IsProtected checks if a package name is in the protected list
func (w *Watchlist) IsProtected(packageName string) bool {
	if !w.config.Settings.Enabled {
		return false
	}
	
	packageName = w.normalizePackageName(packageName)
	
	for _, protected := range w.config.ProtectedPackages {
		if w.matchesPackage(packageName, protected) {
			return true
		}
	}
	
	return false
}

// CheckFuzzyMatch checks if a package matches any fuzzy patterns
func (w *Watchlist) CheckFuzzyMatch(packageName string) []FuzzyMatch {
	var matches []FuzzyMatch
	
	if !w.config.Settings.Enabled {
		return matches
	}
	
	packageName = w.normalizePackageName(packageName)
	
	for _, pattern := range w.config.FuzzyPatterns {
		if !pattern.Enabled {
			continue
		}
		
		if match := w.checkFuzzyPattern(packageName, pattern); match != nil {
			matches = append(matches, *match)
		}
	}
	
	return matches
}

// FuzzyMatch represents a fuzzy pattern match result
type FuzzyMatch struct {
	Pattern     string  `json:"pattern"`
	Package     string  `json:"package"`
	Distance    int     `json:"distance"`
	Confidence  float64 `json:"confidence"`
	Description string  `json:"description"`
}

normalizePackageName normalizes package name for comparison
func (w *Watchlist) normalizePackageName(name string) string {
	if !w.config.Settings.CaseSensitive {
		name = strings.ToLower(name)
	}
	return strings.TrimSpace(name)
}

// matchesPackage checks if package name matches protected package
func (w *Watchlist) matchesPackage(packageName, protected string) bool {
	protected = w.normalizePackageName(protected)
	return packageName == protected
}

// checkFuzzyPattern checks if package matches a fuzzy pattern
func (w *Watchlist) checkFuzzyPattern(packageName string, pattern FuzzyPattern) *FuzzyMatch {
	// Simple pattern matching - can be enhanced with more sophisticated algorithms
	distance := w.calculateEditDistance(packageName, pattern.Pattern)
	
	if distance <= pattern.MaxEditDistance {
		confidence := 1.0 - (float64(distance) / float64(len(pattern.Pattern)))
		return &FuzzyMatch{
			Pattern:     pattern.Pattern,
			Package:     packageName,
			Distance:    distance,
			Confidence:  confidence,
			Description: pattern.Description,
		}
	}
	
	return nil
}

// calculateEditDistance calculates Damerau-Levenshtein distance
func (w *Watchlist) calculateEditDistance(s1, s2 string) int {
	// Simplified edit distance calculation
	// In production, use a proper Damerau-Levenshtein implementation
	len1, len2 := len(s1), len(s2)
	if len1 == 0 {
		return len2
	}
	if len2 == 0 {
		return len1
	}
	
	matrix := make([][]int, len1+1)
	for i := range matrix {
		matrix[i] = make([]int, len2+1)
		matrix[i][0] = i
	}
	for j := 0; j <= len2; j++ {
		matrix[0][j] = j
	}
	
	for i := 1; i <= len1; i++ {
		for j := 1; j <= len2; j++ {
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
	
	return matrix[len1][len2]
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