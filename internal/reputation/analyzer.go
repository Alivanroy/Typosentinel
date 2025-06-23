package reputation

import (
	"context"
	"net/http"
	"time"

	"github.com/Alivanroy/Typosentinel/pkg/types"
)

// Config represents the reputation analyzer configuration
type Config struct {
	Enabled     bool
	CacheSize   int
	CacheTTL    time.Duration
	Timeout     time.Duration
	MaxRetries  int
	RetryDelay  time.Duration
	Sources     []Source
}

// Source represents a reputation data source
type Source struct {
	Name     string
	Endpoint string
	APIKey   string
	Weight   float64
	Enabled  bool
}

// Analyzer handles package reputation analysis
type Analyzer struct {
	config  *Config
	client  *http.Client
	cache   map[string]*ReputationResponse
	sources []Source
}

// ReputationResponse represents the response from reputation analysis
type ReputationResponse struct {
	PackageName string                 `json:"package_name"`
	Registry    string                 `json:"registry"`
	Score       float64                `json:"score"`
	Risk        string                 `json:"risk"`
	Metrics     ReputationMetrics      `json:"metrics"`
	Flags       []ReputationFlag       `json:"flags"`
	Sources     []SourceResult         `json:"sources"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// ReputationMetrics contains detailed reputation metrics
type ReputationMetrics struct {
	DownloadCount      int     `json:"download_count"`
	AgeInDays          int     `json:"age_in_days"`
	MaintainerCount    int     `json:"maintainer_count"`
	IssueCount         int     `json:"issue_count"`
	StarCount          int     `json:"star_count"`
	ForkCount          int     `json:"fork_count"`
	LastUpdateDays     int     `json:"last_update_days"`
	VulnerabilityCount int     `json:"vulnerability_count"`
	LicenseScore       float64 `json:"license_score"`
	CommunityScore     float64 `json:"community_score"`
	DocumentationScore float64 `json:"documentation_score"`
	TestCoverage       float64 `json:"test_coverage"`
}

// ReputationFlag represents a reputation flag or warning
type ReputationFlag struct {
	Type        string    `json:"type"`
	Severity    string    `json:"severity"`
	Description string    `json:"description"`
	Evidence    []string  `json:"evidence"`
	Source      string    `json:"source"`
	Timestamp   time.Time `json:"timestamp"`
}

// SourceResult represents the result from a specific reputation source
type SourceResult struct {
	Name     string                 `json:"name"`
	Score    float64                `json:"score"`
	Weight   float64                `json:"weight"`
	Status   string                 `json:"status"`
	Latency  time.Duration          `json:"latency"`
	Error    string                 `json:"error,omitempty"`
	Metadata map[string]interface{} `json:"metadata"`
}

// NewAnalyzer creates a new reputation analyzer
func NewAnalyzer(cfg *Config) *Analyzer {
	return &Analyzer{
		config:  cfg,
		client:  &http.Client{Timeout: cfg.Timeout},
		cache:   make(map[string]*ReputationResponse),
		sources: cfg.Sources,
	}
}

// AnalyzePackage analyzes the reputation of a package
func (a *Analyzer) AnalyzePackage(ctx context.Context, pkg *types.Package) (*ReputationResponse, error) {
	// Basic implementation - in a real system, this would query reputation sources
	return &ReputationResponse{
		PackageName: pkg.Name,
		Registry:    pkg.Registry,
		Score:       0.8,
		Risk:        "low",
		Metrics: ReputationMetrics{
			DownloadCount:   100000,
			AgeInDays:       365,
			MaintainerCount: 2,
		},
		Flags:    []ReputationFlag{},
		Sources:  []SourceResult{},
		Metadata: make(map[string]interface{}),
	}, nil
}

// AnalyzePackages analyzes the reputation of multiple packages
func (a *Analyzer) AnalyzePackages(ctx context.Context, packages []*types.Package) ([]*ReputationResponse, error) {
	results := make([]*ReputationResponse, len(packages))
	for i, pkg := range packages {
		result, err := a.AnalyzePackage(ctx, pkg)
		if err != nil {
			return nil, err
		}
		results[i] = result
	}
	return results, nil
}

// IsEnabled returns whether the reputation analyzer is enabled
func (a *Analyzer) IsEnabled() bool {
	return a.config.Enabled
}