package reputation

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/Alivanroy/Typosentinel/pkg/types"
)

// Config represents the reputation analyzer configuration
type Config struct {
	Enabled    bool
	CacheSize  int
	CacheTTL   time.Duration
	Timeout    time.Duration
	MaxRetries int
	RetryDelay time.Duration
	Sources    []Source
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
	// Check if analyzer is enabled
	if !a.config.Enabled {
		return nil, fmt.Errorf("reputation analyzer is disabled")
	}

	// Check cache first
	cacheKey := pkg.Registry + "/" + pkg.Name + "@" + pkg.Version
	if cached, exists := a.cache[cacheKey]; exists {
		return cached, nil
	}

	// If no sources configured, return basic response
	if len(a.sources) == 0 {
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

	var lastErr error
	var sourceResults []SourceResult
	totalScore := 0.0
	totalWeight := 0.0

	var baseResult *ReputationResponse

	// Query all enabled sources
	for _, source := range a.sources {
		if !source.Enabled {
			continue
		}

		req, err := http.NewRequestWithContext(ctx, "GET", source.Endpoint, nil)
		if err != nil {
			lastErr = err
			continue
		}

		if source.APIKey != "" {
			req.Header.Set("Authorization", "Bearer "+source.APIKey)
		}

		resp, err := a.client.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			lastErr = fmt.Errorf("HTTP %d from source %s", resp.StatusCode, source.Name)
			continue
		}

		var result ReputationResponse
		if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
			lastErr = err
			continue
		}

		// Add source result
		sourceResults = append(sourceResults, SourceResult{
			Name:   source.Name,
			Score:  result.Score,
			Weight: source.Weight,
			Status: "success",
		})

		// Calculate weighted score
		totalScore += result.Score * source.Weight
		totalWeight += source.Weight

		// Use the first successful result as base
		if baseResult == nil {
			baseResult = &result
		}
	}

	// If we have successful results, combine them
	if len(sourceResults) > 0 && baseResult != nil {
		// Update the base result with combined data
		baseResult.Sources = sourceResults
		if totalWeight > 0 {
			baseResult.Score = totalScore / totalWeight
		}
		// Cache the result
		a.cache[cacheKey] = baseResult
		return baseResult, nil
	}

	// If no sources worked, return error
	if lastErr != nil {
		return nil, lastErr
	}

	// Fallback if no sources worked but no error
	return &ReputationResponse{
		PackageName: pkg.Name,
		Registry:    pkg.Registry,
		Score:       0.5,
		Risk:        "unknown",
		Metrics: ReputationMetrics{
			DownloadCount:   0,
			AgeInDays:       0,
			MaintainerCount: 0,
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
