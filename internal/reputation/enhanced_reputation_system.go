package reputation

import (
	"context"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/Alivanroy/Typosentinel/internal/threat_intelligence"
	"github.com/Alivanroy/Typosentinel/pkg/logger"
	"github.com/Alivanroy/Typosentinel/pkg/types"
)

// EnhancedReputationSystem provides comprehensive reputation analysis with threat intelligence
type EnhancedReputationSystem struct {
    threatIntelManager *threat_intelligence.ThreatIntelligenceManager
    scorer             *EnhancedReputationScorer
    cache              *ReputationCache
    fsCache            *FilesystemCache
    logger             *logger.Logger
    config             *EnhancedReputationConfig
    mu                 sync.RWMutex
}

// EnhancedReputationConfig contains configuration for the enhanced reputation system
type EnhancedReputationConfig struct {
	ThreatIntelEnabled bool                     `json:"threat_intel_enabled"`
	CacheEnabled       bool                     `json:"cache_enabled"`
	CacheTTL           time.Duration            `json:"cache_ttl"`
	MaxCacheSize       int                      `json:"max_cache_size"`
	ThreatIntelSources []ThreatIntelSource      `json:"threat_intel_sources"`
	ScoringWeights     ScoringWeights           `json:"scoring_weights"`
	RiskThresholds     RiskThresholds           `json:"risk_thresholds"`
	MaintainerAnalysis MaintainerAnalysisConfig `json:"maintainer_analysis"`
	CommunityAnalysis  CommunityAnalysisConfig  `json:"community_analysis"`
	UpdateInterval     time.Duration            `json:"update_interval"`
	MaxRetries         int                      `json:"max_retries"`
	RequestTimeout     time.Duration            `json:"request_timeout"`
}

// ThreatIntelSource represents a threat intelligence source configuration
type ThreatIntelSource struct {
	Name        string            `json:"name"`
	Type        string            `json:"type"`
	URL         string            `json:"url"`
	APIKey      string            `json:"api_key,omitempty"`
	Weight      float64           `json:"weight"`
	Enabled     bool              `json:"enabled"`
	Headers     map[string]string `json:"headers,omitempty"`
	Timeout     time.Duration     `json:"timeout"`
	Reliability float64           `json:"reliability"`
}

// ScoringWeights defines weights for different reputation factors
type ScoringWeights struct {
	Popularity    float64 `json:"popularity"`
	Maturity      float64 `json:"maturity"`
	Maintenance   float64 `json:"maintenance"`
	Quality       float64 `json:"quality"`
	Security      float64 `json:"security"`
	ThreatIntel   float64 `json:"threat_intel"`
	Community     float64 `json:"community"`
	Maintainer    float64 `json:"maintainer"`
	Documentation float64 `json:"documentation"`
	Testing       float64 `json:"testing"`
}

// RiskThresholds defines thresholds for risk classification
type RiskThresholds struct {
	Critical float64 `json:"critical"`
	High     float64 `json:"high"`
	Medium   float64 `json:"medium"`
	Low      float64 `json:"low"`
}

// MaintainerAnalysisConfig configures maintainer reputation analysis
type MaintainerAnalysisConfig struct {
	Enabled                bool     `json:"enabled"`
	MinAccountAge          int      `json:"min_account_age_days"`
	MinPublishedPackages   int      `json:"min_published_packages"`
	SuspiciousPatterns     []string `json:"suspicious_patterns"`
	TrustedMaintainers     []string `json:"trusted_maintainers"`
	BlacklistedMaintainers []string `json:"blacklisted_maintainers"`
}

// CommunityAnalysisConfig configures community reputation analysis
type CommunityAnalysisConfig struct {
	Enabled               bool    `json:"enabled"`
	MinStars              int     `json:"min_stars"`
	MinForks              int     `json:"min_forks"`
	MinDownloads          int64   `json:"min_downloads"`
	MaxIssueRatio         float64 `json:"max_issue_ratio"`
	MinDocumentationScore float64 `json:"min_documentation_score"`
}

// EnhancedReputationResult contains comprehensive reputation analysis results
type EnhancedReputationResult struct {
	PackageName        string                   `json:"package_name"`
	Registry           string                   `json:"registry"`
	Version            string                   `json:"version"`
	OverallScore       float64                  `json:"overall_score"`
	RiskLevel          string                   `json:"risk_level"`
	TrustLevel         string                   `json:"trust_level"`
	ComponentScores    ComponentScores          `json:"component_scores"`
	ThreatIntelResults []ThreatIntelResult      `json:"threat_intel_results"`
	MaintainerAnalysis MaintainerAnalysisResult `json:"maintainer_analysis"`
	CommunityAnalysis  CommunityAnalysisResult  `json:"community_analysis"`
	SecurityAnalysis   SecurityAnalysisResult   `json:"security_analysis"`
	QualityMetrics     QualityMetrics           `json:"quality_metrics"`
	ReputationFlags    []ReputationFlag         `json:"reputation_flags"`
	Recommendations    []string                 `json:"recommendations"`
	DataSources        []string                 `json:"data_sources"`
	LastUpdated        time.Time                `json:"last_updated"`
	CacheHit           bool                     `json:"cache_hit"`
	AnalysisDuration   time.Duration            `json:"analysis_duration"`
}

// ComponentScores contains individual component scores
type ComponentScores struct {
	Popularity    float64 `json:"popularity"`
	Maturity      float64 `json:"maturity"`
	Maintenance   float64 `json:"maintenance"`
	Quality       float64 `json:"quality"`
	Security      float64 `json:"security"`
	ThreatIntel   float64 `json:"threat_intel"`
	Community     float64 `json:"community"`
	Maintainer    float64 `json:"maintainer"`
	Documentation float64 `json:"documentation"`
	Testing       float64 `json:"testing"`
}

// ThreatIntelResult contains threat intelligence analysis results
type ThreatIntelResult struct {
	Source      string                 `json:"source"`
	ThreatType  string                 `json:"threat_type"`
	Severity    string                 `json:"severity"`
	Confidence  float64                `json:"confidence"`
	Description string                 `json:"description"`
	Indicators  []string               `json:"indicators"`
	References  []string               `json:"references"`
	FirstSeen   time.Time              `json:"first_seen"`
	LastSeen    time.Time              `json:"last_seen"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// MaintainerAnalysisResult contains maintainer reputation analysis
type MaintainerAnalysisResult struct {
	MaintainerName     string    `json:"maintainer_name"`
	AccountAge         int       `json:"account_age_days"`
	PublishedPackages  int       `json:"published_packages"`
	VerifiedAccount    bool      `json:"verified_account"`
	ReputationScore    float64   `json:"reputation_score"`
	SuspiciousPatterns []string  `json:"suspicious_patterns"`
	TrustLevel         string    `json:"trust_level"`
	LastActivity       time.Time `json:"last_activity"`
	SocialPresence     bool      `json:"social_presence"`
	OrganizationMember bool      `json:"organization_member"`
}

// CommunityAnalysisResult contains community reputation analysis
type CommunityAnalysisResult struct {
	Stars              int     `json:"stars"`
	Forks              int     `json:"forks"`
	Downloads          int64   `json:"downloads"`
	Issues             int     `json:"issues"`
	IssueRatio         float64 `json:"issue_ratio"`
	DocumentationScore float64 `json:"documentation_score"`
	CommunityScore     float64 `json:"community_score"`
	ActiveContributors int     `json:"active_contributors"`
	RecentActivity     bool    `json:"recent_activity"`
	CommunityHealth    string  `json:"community_health"`
}

// SecurityAnalysisResult contains security-specific analysis
type SecurityAnalysisResult struct {
	VulnerabilityCount int       `json:"vulnerability_count"`
	CriticalVulns      int       `json:"critical_vulns"`
	HighVulns          int       `json:"high_vulns"`
	LastSecurityUpdate time.Time `json:"last_security_update"`
	SecurityScore      float64   `json:"security_score"`
	HasSecurityPolicy  bool      `json:"has_security_policy"`
	SignedReleases     bool      `json:"signed_releases"`
	SecurityAudits     int       `json:"security_audits"`
	ComplianceScore    float64   `json:"compliance_score"`
}

// QualityMetrics contains code quality metrics
type QualityMetrics struct {
	TestCoverage        float64 `json:"test_coverage"`
	CodeQualityScore    float64 `json:"code_quality_score"`
	DocumentationScore  float64 `json:"documentation_score"`
	LicenseCompliance   bool    `json:"license_compliance"`
	DependencyHealth    float64 `json:"dependency_health"`
	BuildStatus         string  `json:"build_status"`
	CIIntegration       bool    `json:"ci_integration"`
	StaticAnalysisScore float64 `json:"static_analysis_score"`
}

// ReputationCache manages caching of reputation results
type ReputationCache struct {
	cache   map[string]*CacheEntry
	mu      sync.RWMutex
	maxSize int
	ttl     time.Duration
}

// NewEnhancedReputationSystem creates a new enhanced reputation system
func NewEnhancedReputationSystem(
    threatIntelManager *threat_intelligence.ThreatIntelligenceManager,
    config *EnhancedReputationConfig,
    logger *logger.Logger,
) *EnhancedReputationSystem {
	// Set default configuration if not provided
	if config == nil {
		config = getDefaultEnhancedReputationConfig()
	}

    ers := &EnhancedReputationSystem{
        threatIntelManager: threatIntelManager,
        scorer:             NewEnhancedReputationScorer(),
        cache:              NewReputationCache(config.MaxCacheSize, config.CacheTTL),
        logger:             logger,
        config:             config,
    }
    if os.Getenv("TYPOSENTINEL_FS_CACHE_ENABLED") == "true" {
        base := os.Getenv("TYPOSENTINEL_FS_CACHE_PATH")
        if base == "" { base = "./cache" }
        ers.fsCache = NewFilesystemCache(base)
    }
    return ers
}

// AnalyzePackageReputation performs comprehensive reputation analysis
func (ers *EnhancedReputationSystem) AnalyzePackageReputation(ctx context.Context, pkg *types.Package) (*EnhancedReputationResult, error) {
	startTime := time.Now()

	// Check cache first
    if ers.config.CacheEnabled {
        if ers.fsCache != nil {
            key := ers.generateCacheKey(pkg)
            if fsRes, err := ers.fsCache.Get(key); err == nil && fsRes != nil {
                fsRes.CacheHit = true
                fsRes.AnalysisDuration = time.Since(startTime)
                return fsRes, nil
            }
        }
        if cached := ers.cache.Get(pkg.Name, pkg.Version, pkg.Registry); cached != nil {
            cached.CacheHit = true
            cached.AnalysisDuration = time.Since(startTime)
            return cached, nil
        }
    }

	ers.logger.Info("Starting enhanced reputation analysis", map[string]interface{}{
		"package":  pkg.Name,
		"version":  pkg.Version,
		"registry": pkg.Registry,
	})

	result := &EnhancedReputationResult{
		PackageName:     pkg.Name,
		Registry:        pkg.Registry,
		Version:         pkg.Version,
		LastUpdated:     time.Now(),
		CacheHit:        false,
		DataSources:     []string{},
		ReputationFlags: []ReputationFlag{},
		Recommendations: []string{},
	}

	// Perform basic reputation scoring
	_, err := ers.scorer.CalculateScore(pkg)
	if err != nil {
		ers.logger.Error("Failed to calculate basic reputation score", map[string]interface{}{
			"error":   err.Error(),
			"package": pkg.Name,
		})
		// Continue with default values - detailed analysis will provide component scores
	}

	// Get package metrics for detailed analysis
	metrics, err := ers.scorer.GetPackageMetrics(pkg)
	if err != nil {
		ers.logger.Warn("Failed to get package metrics", map[string]interface{}{
			"error":   err.Error(),
			"package": pkg.Name,
		})
		metrics = ers.scorer.getDefaultMetrics(pkg)
	}

	// Calculate component scores
	result.ComponentScores = ers.calculateComponentScores(metrics, pkg)

	// Perform threat intelligence analysis
	if ers.config.ThreatIntelEnabled && ers.threatIntelManager != nil {
		threatResults, err := ers.analyzeThreatIntelligence(ctx, pkg)
		if err != nil {
			ers.logger.Warn("Failed to analyze threat intelligence", map[string]interface{}{
				"error":   err.Error(),
				"package": pkg.Name,
			})
		} else {
			result.ThreatIntelResults = threatResults
			result.ComponentScores.ThreatIntel = ers.calculateThreatIntelScore(threatResults)
		}
	}

	// Perform maintainer analysis
	if ers.config.MaintainerAnalysis.Enabled {
		maintainerResult := ers.analyzeMaintainer(pkg, metrics)
		result.MaintainerAnalysis = maintainerResult
		result.ComponentScores.Maintainer = maintainerResult.ReputationScore
	}

	// Perform community analysis
	if ers.config.CommunityAnalysis.Enabled {
		communityResult := ers.analyzeCommunity(pkg, metrics)
		result.CommunityAnalysis = communityResult
		result.ComponentScores.Community = communityResult.CommunityScore
	}

	// Perform security analysis
	securityResult := ers.analyzeSecurityMetrics(pkg, metrics)
	result.SecurityAnalysis = securityResult
	result.ComponentScores.Security = securityResult.SecurityScore

	// Perform quality analysis
	qualityResult := ers.analyzeQualityMetrics(pkg, metrics)
	result.QualityMetrics = qualityResult
	result.ComponentScores.Quality = qualityResult.CodeQualityScore

	// Calculate overall score
	result.OverallScore = ers.calculateOverallScore(result.ComponentScores)
	result.RiskLevel = ers.determineRiskLevel(result.OverallScore)
	result.TrustLevel = ers.determineTrustLevel(result.OverallScore)

	// Generate reputation flags and recommendations
	result.ReputationFlags = ers.generateReputationFlags(result)
	result.Recommendations = ers.generateRecommendations(result)

	// Cache the result
    if ers.config.CacheEnabled {
        ers.cache.Set(pkg.Name, pkg.Version, pkg.Registry, result)
        if ers.fsCache != nil {
            key := ers.generateCacheKey(pkg)
            _ = ers.fsCache.Set(key, result, ers.config.CacheTTL)
        }
    }

	result.AnalysisDuration = time.Since(startTime)

	ers.logger.Info("Enhanced reputation analysis completed", map[string]interface{}{
		"package":       pkg.Name,
		"overall_score": result.OverallScore,
		"risk_level":    result.RiskLevel,
		"duration":      result.AnalysisDuration,
	})

	return result, nil
}

// calculateComponentScores calculates individual component scores
func (ers *EnhancedReputationSystem) calculateComponentScores(metrics *PackageMetrics, pkg *types.Package) ComponentScores {
	return ComponentScores{
		Popularity:    ers.scorer.calculatePopularityScore(metrics),
		Maturity:      ers.scorer.calculateMaturityScore(metrics),
		Maintenance:   ers.scorer.calculateMaintenanceScore(metrics),
		Quality:       ers.scorer.calculateQualityScore(metrics),
		Security:      ers.scorer.calculateSecurityScore(metrics),
		Documentation: ers.calculateDocumentationScore(metrics),
		Testing:       ers.calculateTestingScore(metrics),
	}
}

// calculateOverallScore calculates the weighted overall reputation score
func (ers *EnhancedReputationSystem) calculateOverallScore(scores ComponentScores) float64 {
	weights := ers.config.ScoringWeights

	totalScore := (scores.Popularity * weights.Popularity) +
		(scores.Maturity * weights.Maturity) +
		(scores.Maintenance * weights.Maintenance) +
		(scores.Quality * weights.Quality) +
		(scores.Security * weights.Security) +
		(scores.ThreatIntel * weights.ThreatIntel) +
		(scores.Community * weights.Community) +
		(scores.Maintainer * weights.Maintainer) +
		(scores.Documentation * weights.Documentation) +
		(scores.Testing * weights.Testing)

	// Normalize to 0-1 range
	totalWeight := weights.Popularity + weights.Maturity + weights.Maintenance +
		weights.Quality + weights.Security + weights.ThreatIntel +
		weights.Community + weights.Maintainer + weights.Documentation + weights.Testing

	if totalWeight > 0 {
		return totalScore / totalWeight
	}

	return 0.5 // Default neutral score
}

// getDefaultEnhancedReputationConfig returns default configuration
func getDefaultEnhancedReputationConfig() *EnhancedReputationConfig {
	return &EnhancedReputationConfig{
		ThreatIntelEnabled: true,
		CacheEnabled:       true,
		CacheTTL:           1 * time.Hour,
		MaxCacheSize:       10000,
		ScoringWeights: ScoringWeights{
			Popularity:    0.15,
			Maturity:      0.12,
			Maintenance:   0.15,
			Quality:       0.12,
			Security:      0.20,
			ThreatIntel:   0.15,
			Community:     0.05,
			Maintainer:    0.03,
			Documentation: 0.02,
			Testing:       0.01,
		},
		RiskThresholds: RiskThresholds{
			Critical: 0.2,
			High:     0.4,
			Medium:   0.6,
			Low:      0.8,
		},
		MaintainerAnalysis: MaintainerAnalysisConfig{
			Enabled:              true,
			MinAccountAge:        30,
			MinPublishedPackages: 1,
			SuspiciousPatterns:   []string{"fake", "temp", "test", "admin", "root"},
		},
		CommunityAnalysis: CommunityAnalysisConfig{
			Enabled:               true,
			MinStars:              10,
			MinForks:              5,
			MinDownloads:          1000,
			MaxIssueRatio:         0.3,
			MinDocumentationScore: 0.5,
		},
		UpdateInterval: 1 * time.Hour,
		MaxRetries:     3,
		RequestTimeout: 30 * time.Second,
	}
}

// NewReputationCache creates a new reputation cache
func NewReputationCache(maxSize int, ttl time.Duration) *ReputationCache {
	return &ReputationCache{
		cache:   make(map[string]*CacheEntry),
		maxSize: maxSize,
		ttl:     ttl,
	}
}

// Get retrieves a cached reputation result
func (rc *ReputationCache) Get(packageName, version, registry string) *EnhancedReputationResult {
	rc.mu.RLock()
	defer rc.mu.RUnlock()

	key := fmt.Sprintf("%s:%s:%s", registry, packageName, version)
	entry, exists := rc.cache[key]
	if !exists {
		return nil
	}

	// Check if entry is expired
	if time.Since(entry.Timestamp) > rc.ttl {
		delete(rc.cache, key)
		return nil
	}

	entry.Hits++
	return entry.Result
}

// Set stores a reputation result in cache
func (rc *ReputationCache) Set(packageName, version, registry string, result *EnhancedReputationResult) {
	rc.mu.Lock()
	defer rc.mu.Unlock()

	key := fmt.Sprintf("%s:%s:%s", registry, packageName, version)

	// Check cache size and evict if necessary
	if len(rc.cache) >= rc.maxSize {
		rc.evictLRU()
	}

	rc.cache[key] = &CacheEntry{
		Result:    result,
		Timestamp: time.Now(),
		Hits:      1,
	}
}

// evictLRU evicts the least recently used cache entry
func (rc *ReputationCache) evictLRU() {
	var oldestKey string
	var oldestTime time.Time

	for key, entry := range rc.cache {
		if oldestKey == "" || entry.Timestamp.Before(oldestTime) {
			oldestKey = key
			oldestTime = entry.Timestamp
		}
	}

	if oldestKey != "" {
		delete(rc.cache, oldestKey)
	}
}
