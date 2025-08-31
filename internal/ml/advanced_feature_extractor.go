package ml

import (
	"crypto/md5"
	"fmt"
	"math"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/Alivanroy/Typosentinel/pkg/types"
)

// AdvancedFeatureExtractor provides sophisticated feature extraction for package analysis
type AdvancedFeatureExtractor struct {
	config              *FeatureExtractionConfig
	textAnalyzer        *TextAnalyzer
	statAnalyzer        *StatisticalAnalyzer
	behaviorAnalyzer    *BehaviorAnalyzer
	securityAnalyzer    *SecurityAnalyzer
	graphAnalyzer       *GraphAnalyzer
	temporalAnalyzer    *TemporalAnalyzer
	normalizer          *FeatureNormalizer
	featureCache        map[string]*ExtractedFeatures
	metrics             *ExtractionMetrics
	popularPackages     map[string][]string
	suspiciousKeywords  []string
	domainReputations   map[string]float64
	licenseScores       map[string]float64
	normalizationParams NormalizationParams
}

// FeatureExtractionConfig configures feature extraction behavior
type FeatureExtractionConfig struct {
	// Text Analysis
	EnableTextAnalysis bool     `json:"enable_text_analysis"`
	TextFeatures       []string `json:"text_features"`
	LanguageDetection  bool     `json:"language_detection"`
	SentimentAnalysis  bool     `json:"sentiment_analysis"`
	TopicModeling      bool     `json:"topic_modeling"`
	NGramRange         [2]int   `json:"ngram_range"`
	MaxFeatures        int      `json:"max_features"`
	MinDocumentFreq    float64  `json:"min_document_freq"`
	MaxDocumentFreq    float64  `json:"max_document_freq"`

	// Statistical Analysis
	EnableStatAnalysis   bool     `json:"enable_stat_analysis"`
	StatFeatures         []string `json:"stat_features"`
	DistributionAnalysis bool     `json:"distribution_analysis"`
	OutlierDetection     bool     `json:"outlier_detection"`
	CorrelationAnalysis  bool     `json:"correlation_analysis"`
	TimeSeriesAnalysis   bool     `json:"time_series_analysis"`

	// Behavior Analysis
	EnableBehaviorAnalysis bool     `json:"enable_behavior_analysis"`
	BehaviorFeatures       []string `json:"behavior_features"`
	UsagePatterns          bool     `json:"usage_patterns"`
	DependencyAnalysis     bool     `json:"dependency_analysis"`
	VersioningPatterns     bool     `json:"versioning_patterns"`
	MaintenancePatterns    bool     `json:"maintenance_patterns"`

	// Security Analysis
	EnableSecurityAnalysis bool     `json:"enable_security_analysis"`
	SecurityFeatures       []string `json:"security_features"`
	VulnerabilityScanning  bool     `json:"vulnerability_scanning"`
	MalwareDetection       bool     `json:"malware_detection"`
	LicenseAnalysis        bool     `json:"license_analysis"`
	CodeQualityAnalysis    bool     `json:"code_quality_analysis"`

	// Graph Analysis
	EnableGraphAnalysis   bool     `json:"enable_graph_analysis"`
	GraphFeatures         []string `json:"graph_features"`
	DependencyGraphs      bool     `json:"dependency_graphs"`
	SocialNetworkAnalysis bool     `json:"social_network_analysis"`
	CommunityDetection    bool     `json:"community_detection"`
	CentralityMeasures    bool     `json:"centrality_measures"`

	// Temporal Analysis
	EnableTemporalAnalysis bool     `json:"enable_temporal_analysis"`
	TemporalFeatures       []string `json:"temporal_features"`
	TrendAnalysis          bool     `json:"trend_analysis"`
	SeasonalityDetection   bool     `json:"seasonality_detection"`
	AnomalyDetection       bool     `json:"anomaly_detection"`
	ForecastingFeatures    bool     `json:"forecasting_features"`

	// Feature Processing
	Normalization           string `json:"normalization"`
	FeatureSelection        bool   `json:"feature_selection"`
	DimensionalityReduction bool   `json:"dimensionality_reduction"`
	FeatureEngineering      bool   `json:"feature_engineering"`
	CacheFeatures           bool   `json:"cache_features"`
	ParallelProcessing      bool   `json:"parallel_processing"`
	MaxConcurrency          int    `json:"max_concurrency"`
}

// ExtractedFeatures contains all extracted features for a package
type ExtractedFeatures struct {
	PackageID        string                 `json:"package_id"`
	Timestamp        time.Time              `json:"timestamp"`
	TextFeatures     *TextFeatures          `json:"text_features"`
	StatFeatures     *StatisticalFeatures   `json:"stat_features"`
	BehaviorFeatures *BehaviorFeatures      `json:"behavior_features"`
	SecurityFeatures *SecurityFeatures      `json:"security_features"`
	GraphFeatures    *GraphFeatures         `json:"graph_features"`
	TemporalFeatures *TemporalFeatures      `json:"temporal_features"`
	CombinedFeatures []float64              `json:"combined_features"`
	FeatureNames     []string               `json:"feature_names"`
	Metadata         map[string]interface{} `json:"metadata"`
	QualityScore     float64                `json:"quality_score"`
	ExtractionTime   time.Duration          `json:"extraction_time"`
}

// TextFeatures contains text-based features
type TextFeatures struct {
	// Basic Text Metrics
	NameLength        int `json:"name_length"`
	DescriptionLength int `json:"description_length"`
	ReadmeLength      int `json:"readme_length"`
	WordCount         int `json:"word_count"`
	SentenceCount     int `json:"sentence_count"`
	ParagraphCount    int `json:"paragraph_count"`

	// Character Analysis
	AlphaRatio       float64 `json:"alpha_ratio"`
	DigitRatio       float64 `json:"digit_ratio"`
	SpecialCharRatio float64 `json:"special_char_ratio"`
	UppercaseRatio   float64 `json:"uppercase_ratio"`
	LowercaseRatio   float64 `json:"lowercase_ratio"`
	WhitespaceRatio  float64 `json:"whitespace_ratio"`

	// Linguistic Features
	Language            string  `json:"language"`
	LanguageConfidence  float64 `json:"language_confidence"`
	Sentiment           float64 `json:"sentiment"`
	SentimentConfidence float64 `json:"sentiment_confidence"`
	ReadabilityScore    float64 `json:"readability_score"`
	ComplexityScore     float64 `json:"complexity_score"`

	// N-gram Features
	UnigramFreq   map[string]int `json:"unigram_freq"`
	BigramFreq    map[string]int `json:"bigram_freq"`
	TrigramFreq   map[string]int `json:"trigram_freq"`
	CharNgramFreq map[string]int `json:"char_ngram_freq"`

	// Topic and Semantic Features
	Topics             []string  `json:"topics"`
	TopicProbabilities []float64 `json:"topic_probabilities"`
	Keywords           []string  `json:"keywords"`
	KeywordScores      []float64 `json:"keyword_scores"`
	SemanticSimilarity float64   `json:"semantic_similarity"`

	// Suspicious Patterns
	SuspiciousPatterns []string `json:"suspicious_patterns"`
	TyposquattingScore float64  `json:"typosquatting_score"`
	ObfuscationScore   float64  `json:"obfuscation_score"`
	SocialEngScore     float64  `json:"social_eng_score"`
}

// StatisticalFeatures contains statistical analysis features
type StatisticalFeatures struct {
	// Distribution Features
	Mean               float64 `json:"mean"`
	Median             float64 `json:"median"`
	Mode               float64 `json:"mode"`
	StandardDeviation  float64 `json:"standard_deviation"`
	Variance           float64 `json:"variance"`
	Skewness           float64 `json:"skewness"`
	Kurtosis           float64 `json:"kurtosis"`
	Range              float64 `json:"range"`
	InterquartileRange float64 `json:"interquartile_range"`

	// Percentiles
	Percentiles []float64 `json:"percentiles"`
	Quartiles   []float64 `json:"quartiles"`
	Deciles     []float64 `json:"deciles"`

	// Outlier Detection
	Outliers        []float64 `json:"outliers"`
	OutlierCount    int       `json:"outlier_count"`
	OutlierRatio    float64   `json:"outlier_ratio"`
	ZScores         []float64 `json:"z_scores"`
	ModifiedZScores []float64 `json:"modified_z_scores"`

	// Correlation Features
	CorrelationMatrix [][]float64 `json:"correlation_matrix"`
	CorrelationScores []float64   `json:"correlation_scores"`
	MaxCorrelation    float64     `json:"max_correlation"`
	MinCorrelation    float64     `json:"min_correlation"`
	AvgCorrelation    float64     `json:"avg_correlation"`

	// Time Series Features
	Trend             string    `json:"trend"`
	TrendStrength     float64   `json:"trend_strength"`
	Seasonality       bool      `json:"seasonality"`
	SeasonalityPeriod int       `json:"seasonality_period"`
	Stationarity      bool      `json:"stationarity"`
	Autocorrelation   []float64 `json:"autocorrelation"`
}

// BehaviorFeatures contains behavioral analysis features
type BehaviorFeatures struct {
	// Usage Patterns
	DownloadFrequency float64 `json:"download_frequency"`
	DownloadTrend     string  `json:"download_trend"`
	UsageStability    float64 `json:"usage_stability"`
	PopularityScore   float64 `json:"popularity_score"`
	AdoptionRate      float64 `json:"adoption_rate"`
	RetentionRate     float64 `json:"retention_rate"`

	// Dependency Patterns
	DependencyCount      int     `json:"dependency_count"`
	DependentCount       int     `json:"dependent_count"`
	DependencyDepth      int     `json:"dependency_depth"`
	CircularDependencies bool    `json:"circular_dependencies"`
	DependencyStability  float64 `json:"dependency_stability"`
	DependencyRisk       float64 `json:"dependency_risk"`

	// Versioning Patterns
	VersionCount          int     `json:"version_count"`
	VersionFrequency      float64 `json:"version_frequency"`
	VersioningStrategy    string  `json:"versioning_strategy"`
	BreakingChanges       int     `json:"breaking_changes"`
	BackwardCompatibility float64 `json:"backward_compatibility"`
	VersionStability      float64 `json:"version_stability"`

	// Maintenance Patterns
	MaintenanceScore  float64 `json:"maintenance_score"`
	UpdateFrequency   float64 `json:"update_frequency"`
	BugFixRate        float64 `json:"bug_fix_rate"`
	ResponseTime      float64 `json:"response_time"`
	CommunityActivity float64 `json:"community_activity"`
	ContributorCount  int     `json:"contributor_count"`

	// Quality Indicators
	CodeQuality          float64 `json:"code_quality"`
	TestCoverage         float64 `json:"test_coverage"`
	DocumentationQuality float64 `json:"documentation_quality"`
	LicenseCompliance    bool    `json:"license_compliance"`
	SecurityScore        float64 `json:"security_score"`
}

// SecurityFeatures contains security-related features
type SecurityFeatures struct {
	// Vulnerability Analysis
	VulnerabilityCount   int     `json:"vulnerability_count"`
	KnownVulnerabilities int     `json:"known_vulnerabilities"`
	CriticalVulns        int     `json:"critical_vulns"`
	HighVulns            int     `json:"high_vulns"`
	MediumVulns          int     `json:"medium_vulns"`
	LowVulns             int     `json:"low_vulns"`
	VulnerabilityScore   float64 `json:"vulnerability_score"`
	CVSSScore            float64 `json:"cvss_score"`

	// Malware Detection
	MalwareScore          float64  `json:"malware_score"`
	MalwareIndicators     []string `json:"malware_indicators"`
	SuspiciousPatterns    []string `json:"suspicious_patterns"`
	SuspiciousScripts     []string `json:"suspicious_scripts"`
	ObfuscationIndicators []string `json:"obfuscation_indicators"`
	MaliciousBehavior     []string `json:"malicious_behavior"`
	ThreatLevel           string   `json:"threat_level"`

	// Security Policy & Verification
	SecurityScore     float64 `json:"security_score"`
	HasSecurityPolicy bool    `json:"has_security_policy"`
	SignedReleases    bool    `json:"signed_releases"`
	SigstoreVerified  bool    `json:"sigstore_verified"`
	SLSALevel         int     `json:"slsa_level"`
	HasSBOM           bool    `json:"has_sbom"`
	SupplyChainRisk   float64 `json:"supply_chain_risk"`

	// License Analysis
	LicenseType          string  `json:"license_type"`
	LicenseRisk          float64 `json:"license_risk"`
	LicenseCompatibility bool    `json:"license_compatibility"`
	CopyleftRisk         float64 `json:"copyleft_risk"`
	CommercialUse        bool    `json:"commercial_use"`

	// Code Quality
	CodeComplexity       float64 `json:"code_complexity"`
	CyclomaticComplexity float64 `json:"cyclomatic_complexity"`
	CodeDuplication      float64 `json:"code_duplication"`
	CodeSmells           int     `json:"code_smells"`
	TechnicalDebt        float64 `json:"technical_debt"`

	// Trust Indicators
	TrustScore         float64 `json:"trust_score"`
	ReputationScore    float64 `json:"reputation_score"`
	AuthorTrust        float64 `json:"author_trust"`
	CommunityTrust     float64 `json:"community_trust"`
	VerificationStatus bool    `json:"verification_status"`
}

// GraphFeatures contains graph-based analysis features
type GraphFeatures struct {
	// Centrality Measures
	DegreeCentrality      float64 `json:"degree_centrality"`
	BetweennessCentrality float64 `json:"betweenness_centrality"`
	ClosenessCentrality   float64 `json:"closeness_centrality"`
	EigenvectorCentrality float64 `json:"eigenvector_centrality"`
	PageRank              float64 `json:"page_rank"`
	KatzCentrality        float64 `json:"katz_centrality"`

	// Network Properties
	ClusteringCoefficient float64 `json:"clustering_coefficient"`
	LocalClusteringCoeff  float64 `json:"local_clustering_coeff"`
	GlobalClusteringCoeff float64 `json:"global_clustering_coeff"`
	Transitivity          float64 `json:"transitivity"`
	Assortativity         float64 `json:"assortativity"`

	// Community Detection
	CommunityID      int     `json:"community_id"`
	CommunitySize    int     `json:"community_size"`
	Modularity       float64 `json:"modularity"`
	CommunityDensity float64 `json:"community_density"`
	BridgeScore      float64 `json:"bridge_score"`

	// Path Analysis
	ShortestPathLength float64 `json:"shortest_path_length"`
	AveragePathLength  float64 `json:"average_path_length"`
	Diameter           int     `json:"diameter"`
	Radius             int     `json:"radius"`
	Eccentricity       int     `json:"eccentricity"`

	// Structural Features
	DegreeDistribution []int `json:"degree_distribution"`
	InDegree           int   `json:"in_degree"`
	OutDegree          int   `json:"out_degree"`
	TriangleCount      int   `json:"triangle_count"`
	SquareCount        int   `json:"square_count"`
}

// TemporalFeatures contains time-based analysis features
type TemporalFeatures struct {
	// Trend Analysis
	OverallTrend      string  `json:"overall_trend"`
	TrendStrength     float64 `json:"trend_strength"`
	TrendDirection    string  `json:"trend_direction"`
	TrendAcceleration float64 `json:"trend_acceleration"`
	TrendStability    float64 `json:"trend_stability"`

	// Seasonality
	SeasonalPattern       bool      `json:"seasonal_pattern"`
	SeasonalPeriod        int       `json:"seasonal_period"`
	SeasonalStrength      float64   `json:"seasonal_strength"`
	SeasonalVariation     float64   `json:"seasonal_variation"`
	SeasonalDecomposition []float64 `json:"seasonal_decomposition"`

	// Anomaly Detection
	Anomalies        []time.Time `json:"anomalies"`
	AnomalyCount     int         `json:"anomaly_count"`
	AnomalyScore     float64     `json:"anomaly_score"`
	AnomalyFrequency float64     `json:"anomaly_frequency"`
	AnomalySeverity  []float64   `json:"anomaly_severity"`

	// Forecasting Features
	Predictability  float64   `json:"predictability"`
	Volatility      float64   `json:"volatility"`
	Stationarity    bool      `json:"stationarity"`
	Autocorrelation []float64 `json:"autocorrelation"`
	PartialAutocorr []float64 `json:"partial_autocorr"`

	// Lifecycle Features
	LifecycleStage  string  `json:"lifecycle_stage"`
	MaturityScore   float64 `json:"maturity_score"`
	GrowthRate      float64 `json:"growth_rate"`
	DeclineRate     float64 `json:"decline_rate"`
	StabilityPeriod int     `json:"stability_period"`
}

// Supporting analyzer structs
type TextAnalyzer struct {
	config *FeatureExtractionConfig
}

type StatisticalAnalyzer struct {
	config *FeatureExtractionConfig
}

type BehaviorAnalyzer struct {
	config *FeatureExtractionConfig
}

type SecurityAnalyzer struct {
	config *FeatureExtractionConfig
}

type GraphAnalyzer struct {
	config *FeatureExtractionConfig
}

type TemporalAnalyzer struct {
	config *FeatureExtractionConfig
}

type FeatureNormalizer struct {
	method  string
	scalers map[string]*Scaler
	stats   map[string]*FeatureStatistics
}

type Scaler struct {
	Min    float64
	Max    float64
	Mean   float64
	StdDev float64
}

// NormalizationParams contains parameters for feature normalization
type NormalizationParams struct {
	Means   []float64 `json:"means"`
	StdDevs []float64 `json:"std_devs"`
	Mins    []float64 `json:"mins"`
	Maxs    []float64 `json:"maxs"`
}

type ExtractionMetrics struct {
	TotalExtractions      int64         `json:"total_extractions"`
	SuccessfulExtractions int64         `json:"successful_extractions"`
	FailedExtractions     int64         `json:"failed_extractions"`
	AverageTime           time.Duration `json:"average_time"`
	TotalTime             time.Duration `json:"total_time"`
	CacheHits             int64         `json:"cache_hits"`
	CacheMisses           int64         `json:"cache_misses"`
	FeatureCount          int           `json:"feature_count"`
	QualityScore          float64       `json:"quality_score"`
}

// NewAdvancedFeatureExtractor creates a new advanced feature extractor
func NewAdvancedFeatureExtractor(config *FeatureExtractionConfig) *AdvancedFeatureExtractor {
	if config == nil {
		config = DefaultFeatureExtractionConfig()
	}

	return &AdvancedFeatureExtractor{
		config:              config,
		textAnalyzer:        &TextAnalyzer{config: config},
		statAnalyzer:        &StatisticalAnalyzer{config: config},
		behaviorAnalyzer:    &BehaviorAnalyzer{config: config},
		securityAnalyzer:    &SecurityAnalyzer{config: config},
		graphAnalyzer:       &GraphAnalyzer{config: config},
		temporalAnalyzer:    &TemporalAnalyzer{config: config},
		normalizer:          &FeatureNormalizer{method: config.Normalization, scalers: make(map[string]*Scaler), stats: make(map[string]*FeatureStatistics)},
		featureCache:        make(map[string]*ExtractedFeatures),
		metrics:             &ExtractionMetrics{},
		popularPackages:     make(map[string][]string),
		suspiciousKeywords:  []string{},
		domainReputations:   make(map[string]float64),
		licenseScores:       make(map[string]float64),
		normalizationParams: NormalizationParams{},
	}
}

// Helper utility functions

// generatePackageID generates a unique ID for a package
func generatePackageID(packageData map[string]interface{}) string {
	name := getString(packageData, "name")
	version := getString(packageData, "version")
	if name == "" {
		name = "unknown"
	}
	if version == "" {
		version = "unknown"
	}
	hash := md5.Sum([]byte(name + version))
	return fmt.Sprintf("%x", hash)
}

// getString safely extracts a string value from map
func getString(data map[string]interface{}, key string) string {
	if val, ok := data[key]; ok {
		if str, ok := val.(string); ok {
			return str
		}
	}
	return ""
}

// getFloat64 safely extracts a float64 value from map
func getFloat64(data map[string]interface{}, key string) float64 {
	if val, ok := data[key]; ok {
		switch v := val.(type) {
		case float64:
			return v
		case float32:
			return float64(v)
		case int:
			return float64(v)
		case int64:
			return float64(v)
		case string:
			if f, err := strconv.ParseFloat(v, 64); err == nil {
				return f
			}
		}
	}
	return 0.0
}

// getInt safely extracts an int value from map
func getInt(data map[string]interface{}, key string) int {
	if val, ok := data[key]; ok {
		switch v := val.(type) {
		case int:
			return v
		case int64:
			return int(v)
		case float64:
			return int(v)
		case string:
			if i, err := strconv.Atoi(v); err == nil {
				return i
			}
		}
	}
	return 0
}

// getBool safely extracts a bool value from map
func getBool(data map[string]interface{}, key string) bool {
	if val, ok := data[key]; ok {
		if b, ok := val.(bool); ok {
			return b
		}
	}
	return false
}

// getStringSlice safely extracts a string slice from map
func getStringSlice(data map[string]interface{}, key string) []string {
	if val, ok := data[key]; ok {
		if slice, ok := val.([]interface{}); ok {
			result := make([]string, len(slice))
			for i, v := range slice {
				if str, ok := v.(string); ok {
					result[i] = str
				}
			}
			return result
		}
		if slice, ok := val.([]string); ok {
			return slice
		}
	}
	return []string{}
}

// getIntSlice safely extracts an int slice from map
func getIntSlice(data map[string]interface{}, key string) []int {
	if val, ok := data[key]; ok {
		if slice, ok := val.([]interface{}); ok {
			result := make([]int, len(slice))
			for i, v := range slice {
				switch num := v.(type) {
				case int:
					result[i] = num
				case float64:
					result[i] = int(num)
				}
			}
			return result
		}
		if slice, ok := val.([]int); ok {
			return slice
		}
	}
	return []int{}
}

// getFloat64Slice safely extracts a float64 slice from map
func getFloat64Slice(data map[string]interface{}, key string) []float64 {
	if val, ok := data[key]; ok {
		if slice, ok := val.([]interface{}); ok {
			result := make([]float64, len(slice))
			for i, v := range slice {
				switch num := v.(type) {
				case float64:
					result[i] = num
				case float32:
					result[i] = float64(num)
				case int:
					result[i] = float64(num)
				}
			}
			return result
		}
		if slice, ok := val.([]float64); ok {
			return slice
		}
	}
	return []float64{}
}

// getTimeSlice safely extracts a time slice from map
func getTimeSlice(data map[string]interface{}, key string) []time.Time {
	if val, ok := data[key]; ok {
		if slice, ok := val.([]interface{}); ok {
			result := make([]time.Time, 0, len(slice))
			for _, v := range slice {
				if timeStr, ok := v.(string); ok {
					if t, err := time.Parse(time.RFC3339, timeStr); err == nil {
						result = append(result, t)
					}
				}
			}
			return result
		}
	}
	return []time.Time{}
}

// boolToFloat converts bool to float64
func boolToFloat(b bool) float64 {
	if b {
		return 1.0
	}
	return 0.0
}

// Text analysis helper functions

// countSentences counts sentences in text
func countSentences(text string) int {
	sentenceEnders := regexp.MustCompile(`[.!?]+`)
	matches := sentenceEnders.FindAllString(text, -1)
	return len(matches)
}

// countParagraphs counts paragraphs in text
func countParagraphs(text string) int {
	paragraphs := strings.Split(text, "\n\n")
	count := 0
	for _, p := range paragraphs {
		if strings.TrimSpace(p) != "" {
			count++
		}
	}
	return count
}

// calculateCharRatio calculates ratio of characters matching a condition
func calculateCharRatio(text string, condition func(rune) bool) float64 {
	if len(text) == 0 {
		return 0.0
	}
	count := 0
	for _, r := range text {
		if condition(r) {
			count++
		}
	}
	return float64(count) / float64(len(text))
}

// calculateSpecialCharRatio calculates ratio of special characters
func calculateSpecialCharRatio(text string) float64 {
	if len(text) == 0 {
		return 0.0
	}
	count := 0
	for _, r := range text {
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) && !unicode.IsSpace(r) {
			count++
		}
	}
	return float64(count) / float64(len(text))
}

// calculateReadabilityScore calculates readability score (simplified)
func calculateReadabilityScore(text string) float64 {
	words := strings.Fields(text)
	if len(words) == 0 {
		return 0.0
	}

	totalChars := 0
	for _, word := range words {
		totalChars += len(word)
	}

	avgWordLength := float64(totalChars) / float64(len(words))
	sentences := countSentences(text)
	if sentences == 0 {
		sentences = 1
	}
	avgSentenceLength := float64(len(words)) / float64(sentences)

	// Simplified readability formula
	return 206.835 - (1.015 * avgSentenceLength) - (84.6 * avgWordLength)
}

// calculateComplexityScore calculates text complexity score
func calculateComplexityScore(text string) float64 {
	words := strings.Fields(text)
	if len(words) == 0 {
		return 0.0
	}

	complexWords := 0
	for _, word := range words {
		if len(word) > 6 {
			complexWords++
		}
	}

	return float64(complexWords) / float64(len(words))
}

// extractNgrams extracts n-grams from text
func extractNgrams(text string, n int) map[string]int {
	ngrams := make(map[string]int)
	words := strings.Fields(strings.ToLower(text))

	for i := 0; i <= len(words)-n; i++ {
		ngram := strings.Join(words[i:i+n], " ")
		ngrams[ngram]++
	}

	return ngrams
}

// extractCharNgrams extracts character n-grams from text
func extractCharNgrams(text string, n int) map[string]int {
	ngrams := make(map[string]int)
	text = strings.ToLower(text)

	for i := 0; i <= len(text)-n; i++ {
		ngram := text[i : i+n]
		ngrams[ngram]++
	}

	return ngrams
}

// detectSuspiciousPatterns detects suspicious patterns in text
func detectSuspiciousPatterns(text string) []string {
	patterns := []string{}

	// Check for common suspicious patterns
	suspiciousRegexes := []*regexp.Regexp{
		regexp.MustCompile(`(?i)eval\s*\(`),
		regexp.MustCompile(`(?i)exec\s*\(`),
		regexp.MustCompile(`(?i)system\s*\(`),
		regexp.MustCompile(`(?i)shell_exec`),
		regexp.MustCompile(`(?i)base64_decode`),
		regexp.MustCompile(`(?i)obfuscat`),
		regexp.MustCompile(`(?i)malware`),
		regexp.MustCompile(`(?i)backdoor`),
	}

	for _, regex := range suspiciousRegexes {
		if regex.MatchString(text) {
			patterns = append(patterns, regex.String())
		}
	}

	return patterns
}

// calculateTyposquattingScore calculates typosquatting likelihood score
func calculateTyposquattingScore(name string) float64 {
	// Simplified typosquatting detection
	score := 0.0

	// Check for common typosquatting patterns
	if strings.Contains(name, "0") || strings.Contains(name, "1") {
		score += 0.2
	}
	if strings.Contains(name, "-") || strings.Contains(name, "_") {
		score += 0.1
	}
	if len(name) > 20 {
		score += 0.3
	}

	return math.Min(score, 1.0)
}

// calculateObfuscationScore calculates obfuscation score
func calculateObfuscationScore(text string) float64 {
	score := 0.0

	// Check for obfuscation indicators
	if strings.Contains(text, "\\x") {
		score += 0.3
	}
	if strings.Contains(text, "\\u") {
		score += 0.3
	}
	if calculateSpecialCharRatio(text) > 0.3 {
		score += 0.4
	}

	return math.Min(score, 1.0)
}

// calculateSocialEngineeringScore calculates social engineering score
func calculateSocialEngineeringScore(text string) float64 {
	score := 0.0
	lowerText := strings.ToLower(text)

	// Check for social engineering keywords
	socialEngKeywords := []string{
		"urgent", "immediate", "click here", "download now",
		"free", "winner", "congratulations", "limited time",
		"verify", "update", "suspend", "expire",
	}

	for _, keyword := range socialEngKeywords {
		if strings.Contains(lowerText, keyword) {
			score += 0.1
		}
	}

	return math.Min(score, 1.0)
}

// Statistical analysis helper functions

// extractNumericalData extracts numerical values from package data
func extractNumericalData(packageData map[string]interface{}) []float64 {
	var data []float64

	// Extract various numerical metrics
	metrics := []string{
		"download_count", "star_count", "fork_count", "issue_count",
		"contributor_count", "commit_count", "file_count", "line_count",
		"dependency_count", "version_count", "age_days",
	}

	for _, metric := range metrics {
		if val := getFloat64(packageData, metric); val > 0 {
			data = append(data, val)
		}
	}

	return data
}

// calculateMean calculates the mean of a slice
func calculateMean(data []float64) float64 {
	if len(data) == 0 {
		return 0.0
	}
	sum := 0.0
	for _, v := range data {
		sum += v
	}
	return sum / float64(len(data))
}

// calculateMedian calculates the median of a slice
func calculateMedian(data []float64) float64 {
	if len(data) == 0 {
		return 0.0
	}
	sorted := make([]float64, len(data))
	copy(sorted, data)
	sort.Float64s(sorted)

	n := len(sorted)
	if n%2 == 0 {
		return (sorted[n/2-1] + sorted[n/2]) / 2
	}
	return sorted[n/2]
}

// calculateMode calculates the mode of a slice
func calculateMode(data []float64) float64 {
	if len(data) == 0 {
		return 0.0
	}

	freq := make(map[float64]int)
	for _, v := range data {
		freq[v]++
	}

	maxFreq := 0
	mode := data[0]
	for val, f := range freq {
		if f > maxFreq {
			maxFreq = f
			mode = val
		}
	}

	return mode
}

// calculateStdDev calculates the standard deviation
func calculateStdDev(data []float64) float64 {
	if len(data) <= 1 {
		return 0.0
	}

	mean := calculateMean(data)
	sum := 0.0
	for _, v := range data {
		diff := v - mean
		sum += diff * diff
	}

	return math.Sqrt(sum / float64(len(data)-1))
}

// calculateSkewness calculates the skewness
func calculateSkewness(data []float64) float64 {
	if len(data) < 3 {
		return 0.0
	}

	mean := calculateMean(data)
	stdDev := calculateStdDev(data)
	if stdDev == 0 {
		return 0.0
	}

	sum := 0.0
	for _, v := range data {
		normalized := (v - mean) / stdDev
		sum += normalized * normalized * normalized
	}

	return sum / float64(len(data))
}

// calculateKurtosis calculates the kurtosis
func calculateKurtosis(data []float64) float64 {
	if len(data) < 4 {
		return 0.0
	}

	mean := calculateMean(data)
	stdDev := calculateStdDev(data)
	if stdDev == 0 {
		return 0.0
	}

	sum := 0.0
	for _, v := range data {
		normalized := (v - mean) / stdDev
		sum += normalized * normalized * normalized * normalized
	}

	return (sum / float64(len(data))) - 3.0
}

// calculateRange calculates the range
func calculateRange(data []float64) float64 {
	if len(data) == 0 {
		return 0.0
	}

	min, max := data[0], data[0]
	for _, v := range data {
		if v < min {
			min = v
		}
		if v > max {
			max = v
		}
	}

	return max - min
}

// calculateIQR calculates the interquartile range
func calculateIQR(data []float64) float64 {
	if len(data) < 4 {
		return 0.0
	}

	sorted := make([]float64, len(data))
	copy(sorted, data)
	sort.Float64s(sorted)

	n := len(sorted)
	q1 := sorted[n/4]
	q3 := sorted[3*n/4]

	return q3 - q1
}

// calculatePercentiles calculates percentiles
func calculatePercentiles(data []float64, percentiles []float64) []float64 {
	if len(data) == 0 {
		return make([]float64, len(percentiles))
	}

	sorted := make([]float64, len(data))
	copy(sorted, data)
	sort.Float64s(sorted)

	result := make([]float64, len(percentiles))
	for i, p := range percentiles {
		index := int(float64(len(sorted)-1) * p / 100.0)
		if index >= len(sorted) {
			index = len(sorted) - 1
		}
		result[i] = sorted[index]
	}

	return result
}

// detectOutliers detects outliers using IQR method
func detectOutliers(data []float64) []float64 {
	if len(data) < 4 {
		return []float64{}
	}

	sorted := make([]float64, len(data))
	copy(sorted, data)
	sort.Float64s(sorted)

	n := len(sorted)
	q1 := sorted[n/4]
	q3 := sorted[3*n/4]
	iqr := q3 - q1

	lowerBound := q1 - 1.5*iqr
	upperBound := q3 + 1.5*iqr

	var outliers []float64
	for _, v := range data {
		if v < lowerBound || v > upperBound {
			outliers = append(outliers, v)
		}
	}

	return outliers
}

// calculateZScores calculates z-scores
func calculateZScores(data []float64) []float64 {
	if len(data) <= 1 {
		return make([]float64, len(data))
	}

	mean := calculateMean(data)
	stdDev := calculateStdDev(data)
	if stdDev == 0 {
		return make([]float64, len(data))
	}

	zScores := make([]float64, len(data))
	for i, v := range data {
		zScores[i] = (v - mean) / stdDev
	}

	return zScores
}

// calculateModifiedZScores calculates modified z-scores
func calculateModifiedZScores(data []float64) []float64 {
	if len(data) == 0 {
		return []float64{}
	}

	median := calculateMedian(data)

	// Calculate median absolute deviation
	deviations := make([]float64, len(data))
	for i, v := range data {
		deviations[i] = math.Abs(v - median)
	}
	mad := calculateMedian(deviations)

	if mad == 0 {
		return make([]float64, len(data))
	}

	modifiedZScores := make([]float64, len(data))
	for i, v := range data {
		modifiedZScores[i] = 0.6745 * (v - median) / mad
	}

	return modifiedZScores
}

// ExtractFeaturesFromData extracts comprehensive features from package data
func (afe *AdvancedFeatureExtractor) ExtractFeaturesFromData(packageData map[string]interface{}) (*ExtractedFeatures, error) {
	startTime := time.Now()
	defer func() {
		afe.metrics.TotalExtractions++
		afe.metrics.TotalTime += time.Since(startTime)
		afe.metrics.AverageTime = time.Duration(int64(afe.metrics.TotalTime) / afe.metrics.TotalExtractions)
	}()

	packageID := fmt.Sprintf("%v", packageData["id"])
	if packageID == "" {
		packageID = generatePackageID(packageData)
	}

	// Check cache first
	if afe.config.CacheFeatures {
		if cached, exists := afe.featureCache[packageID]; exists {
			afe.metrics.CacheHits++
			return cached, nil
		}
		afe.metrics.CacheMisses++
	}

	features := &ExtractedFeatures{
		PackageID: packageID,
		Timestamp: time.Now(),
		Metadata:  make(map[string]interface{}),
	}

	// Extract different types of features
	var err error

	if afe.config.EnableTextAnalysis {
		features.TextFeatures, err = afe.extractTextFeatures(packageData)
		if err != nil {
			return nil, fmt.Errorf("text feature extraction failed: %w", err)
		}
	}

	if afe.config.EnableStatAnalysis {
		features.StatFeatures, err = afe.extractStatisticalFeatures(packageData)
		if err != nil {
			return nil, fmt.Errorf("statistical feature extraction failed: %w", err)
		}
	}

	if afe.config.EnableBehaviorAnalysis {
		features.BehaviorFeatures, err = afe.extractBehaviorFeatures(packageData)
		if err != nil {
			return nil, fmt.Errorf("behavior feature extraction failed: %w", err)
		}
	}

	if afe.config.EnableSecurityAnalysis {
		features.SecurityFeatures, err = afe.extractSecurityFeatures(packageData)
		if err != nil {
			return nil, fmt.Errorf("security feature extraction failed: %w", err)
		}
	}

	if afe.config.EnableGraphAnalysis {
		features.GraphFeatures, err = afe.extractGraphFeatures(packageData)
		if err != nil {
			return nil, fmt.Errorf("graph feature extraction failed: %w", err)
		}
	}

	if afe.config.EnableTemporalAnalysis {
		features.TemporalFeatures, err = afe.extractTemporalFeatures(packageData)
		if err != nil {
			return nil, fmt.Errorf("temporal feature extraction failed: %w", err)
		}
	}

	// Combine all features into a single vector
	features.CombinedFeatures, features.FeatureNames = afe.combineFeatures(features)

	// Normalize features if configured
	if afe.config.Normalization != "" {
		features.CombinedFeatures = afe.normalizer.Normalize(features.CombinedFeatures, features.FeatureNames)
	}

	// Calculate quality score
	features.QualityScore = afe.calculateQualityScore(features)
	features.ExtractionTime = time.Since(startTime)

	// Cache the result
	if afe.config.CacheFeatures {
		afe.featureCache[packageID] = features
	}

	afe.metrics.SuccessfulExtractions++
	afe.metrics.FeatureCount = len(features.CombinedFeatures)

	return features, nil
}

// extractTextFeatures extracts text-based features
func (afe *AdvancedFeatureExtractor) extractTextFeatures(packageData map[string]interface{}) (*TextFeatures, error) {
	features := &TextFeatures{
		UnigramFreq:   make(map[string]int),
		BigramFreq:    make(map[string]int),
		TrigramFreq:   make(map[string]int),
		CharNgramFreq: make(map[string]int),
	}

	// Extract basic text metrics
	name := getString(packageData, "name")
	description := getString(packageData, "description")
	readme := getString(packageData, "readme")

	features.NameLength = len(name)
	features.DescriptionLength = len(description)
	features.ReadmeLength = len(readme)

	// Combine all text for analysis
	allText := strings.Join([]string{name, description, readme}, " ")
	features.WordCount = len(strings.Fields(allText))
	features.SentenceCount = countSentences(allText)
	features.ParagraphCount = countParagraphs(allText)

	// Character analysis
	features.AlphaRatio = calculateCharRatio(allText, unicode.IsLetter)
	features.DigitRatio = calculateCharRatio(allText, unicode.IsDigit)
	features.SpecialCharRatio = calculateSpecialCharRatio(allText)
	features.UppercaseRatio = calculateCharRatio(allText, unicode.IsUpper)
	features.LowercaseRatio = calculateCharRatio(allText, unicode.IsLower)
	features.WhitespaceRatio = calculateCharRatio(allText, unicode.IsSpace)

	// Language detection (placeholder)
	features.Language = "en"
	features.LanguageConfidence = 0.95

	// Sentiment analysis (placeholder)
	features.Sentiment = 0.1
	features.SentimentConfidence = 0.8

	// Readability and complexity
	features.ReadabilityScore = calculateReadabilityScore(allText)
	features.ComplexityScore = calculateComplexityScore(allText)

	// N-gram analysis
	features.UnigramFreq = extractNgrams(allText, 1)
	features.BigramFreq = extractNgrams(allText, 2)
	features.TrigramFreq = extractNgrams(allText, 3)
	features.CharNgramFreq = extractCharNgrams(allText, 3)

	// Suspicious pattern detection
	features.SuspiciousPatterns = detectSuspiciousPatterns(allText)
	features.TyposquattingScore = calculateTyposquattingScore(name)
	features.ObfuscationScore = calculateObfuscationScore(allText)
	features.SocialEngScore = calculateSocialEngineeringScore(allText)

	return features, nil
}

// extractStatisticalFeatures extracts statistical features
func (afe *AdvancedFeatureExtractor) extractStatisticalFeatures(packageData map[string]interface{}) (*StatisticalFeatures, error) {
	features := &StatisticalFeatures{}

	// Extract numerical data for analysis
	numericalData := extractNumericalData(packageData)
	if len(numericalData) == 0 {
		return features, nil
	}

	// Basic statistics
	features.Mean = calculateMean(numericalData)
	features.Median = calculateMedian(numericalData)
	features.Mode = calculateMode(numericalData)
	features.StandardDeviation = calculateStdDev(numericalData)
	features.Variance = features.StandardDeviation * features.StandardDeviation
	features.Skewness = calculateSkewness(numericalData)
	features.Kurtosis = calculateKurtosis(numericalData)
	features.Range = calculateRange(numericalData)
	features.InterquartileRange = calculateIQR(numericalData)

	// Percentiles and quartiles
	features.Percentiles = calculatePercentiles(numericalData, []float64{10, 25, 50, 75, 90, 95, 99})
	features.Quartiles = calculatePercentiles(numericalData, []float64{25, 50, 75})
	features.Deciles = calculatePercentiles(numericalData, []float64{10, 20, 30, 40, 50, 60, 70, 80, 90})

	// Outlier detection
	features.Outliers = detectOutliers(numericalData)
	features.OutlierCount = len(features.Outliers)
	features.OutlierRatio = float64(features.OutlierCount) / float64(len(numericalData))
	features.ZScores = calculateZScores(numericalData)
	features.ModifiedZScores = calculateModifiedZScores(numericalData)

	return features, nil
}

// extractBehaviorFeatures extracts behavioral features
func (afe *AdvancedFeatureExtractor) extractBehaviorFeatures(packageData map[string]interface{}) (*BehaviorFeatures, error) {
	features := &BehaviorFeatures{}

	// Usage patterns
	features.DownloadFrequency = getFloat64(packageData, "download_frequency")
	features.DownloadTrend = getString(packageData, "download_trend")
	features.UsageStability = getFloat64(packageData, "usage_stability")
	features.PopularityScore = getFloat64(packageData, "popularity_score")
	features.AdoptionRate = getFloat64(packageData, "adoption_rate")
	features.RetentionRate = getFloat64(packageData, "retention_rate")

	// Dependency patterns
	features.DependencyCount = getInt(packageData, "dependency_count")
	features.DependentCount = getInt(packageData, "dependent_count")
	features.DependencyDepth = getInt(packageData, "dependency_depth")
	features.CircularDependencies = getBool(packageData, "circular_dependencies")
	features.DependencyStability = getFloat64(packageData, "dependency_stability")
	features.DependencyRisk = getFloat64(packageData, "dependency_risk")

	// Versioning patterns
	features.VersionCount = getInt(packageData, "version_count")
	features.VersionFrequency = getFloat64(packageData, "version_frequency")
	features.VersioningStrategy = getString(packageData, "versioning_strategy")
	features.BreakingChanges = getInt(packageData, "breaking_changes")
	features.BackwardCompatibility = getFloat64(packageData, "backward_compatibility")
	features.VersionStability = getFloat64(packageData, "version_stability")

	// Maintenance patterns
	features.MaintenanceScore = getFloat64(packageData, "maintenance_score")
	features.UpdateFrequency = getFloat64(packageData, "update_frequency")
	features.BugFixRate = getFloat64(packageData, "bug_fix_rate")
	features.ResponseTime = getFloat64(packageData, "response_time")
	features.CommunityActivity = getFloat64(packageData, "community_activity")
	features.ContributorCount = getInt(packageData, "contributor_count")

	// Quality indicators
	features.CodeQuality = getFloat64(packageData, "code_quality")
	features.TestCoverage = getFloat64(packageData, "test_coverage")
	features.DocumentationQuality = getFloat64(packageData, "documentation_quality")
	features.LicenseCompliance = getBool(packageData, "license_compliance")
	features.SecurityScore = getFloat64(packageData, "security_score")

	return features, nil
}

// extractSecurityFeatures extracts security-related features
func (afe *AdvancedFeatureExtractor) extractSecurityFeatures(packageData map[string]interface{}) (*SecurityFeatures, error) {
	features := &SecurityFeatures{}

	// Vulnerability analysis
	features.VulnerabilityCount = getInt(packageData, "vulnerability_count")
	features.CriticalVulns = getInt(packageData, "critical_vulns")
	features.HighVulns = getInt(packageData, "high_vulns")
	features.MediumVulns = getInt(packageData, "medium_vulns")
	features.LowVulns = getInt(packageData, "low_vulns")
	features.VulnerabilityScore = getFloat64(packageData, "vulnerability_score")
	features.CVSSScore = getFloat64(packageData, "cvss_score")

	// Malware detection
	features.MalwareScore = getFloat64(packageData, "malware_score")
	features.SuspiciousPatterns = getStringSlice(packageData, "suspicious_patterns")
	features.ObfuscationIndicators = getStringSlice(packageData, "obfuscation_indicators")
	features.MaliciousBehavior = getStringSlice(packageData, "malicious_behavior")
	features.ThreatLevel = getString(packageData, "threat_level")

	// License analysis
	features.LicenseType = getString(packageData, "license_type")
	features.LicenseRisk = getFloat64(packageData, "license_risk")
	features.LicenseCompatibility = getBool(packageData, "license_compatibility")
	features.CopyleftRisk = getFloat64(packageData, "copyleft_risk")
	features.CommercialUse = getBool(packageData, "commercial_use")

	// Code quality
	features.CodeComplexity = getFloat64(packageData, "code_complexity")
	features.CyclomaticComplexity = getFloat64(packageData, "cyclomatic_complexity")
	features.CodeDuplication = getFloat64(packageData, "code_duplication")
	features.CodeSmells = getInt(packageData, "code_smells")
	features.TechnicalDebt = getFloat64(packageData, "technical_debt")

	// Trust indicators
	features.TrustScore = getFloat64(packageData, "trust_score")
	features.ReputationScore = getFloat64(packageData, "reputation_score")
	features.AuthorTrust = getFloat64(packageData, "author_trust")
	features.CommunityTrust = getFloat64(packageData, "community_trust")
	features.VerificationStatus = getBool(packageData, "verification_status")

	return features, nil
}

// extractGraphFeatures extracts graph-based features
func (afe *AdvancedFeatureExtractor) extractGraphFeatures(packageData map[string]interface{}) (*GraphFeatures, error) {
	features := &GraphFeatures{}

	// Centrality measures
	features.DegreeCentrality = getFloat64(packageData, "degree_centrality")
	features.BetweennessCentrality = getFloat64(packageData, "betweenness_centrality")
	features.ClosenessCentrality = getFloat64(packageData, "closeness_centrality")
	features.EigenvectorCentrality = getFloat64(packageData, "eigenvector_centrality")
	features.PageRank = getFloat64(packageData, "page_rank")
	features.KatzCentrality = getFloat64(packageData, "katz_centrality")

	// Network properties
	features.ClusteringCoefficient = getFloat64(packageData, "clustering_coefficient")
	features.LocalClusteringCoeff = getFloat64(packageData, "local_clustering_coeff")
	features.GlobalClusteringCoeff = getFloat64(packageData, "global_clustering_coeff")
	features.Transitivity = getFloat64(packageData, "transitivity")
	features.Assortativity = getFloat64(packageData, "assortativity")

	// Community detection
	features.CommunityID = getInt(packageData, "community_id")
	features.CommunitySize = getInt(packageData, "community_size")
	features.Modularity = getFloat64(packageData, "modularity")
	features.CommunityDensity = getFloat64(packageData, "community_density")
	features.BridgeScore = getFloat64(packageData, "bridge_score")

	// Path analysis
	features.ShortestPathLength = getFloat64(packageData, "shortest_path_length")
	features.AveragePathLength = getFloat64(packageData, "average_path_length")
	features.Diameter = getInt(packageData, "diameter")
	features.Radius = getInt(packageData, "radius")
	features.Eccentricity = getInt(packageData, "eccentricity")

	// Structural features
	features.DegreeDistribution = getIntSlice(packageData, "degree_distribution")
	features.InDegree = getInt(packageData, "in_degree")
	features.OutDegree = getInt(packageData, "out_degree")
	features.TriangleCount = getInt(packageData, "triangle_count")
	features.SquareCount = getInt(packageData, "square_count")

	return features, nil
}

// extractTemporalFeatures extracts temporal features
func (afe *AdvancedFeatureExtractor) extractTemporalFeatures(packageData map[string]interface{}) (*TemporalFeatures, error) {
	features := &TemporalFeatures{}

	// Trend analysis
	features.OverallTrend = getString(packageData, "overall_trend")
	features.TrendStrength = getFloat64(packageData, "trend_strength")
	features.TrendDirection = getString(packageData, "trend_direction")
	features.TrendAcceleration = getFloat64(packageData, "trend_acceleration")
	features.TrendStability = getFloat64(packageData, "trend_stability")

	// Seasonality
	features.SeasonalPattern = getBool(packageData, "seasonal_pattern")
	features.SeasonalPeriod = getInt(packageData, "seasonal_period")
	features.SeasonalStrength = getFloat64(packageData, "seasonal_strength")
	features.SeasonalVariation = getFloat64(packageData, "seasonal_variation")
	features.SeasonalDecomposition = getFloat64Slice(packageData, "seasonal_decomposition")

	// Anomaly detection
	features.Anomalies = getTimeSlice(packageData, "anomalies")
	features.AnomalyCount = len(features.Anomalies)
	features.AnomalyScore = getFloat64(packageData, "anomaly_score")
	features.AnomalyFrequency = getFloat64(packageData, "anomaly_frequency")
	features.AnomalySeverity = getFloat64Slice(packageData, "anomaly_severity")

	// Forecasting features
	features.Predictability = getFloat64(packageData, "predictability")
	features.Volatility = getFloat64(packageData, "volatility")
	features.Stationarity = getBool(packageData, "stationarity")
	features.Autocorrelation = getFloat64Slice(packageData, "autocorrelation")
	features.PartialAutocorr = getFloat64Slice(packageData, "partial_autocorr")

	// Lifecycle features
	features.LifecycleStage = getString(packageData, "lifecycle_stage")
	features.MaturityScore = getFloat64(packageData, "maturity_score")
	features.GrowthRate = getFloat64(packageData, "growth_rate")
	features.DeclineRate = getFloat64(packageData, "decline_rate")
	features.StabilityPeriod = getInt(packageData, "stability_period")

	return features, nil
}

// combineFeatures combines all feature types into a single vector
func (afe *AdvancedFeatureExtractor) combineFeatures(features *ExtractedFeatures) ([]float64, []string) {
	var combined []float64
	var names []string

	// Add text features
	if features.TextFeatures != nil {
		textVec, textNames := afe.textFeaturesToVector(features.TextFeatures)
		combined = append(combined, textVec...)
		names = append(names, textNames...)
	}

	// Add statistical features
	if features.StatFeatures != nil {
		statVec, statNames := afe.statFeaturesToVector(features.StatFeatures)
		combined = append(combined, statVec...)
		names = append(names, statNames...)
	}

	// Add behavior features
	if features.BehaviorFeatures != nil {
		behaviorVec, behaviorNames := afe.behaviorFeaturesToVector(features.BehaviorFeatures)
		combined = append(combined, behaviorVec...)
		names = append(names, behaviorNames...)
	}

	// Add security features
	if features.SecurityFeatures != nil {
		securityVec, securityNames := afe.securityFeaturesToVector(features.SecurityFeatures)
		combined = append(combined, securityVec...)
		names = append(names, securityNames...)
	}

	// Add graph features
	if features.GraphFeatures != nil {
		graphVec, graphNames := afe.graphFeaturesToVector(features.GraphFeatures)
		combined = append(combined, graphVec...)
		names = append(names, graphNames...)
	}

	// Add temporal features
	if features.TemporalFeatures != nil {
		temporalVec, temporalNames := afe.temporalFeaturesToVector(features.TemporalFeatures)
		combined = append(combined, temporalVec...)
		names = append(names, temporalNames...)
	}

	return combined, names
}

// calculateQualityScore calculates the overall quality score of extracted features
func (afe *AdvancedFeatureExtractor) calculateQualityScore(features *ExtractedFeatures) float64 {
	score := 0.0
	count := 0

	if features.TextFeatures != nil {
		score += 0.2
		count++
	}
	if features.StatFeatures != nil {
		score += 0.15
		count++
	}
	if features.BehaviorFeatures != nil {
		score += 0.25
		count++
	}
	if features.SecurityFeatures != nil {
		score += 0.2
		count++
	}
	if features.GraphFeatures != nil {
		score += 0.1
		count++
	}
	if features.TemporalFeatures != nil {
		score += 0.1
		count++
	}

	if count == 0 {
		return 0.0
	}

	return score
}

// Helper functions for feature conversion
func (afe *AdvancedFeatureExtractor) textFeaturesToVector(features *TextFeatures) ([]float64, []string) {
	vec := []float64{
		float64(features.NameLength),
		float64(features.DescriptionLength),
		float64(features.ReadmeLength),
		float64(features.WordCount),
		float64(features.SentenceCount),
		float64(features.ParagraphCount),
		features.AlphaRatio,
		features.DigitRatio,
		features.SpecialCharRatio,
		features.UppercaseRatio,
		features.LowercaseRatio,
		features.WhitespaceRatio,
		features.LanguageConfidence,
		features.Sentiment,
		features.SentimentConfidence,
		features.ReadabilityScore,
		features.ComplexityScore,
		features.TyposquattingScore,
		features.ObfuscationScore,
		features.SocialEngScore,
	}

	names := []string{
		"name_length", "description_length", "readme_length",
		"word_count", "sentence_count", "paragraph_count",
		"alpha_ratio", "digit_ratio", "special_char_ratio",
		"uppercase_ratio", "lowercase_ratio", "whitespace_ratio",
		"language_confidence", "sentiment", "sentiment_confidence",
		"readability_score", "complexity_score",
		"typosquatting_score", "obfuscation_score", "social_eng_score",
	}

	return vec, names
}

func (afe *AdvancedFeatureExtractor) statFeaturesToVector(features *StatisticalFeatures) ([]float64, []string) {
	vec := []float64{
		features.Mean,
		features.Median,
		features.Mode,
		features.StandardDeviation,
		features.Variance,
		features.Skewness,
		features.Kurtosis,
		features.Range,
		features.InterquartileRange,
		float64(features.OutlierCount),
		features.OutlierRatio,
		features.MaxCorrelation,
		features.MinCorrelation,
		features.AvgCorrelation,
		features.TrendStrength,
	}

	names := []string{
		"mean", "median", "mode", "std_dev", "variance",
		"skewness", "kurtosis", "range", "iqr",
		"outlier_count", "outlier_ratio",
		"max_correlation", "min_correlation", "avg_correlation",
		"trend_strength",
	}

	return vec, names
}

func (afe *AdvancedFeatureExtractor) behaviorFeaturesToVector(features *BehaviorFeatures) ([]float64, []string) {
	vec := []float64{
		features.DownloadFrequency,
		features.UsageStability,
		features.PopularityScore,
		features.AdoptionRate,
		features.RetentionRate,
		float64(features.DependencyCount),
		float64(features.DependentCount),
		float64(features.DependencyDepth),
		boolToFloat(features.CircularDependencies),
		features.DependencyStability,
		features.DependencyRisk,
		float64(features.VersionCount),
		features.VersionFrequency,
		float64(features.BreakingChanges),
		features.BackwardCompatibility,
		features.VersionStability,
		features.MaintenanceScore,
		features.UpdateFrequency,
		features.BugFixRate,
		features.ResponseTime,
		features.CommunityActivity,
		float64(features.ContributorCount),
		features.CodeQuality,
		features.TestCoverage,
		features.DocumentationQuality,
		boolToFloat(features.LicenseCompliance),
		features.SecurityScore,
	}

	names := []string{
		"download_frequency", "usage_stability", "popularity_score",
		"adoption_rate", "retention_rate", "dependency_count",
		"dependent_count", "dependency_depth", "circular_dependencies",
		"dependency_stability", "dependency_risk", "version_count",
		"version_frequency", "breaking_changes", "backward_compatibility",
		"version_stability", "maintenance_score", "update_frequency",
		"bug_fix_rate", "response_time", "community_activity",
		"contributor_count", "code_quality", "test_coverage",
		"documentation_quality", "license_compliance", "security_score",
	}

	return vec, names
}

func (afe *AdvancedFeatureExtractor) securityFeaturesToVector(features *SecurityFeatures) ([]float64, []string) {
	vec := []float64{
		float64(features.VulnerabilityCount),
		float64(features.CriticalVulns),
		float64(features.HighVulns),
		float64(features.MediumVulns),
		float64(features.LowVulns),
		features.VulnerabilityScore,
		features.CVSSScore,
		features.MalwareScore,
		features.LicenseRisk,
		boolToFloat(features.LicenseCompatibility),
		features.CopyleftRisk,
		boolToFloat(features.CommercialUse),
		features.CodeComplexity,
		features.CyclomaticComplexity,
		features.CodeDuplication,
		float64(features.CodeSmells),
		features.TechnicalDebt,
		features.TrustScore,
		features.ReputationScore,
		features.AuthorTrust,
		features.CommunityTrust,
		boolToFloat(features.VerificationStatus),
	}

	names := []string{
		"vulnerability_count", "critical_vulns", "high_vulns",
		"medium_vulns", "low_vulns", "vulnerability_score",
		"cvss_score", "malware_score", "license_risk",
		"license_compatibility", "copyleft_risk", "commercial_use",
		"code_complexity", "cyclomatic_complexity", "code_duplication",
		"code_smells", "technical_debt", "trust_score",
		"reputation_score", "author_trust", "community_trust",
		"verification_status",
	}

	return vec, names
}

func (afe *AdvancedFeatureExtractor) graphFeaturesToVector(features *GraphFeatures) ([]float64, []string) {
	vec := []float64{
		features.DegreeCentrality,
		features.BetweennessCentrality,
		features.ClosenessCentrality,
		features.EigenvectorCentrality,
		features.PageRank,
		features.KatzCentrality,
		features.ClusteringCoefficient,
		features.LocalClusteringCoeff,
		features.GlobalClusteringCoeff,
		features.Transitivity,
		features.Assortativity,
		float64(features.CommunityID),
		float64(features.CommunitySize),
		features.Modularity,
		features.CommunityDensity,
		features.BridgeScore,
		features.ShortestPathLength,
		features.AveragePathLength,
		float64(features.Diameter),
		float64(features.Radius),
		float64(features.Eccentricity),
		float64(features.InDegree),
		float64(features.OutDegree),
		float64(features.TriangleCount),
		float64(features.SquareCount),
	}

	names := []string{
		"degree_centrality", "betweenness_centrality", "closeness_centrality",
		"eigenvector_centrality", "page_rank", "katz_centrality",
		"clustering_coefficient", "local_clustering_coeff", "global_clustering_coeff",
		"transitivity", "assortativity", "community_id",
		"community_size", "modularity", "community_density",
		"bridge_score", "shortest_path_length", "average_path_length",
		"diameter", "radius", "eccentricity",
		"in_degree", "out_degree", "triangle_count", "square_count",
	}

	return vec, names
}

func (afe *AdvancedFeatureExtractor) temporalFeaturesToVector(features *TemporalFeatures) ([]float64, []string) {
	vec := []float64{
		features.TrendStrength,
		features.TrendAcceleration,
		features.TrendStability,
		boolToFloat(features.SeasonalPattern),
		float64(features.SeasonalPeriod),
		features.SeasonalStrength,
		features.SeasonalVariation,
		float64(features.AnomalyCount),
		features.AnomalyScore,
		features.AnomalyFrequency,
		features.Predictability,
		features.Volatility,
		boolToFloat(features.Stationarity),
		features.MaturityScore,
		features.GrowthRate,
		features.DeclineRate,
		float64(features.StabilityPeriod),
	}

	names := []string{
		"trend_strength", "trend_acceleration", "trend_stability",
		"seasonal_pattern", "seasonal_period", "seasonal_strength",
		"seasonal_variation", "anomaly_count", "anomaly_score",
		"anomaly_frequency", "predictability", "volatility",
		"stationarity", "maturity_score", "growth_rate",
		"decline_rate", "stability_period",
	}

	return vec, names
}

// Normalize normalizes feature values using the configured method
func (fn *FeatureNormalizer) Normalize(features []float64, names []string) []float64 {
	if fn.method == "" {
		return features
	}

	normalized := make([]float64, len(features))
	copy(normalized, features)

	switch fn.method {
	case "min_max":
		return fn.minMaxNormalize(normalized, names)
	case "z_score":
		return fn.zScoreNormalize(normalized, names)
	case "robust":
		return fn.robustNormalize(normalized, names)
	default:
		return normalized
	}
}

func (fn *FeatureNormalizer) minMaxNormalize(features []float64, names []string) []float64 {
	for i, name := range names {
		scaler, exists := fn.scalers[name]
		if !exists {
			scaler = &Scaler{Min: features[i], Max: features[i]}
			fn.scalers[name] = scaler
		}

		if features[i] < scaler.Min {
			scaler.Min = features[i]
		}
		if features[i] > scaler.Max {
			scaler.Max = features[i]
		}

		if scaler.Max != scaler.Min {
			features[i] = (features[i] - scaler.Min) / (scaler.Max - scaler.Min)
		} else {
			features[i] = 0.0
		}
	}
	return features
}

func (fn *FeatureNormalizer) zScoreNormalize(features []float64, names []string) []float64 {
	for i, name := range names {
		scaler, exists := fn.scalers[name]
		if !exists {
			scaler = &Scaler{Mean: features[i], StdDev: 1.0}
			fn.scalers[name] = scaler
		}

		if scaler.StdDev != 0 {
			features[i] = (features[i] - scaler.Mean) / scaler.StdDev
		} else {
			features[i] = 0.0
		}
	}
	return features
}

func (fn *FeatureNormalizer) robustNormalize(features []float64, names []string) []float64 {
	// Placeholder for robust normalization (using median and IQR)
	return features
}

// GetMetrics returns extraction metrics
// ExtractFeatures implements the FeatureExtractor interface
func (afe *AdvancedFeatureExtractor) ExtractFeatures(pkg *types.Package) (*PackageFeatures, error) {
	// Convert types.Package to map[string]interface{} for compatibility
	packageData := map[string]interface{}{
		"id":          pkg.Name,
		"name":        pkg.Name,
		"version":     pkg.Version,
		"registry":    pkg.Registry,
		"description": "",
		"downloads":   0,
		"stars":       0,
		"forks":       0,
	}

	// Add metadata if available
	if pkg.Metadata != nil {
		if desc, ok := pkg.Metadata.Metadata["description"].(string); ok {
			packageData["description"] = desc
		}
		if downloads, ok := pkg.Metadata.Metadata["downloads"].(int64); ok {
			packageData["downloads"] = downloads
		}
	}

	// Extract features using existing method
	extractedFeatures, err := afe.ExtractFeaturesFromData(packageData)
	if err != nil {
		return nil, err
	}

	// Convert ExtractedFeatures to PackageFeatures
	packageFeatures := &PackageFeatures{
		PackageName:        pkg.Name,
		Registry:           pkg.Registry,
		Version:            pkg.Version,
		NameLength:         extractedFeatures.TextFeatures.NameLength,
		NameComplexity:     extractedFeatures.TextFeatures.ComplexityScore,
		NameEntropy:        float64(extractedFeatures.TextFeatures.NameLength), // Placeholder
		VersionComplexity:  1.0,                                                // Placeholder
		DescriptionLength:  extractedFeatures.TextFeatures.DescriptionLength,
		DependencyCount:    extractedFeatures.BehaviorFeatures.DependencyCount,
		DownloadCount:      int64(extractedFeatures.BehaviorFeatures.DownloadFrequency),
		StarCount:          0, // Placeholder
		ForkCount:          0, // Placeholder
		ContributorCount:   extractedFeatures.BehaviorFeatures.ContributorCount,
		AgeInDays:          0, // Placeholder
		TyposquattingScore: extractedFeatures.TextFeatures.TyposquattingScore,
		SuspiciousKeywords: len(extractedFeatures.SecurityFeatures.SuspiciousPatterns),
		VersionSpoofing:    0.0, // Placeholder
		DomainReputation:   extractedFeatures.SecurityFeatures.ReputationScore,
		UpdateFrequency:    extractedFeatures.BehaviorFeatures.UpdateFrequency,
		MaintainerCount:    1, // Placeholder
		IssueCount:         0, // Placeholder
		LicenseScore:       extractedFeatures.SecurityFeatures.LicenseRisk,
	}

	return packageFeatures, nil
}

// GetFeatureNames implements the FeatureExtractor interface
func (afe *AdvancedFeatureExtractor) GetFeatureNames() []string {
	return []string{
		"name_length", "name_complexity", "name_entropy", "version_complexity",
		"description_length", "dependency_count", "download_count", "star_count",
		"fork_count", "contributor_count", "age_in_days", "typosquatting_score",
		"suspicious_keywords", "version_spoofing", "domain_reputation",
		"update_frequency", "maintainer_count", "issue_count", "license_score",
	}
}

// NormalizeFeatures implements the FeatureExtractor interface
func (afe *AdvancedFeatureExtractor) NormalizeFeatures(features *PackageFeatures) []float64 {
	return []float64{
		float64(features.NameLength),
		features.NameComplexity,
		features.NameEntropy,
		features.VersionComplexity,
		float64(features.DescriptionLength),
		float64(features.DependencyCount),
		float64(features.DownloadCount),
		float64(features.StarCount),
		float64(features.ForkCount),
		float64(features.ContributorCount),
		float64(features.AgeInDays),
		features.TyposquattingScore,
		float64(features.SuspiciousKeywords),
		features.VersionSpoofing,
		features.DomainReputation,
		features.UpdateFrequency,
		float64(features.MaintainerCount),
		float64(features.IssueCount),
		features.LicenseScore,
	}
}

func (afe *AdvancedFeatureExtractor) GetMetrics() *ExtractionMetrics {
	return afe.metrics
}

// ClearCache clears the feature cache
func (afe *AdvancedFeatureExtractor) ClearCache() {
	afe.featureCache = make(map[string]*ExtractedFeatures)
	afe.metrics.CacheHits = 0
	afe.metrics.CacheMisses = 0
}

// DefaultFeatureExtractionConfig returns a default configuration
func DefaultFeatureExtractionConfig() *FeatureExtractionConfig {
	return &FeatureExtractionConfig{
		EnableTextAnalysis:      true,
		TextFeatures:            []string{"basic", "linguistic", "ngrams", "suspicious"},
		LanguageDetection:       true,
		SentimentAnalysis:       true,
		TopicModeling:           false,
		NGramRange:              [2]int{1, 3},
		MaxFeatures:             1000,
		MinDocumentFreq:         0.01,
		MaxDocumentFreq:         0.95,
		EnableStatAnalysis:      true,
		StatFeatures:            []string{"distribution", "outliers", "correlation"},
		DistributionAnalysis:    true,
		OutlierDetection:        true,
		CorrelationAnalysis:     true,
		TimeSeriesAnalysis:      false,
		EnableBehaviorAnalysis:  true,
		BehaviorFeatures:        []string{"usage", "dependencies", "versioning", "maintenance"},
		UsagePatterns:           true,
		DependencyAnalysis:      true,
		VersioningPatterns:      true,
		MaintenancePatterns:     true,
		EnableSecurityAnalysis:  true,
		SecurityFeatures:        []string{"vulnerabilities", "malware", "license", "trust"},
		VulnerabilityScanning:   true,
		MalwareDetection:        true,
		LicenseAnalysis:         true,
		CodeQualityAnalysis:     true,
		EnableGraphAnalysis:     false,
		GraphFeatures:           []string{"centrality", "community", "structure"},
		DependencyGraphs:        false,
		SocialNetworkAnalysis:   false,
		CommunityDetection:      false,
		CentralityMeasures:      false,
		EnableTemporalAnalysis:  false,
		TemporalFeatures:        []string{"trends", "seasonality", "anomalies"},
		TrendAnalysis:           false,
		SeasonalityDetection:    false,
		AnomalyDetection:        false,
		ForecastingFeatures:     false,
		Normalization:           "min_max",
		FeatureSelection:        false,
		DimensionalityReduction: false,
		FeatureEngineering:      false,
		CacheFeatures:           true,
		ParallelProcessing:      false,
		MaxConcurrency:          4,
	}
}
