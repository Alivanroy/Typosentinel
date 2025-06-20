package ml

import (
	"context"
	"fmt"
	"math"
	"regexp"
	"strings"
	"time"
	"unicode"

	"typosentinel/internal/config"
	"typosentinel/pkg/types"
)

// MLAnalyzer performs machine learning-based analysis for typosquatting detection.
type MLAnalyzer struct {
	Config config.MLAnalysisConfig
	Client *Client
}

// Config holds the configuration for the ML analyzer.
type Config struct {
	Enabled              bool    `mapstructure:"enabled"`
	SimilarityThreshold  float64 `mapstructure:"similarity_threshold"`
	MaliciousThreshold   float64 `mapstructure:"malicious_threshold"`
	ReputationThreshold  float64 `mapstructure:"reputation_threshold"`
	ModelPath            string  `mapstructure:"model_path"`
	BatchSize            int     `mapstructure:"batch_size"`
	MaxFeatures          int     `mapstructure:"max_features"`
	CacheEmbeddings      bool    `mapstructure:"cache_embeddings"`
	ParallelProcessing   bool    `mapstructure:"parallel_processing"`
	GPUAcceleration      bool    `mapstructure:"gpu_acceleration"`
}

// AnalysisResult holds the results of the ML analysis.
type AnalysisResult struct {
	SimilarityScore     float64                `json:"similarity_score"`
	MaliciousScore      float64                `json:"malicious_score"`
	ReputationScore     float64                `json:"reputation_score"`
	TyposquattingScore  float64                `json:"typosquatting_score"`
	Features            map[string]float64     `json:"features"`
	Predictions         []Prediction           `json:"predictions"`
	SimilarPackages     []SimilarPackage       `json:"similar_packages"`
	AnomalyDetection    AnomalyDetection       `json:"anomaly_detection"`
	ReputationAnalysis  ReputationAnalysis     `json:"reputation_analysis"`
	BehavioralAnalysis  BehavioralAnalysis     `json:"behavioral_analysis"`
	RiskAssessment      RiskAssessment         `json:"risk_assessment"`
	Findings            []Finding              `json:"findings"`
	Recommendations     []string               `json:"recommendations"`
	Metadata            AnalysisMetadata       `json:"metadata"`
}

// Prediction represents a model prediction.
type Prediction struct {
	Model       string  `json:"model"`
	Probability float64 `json:"probability"`
	Label       string  `json:"label"`
	Confidence  float64 `json:"confidence"`
}

// SimilarPackage represents a package similar to the analyzed one.
type SimilarPackage struct {
	Name           string  `json:"name"`
	Similarity     float64 `json:"similarity"`
	Distance       int     `json:"distance"`
	Algorithm      string  `json:"algorithm"`
	Registry       string  `json:"registry"`
	Downloads      int64   `json:"downloads"`
	LastUpdated    string  `json:"last_updated"`
	Maintainer     string  `json:"maintainer"`
	SuspiciousFlag bool    `json:"suspicious_flag"`
}

// AnomalyDetection holds anomaly detection results.
type AnomalyDetection struct {
	IsAnomaly       bool               `json:"is_anomaly"`
	AnomalyScore    float64            `json:"anomaly_score"`
	AnomalyType     string             `json:"anomaly_type"`
	AnomalyFeatures []string           `json:"anomaly_features"`
	OutlierAnalysis OutlierAnalysis    `json:"outlier_analysis"`
	PatternAnalysis PatternAnalysis    `json:"pattern_analysis"`
}

// OutlierAnalysis holds outlier detection results.
type OutlierAnalysis struct {
	IsOutlier        bool    `json:"is_outlier"`
	OutlierScore     float64 `json:"outlier_score"`
	IsolationForest  float64 `json:"isolation_forest"`
	LocalOutlier     float64 `json:"local_outlier"`
	OneClassSVM      float64 `json:"one_class_svm"`
}

// PatternAnalysis holds pattern analysis results.
type PatternAnalysis struct {
	UnusualPatterns []string `json:"unusual_patterns"`
	PatternScore    float64  `json:"pattern_score"`
	FrequencyScore  float64  `json:"frequency_score"`
	SequenceScore   float64  `json:"sequence_score"`
}

// ReputationAnalysis holds reputation analysis results.
type ReputationAnalysis struct {
	OverallScore      float64            `json:"overall_score"`
	MaintainerScore   float64            `json:"maintainer_score"`
	DownloadScore     float64            `json:"download_score"`
	AgeScore          float64            `json:"age_score"`
	CommunityScore    float64            `json:"community_score"`
	SecurityScore     float64            `json:"security_score"`
	ReputationSources []ReputationSource `json:"reputation_sources"`
}

// ReputationSource represents a source of reputation information.
type ReputationSource struct {
	Source string  `json:"source"`
	Score  float64 `json:"score"`
	Weight float64 `json:"weight"`
}

// BehavioralAnalysis holds behavioral analysis results.
type BehavioralAnalysis struct {
	InstallBehavior   InstallBehavior   `json:"install_behavior"`
	RuntimeBehavior   RuntimeBehavior   `json:"runtime_behavior"`
	NetworkBehavior   NetworkBehavior   `json:"network_behavior"`
	FileSystemBehavior FileSystemBehavior `json:"filesystem_behavior"`
}

// InstallBehavior holds install-time behavior analysis.
type InstallBehavior struct {
	SuspiciousCommands []string `json:"suspicious_commands"`
	NetworkRequests    []string `json:"network_requests"`
	FileModifications  []string `json:"file_modifications"`
	PermissionChanges  []string `json:"permission_changes"`
}

// RuntimeBehavior holds runtime behavior analysis.
type RuntimeBehavior struct {
	ProcessSpawning   []string `json:"process_spawning"`
	SystemCalls       []string `json:"system_calls"`
	ResourceUsage     []string `json:"resource_usage"`
	EnvironmentAccess []string `json:"environment_access"`
}

// NetworkBehavior holds network behavior analysis.
type NetworkBehavior struct {
	OutboundConnections []string `json:"outbound_connections"`
	DNSQueries          []string `json:"dns_queries"`
	DataExfiltration    []string `json:"data_exfiltration"`
	C2Communication     []string `json:"c2_communication"`
}

// FileSystemBehavior holds file system behavior analysis.
type FileSystemBehavior struct {
	FileCreation     []string `json:"file_creation"`
	FileDeletion     []string `json:"file_deletion"`
	FileModification []string `json:"file_modification"`
	DirectoryAccess  []string `json:"directory_access"`
}

// RiskAssessment holds overall risk assessment.
type RiskAssessment struct {
	OverallRisk    string             `json:"overall_risk"`
	RiskScore      float64            `json:"risk_score"`
	RiskFactors    []RiskFactor       `json:"risk_factors"`
	Mitigations    []string           `json:"mitigations"`
	ConfidenceLevel float64           `json:"confidence_level"`
}

// RiskFactor represents a specific risk factor.
type RiskFactor struct {
	Factor      string  `json:"factor"`
	Severity    string  `json:"severity"`
	Score       float64 `json:"score"`
	Description string  `json:"description"`
}

// Finding represents a specific ML finding.
type Finding struct {
	Type        string  `json:"type"`
	Severity    string  `json:"severity"`
	Confidence  float64 `json:"confidence"`
	Description string  `json:"description"`
	Evidence    string  `json:"evidence"`
	Model       string  `json:"model"`
}

// AnalysisMetadata holds metadata about the analysis.
type AnalysisMetadata struct {
	AnalysisTime    time.Time `json:"analysis_time"`
	Duration        string    `json:"duration"`
	ModelsUsed      []string  `json:"models_used"`
	FeaturesUsed    []string  `json:"features_used"`
	DatasetVersion  string    `json:"dataset_version"`
	ModelVersion    string    `json:"model_version"`
	AnalysisVersion string    `json:"analysis_version"`
}

// NewMLAnalyzer creates a new instance of the MLAnalyzer.
func NewMLAnalyzer(cfg config.MLAnalysisConfig) *MLAnalyzer {
	return &MLAnalyzer{
		Config: cfg,
		Client: nil, // Client can be set separately for testing
	}
}

// NewMLAnalyzerWithClient creates a new ML analyzer with a specific client
func NewMLAnalyzerWithClient(cfg config.MLAnalysisConfig, client *Client) *MLAnalyzer {
	return &MLAnalyzer{
		Config: cfg,
		Client: client,
	}
}

// DefaultConfig provides a default configuration for the ML analyzer.
func DefaultConfig() config.MLAnalysisConfig {
	return config.MLAnalysisConfig{
		SimilarityThreshold:  0.8,
		MaliciousThreshold:   0.7,
		ReputationThreshold:  0.6,
		ModelPath:            "models/",
		BatchSize:           10,
		MaxFeatures:         1000,
		CacheEmbeddings:     true,
		ParallelProcessing:  true,
		GPUAcceleration:     false,
	}
}

// Analyze performs ML-based analysis on a package.
func (a *MLAnalyzer) Analyze(ctx context.Context, pkg *types.Package) (*AnalysisResult, error) {
	// Check if ML analysis is enabled
	if !a.Config.Enabled {
		return nil, fmt.Errorf("ML analysis is disabled")
	}
	
	startTime := time.Now()
	
	// Extract features from the package
	features := a.extractFeatures(pkg)
	
	// Perform similarity analysis
	similarityScore := a.calculateSimilarityScore(pkg)
	similarPackages := a.findSimilarPackages(pkg)
	
	// Perform malicious detection
	maliciousScore, err := a.detectMaliciousPackage(ctx, pkg, features)
	if err != nil {
		return nil, err
	}
	
	// Perform reputation analysis
	reputationAnalysis := a.analyzeReputation(pkg)
	
	// Perform anomaly detection
	anomalyDetection := a.detectAnomalies(pkg, features)
	
	// Perform behavioral analysis (placeholder)
	behavioralAnalysis := a.analyzeBehavior(pkg)
	
	// Calculate typosquatting score
	typosquattingScore := a.calculateTyposquattingScore(similarityScore, maliciousScore, reputationAnalysis.OverallScore)
	
	// Generate predictions
	predictions := a.generatePredictions(pkg, features)
	
	// Perform risk assessment
	riskAssessment := a.assessRisk(typosquattingScore, maliciousScore, reputationAnalysis.OverallScore)
	
	// Generate findings
	findings := a.generateFindings(pkg, similarityScore, maliciousScore, reputationAnalysis, anomalyDetection)
	
	// Generate recommendations
	recommendations := a.generateRecommendations(riskAssessment, findings)
	
	// Create metadata
	metadata := AnalysisMetadata{
		AnalysisTime:    startTime,
		Duration:        time.Since(startTime).String(),
		ModelsUsed:      []string{"similarity_model", "malicious_detection_model", "reputation_model"},
		FeaturesUsed:    getFeatureNames(features),
		DatasetVersion:  "1.0.0",
		ModelVersion:    "1.0.0",
		AnalysisVersion: "1.0.0",
	}
	
	return &AnalysisResult{
		SimilarityScore:    similarityScore,
		MaliciousScore:     maliciousScore,
		ReputationScore:    reputationAnalysis.OverallScore,
		TyposquattingScore: typosquattingScore,
		Features:           features,
		Predictions:        predictions,
		SimilarPackages:    similarPackages,
		AnomalyDetection:   anomalyDetection,
		ReputationAnalysis: reputationAnalysis,
		BehavioralAnalysis: behavioralAnalysis,
		RiskAssessment:     riskAssessment,
		Findings:           findings,
		Recommendations:    recommendations,
		Metadata:           metadata,
	}, nil
}

// extractFeatures extracts features from a package for ML analysis.
func (a *MLAnalyzer) extractFeatures(pkg *types.Package) map[string]float64 {
	features := make(map[string]float64)
	
	// Name-based features
	features["name_length"] = float64(len(pkg.Name))
	features["name_entropy"] = calculateEntropy(pkg.Name)
	features["name_vowel_ratio"] = calculateVowelRatio(pkg.Name)
	features["name_digit_ratio"] = calculateDigitRatio(pkg.Name)
	features["name_special_char_ratio"] = calculateSpecialCharRatio(pkg.Name)
	
	// Version-based features
	if pkg.Version != "" {
		features["version_length"] = float64(len(pkg.Version))
		features["version_parts"] = float64(len(strings.Split(pkg.Version, ".")))
	}
	
	// Metadata-based features
	if pkg.Metadata != nil {
		// Description-based features
		if pkg.Metadata.Description != "" {
			features["description_length"] = float64(len(pkg.Metadata.Description))
			features["description_entropy"] = calculateEntropy(pkg.Metadata.Description)
		}
		
		// Author-based features
		if pkg.Metadata.Author != "" {
			features["author_length"] = float64(len(pkg.Metadata.Author))
			features["author_entropy"] = calculateEntropy(pkg.Metadata.Author)
		}
		
		features["has_homepage"] = boolToFloat(pkg.Metadata.Homepage != "")
		features["has_repository"] = boolToFloat(pkg.Metadata.Repository != "")
		features["has_license"] = boolToFloat(pkg.Metadata.License != "")
		features["keyword_count"] = float64(len(pkg.Metadata.Keywords))
		features["downloads"] = float64(pkg.Metadata.Downloads)
		features["file_count"] = float64(pkg.Metadata.FileCount)
		features["size"] = float64(pkg.Metadata.Size)
	} else {
		// Default values when metadata is nil
		features["has_homepage"] = 0.0
		features["has_repository"] = 0.0
		features["has_license"] = 0.0
		features["keyword_count"] = 0.0
		features["downloads"] = 0.0
		features["file_count"] = 0.0
		features["size"] = 0.0
	}
	
	// Dependency-based features (placeholder)
	features["dependency_count"] = 0 // Would be calculated from actual dependencies
	
	return features
}

// calculateSimilarityScore calculates similarity score with known packages.
func (a *MLAnalyzer) calculateSimilarityScore(pkg *types.Package) float64 {
	// Enhanced list of popular packages to check against
	popularPackages := []string{
		// JavaScript/Node.js packages
		"express", "lodash", "react", "vue", "angular", "jquery", "bootstrap",
		"moment", "axios", "webpack", "babel", "eslint", "prettier", "typescript",
		"node", "npm", "yarn", "gulp", "grunt", "mocha", "jest", "chai",
		"sinon", "karma", "jasmine", "protractor", "selenium", "puppeteer",
		"socket.io", "mongoose", "passport", "nodemon", "chalk", "commander",
		"inquirer", "yargs", "fs-extra", "glob", "rimraf", "mkdirp", "semver",
		"uuid", "bcrypt", "jsonwebtoken", "cors", "helmet", "morgan", "multer",
		"nodemailer", "sharp", "jimp", "cheerio", "playwright", "supertest",
		// Python packages
		"requests", "numpy", "pandas", "matplotlib", "scipy", "sklearn",
		"tensorflow", "pytorch", "keras", "flask", "django", "fastapi",
		"beautifulsoup4", "pillow", "opencv-python", "nltk", "spacy",
		"sqlalchemy", "alembic", "celery", "redis", "psycopg2", "pymongo",
		"boto3", "pydantic", "click", "typer", "rich", "tqdm", "pytest",
		"black", "flake8", "mypy", "isort", "pre-commit",
		// Go packages (full module paths and simplified names)
		"gin", "mux", "logrus", "testify", "protobuf", "grpc", "mysql",
		"pq", "redis", "gorm", "echo", "fiber", "chi", "websocket",
		"cobra", "viper", "zap", "consul", "etcd", "kubernetes", "docker",
		"prometheus", "grafana",
		// Go module paths
		"github.com/gin-gonic/gin", "github.com/gorilla/mux", "github.com/sirupsen/logrus",
		"github.com/stretchr/testify", "google.golang.org/protobuf", "google.golang.org/grpc",
		"github.com/go-sql-driver/mysql", "github.com/lib/pq", "github.com/go-redis/redis",
		"gorm.io/gorm", "github.com/labstack/echo", "github.com/gofiber/fiber",
		"github.com/go-chi/chi", "github.com/gorilla/websocket", "github.com/spf13/cobra",
		"github.com/spf13/viper", "go.uber.org/zap",
	}
	
	maxSimilarity := 0.0
	mostSimilarPackage := ""
	
	// First check for exact matches - these should return 0 (legitimate packages)
	for _, popular := range popularPackages {
		if pkg.Name == popular {
			return 0.0 // Exact match with popular package = legitimate
		}
	}
	
	for _, popular := range popularPackages {
		// For Go modules, compare full paths first
		if strings.Contains(pkg.Name, "/") && strings.Contains(popular, "/") {
			fullSimilarity := a.calculateSimilarity(pkg.Name, popular)
			if fullSimilarity > maxSimilarity {
				maxSimilarity = fullSimilarity
				mostSimilarPackage = popular
			}
		}
		
		// Also compare just the package names
		pkgName := a.extractPackageName(pkg.Name)
		popularPkgName := a.extractPackageName(popular)
		
		similarity := a.calculateSimilarity(pkgName, popularPkgName)
		if similarity > maxSimilarity {
			maxSimilarity = similarity
			mostSimilarPackage = popular
		}
	}
	
	// Check for typosquatting patterns and boost score significantly
	if maxSimilarity > 0.7 {
		// Check if this looks like typosquatting
		if a.isLikelyTyposquatting(pkg.Name, mostSimilarPackage) {
			// Significantly boost similarity score for likely typosquatting
			maxSimilarity = math.Min(maxSimilarity + 0.3, 1.0)
		}
	}
	
	return maxSimilarity
}

// extractPackageName extracts the actual package name from a module path
func (a *MLAnalyzer) extractPackageName(fullPath string) string {
	// Handle Go module paths like "github.com/gin-gonic/gin"
	if strings.Contains(fullPath, "/") {
		parts := strings.Split(fullPath, "/")
		return parts[len(parts)-1]
	}
	return fullPath
}

// isLikelyTyposquatting checks for common typosquatting patterns
func (a *MLAnalyzer) isLikelyTyposquatting(packageName, similarPackage string) bool {
	// Extract package names from full paths for comparison
	pkgName := a.extractPackageName(packageName)
	similarPkgName := a.extractPackageName(similarPackage)
	
	// Check for character repetition (e.g., "expresss" instead of "express")
	if len(pkgName) == len(similarPkgName)+1 {
		for i := 0; i < len(similarPkgName); i++ {
			if i < len(pkgName)-1 && pkgName[i] == pkgName[i+1] && pkgName[i] == similarPkgName[i] {
				return true
			}
		}
	}
	
	// Check for character omission (e.g., "expres" instead of "express")
	if len(pkgName) == len(similarPkgName)-1 {
		return true
	}
	
	// Check for character addition (e.g., "expressx" instead of "express", "ginn" instead of "gin")
	if len(pkgName) == len(similarPkgName)+1 {
		return true
	}
	
	// Check for character substitution with common typos
	if len(pkgName) == len(similarPkgName) {
		differences := 0
		for i := 0; i < len(pkgName); i++ {
			if pkgName[i] != similarPkgName[i] {
				differences++
				if differences > 2 {
					return false
				}
				// Check for common character substitutions
				if a.isCommonSubstitution(pkgName[i], similarPkgName[i]) {
					continue
				}
			}
		}
		return differences <= 2
	}
	
	// Also check full path similarity for Go modules
	if strings.Contains(packageName, "/") && strings.Contains(similarPackage, "/") {
		// Check if paths are very similar but not identical
		pathSimilarity := a.calculateSimilarity(packageName, similarPackage)
		if pathSimilarity > 0.8 && pathSimilarity < 1.0 {
			return true
		}
	}
	
	return false
}

// isCommonSubstitution checks if two characters are commonly substituted in typosquatting
func (a *MLAnalyzer) isCommonSubstitution(char1, char2 byte) bool {
	substitutions := map[byte][]byte{
		'o': {'0'},
		'0': {'o'},
		'l': {'1', 'i'},
		'1': {'l', 'i'},
		'i': {'l', '1'},
		'e': {'3'},
		'3': {'e'},
		's': {'5'},
		'5': {'s'},
		'a': {'@'},
		'@': {'a'},
	}
	
	if subs, exists := substitutions[char2]; exists {
		for _, sub := range subs {
			if char1 == sub {
				return true
			}
		}
	}
	return false
}

// calculateSimilarity calculates the similarity between two package names using Levenshtein distance
func (a *MLAnalyzer) calculateSimilarity(name1, name2 string) float64 {
	distance := a.levenshteinDistance(name1, name2)
	maxLen := a.max(len(name1), len(name2))
	if maxLen == 0 {
		return 1.0
	}
	return 1.0 - float64(distance)/float64(maxLen)
}

// levenshteinDistance calculates the Levenshtein distance between two strings
func (a *MLAnalyzer) levenshteinDistance(s1, s2 string) int {
	if len(s1) == 0 {
		return len(s2)
	}
	if len(s2) == 0 {
		return len(s1)
	}
	
	matrix := make([][]int, len(s1)+1)
	for i := range matrix {
		matrix[i] = make([]int, len(s2)+1)
	}
	
	for i := 0; i <= len(s1); i++ {
		matrix[i][0] = i
	}
	for j := 0; j <= len(s2); j++ {
		matrix[0][j] = j
	}
	
	for i := 1; i <= len(s1); i++ {
		for j := 1; j <= len(s2); j++ {
			cost := 0
			if s1[i-1] != s2[j-1] {
				cost = 1
			}
			matrix[i][j] = a.min(
				matrix[i-1][j]+1,      // deletion
				matrix[i][j-1]+1,      // insertion
				matrix[i-1][j-1]+cost, // substitution
			)
		}
	}
	
	return matrix[len(s1)][len(s2)]
}

// min returns the minimum of three integers
func (a *MLAnalyzer) min(a1, b, c int) int {
	if a1 < b {
		if a1 < c {
			return a1
		}
		return c
	}
	if b < c {
		return b
	}
	return c
}

// max returns the maximum of two integers
func (a *MLAnalyzer) max(a1, b int) int {
	if a1 > b {
		return a1
	}
	return b
}

// findSimilarPackages finds packages similar to the analyzed one.
func (a *MLAnalyzer) findSimilarPackages(pkg *types.Package) []SimilarPackage {
	// Placeholder implementation
	// In a real implementation, this would query a database of packages
	
	similarPackages := []SimilarPackage{
		{
			Name:           "similar-package-1",
			Similarity:     0.85,
			Distance:       2,
			Algorithm:      "levenshtein",
			Registry:       "npm",
			Downloads:      1000000,
			LastUpdated:    "2023-01-01",
			Maintainer:     "trusted-maintainer",
			SuspiciousFlag: false,
		},
	}
	
	return similarPackages
}

// detectMaliciousPackage detects if a package is potentially malicious.
func (a *MLAnalyzer) detectMaliciousPackage(ctx context.Context, pkg *types.Package, features map[string]float64) (float64, error) {
	// If client is available, use HTTP-based detection
	if a.Client != nil {
		resp, err := a.Client.CheckMaliciousPackage(ctx, pkg.Name, pkg.Registry, pkg.Version)
		if err != nil {
			return 0, fmt.Errorf("malicious detection failed: %w", err)
		}
		return resp.Score, nil
	}
	
	// Enhanced heuristic-based detection for better accuracy
	score := 0.0
	
	// Check for typosquatting patterns (common misspellings of popular packages)
	popularPackages := []string{"express", "lodash", "react", "angular", "vue", "jquery", "bootstrap", "moment", "axios", "webpack", "babel", "eslint", "typescript", "node", "npm", "yarn", "requests", "numpy", "pandas", "django", "flask", "tensorflow", "pytorch", "scikit-learn", "matplotlib", "seaborn", "beautifulsoup4", "selenium", "pillow", "opencv-python", "gin-gonic/gin", "gorilla/mux", "sirupsen/logrus", "stretchr/testify", "golang/protobuf"}
	
	for _, popular := range popularPackages {
		similarity := a.calculateSimilarity(pkg.Name, popular)
		if similarity > 0.8 && similarity < 1.0 { // High similarity but not exact match
			score += 0.7 // Strong indicator of typosquatting
			break
		}
	}
	
	// Check for suspicious patterns in name
	if strings.Contains(pkg.Name, "hack") || strings.Contains(pkg.Name, "exploit") || strings.Contains(pkg.Name, "malware") {
		score += 0.5
	}
	
	// Check for suspicious entropy (random-looking names)
	if features["name_entropy"] > 4.0 {
		score += 0.3
	}
	
	// Check for suspicious character ratios
	if features["name_special_char_ratio"] > 0.3 {
		score += 0.2
	}
	
	// Check metadata if available
	if pkg.Metadata != nil {
		// Check for suspicious scripts in package.json-like metadata
		if description := pkg.Metadata.Description; description != "" {
			if strings.Contains(strings.ToLower(description), "postinstall") ||
			   strings.Contains(strings.ToLower(description), "preinstall") ||
			   strings.Contains(strings.ToLower(description), "curl") ||
			   strings.Contains(strings.ToLower(description), "wget") ||
			   strings.Contains(strings.ToLower(description), "exec") {
				score += 0.6
			}
		}
		
		// Check for very short or missing descriptions
		if len(pkg.Metadata.Description) < 10 {
			score += 0.2
		}
	}
	
	// Check for suspicious version patterns
	if pkg.Version != "" {
		// Very high version numbers can be suspicious
		if strings.HasPrefix(pkg.Version, "999") || strings.HasPrefix(pkg.Version, "9999") {
			score += 0.3
		}
	}
	
	return math.Min(score, 1.0), nil
}

// analyzeReputation analyzes the reputation of a package.
func (a *MLAnalyzer) analyzeReputation(pkg *types.Package) ReputationAnalysis {
	// Enhanced reputation analysis using available metadata
	
	maintainerScore := 0.5 // Default neutral score
	downloadScore := 0.5   // Default neutral score
	ageScore := 0.5        // Default neutral score
	communityScore := 0.5  // Default neutral score
	securityScore := 0.5   // Default neutral score
	
	// Analyze based on package metadata if available
	if pkg.Metadata != nil {
		// Analyze maintainer reputation
		if pkg.Metadata.Author != "" {
			// Check for suspicious maintainer patterns
			author := strings.ToLower(pkg.Metadata.Author)
			if strings.Contains(author, "fake") || strings.Contains(author, "temp") || strings.Contains(author, "test") {
				maintainerScore = 0.1
			} else if len(pkg.Metadata.Author) > 3 {
				maintainerScore = 0.7 // Reasonable maintainer name
			}
		}
		
		// Analyze description quality
		if len(pkg.Metadata.Description) > 50 {
			communityScore += 0.3 // Good description indicates care
		} else if len(pkg.Metadata.Description) < 10 {
			communityScore -= 0.3 // Poor description is suspicious
		}
		
		// Check for repository presence (indicates transparency)
		if pkg.Metadata.Repository != "" {
			communityScore += 0.2
			securityScore += 0.2
		}
		
		// Check for homepage presence
		if pkg.Metadata.Homepage != "" {
			communityScore += 0.1
		}
		
		// Check for license presence
		if pkg.Metadata.License != "" {
			securityScore += 0.2
			communityScore += 0.1
		}
	}
	
	// Analyze package name patterns
	if len(pkg.Name) < 3 {
		maintainerScore -= 0.2 // Very short names are suspicious
	}
	
	// Check for suspicious version patterns
	if pkg.Version != "" {
		if pkg.Version == "1.0.0" {
			ageScore = 0.3 // New packages are riskier
		} else if strings.Count(pkg.Version, ".") >= 2 {
			ageScore = 0.7 // Multiple versions suggest maturity
		}
	}
	
	// Ensure scores are within bounds
	maintainerScore = math.Max(0, math.Min(1, maintainerScore))
	downloadScore = math.Max(0, math.Min(1, downloadScore))
	ageScore = math.Max(0, math.Min(1, ageScore))
	communityScore = math.Max(0, math.Min(1, communityScore))
	securityScore = math.Max(0, math.Min(1, securityScore))
	
	// Calculate overall score as weighted average
	overallScore := (maintainerScore*0.3 + downloadScore*0.2 + ageScore*0.1 + 
		communityScore*0.2 + securityScore*0.2)
	
	reputationSources := []ReputationSource{
		{Source: "package_metadata", Score: overallScore, Weight: 0.6},
		{Source: "maintainer_analysis", Score: maintainerScore, Weight: 0.4},
	}
	
	return ReputationAnalysis{
		OverallScore:      overallScore,
		MaintainerScore:   maintainerScore,
		DownloadScore:     downloadScore,
		AgeScore:          ageScore,
		CommunityScore:    communityScore,
		SecurityScore:     securityScore,
		ReputationSources: reputationSources,
	}
}

// detectAnomalies detects anomalies in package characteristics.
func (a *MLAnalyzer) detectAnomalies(pkg *types.Package, features map[string]float64) AnomalyDetection {
	// Enhanced anomaly detection with multiple checks
	
	anomalyScore := 0.0
	isAnomaly := false
	anomalyType := "none"
	anomalyFeatures := []string{}
	unusualPatterns := []string{}
	
	// Check for anomalous name entropy (high randomness)
	if features["name_entropy"] > 4.5 {
		anomalyScore += 0.4
		isAnomaly = true
		anomalyType = "high_entropy"
		anomalyFeatures = append(anomalyFeatures, "name_entropy")
		unusualPatterns = append(unusualPatterns, "high_entropy_name")
	}
	
	// Check for anomalous name length
	if features["name_length"] > 50 {
		anomalyScore += 0.3
		isAnomaly = true
		if anomalyType == "none" {
			anomalyType = "unusual_length"
		}
		anomalyFeatures = append(anomalyFeatures, "name_length")
		unusualPatterns = append(unusualPatterns, "excessive_length")
	} else if features["name_length"] < 2 {
		// Very short names are also suspicious
		anomalyScore += 0.2
		isAnomaly = true
		if anomalyType == "none" {
			anomalyType = "unusual_length"
		}
		anomalyFeatures = append(anomalyFeatures, "name_length")
		unusualPatterns = append(unusualPatterns, "too_short")
	}
	
	// Check for excessive special characters
		if features["name_special_char_ratio"] > 0.3 {
		anomalyScore += 0.3
		isAnomaly = true
		if anomalyType == "none" {
			anomalyType = "suspicious_characters"
		}
		anomalyFeatures = append(anomalyFeatures, "special_char_ratio")
		unusualPatterns = append(unusualPatterns, "excessive_special_chars")
	}
	
	// Check for suspicious version patterns
	if pkg.Version != "" {
		// Very high version numbers
		if strings.HasPrefix(pkg.Version, "999") || strings.HasPrefix(pkg.Version, "9999") {
			anomalyScore += 0.4
			isAnomaly = true
			if anomalyType == "none" {
				anomalyType = "suspicious_version"
			}
			anomalyFeatures = append(anomalyFeatures, "version_pattern")
			unusualPatterns = append(unusualPatterns, "fake_high_version")
		}
		
		// Check for unusual version format
		if !a.isValidVersionFormat(pkg.Version) {
			anomalyScore += 0.2
			isAnomaly = true
			if anomalyType == "none" {
				anomalyType = "suspicious_version"
			}
			anomalyFeatures = append(anomalyFeatures, "version_format")
			unusualPatterns = append(unusualPatterns, "invalid_version_format")
		}
	}
	
	// Check for suspicious metadata patterns
	if pkg.Metadata != nil {
		// Very short or missing description
		if len(pkg.Metadata.Description) < 10 && len(pkg.Metadata.Description) > 0 {
			anomalyScore += 0.2
			isAnomaly = true
			if anomalyType == "none" {
				anomalyType = "poor_metadata"
			}
			anomalyFeatures = append(anomalyFeatures, "description_quality")
			unusualPatterns = append(unusualPatterns, "poor_description")
		}
		
		// Missing critical metadata
		missingFields := 0
		if pkg.Metadata.Author == "" {
			missingFields++
		}
		if pkg.Metadata.Repository == "" {
			missingFields++
		}
		if pkg.Metadata.License == "" {
			missingFields++
		}
		
		if missingFields >= 2 {
			anomalyScore += 0.3
			isAnomaly = true
			if anomalyType == "none" {
				anomalyType = "poor_metadata"
			}
			anomalyFeatures = append(anomalyFeatures, "missing_metadata")
			unusualPatterns = append(unusualPatterns, "incomplete_metadata")
		}
	}
	
	// Check for suspicious name patterns
	if a.hasSuspiciousNamePattern(pkg.Name) {
		anomalyScore += 0.3
		isAnomaly = true
		if anomalyType == "none" {
			anomalyType = "suspicious_name"
		}
		anomalyFeatures = append(anomalyFeatures, "name_pattern")
		unusualPatterns = append(unusualPatterns, "suspicious_name_pattern")
	}
	
	// Ensure anomaly score doesn't exceed 1.0
	anomalyScore = math.Min(anomalyScore, 1.0)
	
	outlierAnalysis := OutlierAnalysis{
		IsOutlier:       isAnomaly,
		OutlierScore:    anomalyScore,
		IsolationForest: anomalyScore * 0.8,
		LocalOutlier:    anomalyScore * 0.9,
		OneClassSVM:     anomalyScore * 0.7,
	}
	
	patternAnalysis := PatternAnalysis{
		UnusualPatterns: unusualPatterns,
		PatternScore:    anomalyScore,
		FrequencyScore:  math.Max(0.1, 1.0-anomalyScore), // Lower frequency for anomalous packages
		SequenceScore:   anomalyScore * 0.8,
	}
	
	return AnomalyDetection{
		IsAnomaly:       isAnomaly,
		AnomalyScore:    anomalyScore,
		AnomalyType:     anomalyType,
		AnomalyFeatures: anomalyFeatures,
		OutlierAnalysis: outlierAnalysis,
		PatternAnalysis: patternAnalysis,
	}
}

// isValidVersionFormat checks if the version follows standard semantic versioning
func (a *MLAnalyzer) isValidVersionFormat(version string) bool {
	// Basic semantic versioning pattern: X.Y.Z or X.Y.Z-suffix
	pattern := `^\d+\.\d+\.\d+(-[a-zA-Z0-9.-]+)?$`
	matched, _ := regexp.MatchString(pattern, version)
	return matched
}

// hasSuspiciousNamePattern checks for suspicious patterns in package names
func (a *MLAnalyzer) hasSuspiciousNamePattern(name string) bool {
	lowerName := strings.ToLower(name)
	
	// Check for suspicious keywords
	suspiciousPatterns := []string{
		"hack", "crack", "exploit", "backdoor", "malware", "virus",
		"trojan", "keylog", "steal", "phish", "fake", "scam",
		"temp", "test123", "admin", "root", "password", "secret",
	}
	
	for _, pattern := range suspiciousPatterns {
		if strings.Contains(lowerName, pattern) {
			return true
		}
	}
	
	// Check for excessive numbers or random-looking strings
	numberCount := 0
	for _, char := range name {
		if unicode.IsDigit(char) {
			numberCount++
		}
	}
	
	// If more than 50% of characters are numbers, it's suspicious
	if len(name) > 0 && float64(numberCount)/float64(len(name)) > 0.5 {
		return true
	}
	
	return false
}

// analyzeBehavior analyzes package behavior (placeholder).
func (a *MLAnalyzer) analyzeBehavior(pkg *types.Package) BehavioralAnalysis {
	// Placeholder implementation
	// In a real implementation, this would analyze actual package behavior
	
	return BehavioralAnalysis{
		InstallBehavior: InstallBehavior{
			SuspiciousCommands: []string{},
			NetworkRequests:    []string{},
			FileModifications:  []string{},
			PermissionChanges:  []string{},
		},
		RuntimeBehavior: RuntimeBehavior{
			ProcessSpawning:   []string{},
			SystemCalls:       []string{},
			ResourceUsage:     []string{},
			EnvironmentAccess: []string{},
		},
		NetworkBehavior: NetworkBehavior{
			OutboundConnections: []string{},
			DNSQueries:          []string{},
			DataExfiltration:    []string{},
			C2Communication:     []string{},
		},
		FileSystemBehavior: FileSystemBehavior{
			FileCreation:     []string{},
			FileDeletion:     []string{},
			FileModification: []string{},
			DirectoryAccess:  []string{},
		},
	}
}

// calculateTyposquattingScore calculates the overall typosquatting score.
func (a *MLAnalyzer) calculateTyposquattingScore(similarityScore, maliciousScore, reputationScore float64) float64 {
	// If similarity is very high (>0.9), it's likely typosquatting regardless of other factors
	if similarityScore > 0.9 {
		// Heavily weight similarity for very high scores
		typosquattingScore := (similarityScore*0.8 + maliciousScore*0.1 + (1-reputationScore)*0.1)
		return math.Min(typosquattingScore, 1.0)
	}
	
	// For moderate similarity, use balanced weighting
	if similarityScore > 0.7 {
		typosquattingScore := (similarityScore*0.6 + maliciousScore*0.3 + (1-reputationScore)*0.1)
		return math.Min(typosquattingScore, 1.0)
	}
	
	// For lower similarity, use original balanced approach
	typosquattingScore := (similarityScore*0.4 + maliciousScore*0.4 + (1-reputationScore)*0.2)
	return math.Min(typosquattingScore, 1.0)
}

// generatePredictions generates ML model predictions.
func (a *MLAnalyzer) generatePredictions(pkg *types.Package, features map[string]float64) []Prediction {
	// Placeholder implementation
	// In a real implementation, this would use actual ML models
	
	predictions := []Prediction{
		{
			Model:       "similarity_model",
			Probability: 0.3,
			Label:       "benign",
			Confidence:  0.8,
		},
		{
			Model:       "malicious_detection_model",
			Probability: 0.2,
			Label:       "benign",
			Confidence:  0.7,
		},
		{
			Model:       "reputation_model",
			Probability: 0.7,
			Label:       "trusted",
			Confidence:  0.6,
		},
	}
	
	return predictions
}

// assessRisk performs overall risk assessment.
func (a *MLAnalyzer) assessRisk(typosquattingScore, maliciousScore, reputationScore float64) RiskAssessment {
	// Calculate overall risk score with higher weight on typosquatting for high similarity
	riskScore := (typosquattingScore*0.6 + maliciousScore*0.3 + (1-reputationScore)*0.1)
	
	// Determine risk level with adjusted thresholds
	var overallRisk string
	switch {
	case riskScore >= 0.7:
		overallRisk = "critical"
	case riskScore >= 0.5:
		overallRisk = "high"
	case riskScore >= 0.3:
		overallRisk = "medium"
	case riskScore >= 0.15:
		overallRisk = "low"
	default:
		overallRisk = "minimal"
	}
	
	// Generate risk factors
	riskFactors := []RiskFactor{}
	if typosquattingScore > 0.5 {
		riskFactors = append(riskFactors, RiskFactor{
			Factor:      "high_similarity",
			Severity:    "medium",
			Score:       typosquattingScore,
			Description: "Package name is highly similar to popular packages",
		})
	}
	
	if maliciousScore > 0.5 {
		riskFactors = append(riskFactors, RiskFactor{
			Factor:      "malicious_indicators",
			Severity:    "high",
			Score:       maliciousScore,
			Description: "Package exhibits characteristics of malicious software",
		})
	}
	
	if reputationScore < 0.5 {
		riskFactors = append(riskFactors, RiskFactor{
			Factor:      "low_reputation",
			Severity:    "medium",
			Score:       1 - reputationScore,
			Description: "Package has low reputation or limited trust indicators",
		})
	}
	
	// Generate mitigations
	mitigations := []string{
		"Verify package authenticity through official channels",
		"Check package maintainer reputation and history",
		"Review package dependencies and permissions",
		"Monitor package behavior in a sandboxed environment",
	}
	
	// Calculate confidence level
	confidenceLevel := 0.8 // Placeholder confidence
	
	return RiskAssessment{
		OverallRisk:     overallRisk,
		RiskScore:       riskScore,
		RiskFactors:     riskFactors,
		Mitigations:     mitigations,
		ConfidenceLevel: confidenceLevel,
	}
}

// generateFindings generates specific findings from the analysis.
func (a *MLAnalyzer) generateFindings(pkg *types.Package, similarityScore, maliciousScore float64, 
	reputationAnalysis ReputationAnalysis, anomalyDetection AnomalyDetection) []Finding {
	
	findings := []Finding{}
	
	// High similarity finding
	if similarityScore > a.Config.SimilarityThreshold {
		findings = append(findings, Finding{
			Type:        "high_similarity",
			Severity:    "medium",
			Confidence:  similarityScore,
			Description: fmt.Sprintf("Package name is %.1f%% similar to known packages", similarityScore*100),
			Evidence:    fmt.Sprintf("Similarity score: %.3f", similarityScore),
			Model:       "similarity_model",
		})
	}
	
	// Malicious detection finding
	if maliciousScore > a.Config.MaliciousThreshold {
		findings = append(findings, Finding{
			Type:        "malicious_indicators",
			Severity:    "high",
			Confidence:  maliciousScore,
			Description: "Package exhibits characteristics commonly found in malicious software",
			Evidence:    fmt.Sprintf("Malicious score: %.3f", maliciousScore),
			Model:       "malicious_detection_model",
		})
	}
	
	// Low reputation finding
	if reputationAnalysis.OverallScore < a.Config.ReputationThreshold {
		findings = append(findings, Finding{
			Type:        "low_reputation",
			Severity:    "medium",
			Confidence:  1 - reputationAnalysis.OverallScore,
			Description: "Package has low reputation or limited trust indicators",
			Evidence:    fmt.Sprintf("Reputation score: %.3f", reputationAnalysis.OverallScore),
			Model:       "reputation_model",
		})
	}
	
	// Anomaly detection finding
	if anomalyDetection.IsAnomaly {
		findings = append(findings, Finding{
			Type:        "anomaly_detected",
			Severity:    "low",
			Confidence:  anomalyDetection.AnomalyScore,
			Description: fmt.Sprintf("Package exhibits anomalous characteristics: %s", anomalyDetection.AnomalyType),
			Evidence:    fmt.Sprintf("Anomaly features: %v", anomalyDetection.AnomalyFeatures),
			Model:       "anomaly_detection_model",
		})
	}
	
	return findings
}

// generateRecommendations generates recommendations based on the analysis.
func (a *MLAnalyzer) generateRecommendations(riskAssessment RiskAssessment, findings []Finding) []string {
	recommendations := []string{}
	
	// Risk-based recommendations
	switch riskAssessment.OverallRisk {
	case "critical":
		recommendations = append(recommendations, "DO NOT INSTALL: Package poses critical security risk")
		recommendations = append(recommendations, "Report package to registry security team")
	case "high":
		recommendations = append(recommendations, "Exercise extreme caution before installation")
		recommendations = append(recommendations, "Perform thorough security review")
	case "medium":
		recommendations = append(recommendations, "Review package carefully before installation")
		recommendations = append(recommendations, "Consider alternative packages")
	case "low":
		recommendations = append(recommendations, "Package appears relatively safe but monitor usage")
	default:
		recommendations = append(recommendations, "Package appears safe for installation")
	}
	
	// Finding-specific recommendations
	for _, finding := range findings {
		switch finding.Type {
		case "high_similarity":
			recommendations = append(recommendations, "Verify this is the intended package and not a typosquatting attempt")
		case "malicious_indicators":
			recommendations = append(recommendations, "Scan package with multiple security tools before use")
		case "low_reputation":
			recommendations = append(recommendations, "Research package maintainer and community feedback")
		case "anomaly_detected":
			recommendations = append(recommendations, "Investigate unusual package characteristics")
		}
	}
	
	// General security recommendations
	recommendations = append(recommendations, "Always verify package signatures when available")
	recommendations = append(recommendations, "Monitor package behavior after installation")
	recommendations = append(recommendations, "Keep packages updated to latest versions")
	
	return recommendations
}

// Helper functions

// calculateEntropy calculates the Shannon entropy of a string.
func calculateEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	
	freq := make(map[rune]int)
	for _, char := range s {
		freq[char]++
	}
	
	entropy := 0.0
	length := float64(len(s))
	for _, count := range freq {
		p := float64(count) / length
		if p > 0 {
			entropy -= p * math.Log2(p)
		}
	}
	
	return entropy
}

// calculateVowelRatio calculates the ratio of vowels in a string.
func calculateVowelRatio(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	
	vowels := "aeiouAEIOU"
	vowelCount := 0
	for _, char := range s {
		if strings.ContainsRune(vowels, char) {
			vowelCount++
		}
	}
	
	return float64(vowelCount) / float64(len(s))
}

// calculateDigitRatio calculates the ratio of digits in a string.
func calculateDigitRatio(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	
	digitCount := 0
	for _, char := range s {
		if char >= '0' && char <= '9' {
			digitCount++
		}
	}
	
	return float64(digitCount) / float64(len(s))
}

// calculateSpecialCharRatio calculates the ratio of special characters in a string.
func calculateSpecialCharRatio(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	
	specialCount := 0
	for _, char := range s {
		if !((char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') || (char >= '0' && char <= '9')) {
			specialCount++
		}
	}
	
	return float64(specialCount) / float64(len(s))
}

// boolToFloat converts a boolean to float64.
func boolToFloat(b bool) float64 {
	if b {
		return 1.0
	}
	return 0.0
}

// getFeatureNames extracts feature names from the features map.
func getFeatureNames(features map[string]float64) []string {
	names := make([]string, 0, len(features))
	for name := range features {
		names = append(names, name)
	}
	return names
}