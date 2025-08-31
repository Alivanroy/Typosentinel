package ml

import (
	"crypto/sha256"
	"fmt"
	"math"
	"math/rand"
	"regexp"
	"strings"
	"time"
	"unicode"

	"github.com/Alivanroy/Typosentinel/pkg/types"
)

// NewAdvancedFeatureProcessor creates a new advanced feature processor
func NewAdvancedFeatureProcessor() *AdvancedFeatureProcessor {
	return &AdvancedFeatureProcessor{
		normalizers: make(map[string]*FeatureNormalizer),
		encoders:    make(map[string]*FeatureEncoder),
		selectors:   make(map[string]*FeatureSelector),
		augmentors:  make(map[string]DataAugmentor),
		embeddings:  make(map[string]*EmbeddingLayer),
	}
}

// Initialize initializes the advanced feature processor
func (afp *AdvancedFeatureProcessor) Initialize() error {
	afp.mu.Lock()
	defer afp.mu.Unlock()

	// Initialize normalizers
	afp.normalizers["standard"] = &FeatureNormalizer{
		method:  "standard",
		scalers: make(map[string]*Scaler),
	}

	afp.normalizers["minmax"] = &FeatureNormalizer{
		method:  "minmax",
		scalers: make(map[string]*Scaler),
	}

	// Initialize selectors
	afp.selectors["variance"] = &FeatureSelector{
		SelectedFeatures:  make([]int, 0),
		FeatureImportance: make([]float64, 0),
		SelectionMethod:   "variance",
		Threshold:         0.1,
		FeatureNames:      make([]string, 0),
	}

	// Initialize encoders
	afp.encoders["onehot"] = &FeatureEncoder{
		Method:     "onehot",
		Vocabulary: make(map[string]int),
		Dimension:  100,
	}

	afp.encoders["embedding"] = &FeatureEncoder{
		Method:     "embedding",
		Vocabulary: make(map[string]int),
		Embeddings: make(map[string][]float64),
		Dimension:  128,
	}

	// Initialize data augmentors
	afp.augmentors["noise"] = NewNoiseAugmentor()

	// Initialize embedding layers
	afp.embeddings["package_name"] = &EmbeddingLayer{
		VocabSize: 10000,
		EmbedDim:  64,
		Weights:   afp.initializeEmbeddingWeights(10000, 64),
		Trainable: true,
	}

	return nil
}

// ExtractAdvancedFeatures extracts advanced features from a package
func (afp *AdvancedFeatureProcessor) ExtractAdvancedFeatures(pkg *types.Package) (*AdvancedPackageFeatures, error) {
	features := &AdvancedPackageFeatures{
		PackageName:  pkg.Name,
		Version:      pkg.Version,
		Registry:     pkg.Registry,
		CreationDate: time.Now(), // Would be actual creation date in real implementation
	}

	// Extract textual features
	var err error
	features.NameEmbedding, err = afp.extractNameEmbedding(pkg.Name)
	if err != nil {
		return nil, fmt.Errorf("failed to extract name embedding: %w", err)
	}

	var description string
	var keywords []string
	if pkg.Metadata != nil {
		description = pkg.Metadata.Description
		keywords = pkg.Metadata.Keywords
	}

	features.DescriptionEmbedding, err = afp.extractDescriptionEmbedding(description)
	if err != nil {
		return nil, fmt.Errorf("failed to extract description embedding: %w", err)
	}

	features.KeywordEmbeddings, err = afp.extractKeywordEmbeddings(keywords)
	if err != nil {
		return nil, fmt.Errorf("failed to extract keyword embeddings: %w", err)
	}

	// Extract statistical features
	features.NameEntropy = afp.calculateStringEntropy(pkg.Name)
	features.NameComplexity = afp.calculateNameComplexity(pkg.Name)
	features.VersionComplexity = afp.calculateVersionComplexity(pkg.Version)
	features.DependencyComplexity = afp.calculateDependencyComplexity(pkg.Dependencies)

	// Extract behavioral features
	features.DownloadPattern = afp.extractDownloadPattern(pkg)
	features.UpdatePattern = afp.extractUpdatePattern(pkg)
	features.DependencyPattern = afp.extractDependencyPattern(pkg.Dependencies)
	var author string
	if pkg.Metadata != nil {
		author = pkg.Metadata.Author
	}
	features.MaintainerPattern = afp.extractMaintainerPattern(author)

	// Extract security features
	features.VulnerabilityHistory = afp.extractVulnerabilityHistory(pkg)
	features.SecurityScores = afp.extractSecurityScores(pkg)
	features.TrustIndicators = afp.extractTrustIndicators(pkg)

	// Extract graph features
	features.DependencyGraph = afp.extractDependencyGraph(pkg.Dependencies)
	features.SimilarityGraph = afp.extractSimilarityGraph(pkg)
	features.CommunityFeatures = afp.extractCommunityFeatures(pkg)

	// Extract temporal features
	features.TimeSeriesFeatures = afp.extractTimeSeriesFeatures(pkg)
	features.SeasonalityFeatures = afp.extractSeasonalityFeatures(pkg)
	features.TrendFeatures = afp.extractTrendFeatures(pkg)

	return features, nil
}

// extractNameEmbedding creates an embedding vector for package name
func (afp *AdvancedFeatureProcessor) extractNameEmbedding(name string) ([]float64, error) {
	embeddingLayer := afp.embeddings["package_name"]
	if embeddingLayer == nil {
		return nil, fmt.Errorf("package name embedding layer not initialized")
	}

	// Convert name to character-level features
	charFeatures := afp.extractCharacterFeatures(name)

	// Create embedding using character features
	embedding := make([]float64, embeddingLayer.EmbedDim)
	for i, char := range name {
		if i >= len(embedding) {
			break
		}
		// Simple character-based embedding
		embedding[i%embeddingLayer.EmbedDim] += float64(char) / 1000.0
	}

	// Add character-level statistical features
	for i, feature := range charFeatures {
		if i < len(embedding) {
			embedding[i] += feature
		}
	}

	// Normalize embedding
	norm := 0.0
	for _, val := range embedding {
		norm += val * val
	}
	norm = math.Sqrt(norm)
	if norm > 0 {
		for i := range embedding {
			embedding[i] /= norm
		}
	}

	return embedding, nil
}

// extractDescriptionEmbedding creates an embedding vector for package description
func (afp *AdvancedFeatureProcessor) extractDescriptionEmbedding(description string) ([]float64, error) {
	if description == "" {
		return make([]float64, 128), nil // Return zero vector for empty description
	}

	// Tokenize description
	tokens := afp.tokenizeText(description)

	// Create TF-IDF like features
	tfIdf := afp.calculateTFIDF(tokens)

	// Convert to fixed-size embedding
	embedding := make([]float64, 128)
	for i, score := range tfIdf {
		if i >= len(embedding) {
			break
		}
		embedding[i] = score
	}

	// Add semantic features
	semanticFeatures := afp.extractSemanticFeatures(description)
	for i, feature := range semanticFeatures {
		if i+64 < len(embedding) {
			embedding[i+64] = feature
		}
	}

	return embedding, nil
}

// extractKeywordEmbeddings creates embeddings for package keywords
func (afp *AdvancedFeatureProcessor) extractKeywordEmbeddings(keywords []string) ([]float64, error) {
	if len(keywords) == 0 {
		return make([]float64, 64), nil
	}

	// Aggregate keyword embeddings
	embedding := make([]float64, 64)
	for _, keyword := range keywords {
		keywordEmb, err := afp.extractNameEmbedding(keyword)
		if err != nil {
			continue
		}

		// Add to aggregate embedding
		for i, val := range keywordEmb {
			if i < len(embedding) {
				embedding[i] += val
			}
		}
	}

	// Normalize by number of keywords
	if len(keywords) > 0 {
		for i := range embedding {
			embedding[i] /= float64(len(keywords))
		}
	}

	return embedding, nil
}

// calculateStringEntropy calculates the entropy of a string
func (afp *AdvancedFeatureProcessor) calculateStringEntropy(s string) float64 {
	if len(s) == 0 {
		return 0.0
	}

	// Count character frequencies
	freq := make(map[rune]int)
	for _, char := range s {
		freq[char]++
	}

	// Calculate entropy
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

// calculateNameComplexity calculates the complexity of a package name
func (afp *AdvancedFeatureProcessor) calculateNameComplexity(name string) float64 {
	if len(name) == 0 {
		return 0.0
	}

	complexity := 0.0

	// Length factor
	complexity += float64(len(name)) * 0.1

	// Character diversity
	uniqueChars := make(map[rune]bool)
	for _, char := range name {
		uniqueChars[char] = true
	}
	complexity += float64(len(uniqueChars)) * 0.2

	// Special character count
	specialChars := 0
	for _, char := range name {
		if !unicode.IsLetter(char) && !unicode.IsDigit(char) {
			specialChars++
		}
	}
	complexity += float64(specialChars) * 0.3

	// Case transitions
	caseTransitions := 0
	runes := []rune(name)
	for i := 1; i < len(runes); i++ {
		if unicode.IsUpper(runes[i-1]) != unicode.IsUpper(runes[i]) {
			caseTransitions++
		}
	}
	complexity += float64(caseTransitions) * 0.2

	// Number sequences
	numberSeqs := len(regexp.MustCompile(`\d+`).FindAllString(name, -1))
	complexity += float64(numberSeqs) * 0.15

	return complexity
}

// calculateVersionComplexity calculates the complexity of a version string
func (afp *AdvancedFeatureProcessor) calculateVersionComplexity(version string) float64 {
	if version == "" {
		return 0.0
	}

	complexity := 0.0

	// Semantic versioning compliance
	semVerRegex := regexp.MustCompile(`^\d+\.\d+\.\d+`)
	if semVerRegex.MatchString(version) {
		complexity += 1.0 // Lower complexity for standard semver
	} else {
		complexity += 3.0 // Higher complexity for non-standard versions
	}

	// Pre-release indicators
	preReleaseRegex := regexp.MustCompile(`(alpha|beta|rc|dev|snapshot)`)
	if preReleaseRegex.MatchString(strings.ToLower(version)) {
		complexity += 2.0
	}

	// Length factor
	complexity += float64(len(version)) * 0.1

	// Special characters
	specialChars := len(regexp.MustCompile(`[^\w\.]`).FindAllString(version, -1))
	complexity += float64(specialChars) * 0.5

	return complexity
}

// calculateDependencyComplexity calculates the complexity of dependencies
func (afp *AdvancedFeatureProcessor) calculateDependencyComplexity(dependencies []types.Dependency) float64 {
	if len(dependencies) == 0 {
		return 0.0
	}

	complexity := 0.0

	// Number of dependencies
	complexity += float64(len(dependencies)) * 0.1

	// Version constraint complexity
	for _, dep := range dependencies {
		// Complex version constraints increase complexity
		if strings.Contains(dep.Version, "~") || strings.Contains(dep.Version, "^") {
			complexity += 0.5
		}
		if strings.Contains(dep.Version, ">=") || strings.Contains(dep.Version, "<=") {
			complexity += 0.3
		}
		if strings.Contains(dep.Version, "*") {
			complexity += 1.0
		}
	}

	// Dependency depth (simplified)
	complexity += float64(len(dependencies)) * 0.05

	return complexity
}

// extractDownloadPattern extracts download pattern features
func (afp *AdvancedFeatureProcessor) extractDownloadPattern(pkg *types.Package) []float64 {
	// Simulate download pattern analysis
	pattern := make([]float64, 24) // 24-hour pattern

	// Generate synthetic download pattern based on package characteristics
	hash := afp.hashString(pkg.Name)
	for i := range pattern {
		// Create a pseudo-random but deterministic pattern
		pattern[i] = math.Sin(float64(i)*math.Pi/12.0 + float64(hash%100)/100.0*2*math.Pi)
		pattern[i] = (pattern[i] + 1.0) / 2.0 // Normalize to [0,1]
	}

	return pattern
}

// extractUpdatePattern extracts update pattern features
func (afp *AdvancedFeatureProcessor) extractUpdatePattern(pkg *types.Package) []float64 {
	// Simulate update pattern analysis
	pattern := make([]float64, 12) // Monthly pattern

	// Generate synthetic update pattern
	hash := afp.hashString(pkg.Name + pkg.Version)
	for i := range pattern {
		// Create a pseudo-random but deterministic pattern
		pattern[i] = math.Cos(float64(i)*math.Pi/6.0 + float64(hash%100)/100.0*2*math.Pi)
		pattern[i] = math.Max(0, pattern[i]) // Only positive values
	}

	return pattern
}

// extractDependencyPattern extracts dependency pattern features
func (afp *AdvancedFeatureProcessor) extractDependencyPattern(dependencies []types.Dependency) []float64 {
	pattern := make([]float64, 16)

	if len(dependencies) == 0 {
		return pattern
	}

	// Dependency count features
	pattern[0] = float64(len(dependencies))
	pattern[1] = math.Log(float64(len(dependencies)) + 1)

	// Version constraint patterns
	constraintTypes := map[string]int{
		"exact":  0,
		"range":  0,
		"latest": 0,
		"loose":  0,
	}

	for _, dep := range dependencies {
		if dep.Version == "*" || dep.Version == "latest" {
			constraintTypes["latest"]++
		} else if strings.Contains(dep.Version, ">=") || strings.Contains(dep.Version, "<=") {
			constraintTypes["range"]++
		} else if strings.Contains(dep.Version, "~") || strings.Contains(dep.Version, "^") {
			constraintTypes["loose"]++
		} else {
			constraintTypes["exact"]++
		}
	}

	pattern[2] = float64(constraintTypes["exact"]) / float64(len(dependencies))
	pattern[3] = float64(constraintTypes["range"]) / float64(len(dependencies))
	pattern[4] = float64(constraintTypes["latest"]) / float64(len(dependencies))
	pattern[5] = float64(constraintTypes["loose"]) / float64(len(dependencies))

	// Dependency name entropy
	depNames := make([]string, len(dependencies))
	for i, dep := range dependencies {
		depNames[i] = dep.Name
	}
	pattern[6] = afp.calculateStringEntropy(strings.Join(depNames, ""))

	// Average dependency name length
	totalLength := 0
	for _, dep := range dependencies {
		totalLength += len(dep.Name)
	}
	pattern[7] = float64(totalLength) / float64(len(dependencies))

	// Fill remaining with statistical features
	for i := 8; i < len(pattern); i++ {
		pattern[i] = float64(i) * 0.1 // Placeholder features
	}

	return pattern
}

// extractMaintainerPattern extracts maintainer pattern features
func (afp *AdvancedFeatureProcessor) extractMaintainerPattern(author string) []float64 {
	pattern := make([]float64, 8)

	if author == "" {
		return pattern
	}

	// Author name features
	pattern[0] = float64(len(author))
	pattern[1] = afp.calculateStringEntropy(author)
	pattern[2] = afp.calculateNameComplexity(author)

	// Email pattern detection
	emailRegex := regexp.MustCompile(`[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`)
	if emailRegex.MatchString(author) {
		pattern[3] = 1.0
	}

	// Organization pattern detection
	orgPatterns := []string{"inc", "corp", "ltd", "llc", "org", "team"}
	for _, orgPattern := range orgPatterns {
		if strings.Contains(strings.ToLower(author), orgPattern) {
			pattern[4] = 1.0
			break
		}
	}

	// Character type distribution
	letters, digits, special := 0, 0, 0
	for _, char := range author {
		if unicode.IsLetter(char) {
			letters++
		} else if unicode.IsDigit(char) {
			digits++
		} else {
			special++
		}
	}
	total := float64(len(author))
	if total > 0 {
		pattern[5] = float64(letters) / total
		pattern[6] = float64(digits) / total
		pattern[7] = float64(special) / total
	}

	return pattern
}

// extractVulnerabilityHistory extracts vulnerability history features
func (afp *AdvancedFeatureProcessor) extractVulnerabilityHistory(pkg *types.Package) []float64 {
	// Simulate vulnerability history analysis
	history := make([]float64, 10)

	// Generate synthetic vulnerability features based on package characteristics
	hash := afp.hashString(pkg.Name + "vuln")
	baseRisk := float64(hash%100) / 100.0

	// Historical vulnerability count (simulated)
	history[0] = baseRisk * 5.0 // Total vulnerabilities
	history[1] = baseRisk * 2.0 // Critical vulnerabilities
	history[2] = baseRisk * 3.0 // High vulnerabilities
	history[3] = baseRisk * 4.0 // Medium vulnerabilities
	history[4] = baseRisk * 1.0 // Low vulnerabilities

	// Time-based features
	history[5] = baseRisk * 365.0 // Days since last vulnerability
	history[6] = baseRisk * 30.0  // Average time to fix
	history[7] = baseRisk         // Vulnerability trend

	// Patch availability
	history[8] = 1.0 - baseRisk // Patch availability rate
	history[9] = baseRisk * 0.5 // Unpatched vulnerabilities

	return history
}

// extractSecurityScores extracts security score features
func (afp *AdvancedFeatureProcessor) extractSecurityScores(pkg *types.Package) []float64 {
	scores := make([]float64, 8)

	// Generate synthetic security scores
	hash := afp.hashString(pkg.Name + "security")
	baseScore := float64(hash%100) / 100.0

	// Various security metrics
	scores[0] = 1.0 - baseScore     // Overall security score
	scores[1] = 1.0 - baseScore*0.8 // Code quality score
	scores[2] = 1.0 - baseScore*0.6 // Dependency security score
	scores[3] = 1.0 - baseScore*0.7 // Maintainer trust score
	scores[4] = 1.0 - baseScore*0.5 // Community trust score
	scores[5] = baseScore * 0.3     // Risk indicators
	scores[6] = 1.0 - baseScore*0.4 // License compliance score
	scores[7] = 1.0 - baseScore*0.9 // Supply chain security score

	return scores
}

// extractTrustIndicators extracts trust indicator features
func (afp *AdvancedFeatureProcessor) extractTrustIndicators(pkg *types.Package) []float64 {
	indicators := make([]float64, 12)

	// Generate synthetic trust indicators
	hash := afp.hashString(pkg.Name + "trust")
	baseTrust := float64(hash%100) / 100.0

	// Repository indicators
	indicators[0] = baseTrust       // Repository exists
	indicators[1] = baseTrust * 0.8 // Repository activity
	indicators[2] = baseTrust * 0.9 // Documentation quality
	indicators[3] = baseTrust * 0.7 // Test coverage

	// Community indicators
	indicators[4] = baseTrust * 0.6 // Download count
	indicators[5] = baseTrust * 0.5 // GitHub stars
	indicators[6] = baseTrust * 0.4 // Community size
	indicators[7] = baseTrust * 0.8 // Issue response time

	// Maintainer indicators
	indicators[8] = baseTrust * 0.9   // Maintainer reputation
	indicators[9] = baseTrust * 0.7   // Maintainer activity
	indicators[10] = baseTrust * 0.6  // Multiple maintainers
	indicators[11] = baseTrust * 0.85 // Verified publisher

	return indicators
}

// extractDependencyGraph extracts dependency graph features
func (afp *AdvancedFeatureProcessor) extractDependencyGraph(dependencies []types.Dependency) [][]float64 {
	// Create a simplified adjacency matrix representation
	maxNodes := 20 // Limit graph size for computational efficiency
	graph := make([][]float64, maxNodes)
	for i := range graph {
		graph[i] = make([]float64, maxNodes)
	}

	// Fill graph with dependency relationships
	for i, dep := range dependencies {
		if i >= maxNodes {
			break
		}

		// Self-connection with dependency strength
		graph[i][i] = 1.0

		// Connect to other dependencies based on name similarity
		for j, otherDep := range dependencies {
			if j >= maxNodes || i == j {
				continue
			}

			similarity := afp.calculateStringSimilarity(dep.Name, otherDep.Name)
			if similarity > 0.3 { // Threshold for connection
				graph[i][j] = similarity
			}
		}
	}

	return graph
}

// extractSimilarityGraph extracts similarity graph features
func (afp *AdvancedFeatureProcessor) extractSimilarityGraph(pkg *types.Package) [][]float64 {
	// Create a similarity graph based on package characteristics
	graphSize := 10
	graph := make([][]float64, graphSize)
	for i := range graph {
		graph[i] = make([]float64, graphSize)
	}

	// Generate synthetic similarity connections
	hash := afp.hashString(pkg.Name + "similarity")
	for i := 0; i < graphSize; i++ {
		for j := 0; j < graphSize; j++ {
			if i == j {
				graph[i][j] = 1.0
			} else {
				// Generate similarity based on hash and indices
				sim := float64((hash+i*j)%100) / 100.0
				if sim > 0.7 {
					graph[i][j] = sim
				}
			}
		}
	}

	return graph
}

// extractCommunityFeatures extracts community-based features
func (afp *AdvancedFeatureProcessor) extractCommunityFeatures(pkg *types.Package) []float64 {
	features := make([]float64, 16)

	// Generate synthetic community features
	hash := afp.hashString(pkg.Name + "community")
	baseMetric := float64(hash%100) / 100.0

	// Download and usage metrics
	features[0] = baseMetric * 1000000 // Total downloads
	features[1] = baseMetric * 10000   // Weekly downloads
	features[2] = baseMetric * 1000    // Daily downloads
	features[3] = baseMetric * 500     // Dependent packages

	// Repository metrics
	features[4] = baseMetric * 1000 // GitHub stars
	features[5] = baseMetric * 100  // GitHub forks
	features[6] = baseMetric * 50   // GitHub watchers
	features[7] = baseMetric * 200  // GitHub issues

	// Community engagement
	features[8] = baseMetric * 20  // Contributors
	features[9] = baseMetric * 100 // Commits
	features[10] = baseMetric * 10 // Releases
	features[11] = baseMetric * 30 // Pull requests

	// Quality indicators
	features[12] = baseMetric       // Test coverage
	features[13] = baseMetric * 0.8 // Documentation coverage
	features[14] = baseMetric * 0.9 // Code quality score
	features[15] = baseMetric * 0.7 // Maintenance score

	return features
}

// extractTimeSeriesFeatures extracts time series features
func (afp *AdvancedFeatureProcessor) extractTimeSeriesFeatures(pkg *types.Package) [][]float64 {
	// Create time series features for the last 30 days
	timeSteps := 30
	numFeatures := 8
	timeSeries := make([][]float64, timeSteps)
	for i := range timeSeries {
		timeSeries[i] = make([]float64, numFeatures)
	}

	// Generate synthetic time series data
	hash := afp.hashString(pkg.Name + "timeseries")
	for t := 0; t < timeSteps; t++ {
		// Downloads over time
		timeSeries[t][0] = math.Sin(float64(t)*math.Pi/15.0) * float64((hash+t)%100) / 100.0

		// Issues over time
		timeSeries[t][1] = math.Cos(float64(t)*math.Pi/10.0) * float64((hash+t*2)%50) / 50.0

		// Commits over time
		timeSeries[t][2] = math.Sin(float64(t)*math.Pi/7.0) * float64((hash+t*3)%30) / 30.0

		// Vulnerability reports over time
		timeSeries[t][3] = float64((hash+t*5)%10) / 100.0

		// Community activity
		timeSeries[t][4] = math.Sin(float64(t)*math.Pi/20.0) * float64((hash+t*7)%80) / 80.0

		// Dependency updates
		timeSeries[t][5] = float64((hash+t*11)%20) / 100.0

		// Security alerts
		timeSeries[t][6] = float64((hash+t*13)%5) / 50.0

		// Maintenance activity
		timeSeries[t][7] = math.Cos(float64(t)*math.Pi/25.0) * float64((hash+t*17)%60) / 60.0
	}

	return timeSeries
}

// extractSeasonalityFeatures extracts seasonality features
func (afp *AdvancedFeatureProcessor) extractSeasonalityFeatures(pkg *types.Package) []float64 {
	features := make([]float64, 12) // Monthly seasonality

	// Generate synthetic seasonality patterns
	hash := afp.hashString(pkg.Name + "seasonality")
	for month := 0; month < 12; month++ {
		// Create seasonal patterns based on package characteristics
		seasonalFactor := math.Sin(float64(month)*math.Pi/6.0) + 1.0
		features[month] = seasonalFactor * float64((hash+month)%100) / 100.0
	}

	return features
}

// extractTrendFeatures extracts trend features
func (afp *AdvancedFeatureProcessor) extractTrendFeatures(pkg *types.Package) []float64 {
	features := make([]float64, 8)

	// Generate synthetic trend features
	hash := afp.hashString(pkg.Name + "trend")
	baseTrend := float64(hash%100) / 100.0

	// Download trends
	features[0] = baseTrend*2.0 - 1.0 // Download growth rate (-1 to 1)
	features[1] = baseTrend * 0.5     // Download acceleration

	// Community trends
	features[2] = baseTrend*2.0 - 1.0 // Star growth rate
	features[3] = baseTrend*2.0 - 1.0 // Contributor growth rate

	// Quality trends
	features[4] = baseTrend*2.0 - 1.0 // Code quality trend
	features[5] = baseTrend*2.0 - 1.0 // Security trend

	// Maintenance trends
	features[6] = baseTrend*2.0 - 1.0 // Update frequency trend
	features[7] = baseTrend*2.0 - 1.0 // Issue resolution trend

	return features
}

// NormalizeFeatures normalizes features for neural network input
func (afp *AdvancedFeatureProcessor) NormalizeFeatures(features *AdvancedPackageFeatures) ([]float64, error) {
	// Flatten all features into a single vector
	normalizedFeatures := make([]float64, 0)

	// Add basic features
	normalizedFeatures = append(normalizedFeatures, afp.normalizeStringFeature(features.PackageName)...)
	normalizedFeatures = append(normalizedFeatures, afp.normalizeStringFeature(features.Version)...)
	normalizedFeatures = append(normalizedFeatures, afp.normalizeStringFeature(features.Registry)...)

	// Add embeddings
	normalizedFeatures = append(normalizedFeatures, features.NameEmbedding...)
	normalizedFeatures = append(normalizedFeatures, features.DescriptionEmbedding...)
	normalizedFeatures = append(normalizedFeatures, features.KeywordEmbeddings...)

	// Add statistical features
	normalizedFeatures = append(normalizedFeatures, afp.normalizeValue(features.NameEntropy, 0, 10))
	normalizedFeatures = append(normalizedFeatures, afp.normalizeValue(features.NameComplexity, 0, 20))
	normalizedFeatures = append(normalizedFeatures, afp.normalizeValue(features.VersionComplexity, 0, 15))
	normalizedFeatures = append(normalizedFeatures, afp.normalizeValue(features.DependencyComplexity, 0, 50))

	// Add behavioral features
	normalizedFeatures = append(normalizedFeatures, features.DownloadPattern...)
	normalizedFeatures = append(normalizedFeatures, features.UpdatePattern...)
	normalizedFeatures = append(normalizedFeatures, features.DependencyPattern...)
	normalizedFeatures = append(normalizedFeatures, features.MaintainerPattern...)

	// Add security features
	normalizedFeatures = append(normalizedFeatures, features.VulnerabilityHistory...)
	normalizedFeatures = append(normalizedFeatures, features.SecurityScores...)
	normalizedFeatures = append(normalizedFeatures, features.TrustIndicators...)

	// Add community features
	normalizedFeatures = append(normalizedFeatures, features.CommunityFeatures...)

	// Add temporal features (flattened)
	for _, timeStep := range features.TimeSeriesFeatures {
		normalizedFeatures = append(normalizedFeatures, timeStep...)
	}
	normalizedFeatures = append(normalizedFeatures, features.SeasonalityFeatures...)
	normalizedFeatures = append(normalizedFeatures, features.TrendFeatures...)

	// Ensure fixed size (pad or truncate)
	targetSize := 512 // Target feature vector size
	if len(normalizedFeatures) > targetSize {
		normalizedFeatures = normalizedFeatures[:targetSize]
	} else {
		// Pad with zeros
		for len(normalizedFeatures) < targetSize {
			normalizedFeatures = append(normalizedFeatures, 0.0)
		}
	}

	return normalizedFeatures, nil
}

// Helper methods

// extractCharacterFeatures extracts character-level features from text
func (afp *AdvancedFeatureProcessor) extractCharacterFeatures(text string) []float64 {
	features := make([]float64, 32)

	if len(text) == 0 {
		return features
	}

	// Character type counts
	letters, digits, special, upper, lower := 0, 0, 0, 0, 0
	for _, char := range text {
		if unicode.IsLetter(char) {
			letters++
			if unicode.IsUpper(char) {
				upper++
			} else {
				lower++
			}
		} else if unicode.IsDigit(char) {
			digits++
		} else {
			special++
		}
	}

	total := float64(len(text))
	features[0] = float64(letters) / total
	features[1] = float64(digits) / total
	features[2] = float64(special) / total
	features[3] = float64(upper) / total
	features[4] = float64(lower) / total

	// Length features
	features[5] = math.Log(total + 1)
	features[6] = total

	// Entropy
	features[7] = afp.calculateStringEntropy(text)

	// Character n-grams (simplified)
	for i := 8; i < len(features); i++ {
		if i-8 < len(text) {
			features[i] = float64(text[i-8]) / 255.0
		}
	}

	return features
}

// tokenizeText tokenizes text into words
func (afp *AdvancedFeatureProcessor) tokenizeText(text string) []string {
	// Simple tokenization
	text = strings.ToLower(text)
	words := regexp.MustCompile(`\w+`).FindAllString(text, -1)
	return words
}

// calculateTFIDF calculates TF-IDF scores for tokens
func (afp *AdvancedFeatureProcessor) calculateTFIDF(tokens []string) []float64 {
	if len(tokens) == 0 {
		return make([]float64, 64)
	}

	// Calculate term frequencies
	tf := make(map[string]float64)
	for _, token := range tokens {
		tf[token]++
	}

	// Normalize by document length
	for token := range tf {
		tf[token] /= float64(len(tokens))
	}

	// Convert to fixed-size vector (simplified)
	vector := make([]float64, 64)
	i := 0
	for _, score := range tf {
		if i >= len(vector) {
			break
		}
		vector[i] = score
		i++
	}

	return vector
}

// extractSemanticFeatures extracts semantic features from text
func (afp *AdvancedFeatureProcessor) extractSemanticFeatures(text string) []float64 {
	features := make([]float64, 64)

	// Simple semantic features based on keywords
	semanticKeywords := map[string]float64{
		"security":  1.0,
		"crypto":    0.9,
		"auth":      0.8,
		"test":      0.7,
		"util":      0.6,
		"helper":    0.5,
		"framework": 0.8,
		"library":   0.7,
		"api":       0.6,
		"client":    0.5,
		"server":    0.6,
		"database":  0.7,
		"web":       0.5,
		"http":      0.6,
		"json":      0.4,
		"xml":       0.4,
	}

	textLower := strings.ToLower(text)
	i := 0
	for keyword, weight := range semanticKeywords {
		if i >= len(features) {
			break
		}
		if strings.Contains(textLower, keyword) {
			features[i] = weight
		}
		i++
	}

	return features
}

// calculateStringSimilarity calculates similarity between two strings
func (afp *AdvancedFeatureProcessor) calculateStringSimilarity(s1, s2 string) float64 {
	if s1 == s2 {
		return 1.0
	}

	// Simple Jaccard similarity on character bigrams
	bigrams1 := afp.extractBigrams(s1)
	bigrams2 := afp.extractBigrams(s2)

	intersection := 0
	for bigram := range bigrams1 {
		if bigrams2[bigram] {
			intersection++
		}
	}

	union := len(bigrams1) + len(bigrams2) - intersection
	if union == 0 {
		return 0.0
	}

	return float64(intersection) / float64(union)
}

// extractBigrams extracts character bigrams from a string
func (afp *AdvancedFeatureProcessor) extractBigrams(s string) map[string]bool {
	bigrams := make(map[string]bool)
	for i := 0; i < len(s)-1; i++ {
		bigram := s[i : i+2]
		bigrams[bigram] = true
	}
	return bigrams
}

// normalizeStringFeature normalizes a string feature to a fixed-size vector
func (afp *AdvancedFeatureProcessor) normalizeStringFeature(s string) []float64 {
	features := make([]float64, 8)

	if s == "" {
		return features
	}

	// Basic string features
	features[0] = float64(len(s)) / 100.0               // Normalized length
	features[1] = afp.calculateStringEntropy(s) / 10.0  // Normalized entropy
	features[2] = afp.calculateNameComplexity(s) / 20.0 // Normalized complexity

	// Hash-based features for uniqueness
	hash := afp.hashString(s)
	features[3] = float64(hash%256) / 255.0
	features[4] = float64((hash>>8)%256) / 255.0
	features[5] = float64((hash>>16)%256) / 255.0
	features[6] = float64((hash>>24)%256) / 255.0

	// Character distribution
	features[7] = afp.calculateCharacterDistribution(s)

	return features
}

// ProcessFeatures processes features using the advanced feature processor
func (afp *AdvancedFeatureProcessor) ProcessFeatures(input map[string]interface{}) (*ProcessedData, error) {
	afp.mu.RLock()
	defer afp.mu.RUnlock()

	// Extract features from input
	features, ok := input["features"]
	if !ok {
		return nil, fmt.Errorf("features not found in input")
	}

	// Convert to AdvancedPackageFeatures if needed
	var packageFeatures *AdvancedPackageFeatures
	switch f := features.(type) {
	case *AdvancedPackageFeatures:
		packageFeatures = f
	case map[string]interface{}:
		// Convert map to AdvancedPackageFeatures
		packageFeatures = &AdvancedPackageFeatures{}
		// Basic conversion - in a real implementation, you'd properly map all fields
		if name, ok := f["package_name"].(string); ok {
			packageFeatures.PackageName = name
		}
		if version, ok := f["version"].(string); ok {
			packageFeatures.Version = version
		}
	default:
		return nil, fmt.Errorf("unsupported features type: %T", features)
	}

	// Normalize features
	normalizedFeatures, err := afp.NormalizeFeatures(packageFeatures)
	if err != nil {
		return nil, fmt.Errorf("failed to normalize features: %w", err)
	}

	// Create ProcessedData
	processedData := &ProcessedData{
		OriginalID:         fmt.Sprintf("proc_%d", time.Now().UnixNano()),
		ProcessedID:        fmt.Sprintf("processed_%d", time.Now().UnixNano()),
		ProcessingTime:     time.Now(),
		ProcessorName:      "AdvancedFeatureProcessor",
		ExtractedFeatures:  normalizedFeatures,
		NormalizedFeatures: normalizedFeatures,
		FeatureNames:       afp.getFeatureNames(),
		ProcessingDuration: time.Since(time.Now()),
	}

	return processedData, nil
}

// getFeatureNames returns the names of features in the normalized vector
func (afp *AdvancedFeatureProcessor) getFeatureNames() []string {
	// Return standard feature names for the 512-dimensional vector
	names := make([]string, 512)
	for i := 0; i < 512; i++ {
		names[i] = fmt.Sprintf("feature_%d", i)
	}
	return names
}

// normalizeValue normalizes a value to [0,1] range
func (afp *AdvancedFeatureProcessor) normalizeValue(value, min, max float64) float64 {
	if max <= min {
		return 0.0
	}
	normalized := (value - min) / (max - min)
	return math.Max(0.0, math.Min(1.0, normalized))
}

// hashString creates a hash of a string
func (afp *AdvancedFeatureProcessor) hashString(s string) int {
	hash := sha256.Sum256([]byte(s))
	result := 0
	for i := 0; i < 4; i++ {
		result = (result << 8) | int(hash[i])
	}
	if result < 0 {
		result = -result
	}
	return result
}

// calculateCharacterDistribution calculates character distribution metric
func (afp *AdvancedFeatureProcessor) calculateCharacterDistribution(s string) float64 {
	if len(s) == 0 {
		return 0.0
	}

	// Count character types
	counts := make(map[string]int)
	for _, char := range s {
		if unicode.IsLetter(char) {
			counts["letter"]++
		} else if unicode.IsDigit(char) {
			counts["digit"]++
		} else {
			counts["special"]++
		}
	}

	// Calculate distribution entropy
	entropy := 0.0
	total := float64(len(s))
	for _, count := range counts {
		if count > 0 {
			p := float64(count) / total
			entropy -= p * math.Log2(p)
		}
	}

	return entropy
}

// initializeEmbeddingWeights initializes embedding weights
func (afp *AdvancedFeatureProcessor) initializeEmbeddingWeights(vocabSize, embedDim int) [][]float64 {
	weights := make([][]float64, vocabSize)
	for i := range weights {
		weights[i] = make([]float64, embedDim)
		for j := range weights[i] {
			// Xavier initialization
			weights[i][j] = (rand.Float64()*2.0 - 1.0) * math.Sqrt(6.0/float64(vocabSize+embedDim))
		}
	}
	return weights
}
