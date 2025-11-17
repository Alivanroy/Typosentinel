package ml

import (
	"context"
	"fmt"
	"math"
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/Alivanroy/Typosentinel/internal/config"
	"github.com/Alivanroy/Typosentinel/pkg/logger"
	"github.com/Alivanroy/Typosentinel/pkg/types"
)

// AdaptiveThresholdManager manages ecosystem-specific ML thresholds
type AdaptiveThresholdManager struct {
	config           *config.Config
	ecosystemModels  map[string]*EcosystemModel
	thresholds       map[string]*ThresholdSet
	performanceStats map[string]*PerformanceStats
	mu               sync.RWMutex
	logger           *logger.Logger
	updateInterval   time.Duration
	lastUpdate       time.Time
}

// EcosystemModel represents an ML model specific to a package ecosystem
type EcosystemModel struct {
	Ecosystem       string                 `json:"ecosystem"`
	ModelVersion    string                 `json:"model_version"`
	ModelPath       string                 `json:"model_path"`
	FeatureWeights  map[string]float64     `json:"feature_weights"`
	TrainingMetrics TrainingMetrics        `json:"training_metrics"`
	LastTrained     time.Time              `json:"last_trained"`
	IsActive        bool                   `json:"is_active"`
	Metadata        map[string]interface{} `json:"metadata"`
}

// ThresholdSet represents adaptive thresholds for different threat types
type ThresholdSet struct {
	Ecosystem              string            `json:"ecosystem"`
	TyposquattingThreshold float64           `json:"typosquatting_threshold"`
	ConfusionThreshold     float64           `json:"confusion_threshold"`
	SupplyChainThreshold   float64           `json:"supply_chain_threshold"`
	MalwareThreshold       float64           `json:"malware_threshold"`
	ConfidenceLevel        float64           `json:"confidence_level"`
	LastUpdated            time.Time         `json:"last_updated"`
	AdaptationHistory      []ThresholdChange `json:"adaptation_history"`
}

// PerformanceStats tracks model performance metrics
type PerformanceStats struct {
	Ecosystem      string    `json:"ecosystem"`
	TruePositives  int       `json:"true_positives"`
	FalsePositives int       `json:"false_positives"`
	TrueNegatives  int       `json:"true_negatives"`
	FalseNegatives int       `json:"false_negatives"`
	Precision      float64   `json:"precision"`
	Recall         float64   `json:"recall"`
	F1Score        float64   `json:"f1_score"`
	Accuracy       float64   `json:"accuracy"`
	LastCalculated time.Time `json:"last_calculated"`
}

// TrainingMetrics represents model training performance
type TrainingMetrics struct {
	Accuracy       float64       `json:"accuracy"`
	Precision      float64       `json:"precision"`
	Recall         float64       `json:"recall"`
	F1Score        float64       `json:"f1_score"`
	AUC            float64       `json:"auc"`
	TrainingLoss   float64       `json:"training_loss"`
	ValidationLoss float64       `json:"validation_loss"`
	TrainingTime   time.Duration `json:"training_time"`
	DatasetSize    int           `json:"dataset_size"`
}

// ThresholdChange represents a threshold adaptation event
type ThresholdChange struct {
	ThreatType      string    `json:"threat_type"`
	OldThreshold    float64   `json:"old_threshold"`
	NewThreshold    float64   `json:"new_threshold"`
	Reason          string    `json:"reason"`
	Timestamp       time.Time `json:"timestamp"`
	PerformanceGain float64   `json:"performance_gain"`
}

// AdaptiveResult represents the result of adaptive threshold analysis
type AdaptiveResult struct {
	Ecosystem            string                 `json:"ecosystem"`
	OriginalScore        float64                `json:"original_score"`
	AdjustedScore        float64                `json:"adjusted_score"`
	ThresholdUsed        float64                `json:"threshold_used"`
	ModelVersion         string                 `json:"model_version"`
	ConfidenceLevel      float64                `json:"confidence_level"`
	FeatureContributions map[string]float64     `json:"feature_contributions"`
	AdaptationApplied    bool                   `json:"adaptation_applied"`
	Details              map[string]interface{} `json:"details"`
}

// NewAdaptiveThresholdManager creates a new adaptive threshold manager
func NewAdaptiveThresholdManager(config *config.Config, logger *logger.Logger) *AdaptiveThresholdManager {
	return &AdaptiveThresholdManager{
		config:           config,
		ecosystemModels:  make(map[string]*EcosystemModel),
		thresholds:       make(map[string]*ThresholdSet),
		performanceStats: make(map[string]*PerformanceStats),
		logger:           logger,
		updateInterval:   24 * time.Hour, // Default 24 hour update interval
	}
}

// Initialize sets up the adaptive threshold system
func (atm *AdaptiveThresholdManager) Initialize(ctx context.Context) error {
	atm.mu.Lock()
	defer atm.mu.Unlock()

	atm.logger.Info("Initializing adaptive threshold manager")

	// Load ecosystem models
	if err := atm.loadEcosystemModels(); err != nil {
		return fmt.Errorf("failed to load ecosystem models: %w", err)
	}

	// Initialize default thresholds
	if err := atm.initializeDefaultThresholds(); err != nil {
		return fmt.Errorf("failed to initialize default thresholds: %w", err)
	}

	// Load performance statistics
	if err := atm.loadPerformanceStats(); err != nil {
		return fmt.Errorf("failed to load performance stats: %w", err)
	}

	// Start background adaptation process
	go atm.startAdaptationLoop(ctx)

	atm.logger.Info("Adaptive threshold manager initialized successfully")
	return nil
}

// GetAdaptiveThreshold returns the adaptive threshold for a specific ecosystem and threat type
func (atm *AdaptiveThresholdManager) GetAdaptiveThreshold(ecosystem, threatType string) float64 {
	atm.mu.RLock()
	defer atm.mu.RUnlock()

	thresholdSet, exists := atm.thresholds[ecosystem]
	if !exists {
		// Fall back to generic thresholds
		thresholdSet = atm.thresholds["generic"]
		if thresholdSet == nil {
			return atm.getDefaultThreshold(threatType)
		}
	}

	switch threatType {
	case "typosquatting":
		return thresholdSet.TyposquattingThreshold
	case "dependency_confusion":
		return thresholdSet.ConfusionThreshold
	case "supply_chain":
		return thresholdSet.SupplyChainThreshold
	case "malware":
		return thresholdSet.MalwareThreshold
	default:
		return 0.7 // Default threshold
	}
}

// AnalyzeWithAdaptiveThresholds performs analysis with ecosystem-specific adaptations
func (atm *AdaptiveThresholdManager) AnalyzeWithAdaptiveThresholds(ctx context.Context, pkg *types.Package, originalScore float64, threatType string) (*AdaptiveResult, error) {
	ecosystem := atm.determineEcosystem(pkg)

	result := &AdaptiveResult{
		Ecosystem:            ecosystem,
		OriginalScore:        originalScore,
		AdjustedScore:        originalScore,
		FeatureContributions: make(map[string]float64),
		Details:              make(map[string]interface{}),
	}

	// Get ecosystem-specific model
	model := atm.getEcosystemModel(ecosystem)
	if model != nil {
		result.ModelVersion = model.ModelVersion

		// Apply ecosystem-specific adjustments
		adjustedScore, err := atm.applyEcosystemAdjustments(pkg, originalScore, model)
		if err != nil {
			atm.logger.Warn("Failed to apply ecosystem adjustments", map[string]interface{}{"error": err})
		} else {
			result.AdjustedScore = adjustedScore
			result.AdaptationApplied = true
		}
	}

	// Get adaptive threshold
	threshold := atm.GetAdaptiveThreshold(ecosystem, threatType)
	result.ThresholdUsed = threshold

	// Calculate confidence level
	result.ConfidenceLevel = atm.calculateConfidenceLevel(ecosystem, result.AdjustedScore, threshold)

	// Add feature contributions
	result.FeatureContributions = atm.calculateFeatureContributions(pkg, model)

	// Add analysis details
	result.Details["ecosystem_detected"] = ecosystem
	result.Details["model_available"] = model != nil
    result.Details["threshold_source"] = atm.GetThresholdSource(ecosystem)

	return result, nil
}

// UpdatePerformanceStats updates performance statistics for threshold adaptation
func (atm *AdaptiveThresholdManager) UpdatePerformanceStats(ecosystem string, prediction, actual bool, score float64) {
	atm.mu.Lock()
	defer atm.mu.Unlock()

	stats, exists := atm.performanceStats[ecosystem]
	if !exists {
		stats = &PerformanceStats{
			Ecosystem: ecosystem,
		}
		atm.performanceStats[ecosystem] = stats
	}

	// Update confusion matrix
	if prediction && actual {
		stats.TruePositives++
	} else if prediction && !actual {
		stats.FalsePositives++
	} else if !prediction && actual {
		stats.FalseNegatives++
	} else {
		stats.TrueNegatives++
	}

	// Recalculate metrics
	atm.recalculateMetrics(stats)
	stats.LastCalculated = time.Now()
}

// AdaptThresholds adapts thresholds based on performance feedback
func (atm *AdaptiveThresholdManager) AdaptThresholds(ctx context.Context) error {
	atm.mu.Lock()
	defer atm.mu.Unlock()

	atm.logger.Info("Starting threshold adaptation")

	for ecosystem, stats := range atm.performanceStats {
		thresholdSet, exists := atm.thresholds[ecosystem]
		if !exists {
			continue
		}

		// Adapt each threshold type based on performance
		if err := atm.adaptThresholdForType(ecosystem, "typosquatting", stats, thresholdSet); err != nil {
			atm.logger.Warn("Failed to adapt typosquatting threshold", map[string]interface{}{"ecosystem": ecosystem, "error": err})
		}

		if err := atm.adaptThresholdForType(ecosystem, "dependency_confusion", stats, thresholdSet); err != nil {
			atm.logger.Warn("Failed to adapt confusion threshold", map[string]interface{}{"ecosystem": ecosystem, "error": err})
		}

		if err := atm.adaptThresholdForType(ecosystem, "supply_chain", stats, thresholdSet); err != nil {
			atm.logger.Warn("Failed to adapt supply chain threshold", map[string]interface{}{"ecosystem": ecosystem, "error": err})
		}

		thresholdSet.LastUpdated = time.Now()
	}

	atm.lastUpdate = time.Now()
	atm.logger.Info("Threshold adaptation completed")
	return nil
}

// Helper methods

func (atm *AdaptiveThresholdManager) loadEcosystemModels() error {
	// Load NPM model
	atm.ecosystemModels["npm"] = &EcosystemModel{
		Ecosystem:    "npm",
		ModelVersion: "1.0.0",
		ModelPath:    "models/npm_model.pkl",
		FeatureWeights: map[string]float64{
			"name_similarity":       0.3,
			"download_count":        0.2,
			"maintainer_reputation": 0.25,
			"version_pattern":       0.15,
			"dependency_risk":       0.1,
		},
		IsActive:    true,
		LastTrained: time.Now().AddDate(0, -1, 0), // 1 month ago
	}

	// Load PyPI model
	atm.ecosystemModels["pypi"] = &EcosystemModel{
		Ecosystem:    "pypi",
		ModelVersion: "1.0.0",
		ModelPath:    "models/pypi_model.pkl",
		FeatureWeights: map[string]float64{
			"name_similarity":     0.35,
			"author_reputation":   0.25,
			"package_metadata":    0.2,
			"version_history":     0.15,
			"dependency_analysis": 0.05,
		},
		IsActive:    true,
		LastTrained: time.Now().AddDate(0, -1, 0),
	}

	// Load Go modules model
	atm.ecosystemModels["go"] = &EcosystemModel{
		Ecosystem:    "go",
		ModelVersion: "1.0.0",
		ModelPath:    "models/go_model.pkl",
		FeatureWeights: map[string]float64{
			"module_path_similarity": 0.4,
			"repository_analysis":    0.3,
			"version_semantics":      0.2,
			"import_patterns":        0.1,
		},
		IsActive:    true,
		LastTrained: time.Now().AddDate(0, -1, 0),
	}

	// Generic fallback model
	atm.ecosystemModels["generic"] = &EcosystemModel{
		Ecosystem:    "generic",
		ModelVersion: "1.0.0",
		ModelPath:    "models/generic_model.pkl",
		FeatureWeights: map[string]float64{
			"name_similarity":     0.5,
			"metadata_analysis":   0.3,
			"behavioral_patterns": 0.2,
		},
		IsActive:    true,
		LastTrained: time.Now().AddDate(0, -1, 0),
	}

	return nil
}

func (atm *AdaptiveThresholdManager) initializeDefaultThresholds() error {
	// NPM thresholds
	atm.thresholds["npm"] = &ThresholdSet{
		Ecosystem:              "npm",
		TyposquattingThreshold: 0.7,
		ConfusionThreshold:     0.75,
		SupplyChainThreshold:   0.8,
		MalwareThreshold:       0.85,
		ConfidenceLevel:        0.9,
		LastUpdated:            time.Now(),
		AdaptationHistory:      []ThresholdChange{},
	}

	// PyPI thresholds
	atm.thresholds["pypi"] = &ThresholdSet{
		Ecosystem:              "pypi",
		TyposquattingThreshold: 0.75,
		ConfusionThreshold:     0.7,
		SupplyChainThreshold:   0.8,
		MalwareThreshold:       0.85,
		ConfidenceLevel:        0.85,
		LastUpdated:            time.Now(),
		AdaptationHistory:      []ThresholdChange{},
	}

	// Go modules thresholds
	atm.thresholds["go"] = &ThresholdSet{
		Ecosystem:              "go",
		TyposquattingThreshold: 0.8,
		ConfusionThreshold:     0.75,
		SupplyChainThreshold:   0.85,
		MalwareThreshold:       0.9,
		ConfidenceLevel:        0.95,
		LastUpdated:            time.Now(),
		AdaptationHistory:      []ThresholdChange{},
	}

	// Generic thresholds
	atm.thresholds["generic"] = &ThresholdSet{
		Ecosystem:              "generic",
		TyposquattingThreshold: 0.7,
		ConfusionThreshold:     0.7,
		SupplyChainThreshold:   0.7,
		MalwareThreshold:       0.8,
		ConfidenceLevel:        0.8,
		LastUpdated:            time.Now(),
		AdaptationHistory:      []ThresholdChange{},
	}

	return nil
}

func (atm *AdaptiveThresholdManager) loadPerformanceStats() error {
	// Initialize empty performance stats for each ecosystem
	for ecosystem := range atm.thresholds {
		atm.performanceStats[ecosystem] = &PerformanceStats{
			Ecosystem:      ecosystem,
			LastCalculated: time.Now(),
		}
	}
	return nil
}

func (atm *AdaptiveThresholdManager) startAdaptationLoop(ctx context.Context) {
	ticker := time.NewTicker(atm.updateInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := atm.AdaptThresholds(ctx); err != nil {
				atm.logger.Error("Failed to adapt thresholds", map[string]interface{}{"error": err})
			}
		}
	}
}

func (atm *AdaptiveThresholdManager) determineEcosystem(pkg *types.Package) string {
	// Determine ecosystem based on package metadata
	if pkg.Registry != "" {
		switch {
		case strings.Contains(pkg.Registry, "npmjs"):
			return "npm"
		case strings.Contains(pkg.Registry, "pypi"):
			return "pypi"
		case strings.Contains(pkg.Registry, "golang") || strings.Contains(pkg.Registry, "proxy.golang.org"):
			return "go"
		case strings.Contains(pkg.Registry, "crates.io"):
			return "rust"
		}
	}

	// Fallback to generic
	return "generic"
}

func (atm *AdaptiveThresholdManager) getEcosystemModel(ecosystem string) *EcosystemModel {
	atm.mu.RLock()
	defer atm.mu.RUnlock()

	model, exists := atm.ecosystemModels[ecosystem]
	if !exists || !model.IsActive {
		// Fall back to generic model
		return atm.ecosystemModels["generic"]
	}
	return model
}

func (atm *AdaptiveThresholdManager) applyEcosystemAdjustments(pkg *types.Package, originalScore float64, model *EcosystemModel) (float64, error) {
	// Apply ecosystem-specific feature weights and adjustments
	adjustedScore := originalScore

	// Example ecosystem-specific adjustments
	switch model.Ecosystem {
	case "npm":
		// NPM packages with scoped names are less likely to be malicious
		if strings.HasPrefix(pkg.Name, "@") {
			adjustedScore *= 0.8
		}
	case "pypi":
		// PyPI packages with underscores are more common and less suspicious
		if strings.Contains(pkg.Name, "_") {
			adjustedScore *= 0.9
		}
	case "go":
		// Go modules with domain prefixes are more trustworthy
		if strings.Contains(pkg.Name, ".") && strings.Count(pkg.Name, "/") >= 2 {
			adjustedScore *= 0.7
		}
	}

	return adjustedScore, nil
}

func (atm *AdaptiveThresholdManager) calculateConfidenceLevel(ecosystem string, score, threshold float64) float64 {
	// Calculate confidence based on distance from threshold
	distance := abs(score - threshold)
	confidence := 0.5 + (distance * 0.5) // Base confidence + distance factor

	if confidence > 1.0 {
		confidence = 1.0
	}

	return confidence
}

func (atm *AdaptiveThresholdManager) calculateFeatureContributions(pkg *types.Package, model *EcosystemModel) map[string]float64 {
	contributions := make(map[string]float64)

	if model != nil && pkg != nil {
		// Calculate feature contributions based on model weights and package characteristics
		for feature, weight := range model.FeatureWeights {
			var featureValue float64

			switch feature {
			case "name_similarity":
				// Calculate name similarity contribution
				featureValue = atm.calculateNameSimilarityScore(pkg.Name)
			case "version_pattern":
				// Calculate version pattern contribution
				featureValue = atm.calculateVersionPatternScore(pkg.Version)
			case "author_reputation":
				// Calculate author reputation contribution
				var author string
				if pkg.Metadata != nil {
					author = pkg.Metadata.Author
				}
				featureValue = atm.calculateAuthorReputationScore(author)
			case "download_count":
				// Calculate download count contribution (normalized)
				var downloads int64
				if pkg.Metadata != nil {
					downloads = pkg.Metadata.Downloads
				}
				featureValue = atm.normalizeDownloadCount(downloads)
			case "dependency_risk":
				// Calculate dependency risk contribution
				depNames := make([]string, len(pkg.Dependencies))
				for i, dep := range pkg.Dependencies {
					depNames[i] = dep.Name
				}
				featureValue = atm.calculateDependencyRiskScore(depNames)
			case "age_factor":
				// Calculate package age contribution
				featureValue = atm.calculateAgeFactorScore(pkg.AnalyzedAt)
			default:
				// Default feature value
				featureValue = 0.5
			}

			// Weight the feature value
			contributions[feature] = weight * featureValue
		}
	}

	return contributions
}

func (atm *AdaptiveThresholdManager) calculateNameSimilarityScore(name string) float64 {
	// Simple heuristic for name similarity to popular packages
	if len(name) < 3 {
		return 0.8 // Very short names are suspicious
	}

	// Check for common typosquatting patterns
	suspiciousPatterns := []string{"0", "1", "l", "I", "o", "O"}
	score := 0.0
	for _, pattern := range suspiciousPatterns {
		if strings.Contains(name, pattern) {
			score += 0.2
		}
	}

	return math.Min(score, 1.0)
}

func (atm *AdaptiveThresholdManager) calculateVersionPatternScore(version string) float64 {
	if version == "" {
		return 0.7 // Missing version is suspicious
	}

	// Check for semantic versioning
	semverRegex := regexp.MustCompile(`^\d+\.\d+\.\d+`)
	if semverRegex.MatchString(version) {
		return 0.1 // Good versioning pattern
	}

	return 0.5 // Neutral score for other patterns
}

func (atm *AdaptiveThresholdManager) calculateAuthorReputationScore(author string) float64 {
	if author == "" {
		return 0.6 // Missing author is somewhat suspicious
	}

	// Simple heuristics for author reputation
	if len(author) < 3 {
		return 0.8 // Very short author names are suspicious
	}

	// Check for random-looking names
	digitCount := 0
	for _, r := range author {
		if unicode.IsDigit(r) {
			digitCount++
		}
	}

	if digitCount > len(author)/2 {
		return 0.7 // Too many digits in author name
	}

	return 0.2 // Normal author name
}

func (atm *AdaptiveThresholdManager) normalizeDownloadCount(downloads int64) float64 {
	if downloads == 0 {
		return 0.8 // No downloads is suspicious
	}

	// Logarithmic normalization
	normalizedScore := math.Log10(float64(downloads)) / 10.0
	if normalizedScore > 1.0 {
		normalizedScore = 1.0
	}

	// Invert score (higher downloads = lower suspicion)
	return 1.0 - normalizedScore
}

func (atm *AdaptiveThresholdManager) calculateDependencyRiskScore(dependencies []string) float64 {
	if len(dependencies) == 0 {
		return 0.3 // No dependencies might be suspicious for some packages
	}

	// Simple risk calculation based on dependency count
	if len(dependencies) > 50 {
		return 0.7 // Too many dependencies
	}

	return 0.2 // Normal dependency count
}

func (atm *AdaptiveThresholdManager) calculateAgeFactorScore(createdAt time.Time) float64 {
	if createdAt.IsZero() {
		return 0.5 // Unknown age
	}

	age := time.Since(createdAt)

	// Very new packages are more suspicious
	if age.Hours() < 24 {
		return 0.8 // Less than 1 day old
	} else if age.Hours() < 168 { // Less than 1 week
		return 0.6
	} else if age.Hours() < 720 { // Less than 1 month
		return 0.4
	}

	return 0.2 // Mature package
}

func (atm *AdaptiveThresholdManager) getDefaultThreshold(threatType string) float64 {
	defaultThresholds := map[string]float64{
		"typosquatting":        0.7,
		"dependency_confusion": 0.7,
		"supply_chain":         0.7,
		"malware":              0.8,
	}

	if threshold, exists := defaultThresholds[threatType]; exists {
		return threshold
	}
	return 0.7
}

func (atm *AdaptiveThresholdManager) GetThresholdSource(ecosystem string) string {
    _, exists := atm.thresholds[ecosystem]
    if exists {
        return "ecosystem_specific"
    }
    return "generic_fallback"
}

func (atm *AdaptiveThresholdManager) recalculateMetrics(stats *PerformanceStats) {
	total := stats.TruePositives + stats.FalsePositives + stats.TrueNegatives + stats.FalseNegatives
	if total == 0 {
		return
	}

	// Calculate precision
	if stats.TruePositives+stats.FalsePositives > 0 {
		stats.Precision = float64(stats.TruePositives) / float64(stats.TruePositives+stats.FalsePositives)
	}

	// Calculate recall
	if stats.TruePositives+stats.FalseNegatives > 0 {
		stats.Recall = float64(stats.TruePositives) / float64(stats.TruePositives+stats.FalseNegatives)
	}

	// Calculate F1 score
	if stats.Precision+stats.Recall > 0 {
		stats.F1Score = 2 * (stats.Precision * stats.Recall) / (stats.Precision + stats.Recall)
	}

	// Calculate accuracy
	stats.Accuracy = float64(stats.TruePositives+stats.TrueNegatives) / float64(total)
}

func (atm *AdaptiveThresholdManager) adaptThresholdForType(ecosystem, threatType string, stats *PerformanceStats, thresholdSet *ThresholdSet) error {
	// Simple threshold adaptation based on F1 score
	if stats.F1Score < 0.8 { // If F1 score is below 80%
		oldThreshold := atm.getCurrentThreshold(thresholdSet, threatType)
		newThreshold := oldThreshold

		// Adjust threshold based on precision/recall balance
		if stats.Precision < stats.Recall {
			// Too many false positives, increase threshold
			newThreshold += 0.05
		} else {
			// Too many false negatives, decrease threshold
			newThreshold -= 0.05
		}

		// Ensure threshold stays within bounds
		if newThreshold < 0.1 {
			newThreshold = 0.1
		} else if newThreshold > 0.95 {
			newThreshold = 0.95
		}

		// Apply the new threshold
		if newThreshold != oldThreshold {
			atm.setThreshold(thresholdSet, threatType, newThreshold)

			// Record the change
			change := ThresholdChange{
				ThreatType:      threatType,
				OldThreshold:    oldThreshold,
				NewThreshold:    newThreshold,
				Reason:          fmt.Sprintf("F1 score optimization (%.3f)", stats.F1Score),
				Timestamp:       time.Now(),
				PerformanceGain: newThreshold - oldThreshold,
			}
			thresholdSet.AdaptationHistory = append(thresholdSet.AdaptationHistory, change)
		}
	}

	return nil
}

func (atm *AdaptiveThresholdManager) getCurrentThreshold(thresholdSet *ThresholdSet, threatType string) float64 {
	switch threatType {
	case "typosquatting":
		return thresholdSet.TyposquattingThreshold
	case "dependency_confusion":
		return thresholdSet.ConfusionThreshold
	case "supply_chain":
		return thresholdSet.SupplyChainThreshold
	case "malware":
		return thresholdSet.MalwareThreshold
	default:
		return 0.7
	}
}

func (atm *AdaptiveThresholdManager) setThreshold(thresholdSet *ThresholdSet, threatType string, threshold float64) {
	switch threatType {
	case "typosquatting":
		thresholdSet.TyposquattingThreshold = threshold
	case "dependency_confusion":
		thresholdSet.ConfusionThreshold = threshold
	case "supply_chain":
		thresholdSet.SupplyChainThreshold = threshold
	case "malware":
		thresholdSet.MalwareThreshold = threshold
	}
}

func abs(x float64) float64 {
	if x < 0 {
		return -x
	}
	return x
}
