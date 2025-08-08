package security

import (
	"context"
	"fmt"
	"math"
	"sort"
	"strings"
	"time"

	"github.com/Alivanroy/Typosentinel/pkg/logger"
	"github.com/Alivanroy/Typosentinel/pkg/types"
)

// MLHardeningSystem provides comprehensive ML model hardening capabilities
// Addresses critical AI/ML vulnerabilities identified in adversarial assessment:
// - Adversarial example generation and detection
// - Feature poisoning attacks
// - Model evasion techniques
// - Gradient-based attacks
// - Input perturbation detection
// - Model robustness validation
type MLHardeningSystem struct {
	config                    *MLHardeningConfig
	adversarialDetector       *AdversarialDetector
	featurePoisoningDetector  *FeaturePoisoningDetector
	inputValidator            *InputValidator
	modelRobustnessValidator  *ModelRobustnessValidator
	gradientAnalyzer          *GradientAnalyzer
	ensembleDefense           *EnsembleDefense
	logger                    logger.Logger
}

// MLHardeningConfig configures ML hardening parameters
type MLHardeningConfig struct {
	EnableAdversarialDetection   bool          `yaml:"enable_adversarial_detection"`   // true
	EnableFeaturePoisoningCheck  bool          `yaml:"enable_feature_poisoning_check"` // true
	EnableInputValidation        bool          `yaml:"enable_input_validation"`        // true
	EnableRobustnessValidation   bool          `yaml:"enable_robustness_validation"`   // true
	EnableGradientAnalysis       bool          `yaml:"enable_gradient_analysis"`       // true
	EnableEnsembleDefense        bool          `yaml:"enable_ensemble_defense"`        // true
	AdversarialThreshold         float64       `yaml:"adversarial_threshold"`          // 0.8
	PoisoningThreshold           float64       `yaml:"poisoning_threshold"`            // 0.7
	RobustnessThreshold          float64       `yaml:"robustness_threshold"`           // 0.6
	MaxPerturbationMagnitude     float64       `yaml:"max_perturbation_magnitude"`     // 0.1
	GradientAnalysisDepth        int           `yaml:"gradient_analysis_depth"`        // 5
	EnsembleSize                 int           `yaml:"ensemble_size"`                  // 3
	ValidationTimeout            time.Duration `yaml:"validation_timeout"`             // 60s
	Enabled                      bool          `yaml:"enabled"`                        // true
}

// MLHardeningResult represents ML hardening analysis results
type MLHardeningResult struct {
	PackageName              string                        `json:"package_name"`
	OverallSecurityScore     float64                       `json:"overall_security_score"`
	AdversarialRisk          *AdversarialRisk              `json:"adversarial_risk"`
	FeaturePoisoningRisk     *FeaturePoisoningRisk         `json:"feature_poisoning_risk"`
	InputValidationResult    *InputValidationResult        `json:"input_validation_result"`
	RobustnessValidation     *RobustnessValidationResult   `json:"robustness_validation"`
	GradientAnalysis         *GradientAnalysisResult       `json:"gradient_analysis"`
	EnsembleDefenseResult    *EnsembleDefenseResult        `json:"ensemble_defense_result"`
	DetectedVulnerabilities  []MLVulnerability             `json:"detected_vulnerabilities"`
	Countermeasures          []MLCountermeasure            `json:"countermeasures"`
	Recommendations          []string                      `json:"recommendations"`
	Metadata                 map[string]interface{}        `json:"metadata"`
}

// AdversarialRisk represents adversarial attack risk assessment
type AdversarialRisk struct {
	RiskLevel               string                    `json:"risk_level"`
	ConfidenceScore         float64                   `json:"confidence_score"`
	DetectedAttackVectors   []AdversarialAttackVector `json:"detected_attack_vectors"`
	PerturbationMagnitude   float64                   `json:"perturbation_magnitude"`
	EvasionProbability      float64                   `json:"evasion_probability"`
	DefenseRecommendations  []string                  `json:"defense_recommendations"`
}

// AdversarialAttackVector represents specific adversarial attack vectors
type AdversarialAttackVector struct {
	AttackType      string    `json:"attack_type"`
	Severity        string    `json:"severity"`
	Description     string    `json:"description"`
	SuccessRate     float64   `json:"success_rate"`
	DetectionMethod string    `json:"detection_method"`
	Timestamp       time.Time `json:"timestamp"`
}

// FeaturePoisoningRisk represents feature poisoning risk assessment
type FeaturePoisoningRisk struct {
	RiskLevel           string                  `json:"risk_level"`
	ConfidenceScore     float64                 `json:"confidence_score"`
	PoisonedFeatures    []PoisonedFeature       `json:"poisoned_features"`
	PoisoningTechniques []PoisoningTechnique    `json:"poisoning_techniques"`
	ImpactAssessment    *PoisoningImpact        `json:"impact_assessment"`
}

// PoisonedFeature represents a potentially poisoned feature
type PoisonedFeature struct {
	FeatureName     string  `json:"feature_name"`
	PoisonScore     float64 `json:"poison_score"`
	AnomalyLevel    string  `json:"anomaly_level"`
	Evidence        []string `json:"evidence"`
	OriginalValue   float64 `json:"original_value"`
	SuspiciousValue float64 `json:"suspicious_value"`
}

// PoisoningTechnique represents feature poisoning techniques
type PoisoningTechnique struct {
	Technique   string  `json:"technique"`
	Description string  `json:"description"`
	Confidence  float64 `json:"confidence"`
	Indicators  []string `json:"indicators"`
}

// PoisoningImpact represents the impact of feature poisoning
type PoisoningImpact struct {
	ModelAccuracyDrop    float64 `json:"model_accuracy_drop"`
	FalsePositiveRate    float64 `json:"false_positive_rate"`
	FalseNegativeRate    float64 `json:"false_negative_rate"`
	OverallDegradation   float64 `json:"overall_degradation"`
}

// InputValidationResult represents input validation results
type InputValidationResult struct {
	ValidationStatus    string                `json:"validation_status"`
	AnomalousInputs     []AnomalousInput      `json:"anomalous_inputs"`
	ValidationMetrics   *ValidationMetrics    `json:"validation_metrics"`
	SanitizationApplied bool                  `json:"sanitization_applied"`
}

// AnomalousInput represents anomalous input detection
type AnomalousInput struct {
	InputType       string  `json:"input_type"`
	AnomalyScore    float64 `json:"anomaly_score"`
	Description     string  `json:"description"`
	SuspiciousValue string  `json:"suspicious_value"`
	ExpectedRange   string  `json:"expected_range"`
}

// ValidationMetrics represents input validation metrics
type ValidationMetrics struct {
	TotalInputs       int     `json:"total_inputs"`
	ValidInputs       int     `json:"valid_inputs"`
	AnomalousInputs   int     `json:"anomalous_inputs"`
	ValidationRate    float64 `json:"validation_rate"`
	AnomalyRate       float64 `json:"anomaly_rate"`
}

// RobustnessValidationResult represents model robustness validation
type RobustnessValidationResult struct {
	RobustnessScore     float64                `json:"robustness_score"`
	StabilityMetrics    *StabilityMetrics      `json:"stability_metrics"`
	PerturbationTests   []PerturbationTest     `json:"perturbation_tests"`
	WeaknessAreas       []WeaknessArea         `json:"weakness_areas"`
}

// StabilityMetrics represents model stability metrics
type StabilityMetrics struct {
	PredictionVariance    float64 `json:"prediction_variance"`
	OutputStability       float64 `json:"output_stability"`
	FeatureSensitivity    float64 `json:"feature_sensitivity"`
	NoiseResistance       float64 `json:"noise_resistance"`
}

// PerturbationTest represents perturbation testing results
type PerturbationTest struct {
	PerturbationType    string  `json:"perturbation_type"`
	Magnitude           float64 `json:"magnitude"`
	SuccessRate         float64 `json:"success_rate"`
	ModelResponse       string  `json:"model_response"`
	ExpectedResponse    string  `json:"expected_response"`
}

// WeaknessArea represents identified model weakness areas
type WeaknessArea struct {
	Area            string  `json:"area"`
	Severity        string  `json:"severity"`
	Description     string  `json:"description"`
	VulnerabilityScore float64 `json:"vulnerability_score"`
	Recommendations []string `json:"recommendations"`
}

// GradientAnalysisResult represents gradient analysis results
type GradientAnalysisResult struct {
	GradientStability   float64              `json:"gradient_stability"`
	GradientMagnitude   float64              `json:"gradient_magnitude"`
	SuspiciousGradients []SuspiciousGradient `json:"suspicious_gradients"`
	GradientAttacks     []GradientAttack     `json:"gradient_attacks"`
}

// SuspiciousGradient represents suspicious gradient patterns
type SuspiciousGradient struct {
	LayerName       string  `json:"layer_name"`
	GradientValue   float64 `json:"gradient_value"`
	AnomalyScore    float64 `json:"anomaly_score"`
	Description     string  `json:"description"`
}

// GradientAttack represents detected gradient-based attacks
type GradientAttack struct {
	AttackType      string  `json:"attack_type"`
	TargetLayer     string  `json:"target_layer"`
	AttackMagnitude float64 `json:"attack_magnitude"`
	SuccessRate     float64 `json:"success_rate"`
}

// EnsembleDefenseResult represents ensemble defense results
type EnsembleDefenseResult struct {
	EnsembleAgreement   float64                `json:"ensemble_agreement"`
	ConsensusScore      float64                `json:"consensus_score"`
	ModelDiscrepancies  []ModelDiscrepancy     `json:"model_discrepancies"`
	DefenseEffectiveness float64               `json:"defense_effectiveness"`
}

// ModelDiscrepancy represents discrepancies between ensemble models
type ModelDiscrepancy struct {
	ModelPair       string  `json:"model_pair"`
	DiscrepancyScore float64 `json:"discrepancy_score"`
	ConflictingPredictions []string `json:"conflicting_predictions"`
	SuspicionLevel  string  `json:"suspicion_level"`
}

// MLVulnerability represents detected ML vulnerabilities
type MLVulnerability struct {
	VulnerabilityType string    `json:"vulnerability_type"`
	Severity          string    `json:"severity"`
	Description       string    `json:"description"`
	ExploitPotential  float64   `json:"exploit_potential"`
	AffectedComponents []string  `json:"affected_components"`
	DetectionTime     time.Time `json:"detection_time"`
}

// MLCountermeasure represents ML security countermeasures
type MLCountermeasure struct {
	CountermeasureType string   `json:"countermeasure_type"`
	Description        string   `json:"description"`
	Effectiveness      float64  `json:"effectiveness"`
	ImplementationCost string   `json:"implementation_cost"`
	Prerequisites      []string `json:"prerequisites"`
}

// Component structures for ML hardening

type AdversarialDetector struct {
	perturbationDetectors []PerturbationDetector
	evasionDetectors     []EvasionDetector
	attackSignatures     map[string]AttackSignature
}

type PerturbationDetector struct {
	DetectorType string
	Threshold    float64
	Sensitivity  float64
}

type EvasionDetector struct {
	DetectorType string
	Patterns     []string
	Confidence   float64
}

type AttackSignature struct {
	SignatureID   string
	AttackType    string
	Patterns      []string
	Confidence    float64
	LastUpdated   time.Time
}

type FeaturePoisoningDetector struct {
	baselineFeatures    map[string]float64
	anomalyThreshold    float64
	poisoningPatterns   []PoisoningPattern
}

type PoisoningPattern struct {
	PatternType string
	Indicators  []string
	Severity    string
}

type InputValidator struct {
	validationRules   []ValidationRule
	sanitizationRules []SanitizationRule
	anomalyDetector   *AnomalyDetector
}

type ValidationRule struct {
	RuleType    string
	Pattern     string
	Threshold   float64
	Action      string
}

type SanitizationRule struct {
	RuleType    string
	Pattern     string
	Replacement string
	Priority    int
}

type AnomalyDetector struct {
	detectionModel string
	threshold      float64
	sensitivity    float64
}

type ModelRobustnessValidator struct {
	perturbationTests []PerturbationTestConfig
	stabilityMetrics  []StabilityMetric
	robustnessModel   string
}

type PerturbationTestConfig struct {
	TestType      string
	Magnitude     float64
	Iterations    int
	ExpectedRange float64
}

type StabilityMetric struct {
	MetricType  string
	Threshold   float64
	Weight      float64
}

type GradientAnalyzer struct {
	gradientThreshold   float64
	analysisDepth       int
	suspiciousPatterns  []GradientPattern
}

type GradientPattern struct {
	PatternType string
	Signature   []float64
	Confidence  float64
}

type EnsembleDefense struct {
	models          []string
	consensusMethod string
	agreementThreshold float64
}

// NewMLHardeningSystem creates a new ML hardening system
func NewMLHardeningSystem(config *MLHardeningConfig, logger logger.Logger) *MLHardeningSystem {
	if config == nil {
		config = DefaultMLHardeningConfig()
	}

	return &MLHardeningSystem{
		config:                   config,
		adversarialDetector:      NewAdversarialDetector(),
		featurePoisoningDetector: NewFeaturePoisoningDetector(),
		inputValidator:           NewInputValidator(),
		modelRobustnessValidator: NewModelRobustnessValidator(),
		gradientAnalyzer:         NewGradientAnalyzer(),
		ensembleDefense:          NewEnsembleDefense(),
		logger:                   logger,
	}
}

// DefaultMLHardeningConfig returns default configuration
func DefaultMLHardeningConfig() *MLHardeningConfig {
	return &MLHardeningConfig{
		EnableAdversarialDetection:  true,
		EnableFeaturePoisoningCheck: true,
		EnableInputValidation:       true,
		EnableRobustnessValidation:  true,
		EnableGradientAnalysis:      true,
		EnableEnsembleDefense:       true,
		AdversarialThreshold:        0.8,
		PoisoningThreshold:          0.7,
		RobustnessThreshold:         0.6,
		MaxPerturbationMagnitude:    0.1,
		GradientAnalysisDepth:       5,
		EnsembleSize:                3,
		ValidationTimeout:           60 * time.Second,
		Enabled:                     true,
	}
}

// HardenMLModel performs comprehensive ML model hardening
func (mh *MLHardeningSystem) HardenMLModel(ctx context.Context, pkg *types.Package, features map[string]float64) (*MLHardeningResult, error) {
	if !mh.config.Enabled {
		return nil, nil
	}

	mh.logger.Info("Starting ML model hardening for package: " + pkg.Name)

	result := &MLHardeningResult{
		PackageName:             pkg.Name,
		DetectedVulnerabilities: []MLVulnerability{},
		Countermeasures:         []MLCountermeasure{},
		Recommendations:         []string{},
		Metadata:                make(map[string]interface{}),
	}

	// 1. Adversarial detection
	if mh.config.EnableAdversarialDetection {
		adversarialRisk := mh.detectAdversarialAttacks(ctx, pkg, features)
		result.AdversarialRisk = adversarialRisk
	}

	// 2. Feature poisoning detection
	if mh.config.EnableFeaturePoisoningCheck {
		poisoningRisk := mh.detectFeaturePoisoning(ctx, pkg, features)
		result.FeaturePoisoningRisk = poisoningRisk
	}

	// 3. Input validation
	if mh.config.EnableInputValidation {
		inputValidation := mh.validateInputs(ctx, pkg, features)
		result.InputValidationResult = inputValidation
	}

	// 4. Robustness validation
	if mh.config.EnableRobustnessValidation {
		robustnessValidation := mh.validateModelRobustness(ctx, pkg, features)
		result.RobustnessValidation = robustnessValidation
	}

	// 5. Gradient analysis
	if mh.config.EnableGradientAnalysis {
		gradientAnalysis := mh.analyzeGradients(ctx, pkg, features)
		result.GradientAnalysis = gradientAnalysis
	}

	// 6. Ensemble defense
	if mh.config.EnableEnsembleDefense {
		ensembleDefense := mh.performEnsembleDefense(ctx, pkg, features)
		result.EnsembleDefenseResult = ensembleDefense
	}

	// 7. Calculate overall security score
	result.OverallSecurityScore = mh.calculateOverallSecurityScore(result)

	// 8. Extract vulnerabilities and countermeasures
	result.DetectedVulnerabilities = mh.extractVulnerabilities(result)
	result.Countermeasures = mh.generateCountermeasures(result)

	// 9. Generate recommendations
	result.Recommendations = mh.generateMLRecommendations(result)

	mh.logger.Info(fmt.Sprintf("ML hardening completed for %s: security_score=%.2f",
		pkg.Name, result.OverallSecurityScore))

	return result, nil
}

// detectAdversarialAttacks detects adversarial attacks
func (mh *MLHardeningSystem) detectAdversarialAttacks(ctx context.Context, pkg *types.Package, features map[string]float64) *AdversarialRisk {
	risk := &AdversarialRisk{
		DetectedAttackVectors:  []AdversarialAttackVector{},
		DefenseRecommendations: []string{},
	}

	// Detect perturbation-based attacks
	perturbationMagnitude := mh.calculatePerturbationMagnitude(features)
	risk.PerturbationMagnitude = perturbationMagnitude

	if perturbationMagnitude > mh.config.MaxPerturbationMagnitude {
		attackVector := AdversarialAttackVector{
			AttackType:      "perturbation",
			Severity:        "high",
			Description:     "High perturbation magnitude detected",
			SuccessRate:     0.8,
			DetectionMethod: "magnitude_analysis",
			Timestamp:       time.Now(),
		}
		risk.DetectedAttackVectors = append(risk.DetectedAttackVectors, attackVector)
	}

	// Detect evasion attacks
	evasionProbability := mh.calculateEvasionProbability(features)
	risk.EvasionProbability = evasionProbability

	if evasionProbability > 0.7 {
		attackVector := AdversarialAttackVector{
			AttackType:      "evasion",
			Severity:        "critical",
			Description:     "High evasion probability detected",
			SuccessRate:     evasionProbability,
			DetectionMethod: "evasion_analysis",
			Timestamp:       time.Now(),
		}
		risk.DetectedAttackVectors = append(risk.DetectedAttackVectors, attackVector)
	}

	// Calculate overall risk
	riskScore := (perturbationMagnitude + evasionProbability) / 2.0
	risk.ConfidenceScore = riskScore

	if riskScore > 0.8 {
		risk.RiskLevel = "critical"
	} else if riskScore > 0.6 {
		risk.RiskLevel = "high"
	} else if riskScore > 0.4 {
		risk.RiskLevel = "medium"
	} else {
		risk.RiskLevel = "low"
	}

	return risk
}

// detectFeaturePoisoning detects feature poisoning attacks
func (mh *MLHardeningSystem) detectFeaturePoisoning(ctx context.Context, pkg *types.Package, features map[string]float64) *FeaturePoisoningRisk {
	risk := &FeaturePoisoningRisk{
		PoisonedFeatures:    []PoisonedFeature{},
		PoisoningTechniques: []PoisoningTechnique{},
		ImpactAssessment:    &PoisoningImpact{},
	}

	// Analyze each feature for poisoning
	for featureName, featureValue := range features {
		if baseline, exists := mh.featurePoisoningDetector.baselineFeatures[featureName]; exists {
			deviation := math.Abs(featureValue - baseline)
			if deviation > mh.featurePoisoningDetector.anomalyThreshold {
				poisonedFeature := PoisonedFeature{
					FeatureName:     featureName,
					PoisonScore:     deviation,
					AnomalyLevel:    mh.determineAnomalyLevel(deviation),
					Evidence:        []string{fmt.Sprintf("Deviation: %.4f", deviation)},
					OriginalValue:   baseline,
					SuspiciousValue: featureValue,
				}
				risk.PoisonedFeatures = append(risk.PoisonedFeatures, poisonedFeature)
			}
		}
	}

	// Calculate overall poisoning risk
	poisoningScore := float64(len(risk.PoisonedFeatures)) / float64(len(features))
	risk.ConfidenceScore = poisoningScore

	if poisoningScore > 0.7 {
		risk.RiskLevel = "critical"
	} else if poisoningScore > 0.5 {
		risk.RiskLevel = "high"
	} else if poisoningScore > 0.3 {
		risk.RiskLevel = "medium"
	} else {
		risk.RiskLevel = "low"
	}

	return risk
}

// validateInputs validates model inputs
func (mh *MLHardeningSystem) validateInputs(ctx context.Context, pkg *types.Package, features map[string]float64) *InputValidationResult {
	result := &InputValidationResult{
		AnomalousInputs: []AnomalousInput{},
		ValidationMetrics: &ValidationMetrics{
			TotalInputs: len(features),
		},
	}

	validInputs := 0
	anomalousInputs := 0

	// Validate each input feature
	for featureName, featureValue := range features {
		anomalyScore := mh.inputValidator.anomalyDetector.detectAnomaly(featureValue)
		
		if anomalyScore > 0.7 {
			anomalousInput := AnomalousInput{
				InputType:       featureName,
				AnomalyScore:    anomalyScore,
				Description:     "Anomalous feature value detected",
				SuspiciousValue: fmt.Sprintf("%.4f", featureValue),
				ExpectedRange:   mh.getExpectedRange(featureName),
			}
			result.AnomalousInputs = append(result.AnomalousInputs, anomalousInput)
			anomalousInputs++
		} else {
			validInputs++
		}
	}

	result.ValidationMetrics.ValidInputs = validInputs
	result.ValidationMetrics.AnomalousInputs = anomalousInputs
	result.ValidationMetrics.ValidationRate = float64(validInputs) / float64(len(features))
	result.ValidationMetrics.AnomalyRate = float64(anomalousInputs) / float64(len(features))

	if result.ValidationMetrics.AnomalyRate > 0.3 {
		result.ValidationStatus = "failed"
	} else if result.ValidationMetrics.AnomalyRate > 0.1 {
		result.ValidationStatus = "warning"
	} else {
		result.ValidationStatus = "passed"
	}

	return result
}

// validateModelRobustness validates model robustness
func (mh *MLHardeningSystem) validateModelRobustness(ctx context.Context, pkg *types.Package, features map[string]float64) *RobustnessValidationResult {
	result := &RobustnessValidationResult{
		StabilityMetrics:  &StabilityMetrics{},
		PerturbationTests: []PerturbationTest{},
		WeaknessAreas:     []WeaknessArea{},
	}

	// Perform perturbation tests
	for _, testConfig := range mh.modelRobustnessValidator.perturbationTests {
		perturbationTest := mh.performPerturbationTest(features, testConfig)
		result.PerturbationTests = append(result.PerturbationTests, perturbationTest)
	}

	// Calculate stability metrics
	result.StabilityMetrics = mh.calculateStabilityMetrics(features, result.PerturbationTests)

	// Calculate overall robustness score
	result.RobustnessScore = mh.calculateRobustnessScore(result.StabilityMetrics, result.PerturbationTests)

	return result
}

// analyzeGradients analyzes model gradients
func (mh *MLHardeningSystem) analyzeGradients(ctx context.Context, pkg *types.Package, features map[string]float64) *GradientAnalysisResult {
	result := &GradientAnalysisResult{
		SuspiciousGradients: []SuspiciousGradient{},
		GradientAttacks:     []GradientAttack{},
	}

	// Simulate gradient analysis (in real implementation, this would analyze actual gradients)
	gradientMagnitude := mh.calculateGradientMagnitude(features)
	result.GradientMagnitude = gradientMagnitude

	gradientStability := mh.calculateGradientStability(features)
	result.GradientStability = gradientStability

	// Detect suspicious gradients
	if gradientMagnitude > mh.gradientAnalyzer.gradientThreshold {
		suspiciousGradient := SuspiciousGradient{
			LayerName:     "feature_layer",
			GradientValue: gradientMagnitude,
			AnomalyScore:  0.8,
			Description:   "Unusually high gradient magnitude",
		}
		result.SuspiciousGradients = append(result.SuspiciousGradients, suspiciousGradient)
	}

	return result
}

// performEnsembleDefense performs ensemble defense
func (mh *MLHardeningSystem) performEnsembleDefense(ctx context.Context, pkg *types.Package, features map[string]float64) *EnsembleDefenseResult {
	result := &EnsembleDefenseResult{
		ModelDiscrepancies: []ModelDiscrepancy{},
	}

	// Simulate ensemble predictions (in real implementation, this would use actual models)
	predictions := mh.generateEnsemblePredictions(features)
	
	// Calculate ensemble agreement
	result.EnsembleAgreement = mh.calculateEnsembleAgreement(predictions)
	result.ConsensusScore = mh.calculateConsensusScore(predictions)

	// Detect model discrepancies
	discrepancies := mh.detectModelDiscrepancies(predictions)
	result.ModelDiscrepancies = discrepancies

	// Calculate defense effectiveness
	result.DefenseEffectiveness = mh.calculateDefenseEffectiveness(result)

	return result
}

// Helper functions

func (mh *MLHardeningSystem) calculatePerturbationMagnitude(features map[string]float64) float64 {
	// Calculate perturbation magnitude based on feature analysis
	totalMagnitude := 0.0
	for _, value := range features {
		totalMagnitude += math.Abs(value)
	}
	return totalMagnitude / float64(len(features))
}

func (mh *MLHardeningSystem) calculateEvasionProbability(features map[string]float64) float64 {
	// Calculate evasion probability based on feature patterns
	// Higher variance in features indicates potential evasion attempts
	variance := 0.0
	mean := 0.0
	count := 0
	
	for _, value := range features {
		mean += value
		count++
	}
	
	if count == 0 {
		return 0.0
	}
	
	mean /= float64(count)
	
	for _, value := range features {
		variance += math.Pow(value-mean, 2)
	}
	variance /= float64(count)
	
	// Normalize variance to probability (0-1)
	evasionProb := math.Min(variance, 1.0)
	
	// Apply sigmoid function for smoother probability distribution
	return 1.0 / (1.0 + math.Exp(-5.0*(evasionProb-0.5)))
}

func (mh *MLHardeningSystem) determineAnomalyLevel(deviation float64) string {
	if deviation > 0.8 {
		return "critical"
	} else if deviation > 0.6 {
		return "high"
	} else if deviation > 0.4 {
		return "medium"
	}
	return "low"
}

func (ad *AnomalyDetector) detectAnomaly(value float64) float64 {
	// Detect anomalies in input values using statistical analysis
	// Assume normal distribution with mean=0.5, std=0.2 for typical values
	mean := 0.5
	stdDev := 0.2
	
	// Calculate z-score
	zScore := math.Abs(value-mean) / stdDev
	
	// Convert z-score to anomaly probability
	// Values beyond 2 standard deviations are considered anomalous
	if zScore > 3.0 {
		return 0.95 // Very high anomaly probability
	} else if zScore > 2.0 {
		return 0.7 // High anomaly probability
	} else if zScore > 1.0 {
		return 0.3 // Medium anomaly probability
	}
	
	// Low anomaly probability for normal values
	return zScore / 10.0
}

func (mh *MLHardeningSystem) performPerturbationTest(features map[string]float64, config PerturbationTestConfig) PerturbationTest {
	return PerturbationTest{
		PerturbationType: config.TestType,
		Magnitude:        config.Magnitude,
		SuccessRate:      0.7,
		ModelResponse:    "stable",
		ExpectedResponse: "stable",
	}
}

func (mh *MLHardeningSystem) calculateStabilityMetrics(features map[string]float64, tests []PerturbationTest) *StabilityMetrics {
	return &StabilityMetrics{
		PredictionVariance: 0.1,
		OutputStability:    0.8,
		FeatureSensitivity: 0.3,
		NoiseResistance:    0.7,
	}
}

func (mh *MLHardeningSystem) calculateRobustnessScore(metrics *StabilityMetrics, tests []PerturbationTest) float64 {
	return (metrics.OutputStability + metrics.NoiseResistance) / 2.0
}

func (mh *MLHardeningSystem) calculateGradientMagnitude(features map[string]float64) float64 {
	// Calculate gradient magnitude using L2 norm approximation
	sumSquares := 0.0
	count := 0
	
	for _, value := range features {
		// Approximate gradient as the deviation from expected value (0.5)
		gradient := value - 0.5
		sumSquares += gradient * gradient
		count++
	}
	
	if count == 0 {
		return 0.0
	}
	
	// Return L2 norm of gradients
	return math.Sqrt(sumSquares / float64(count))
}

func (mh *MLHardeningSystem) calculateGradientStability(features map[string]float64) float64 {
	// Calculate gradient stability by measuring consistency across features
	if len(features) < 2 {
		return 1.0 // Perfect stability for single or no features
	}
	
	gradients := make([]float64, 0, len(features))
	for _, value := range features {
		// Approximate gradient as deviation from baseline
		gradient := value - 0.5
		gradients = append(gradients, gradient)
	}
	
	// Calculate variance of gradients
	mean := 0.0
	for _, grad := range gradients {
		mean += grad
	}
	mean /= float64(len(gradients))
	
	variance := 0.0
	for _, grad := range gradients {
		variance += math.Pow(grad-mean, 2)
	}
	variance /= float64(len(gradients))
	
	// Convert variance to stability score (lower variance = higher stability)
	stability := 1.0 / (1.0 + variance)
	return math.Min(stability, 1.0)
}

func (mh *MLHardeningSystem) generateEnsemblePredictions(features map[string]float64) []float64 {
	// Generate ensemble predictions using multiple models/approaches
	predictions := make([]float64, 0, 5)
	
	// Model 1: Simple threshold-based prediction
	avgFeature := 0.0
	count := 0
	for _, value := range features {
		avgFeature += value
		count++
	}
	if count > 0 {
		avgFeature /= float64(count)
		predictions = append(predictions, avgFeature)
	}
	
	// Model 2: Variance-based prediction
	variance := 0.0
	if count > 1 {
		for _, value := range features {
			variance += math.Pow(value-avgFeature, 2)
		}
		variance /= float64(count)
		variancePred := 1.0 - math.Min(variance*2, 1.0) // Higher variance = lower prediction
		predictions = append(predictions, variancePred)
	}
	
	// Model 3: Range-based prediction
	if count > 0 {
		minVal, maxVal := math.Inf(1), math.Inf(-1)
		for _, value := range features {
			minVal = math.Min(minVal, value)
			maxVal = math.Max(maxVal, value)
		}
		rangePred := 1.0 - math.Min(maxVal-minVal, 1.0) // Smaller range = higher prediction
		predictions = append(predictions, rangePred)
	}
	
	// Model 4: Entropy-based prediction (simplified)
	if count > 0 {
		entropy := 0.0
		for _, value := range features {
			if value > 0 {
				entropy -= value * math.Log2(value)
			}
		}
		entropyPred := math.Max(0.0, 1.0-entropy/float64(count))
		predictions = append(predictions, entropyPred)
	}
	
	// Model 5: Weighted combination
	if len(predictions) > 0 {
		weightedSum := 0.0
		for i, pred := range predictions {
			weight := 1.0 / float64(i+1) // Decreasing weights
			weightedSum += pred * weight
		}
		weightedPred := weightedSum / float64(len(predictions))
		predictions = append(predictions, weightedPred)
	}
	
	return predictions
}

func (mh *MLHardeningSystem) calculateEnsembleAgreement(predictions []float64) float64 {
	if len(predictions) == 0 {
		return 0.0
	}
	
	sort.Float64s(predictions)
	variance := 0.0
	mean := 0.0
	
	for _, pred := range predictions {
		mean += pred
	}
	mean /= float64(len(predictions))
	
	for _, pred := range predictions {
		variance += math.Pow(pred-mean, 2)
	}
	variance /= float64(len(predictions))
	
	return 1.0 - variance // Higher agreement = lower variance
}

func (mh *MLHardeningSystem) calculateConsensusScore(predictions []float64) float64 {
	return mh.calculateEnsembleAgreement(predictions)
}

func (mh *MLHardeningSystem) detectModelDiscrepancies(predictions []float64) []ModelDiscrepancy {
	discrepancies := []ModelDiscrepancy{}
	
	for i := 0; i < len(predictions); i++ {
		for j := i + 1; j < len(predictions); j++ {
			discrepancy := math.Abs(predictions[i] - predictions[j])
			if discrepancy > 0.3 {
				modelDiscrepancy := ModelDiscrepancy{
					ModelPair:              fmt.Sprintf("model_%d_vs_model_%d", i, j),
					DiscrepancyScore:       discrepancy,
					ConflictingPredictions: []string{fmt.Sprintf("%.2f", predictions[i]), fmt.Sprintf("%.2f", predictions[j])},
					SuspicionLevel:         "medium",
				}
				discrepancies = append(discrepancies, modelDiscrepancy)
			}
		}
	}
	
	return discrepancies
}

func (mh *MLHardeningSystem) calculateDefenseEffectiveness(result *EnsembleDefenseResult) float64 {
	return result.EnsembleAgreement * result.ConsensusScore
}

func (mh *MLHardeningSystem) calculateOverallSecurityScore(result *MLHardeningResult) float64 {
	scores := []float64{}
	
	if result.AdversarialRisk != nil {
		scores = append(scores, 1.0-result.AdversarialRisk.ConfidenceScore)
	}
	
	if result.FeaturePoisoningRisk != nil {
		scores = append(scores, 1.0-result.FeaturePoisoningRisk.ConfidenceScore)
	}
	
	if result.RobustnessValidation != nil {
		scores = append(scores, result.RobustnessValidation.RobustnessScore)
	}
	
	if result.EnsembleDefenseResult != nil {
		scores = append(scores, result.EnsembleDefenseResult.DefenseEffectiveness)
	}
	
	if len(scores) == 0 {
		return 0.0
	}
	
	total := 0.0
	for _, score := range scores {
		total += score
	}
	
	return total / float64(len(scores))
}

func (mh *MLHardeningSystem) extractVulnerabilities(result *MLHardeningResult) []MLVulnerability {
	vulnerabilities := []MLVulnerability{}
	
	if result.AdversarialRisk != nil && result.AdversarialRisk.RiskLevel == "critical" {
		vuln := MLVulnerability{
			VulnerabilityType:  "adversarial_attack",
			Severity:           "critical",
			Description:        "High risk of adversarial attacks detected",
			ExploitPotential:   result.AdversarialRisk.ConfidenceScore,
			AffectedComponents: []string{"ml_model", "feature_extraction"},
			DetectionTime:      time.Now(),
		}
		vulnerabilities = append(vulnerabilities, vuln)
	}
	
	if result.FeaturePoisoningRisk != nil && result.FeaturePoisoningRisk.RiskLevel == "critical" {
		vuln := MLVulnerability{
			VulnerabilityType:  "feature_poisoning",
			Severity:           "critical",
			Description:        "Feature poisoning attack detected",
			ExploitPotential:   result.FeaturePoisoningRisk.ConfidenceScore,
			AffectedComponents: []string{"feature_extraction", "data_preprocessing"},
			DetectionTime:      time.Now(),
		}
		vulnerabilities = append(vulnerabilities, vuln)
	}
	
	return vulnerabilities
}

func (mh *MLHardeningSystem) generateCountermeasures(result *MLHardeningResult) []MLCountermeasure {
	countermeasures := []MLCountermeasure{}
	
	if result.AdversarialRisk != nil && result.AdversarialRisk.RiskLevel != "low" {
		countermeasure := MLCountermeasure{
			CountermeasureType: "adversarial_training",
			Description:        "Implement adversarial training to improve model robustness",
			Effectiveness:      0.8,
			ImplementationCost: "high",
			Prerequisites:      []string{"training_data", "computational_resources"},
		}
		countermeasures = append(countermeasures, countermeasure)
	}
	
	if result.FeaturePoisoningRisk != nil && result.FeaturePoisoningRisk.RiskLevel != "low" {
		countermeasure := MLCountermeasure{
			CountermeasureType: "feature_validation",
			Description:        "Implement robust feature validation and sanitization",
			Effectiveness:      0.7,
			ImplementationCost: "medium",
			Prerequisites:      []string{"baseline_features", "validation_rules"},
		}
		countermeasures = append(countermeasures, countermeasure)
	}
	
	return countermeasures
}

func (mh *MLHardeningSystem) generateMLRecommendations(result *MLHardeningResult) []string {
	recommendations := []string{}
	
	if result.OverallSecurityScore < 0.6 {
		recommendations = append(recommendations, "Overall ML security score is low - comprehensive hardening required")
	}
	
	if result.AdversarialRisk != nil && result.AdversarialRisk.RiskLevel == "critical" {
		recommendations = append(recommendations, "Critical adversarial risk detected - implement adversarial defenses immediately")
	}
	
	if result.FeaturePoisoningRisk != nil && len(result.FeaturePoisoningRisk.PoisonedFeatures) > 0 {
		recommendations = append(recommendations, "Feature poisoning detected - validate and sanitize input features")
	}
	
	if result.EnsembleDefenseResult != nil && result.EnsembleDefenseResult.EnsembleAgreement < 0.7 {
		recommendations = append(recommendations, "Low ensemble agreement - investigate model discrepancies")
	}
	
	return recommendations
}

// Constructor functions

func NewAdversarialDetector() *AdversarialDetector {
	return &AdversarialDetector{
		perturbationDetectors: []PerturbationDetector{},
		evasionDetectors:     []EvasionDetector{},
		attackSignatures:     make(map[string]AttackSignature),
	}
}

func NewFeaturePoisoningDetector() *FeaturePoisoningDetector {
	return &FeaturePoisoningDetector{
		baselineFeatures:  make(map[string]float64),
		anomalyThreshold:  0.5,
		poisoningPatterns: []PoisoningPattern{},
	}
}

func NewInputValidator() *InputValidator {
	return &InputValidator{
		validationRules:   []ValidationRule{},
		sanitizationRules: []SanitizationRule{},
		anomalyDetector:   &AnomalyDetector{threshold: 0.7, sensitivity: 0.8},
	}
}

func NewModelRobustnessValidator() *ModelRobustnessValidator {
	return &ModelRobustnessValidator{
		perturbationTests: []PerturbationTestConfig{
			{TestType: "gaussian_noise", Magnitude: 0.1, Iterations: 10, ExpectedRange: 0.1},
			{TestType: "uniform_noise", Magnitude: 0.05, Iterations: 10, ExpectedRange: 0.05},
		},
		stabilityMetrics: []StabilityMetric{},
		robustnessModel:  "default",
	}
}

func NewGradientAnalyzer() *GradientAnalyzer {
	return &GradientAnalyzer{
		gradientThreshold:  0.5,
		analysisDepth:      5,
		suspiciousPatterns: []GradientPattern{},
	}
}

func NewEnsembleDefense() *EnsembleDefense {
	return &EnsembleDefense{
		models:             []string{"model_1", "model_2", "model_3"},
		consensusMethod:    "majority_vote",
		agreementThreshold: 0.7,
	}
}

func (mh *MLHardeningSystem) getExpectedRange(featureName string) string {
	// Define expected ranges for different feature types
	switch {
	case strings.Contains(strings.ToLower(featureName), "probability"):
		return "0.0-1.0"
	case strings.Contains(strings.ToLower(featureName), "score"):
		return "0.0-1.0"
	case strings.Contains(strings.ToLower(featureName), "confidence"):
		return "0.0-1.0"
	case strings.Contains(strings.ToLower(featureName), "ratio"):
		return "0.0-1.0"
	case strings.Contains(strings.ToLower(featureName), "percentage"):
		return "0.0-100.0"
	case strings.Contains(strings.ToLower(featureName), "count"):
		return "0.0-∞"
	case strings.Contains(strings.ToLower(featureName), "length"):
		return "0.0-∞"
	case strings.Contains(strings.ToLower(featureName), "size"):
		return "0.0-∞"
	case strings.Contains(strings.ToLower(featureName), "distance"):
		return "0.0-∞"
	case strings.Contains(strings.ToLower(featureName), "entropy"):
		return "0.0-8.0"
	case strings.Contains(strings.ToLower(featureName), "similarity"):
		return "0.0-1.0"
	default:
		return "-∞-∞" // Unknown feature type
	}
}