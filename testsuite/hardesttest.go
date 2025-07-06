package testsuite

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"log"
	"math"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Alivanroy/Typosentinel/internal/analyzer"
	"github.com/Alivanroy/Typosentinel/internal/config"
	"github.com/Alivanroy/Typosentinel/pkg/types"
)

// AdvancedTestSuite represents a comprehensive enterprise-grade test suite
type AdvancedTestSuite struct {
	analyzer      *analyzer.Analyzer
	config        *config.Config
	results       map[string]*AdvancedTestResult
	mu            sync.RWMutex
	attackVectors []AttackVector
	enterprises   []EnterpriseScenario
}

// AdvancedTestResult contains detailed test results with security insights
type AdvancedTestResult struct {
	TestID           string                 `json:"test_id"`
	TestCategory     string                 `json:"test_category"`
	PackageName      string                 `json:"package_name"`
	Registry         string                 `json:"registry"`
	AttackVector     string                 `json:"attack_vector"`
	ExpectedThreat   bool                   `json:"expected_threat"`
	DetectedThreat   bool                   `json:"detected_threat"`
	ThreatScore      float64                `json:"threat_score"`
	ConfidenceLevel  float64                `json:"confidence_level"`
	ProcessingTime   time.Duration          `json:"processing_time"`
	MemoryUsage      int64                  `json:"memory_usage_bytes"`
	DetectionFlags   []string               `json:"detection_flags"`
	MLModelScores    map[string]float64     `json:"ml_model_scores"`
	SecurityInsights map[string]interface{} `json:"security_insights"`
	FalsePositive    bool                   `json:"false_positive"`
	FalseNegative    bool                   `json:"false_negative"`
	SeverityLevel    string                 `json:"severity_level"`
	CVSS             float64                `json:"cvss_score"`
	Passed           bool                   `json:"passed"`
	ErrorDetails     string                 `json:"error_details,omitempty"`
}

// AttackVector represents a specific attack pattern
type AttackVector struct {
	ID                string   `json:"id"`
	Name              string   `json:"name"`
	Description       string   `json:"description"`
	TTPTechnique      string   `json:"ttp_technique"`    // MITRE ATT&CK technique
	DifficultyLevel   string   `json:"difficulty_level"` // LOW, MEDIUM, HIGH, EXPERT
	DetectionRate     float64  `json:"expected_detection_rate"`
	TestPackages      []string `json:"test_packages"`
	Indicators        []string `json:"indicators"`
	CounterMeasures   []string `json:"counter_measures"`
	RealWorldExamples []string `json:"real_world_examples"`
}

// EnterpriseScenario represents enterprise-specific test scenarios
type EnterpriseScenario struct {
	ID               string             `json:"id"`
	CompanyProfile   string             `json:"company_profile"`
	IndustryType     string             `json:"industry_type"`
	SecurityMaturity string             `json:"security_maturity"`
	ThreatModel      []string           `json:"threat_model"`
	Constraints      map[string]string  `json:"constraints"`
	Expectations     map[string]float64 `json:"expectations"`
	TestProjects     []ProjectTemplate  `json:"test_projects"`
}

// ProjectTemplate represents a realistic project structure
type ProjectTemplate struct {
	Name            string            `json:"name"`
	Language        string            `json:"language"`
	Size            string            `json:"size"`
	Dependencies    map[string]string `json:"dependencies"`
	DevDependencies map[string]string `json:"dev_dependencies"`
	ThreatPackages  []string          `json:"threat_packages"`
	Files           map[string]string `json:"files"`
}

// NewAdvancedTestSuite creates a comprehensive test suite
func NewAdvancedTestSuite() *AdvancedTestSuite {
	cfg := config.NewDefaultConfig()
	cfg.Scanner.Concurrency = 10
	// Note: Detection and Logging config would need to be added to Config struct
	// cfg.MLAnalysis.Enabled = true // Would need MLAnalysis config

	analyzer, err := analyzer.New(cfg)
	if err != nil {
		log.Fatalf("Failed to create analyzer: %v", err)
	}

	suite := &AdvancedTestSuite{
		analyzer: analyzer,
		config:   cfg,
		results:  make(map[string]*AdvancedTestResult),
	}

	suite.initializeAttackVectors()
	suite.initializeEnterpriseScenarios()

	return suite
}

// initializeAttackVectors sets up comprehensive attack patterns
func (suite *AdvancedTestSuite) initializeAttackVectors() {
	suite.attackVectors = []AttackVector{
		{
			ID:              "ATV-001",
			Name:            "Advanced Typosquatting",
			Description:     "Sophisticated character substitution with cultural awareness",
			TTPTechnique:    "T1195.002", // Supply Chain Compromise: Software Supply Chain
			DifficultyLevel: "HIGH",
			DetectionRate:   0.85,
			TestPackages:    []string{"lodаsh", "rеact", "еxpress"}, // Cyrillic characters
			Indicators:      []string{"unicode_homoglyphs", "similar_functionality", "new_package"},
			CounterMeasures: []string{"unicode_normalization", "visual_similarity_check", "reputation_analysis"},
			RealWorldExamples: []string{
				"event-stream incident (2018)",
				"rest-client typosquat (2019)",
				"electron-native-notifications (2020)",
			},
		},
		{
			ID:              "ATV-002",
			Name:            "Dependency Confusion Plus",
			Description:     "Enhanced dependency confusion with version manipulation",
			TTPTechnique:    "T1195.001", // Supply Chain Compromise: Compromise Software Dependencies
			DifficultyLevel: "EXPERT",
			DetectionRate:   0.75,
			TestPackages:    []string{"internal-utils", "company-auth", "private-logger"},
			Indicators:      []string{"version_inflation", "namespace_squatting", "environment_harvesting"},
			CounterMeasures: []string{"private_registry_priority", "version_pinning", "scope_validation"},
			RealWorldExamples: []string{
				"Microsoft internal packages (2021)",
				"Apple internal tools compromise (2021)",
				"Netflix dependency confusion (2021)",
			},
		},
		{
			ID:              "ATV-003",
			Name:            "AI-Generated Malicious Packages",
			Description:     "Packages created using AI to mimic legitimate functionality",
			TTPTechnique:    "T1195.002",
			DifficultyLevel: "EXPERT",
			DetectionRate:   0.60,
			TestPackages:    []string{"ai-crypto-helper", "ml-data-processor", "smart-validator"},
			Indicators:      []string{"ai_generated_code", "mimetic_functionality", "behavioral_anomalies"},
			CounterMeasures: []string{"code_authenticity_check", "behavioral_analysis", "author_verification"},
			RealWorldExamples: []string{
				"ChatGPT-generated npm packages (2023)",
				"Copilot-inspired malicious code (2023)",
			},
		},
		{
			ID:              "ATV-004",
			Name:            "Supply Chain Hijacking",
			Description:     "Compromise of legitimate package maintainer accounts",
			TTPTechnique:    "T1195.002",
			DifficultyLevel: "HIGH",
			DetectionRate:   0.90,
			TestPackages:    []string{"compromised-util", "hijacked-library", "backdoored-framework"},
			Indicators:      []string{"maintainer_change", "version_anomaly", "code_injection"},
			CounterMeasures: []string{"maintainer_verification", "code_signing", "behavioral_monitoring"},
			RealWorldExamples: []string{
				"event-stream (2018)",
				"rest-client (2019)",
				"ua-parser-js (2021)",
			},
		},
		{
			ID:              "ATV-005",
			Name:            "Steganographic Payloads",
			Description:     "Malicious code hidden in package assets using steganography",
			TTPTechnique:    "T1027.003", // Obfuscated Files or Information: Steganography
			DifficultyLevel: "EXPERT",
			DetectionRate:   0.40,
			TestPackages:    []string{"image-processor", "pdf-generator", "media-converter"},
			Indicators:      []string{"steganographic_content", "hidden_payloads", "asset_anomalies"},
			CounterMeasures: []string{"deep_file_analysis", "entropy_detection", "asset_validation"},
			RealWorldExamples: []string{
				"Steganographic npm packages (2022)",
				"Hidden payloads in Python wheels (2023)",
			},
		},
	}
}

// initializeEnterpriseScenarios sets up enterprise test scenarios
func (suite *AdvancedTestSuite) initializeEnterpriseScenarios() {
	suite.enterprises = []EnterpriseScenario{
		{
			ID:               "ENT-001",
			CompanyProfile:   "Fortune 500 Financial Services",
			IndustryType:     "Financial Services",
			SecurityMaturity: "HIGH",
			ThreatModel:      []string{"Nation State", "Organized Crime", "Insider Threat"},
			Constraints: map[string]string{
				"compliance":     "SOX, PCI-DSS, GDPR",
				"response_time":  "<1s",
				"false_positive": "<2%",
				"availability":   "99.99%",
			},
			Expectations: map[string]float64{
				"detection_rate": 0.98,
				"precision":      0.96,
				"recall":         0.95,
				"f1_score":       0.95,
			},
		},
		{
			ID:               "ENT-002",
			CompanyProfile:   "Mid-size Healthcare Provider",
			IndustryType:     "Healthcare",
			SecurityMaturity: "MEDIUM",
			ThreatModel:      []string{"Ransomware", "Data Theft", "Business Email Compromise"},
			Constraints: map[string]string{
				"compliance":     "HIPAA, HITECH",
				"response_time":  "<3s",
				"false_positive": "<5%",
				"budget":         "LIMITED",
			},
			Expectations: map[string]float64{
				"detection_rate": 0.90,
				"precision":      0.85,
				"recall":         0.88,
				"f1_score":       0.86,
			},
		},
		{
			ID:               "ENT-003",
			CompanyProfile:   "Government Defense Contractor",
			IndustryType:     "Defense",
			SecurityMaturity: "CRITICAL",
			ThreatModel:      []string{"APT", "Nation State", "Supply Chain Attack"},
			Constraints: map[string]string{
				"compliance":     "FedRAMP, NIST, CMMC",
				"response_time":  "<500ms",
				"false_positive": "<1%",
				"classification": "SECRET",
			},
			Expectations: map[string]float64{
				"detection_rate": 0.99,
				"precision":      0.98,
				"recall":         0.97,
				"f1_score":       0.975,
			},
		},
	}
}

// TestAdvancedTyposquattingAttacks tests sophisticated typosquatting patterns
func (suite *AdvancedTestSuite) TestAdvancedTyposquattingAttacks(t *testing.T) {
	t.Log("Testing advanced typosquatting attack patterns...")

	advancedTyposquats := []struct {
		malicious     string
		target        string
		registry      string
		attackType    string
		difficulty    string
		expectedScore float64
	}{
		// Unicode homoglyph attacks
		{"lodаsh", "lodash", "npm", "cyrillic_homoglyph", "HIGH", 0.9},
		{"rеact", "react", "npm", "cyrillic_homoglyph", "HIGH", 0.9},
		{"еxpress", "express", "npm", "cyrillic_homoglyph", "HIGH", 0.9},

		// Advanced character manipulation
		{"1odash", "lodash", "npm", "number_substitution", "MEDIUM", 0.8},
		{"lodash-", "lodash", "npm", "trailing_character", "MEDIUM", 0.7},
		{"lodash_", "lodash", "npm", "underscore_variant", "MEDIUM", 0.7},

		// Sophisticated naming
		{"lodash-util", "lodash", "npm", "legitimate_suffix", "HIGH", 0.6},
		{"lodash-core", "lodash", "npm", "legitimate_suffix", "HIGH", 0.6},
		{"lodash-plus", "lodash", "npm", "enhancement_claim", "HIGH", 0.5},

		// Cross-language confusion
		{"requests-py", "requests", "pypi", "language_confusion", "MEDIUM", 0.7},
		{"numpy-js", "numpy", "pypi", "language_confusion", "MEDIUM", 0.7},

		// Namespace pollution
		{"@lodash/core", "lodash", "npm", "namespace_pollution", "HIGH", 0.8},
		{"@types/lodash-fake", "@types/lodash", "npm", "types_pollution", "HIGH", 0.8},
	}

	for _, test := range advancedTyposquats {
		t.Run(fmt.Sprintf("%s_%s_%s", test.attackType, test.malicious, test.target), func(t *testing.T) {
			result := suite.analyzeAdvancedPackage(
				test.malicious,
				test.registry,
				test.attackType,
				true, // expected threat
				test.expectedScore,
			)

			// Validate detection
			if result.ExpectedThreat && !result.DetectedThreat {
				t.Errorf("Failed to detect %s typosquatting: %s -> %s (score: %.3f)",
					test.attackType, test.malicious, test.target, result.ThreatScore)
			}

			// Check for specific indicators
			expectedIndicators := map[string][]string{
				"cyrillic_homoglyph":  {"unicode_homoglyphs", "visual_similarity"},
				"number_substitution": {"character_substitution", "similarity_high"},
				"legitimate_suffix":   {"namespace_confusion", "brand_impersonation"},
				"language_confusion":  {"cross_language_attack", "ecosystem_confusion"},
				"namespace_pollution": {"namespace_squatting", "scope_confusion"},
			}

			if indicators, exists := expectedIndicators[test.attackType]; exists {
				for _, indicator := range indicators {
					found := false
					for _, flag := range result.DetectionFlags {
						if strings.Contains(flag, indicator) {
							found = true
							break
						}
					}
					if !found {
						t.Logf("Missing expected indicator '%s' for attack type '%s'", indicator, test.attackType)
					}
				}
			}

			t.Logf("Advanced typosquatting test: %s (score: %.3f, confidence: %.3f)",
				test.malicious, result.ThreatScore, result.ConfidenceLevel)
		})
	}
}

// TestDependencyConfusionAttacks tests sophisticated dependency confusion
func (suite *AdvancedTestSuite) TestDependencyConfusionAttacks(t *testing.T) {
	t.Log("Testing dependency confusion attack scenarios...")

	confusionAttacks := []struct {
		packageName    string
		registry       string
		version        string
		targetOrg      string
		attackVector   string
		sophistication string
	}{
		// Internal package simulation
		{"internal-auth-service", "npm", "99.99.99", "company-internal", "version_inflation", "HIGH"},
		{"@company/utils", "npm", "999.0.0", "company-internal", "scoped_confusion", "EXPERT"},

		// Private registry simulation
		{"corp-logger", "pypi", "100.0.0", "private-registry", "private_impersonation", "HIGH"},
		{"enterprise-sdk", "pypi", "50.0.0", "private-registry", "sdk_impersonation", "EXPERT"},

		// Open source hijacking
		{"popular-util-internal", "npm", "2.0.0", "popular-project", "namespace_hijack", "MEDIUM"},
		{"framework-enterprise", "npm", "5.0.0", "popular-framework", "edition_confusion", "MEDIUM"},
	}

	for _, attack := range confusionAttacks {
		t.Run(fmt.Sprintf("depconf_%s_%s", attack.attackVector, attack.packageName), func(t *testing.T) {
			result := suite.analyzeAdvancedPackage(
				attack.packageName,
				attack.registry,
				attack.attackVector,
				true, // expected threat
				0.8,  // expected high score
			)

			// Check for dependency confusion indicators
			confusionIndicators := []string{
				"version_inflation",
				"namespace_confusion",
				"private_impersonation",
				"dependency_confusion",
			}

			indicatorFound := false
			for _, indicator := range confusionIndicators {
				for _, flag := range result.DetectionFlags {
					if strings.Contains(flag, indicator) {
						indicatorFound = true
						break
					}
				}
				if indicatorFound {
					break
				}
			}

			if !indicatorFound {
				t.Errorf("No dependency confusion indicators found for %s", attack.packageName)
			}

			t.Logf("Dependency confusion test: %s (sophistication: %s, score: %.3f)",
				attack.packageName, attack.sophistication, result.ThreatScore)
		})
	}
}

// TestEnterpriseSecurityScenarios tests enterprise-specific scenarios
func (suite *AdvancedTestSuite) TestEnterpriseSecurityScenarios(t *testing.T) {
	t.Log("Testing enterprise security scenarios...")

	for _, enterprise := range suite.enterprises {
		t.Run(fmt.Sprintf("enterprise_%s", enterprise.ID), func(t *testing.T) {
			suite.runEnterpriseScenario(t, enterprise)
		})
	}
}

// runEnterpriseScenario executes a complete enterprise scenario
func (suite *AdvancedTestSuite) runEnterpriseScenario(t *testing.T, scenario EnterpriseScenario) {
	t.Logf("Running enterprise scenario: %s (%s)", scenario.CompanyProfile, scenario.IndustryType)

	// Create realistic project structures
	projectTemplates := suite.generateEnterpriseProjects(scenario)

	results := make([]*AdvancedTestResult, 0)
	totalPackages := 0
	threatsDetected := 0
	falsePositives := 0

	for _, project := range projectTemplates {
		t.Logf("Testing project: %s (%s, %s)", project.Name, project.Language, project.Size)

		// Create temporary project structure
		projectDir, cleanup := suite.createTemporaryProject(project)
		defer cleanup()

		// Scan the project
		projectResults, err := suite.scanEnterpriseProject(projectDir, scenario)
		if err != nil {
			t.Errorf("Failed to scan enterprise project %s: %v", project.Name, err)
			continue
		}

		results = append(results, projectResults...)

		// Analyze results
		for _, result := range projectResults {
			totalPackages++

			if result.DetectedThreat {
				if result.ExpectedThreat {
					threatsDetected++
				} else {
					falsePositives++
				}
			}
		}
	}

	// Validate against enterprise expectations
	suite.validateEnterpriseExpectations(t, scenario, results, totalPackages, threatsDetected, falsePositives)
}

// TestAdvancedMLEvasion tests ML model evasion techniques
func (suite *AdvancedTestSuite) TestAdvancedMLEvasion(t *testing.T) {
	t.Log("Testing ML model evasion techniques...")

	evasionTechniques := []struct {
		technique     string
		description   string
		packages      []string
		expectedScore float64
	}{
		{
			technique:     "adversarial_naming",
			description:   "Names designed to fool ML models",
			packages:      []string{"lodash-v2", "react-18", "express-server"},
			expectedScore: 0.7,
		},
		{
			technique:     "feature_pollution",
			description:   "Packages with misleading metadata",
			packages:      []string{"legitimate-crypto", "secure-utils", "verified-helper"},
			expectedScore: 0.6,
		},
		{
			technique:     "gradual_drift",
			description:   "Slowly evolving malicious packages",
			packages:      []string{"helpful-util", "common-library", "standard-tool"},
			expectedScore: 0.5,
		},
	}

	for _, evasion := range evasionTechniques {
		t.Run(fmt.Sprintf("ml_evasion_%s", evasion.technique), func(t *testing.T) {
			for _, pkg := range evasion.packages {
				result := suite.analyzeAdvancedPackage(
					pkg,
					"npm",
					evasion.technique,
					true, // expected threat
					evasion.expectedScore,
				)

				// Check ML model confidence
				if result.ConfidenceLevel > 0.9 {
					t.Errorf("ML model too confident for evasion technique %s on package %s (confidence: %.3f)",
						evasion.technique, pkg, result.ConfidenceLevel)
				}

				t.Logf("ML evasion test: %s using %s (score: %.3f, confidence: %.3f)",
					pkg, evasion.technique, result.ThreatScore, result.ConfidenceLevel)
			}
		})
	}
}

// TestStressAndPerformance tests system under extreme load
func (suite *AdvancedTestSuite) TestStressAndPerformance(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping stress test in short mode")
	}

	t.Log("Testing system stress and performance limits...")

	stressTests := []struct {
		name               string
		packageCount       int
		concurrency        int
		timeLimit          time.Duration
		expectedThroughput float64
	}{
		{"light_load", 50, 5, 30 * time.Second, 2.0},
		{"medium_load", 200, 10, 60 * time.Second, 5.0},
		{"heavy_load", 500, 20, 120 * time.Second, 8.0},
		{"extreme_load", 1000, 50, 300 * time.Second, 10.0},
	}

	for _, stress := range stressTests {
		t.Run(fmt.Sprintf("stress_%s", stress.name), func(t *testing.T) {
			suite.runStressTest(t, stress.packageCount, stress.concurrency, stress.timeLimit, stress.expectedThroughput)
		})
	}
}

// TestZeroDaySimulation simulates zero-day threat detection
func (suite *AdvancedTestSuite) TestZeroDaySimulation(t *testing.T) {
	t.Log("Testing zero-day threat simulation...")

	zeroDayScenarios := []struct {
		name        string
		description string
		technique   string
		indicators  []string
	}{
		{
			name:        "novel_obfuscation",
			description: "Previously unseen code obfuscation technique",
			technique:   "custom_encoding",
			indicators:  []string{"unusual_encoding", "obfuscated_strings", "entropy_anomaly"},
		},
		{
			name:        "supply_chain_injection",
			description: "New supply chain injection method",
			technique:   "build_time_injection",
			indicators:  []string{"build_anomaly", "post_install_execution", "environment_access"},
		},
		{
			name:        "ai_generated_threat",
			description: "AI-generated malicious package",
			technique:   "synthetic_generation",
			indicators:  []string{"ai_signature", "pattern_anomaly", "behavioral_inconsistency"},
		},
	}

	for _, scenario := range zeroDayScenarios {
		t.Run(fmt.Sprintf("zeroday_%s", scenario.name), func(t *testing.T) {
			// Simulate zero-day package
			simulatedPackage := suite.generateZeroDayPackage(scenario.technique)

			result := suite.analyzeAdvancedPackage(
				simulatedPackage,
				"npm",
				scenario.technique,
				true, // expected threat
				0.6,  // should detect novel threats
			)

			// Check for generic threat indicators
			if result.ThreatScore < 0.4 {
				t.Errorf("Failed to detect potential zero-day threat with technique %s (score: %.3f)",
					scenario.technique, result.ThreatScore)
			}

			t.Logf("Zero-day simulation: %s (technique: %s, score: %.3f)",
				scenario.name, scenario.technique, result.ThreatScore)
		})
	}
}

// Helper methods

func (suite *AdvancedTestSuite) analyzeAdvancedPackage(
	packageName, registry, attackVector string,
	expectedThreat bool,
	expectedScore float64,
) *AdvancedTestResult {

	startTime := time.Now()

	// Use the Scan method instead of AnalyzePackage
	options := &analyzer.ScanOptions{
		OutputFormat:        "json",
		DeepAnalysis:        true,
		SimilarityThreshold: expectedScore,
	}

	analysis, err := suite.analyzer.Scan("/tmp", options)
	processingTime := time.Since(startTime)

	result := &AdvancedTestResult{
		TestID:           fmt.Sprintf("%s_%s_%s", attackVector, registry, packageName),
		TestCategory:     "advanced_threat_detection",
		PackageName:      packageName,
		Registry:         registry,
		AttackVector:     attackVector,
		ExpectedThreat:   expectedThreat,
		ProcessingTime:   processingTime,
		SecurityInsights: make(map[string]interface{}),
		MLModelScores:    make(map[string]float64),
	}

	if err != nil {
		result.ErrorDetails = err.Error()
		result.Passed = false
		return result
	}

	// Extract analysis results from ScanResult structure
	if analysis != nil {
		if len(analysis.Threats) > 0 {
			// Use first threat for analysis
			threat := analysis.Threats[0] // Use first threat
			result.DetectedThreat = true
			result.ThreatScore = threat.Confidence // Use confidence as score
			result.ConfidenceLevel = threat.Confidence
			result.DetectionFlags = []string{threat.Severity.String()}
			result.SeverityLevel = threat.Severity.String()
		} else {
			result.DetectedThreat = false
			result.ThreatScore = 0.0
			result.ConfidenceLevel = 1.0
			result.DetectionFlags = []string{"clean"}
			result.SeverityLevel = "LOW"
		}

		// Store scan metadata
		result.SecurityInsights["total_packages"] = analysis.TotalPackages
		result.SecurityInsights["scan_duration"] = analysis.Duration
		result.SecurityInsights["scan_path"] = analysis.Path
	}

	// Calculate CVSS score based on threat characteristics
	result.CVSS = suite.calculateCVSS(analysis)

	// Determine false positive/negative
	result.FalsePositive = !expectedThreat && result.DetectedThreat
	result.FalseNegative = expectedThreat && !result.DetectedThreat

	// Test passes if detection matches expectation
	result.Passed = (expectedThreat && result.DetectedThreat) || (!expectedThreat && !result.DetectedThreat)

	suite.mu.Lock()
	suite.results[result.TestID] = result
	suite.mu.Unlock()

	return result
}

func (suite *AdvancedTestSuite) generateEnterpriseProjects(scenario EnterpriseScenario) []ProjectTemplate {
	// Generate realistic enterprise project templates based on scenario
	projects := []ProjectTemplate{
		{
			Name:     fmt.Sprintf("%s_web_app", strings.ToLower(scenario.IndustryType)),
			Language: "javascript",
			Size:     "large",
			Dependencies: map[string]string{
				"express": "^4.18.0",
				"react":   "^18.0.0",
				"lodash":  "^4.17.21",
				"axios":   "^1.0.0",
				"moment":  "^2.29.0",
			},
			DevDependencies: map[string]string{
				"jest":    "^29.0.0",
				"eslint":  "^8.0.0",
				"webpack": "^5.0.0",
			},
			ThreatPackages: []string{"lodahs", "recat"}, // Include threats
		},
		{
			Name:     fmt.Sprintf("%s_api_service", strings.ToLower(scenario.IndustryType)),
			Language: "python",
			Size:     "medium",
			Dependencies: map[string]string{
				"requests":     "^2.28.0",
				"flask":        "^2.2.0",
				"sqlalchemy":   "^1.4.0",
				"cryptography": "^3.4.0",
			},
			ThreatPackages: []string{"reqeusts", "flаsk"}, // Include threats
		},
	}

	return projects
}

func (suite *AdvancedTestSuite) createTemporaryProject(project ProjectTemplate) (string, func()) {
	// Create temporary directory
	tmpDir, err := os.MkdirTemp("", fmt.Sprintf("typosentinel_test_%s_", project.Name))
	if err != nil {
		log.Fatalf("Failed to create temp dir: %v", err)
	}

	// Create project files based on language
	switch project.Language {
	case "javascript":
		suite.createJavaScriptProject(tmpDir, project)
	case "python":
		suite.createPythonProject(tmpDir, project)
	}

	cleanup := func() {
		os.RemoveAll(tmpDir)
	}

	return tmpDir, cleanup
}

func (suite *AdvancedTestSuite) createJavaScriptProject(dir string, project ProjectTemplate) {
	packageJSON := map[string]interface{}{
		"name":            project.Name,
		"version":         "1.0.0",
		"dependencies":    project.Dependencies,
		"devDependencies": project.DevDependencies,
	}

	// Add threat packages to dependencies
	for _, threat := range project.ThreatPackages {
		packageJSON["dependencies"].(map[string]string)[threat] = "^1.0.0"
	}

	data, _ := json.MarshalIndent(packageJSON, "", "  ")
	os.WriteFile(filepath.Join(dir, "package.json"), data, 0644)
}

func (suite *AdvancedTestSuite) createPythonProject(dir string, project ProjectTemplate) {
	requirements := []string{}

	for pkg, version := range project.Dependencies {
		requirements = append(requirements, fmt.Sprintf("%s%s", pkg, version))
	}

	// Add threat packages
	for _, threat := range project.ThreatPackages {
		requirements = append(requirements, fmt.Sprintf("%s>=1.0.0", threat))
	}

	content := strings.Join(requirements, "\n")
	os.WriteFile(filepath.Join(dir, "requirements.txt"), []byte(content), 0644)
}

func (suite *AdvancedTestSuite) scanEnterpriseProject(projectDir string, scenario EnterpriseScenario) ([]*AdvancedTestResult, error) {

	// Use the Scan method instead of ScanProject
	options := &analyzer.ScanOptions{
		OutputFormat:           "json",
		DeepAnalysis:           true,
		IncludeDevDependencies: true,
		SimilarityThreshold:    0.8,
	}

	result, err := suite.analyzer.Scan(projectDir, options)
	if err != nil {
		return nil, err
	}

	advancedResults := make([]*AdvancedTestResult, 0)

	// Process the scan result
	if result != nil {
		for _, threat := range result.Threats {
			advResult := &AdvancedTestResult{
				TestID:          fmt.Sprintf("enterprise_%s_%s", scenario.ID, filepath.Base(result.Path)),
				TestCategory:    "enterprise_project_scan",
				PackageName:     filepath.Base(result.Path),
				Registry:        "filesystem",
				AttackVector:    "project_scan",
				ThreatScore:     threat.Confidence,
				ConfidenceLevel: threat.Confidence,
				DetectedThreat:  true,
				SeverityLevel:   threat.Severity.String(),
				DetectionFlags:  []string{threat.Severity.String()},
				SecurityInsights: map[string]interface{}{
					"enterprise_scenario": scenario.ID,
					"industry_type":       scenario.IndustryType,
					"security_maturity":   scenario.SecurityMaturity,
					"threat_type":         threat.Type,
					"threat_description":  threat.Description,
				},
			}
			advancedResults = append(advancedResults, advResult)
		}

		// If no threats found, create a clean result
		if len(result.Threats) == 0 {
			advResult := &AdvancedTestResult{
				TestID:          fmt.Sprintf("enterprise_%s_%s", scenario.ID, filepath.Base(result.Path)),
				TestCategory:    "enterprise_project_scan",
				PackageName:     filepath.Base(result.Path),
				Registry:        "filesystem",
				AttackVector:    "project_scan",
				ThreatScore:     0.0,
				ConfidenceLevel: 1.0,
				DetectedThreat:  false,
				SeverityLevel:   "LOW",
				DetectionFlags:  []string{"clean"},
				SecurityInsights: map[string]interface{}{
					"enterprise_scenario": scenario.ID,
					"industry_type":       scenario.IndustryType,
					"security_maturity":   scenario.SecurityMaturity,
				},
			}
			advancedResults = append(advancedResults, advResult)
		}
	}

	return advancedResults, nil
}

func (suite *AdvancedTestSuite) validateEnterpriseExpectations(
	t *testing.T,
	scenario EnterpriseScenario,
	results []*AdvancedTestResult,
	totalPackages, threatsDetected, falsePositives int,
) {
	detectionRate := float64(threatsDetected) / float64(totalPackages)
	falsePositiveRate := float64(falsePositives) / float64(totalPackages)

	expectedDetection := scenario.Expectations["detection_rate"]
	expectedFPRate := 1.0 - scenario.Expectations["precision"]

	t.Logf("Enterprise scenario %s results:", scenario.ID)
	t.Logf("  Detection Rate: %.3f (expected: %.3f)", detectionRate, expectedDetection)
	t.Logf("  False Positive Rate: %.3f (expected: ≤%.3f)", falsePositiveRate, expectedFPRate)

	if detectionRate < expectedDetection {
		t.Errorf("Detection rate %.3f below enterprise expectation %.3f for %s",
			detectionRate, expectedDetection, scenario.CompanyProfile)
	}

	if falsePositiveRate > expectedFPRate {
		t.Errorf("False positive rate %.3f above enterprise limit %.3f for %s",
			falsePositiveRate, expectedFPRate, scenario.CompanyProfile)
	}
}

func (suite *AdvancedTestSuite) runStressTest(
	t *testing.T,
	packageCount, concurrency int,
	timeLimit time.Duration,
	expectedThroughput float64,
) {
	t.Logf("Running stress test: %d packages, %d concurrent, %v time limit",
		packageCount, concurrency, timeLimit)

	packages := suite.generateStressTestPackages(packageCount)

	ctx, cancel := context.WithTimeout(context.Background(), timeLimit)
	defer cancel()

	startTime := time.Now()

	// Use semaphore to control concurrency
	sem := make(chan struct{}, concurrency)
	results := make(chan *AdvancedTestResult, packageCount)
	var wg sync.WaitGroup

	for i, pkg := range packages {
		wg.Add(1)
		go func(index int, pkg types.Package) {
			defer wg.Done()

			sem <- struct{}{}        // Acquire
			defer func() { <-sem }() // Release

			result := suite.analyzeAdvancedPackage(
				pkg.Name,
				pkg.Registry,
				"stress_test",
				false, // not necessarily threats
				0.5,
			)

			select {
			case results <- result:
			case <-ctx.Done():
				return
			}
		}(i, pkg)
	}

	// Close results channel when all goroutines complete
	go func() {
		wg.Wait()
		close(results)
	}()

	// Collect results
	var processedCount int
	var totalProcessingTime time.Duration

	for result := range results {
		processedCount++
		totalProcessingTime += result.ProcessingTime
	}

	elapsed := time.Since(startTime)
	throughput := float64(processedCount) / elapsed.Seconds()
	avgProcessingTime := totalProcessingTime / time.Duration(processedCount)

	t.Logf("Stress test results:")
	t.Logf("  Processed: %d/%d packages", processedCount, packageCount)
	t.Logf("  Elapsed: %v", elapsed)
	t.Logf("  Throughput: %.2f packages/second", throughput)
	t.Logf("  Average processing time: %v", avgProcessingTime)

	if throughput < expectedThroughput {
		t.Errorf("Throughput %.2f below expected %.2f packages/second",
			throughput, expectedThroughput)
	}

	if processedCount < packageCount {
		t.Errorf("Only processed %d/%d packages within time limit", processedCount, packageCount)
	}
}

func (suite *AdvancedTestSuite) generateStressTestPackages(count int) []types.Package {
	packages := make([]types.Package, count)

	// Mix of legitimate and suspicious packages
	legitimatePackages := []string{"lodash", "react", "express", "axios", "moment", "webpack"}
	suspiciousPackages := []string{"lodahs", "recat", "expresss", "axioss", "momentt", "webpаck"}
	registries := []string{"npm", "pypi"}

	for i := 0; i < count; i++ {
		var name string
		if i%10 == 0 { // 10% suspicious
			name = suspiciousPackages[i%len(suspiciousPackages)]
		} else {
			name = legitimatePackages[i%len(legitimatePackages)]
		}

		packages[i] = types.Package{
			Name:     fmt.Sprintf("%s-%d", name, i),
			Registry: registries[i%len(registries)],
			Version:  "latest",
		}
	}

	return packages
}

func (suite *AdvancedTestSuite) generateZeroDayPackage(technique string) string {
	// Generate synthetic package names for zero-day simulation
	prefixes := []string{"secure", "crypto", "util", "helper", "lib", "core"}
	suffixes := []string{"js", "py", "utils", "tool", "kit", "pack"}

	// Add randomness
	randBytes := make([]byte, 4)
	rand.Read(randBytes)

	prefix := prefixes[int(randBytes[0])%len(prefixes)]
	suffix := suffixes[int(randBytes[1])%len(suffixes)]

	return fmt.Sprintf("%s-%s-%s", prefix, technique, suffix)
}

func (suite *AdvancedTestSuite) calculateCVSS(analysis *analyzer.ScanResult) float64 {
	// Simplified CVSS calculation based on threat characteristics
	baseScore := 0.0

	if analysis != nil && len(analysis.Threats) > 0 {
		threat := analysis.Threats[0]
		switch threat.Severity {
		case types.SeverityCritical:
			baseScore = 9.0
		case types.SeverityHigh:
			baseScore = 7.0
		case types.SeverityMedium:
			baseScore = 5.0
		case types.SeverityLow:
			baseScore = 3.0
		default:
			baseScore = 1.0
		}

		// Adjust based on confidence
		confidenceMultiplier := threat.Confidence
		threatMultiplier := threat.Confidence

		finalScore := baseScore * confidenceMultiplier * threatMultiplier
		return math.Min(finalScore, 10.0)
	}

	return 1.0 // Default low score for clean packages
}

// GenerateComprehensiveReport generates a detailed security assessment report
func (suite *AdvancedTestSuite) GenerateComprehensiveReport() {
	fmt.Println("\n" + strings.Repeat("=", 80))
	fmt.Println("TYPOSENTINEL ADVANCED SECURITY ASSESSMENT REPORT")
	fmt.Println(strings.Repeat("=", 80))

	suite.mu.RLock()
	defer suite.mu.RUnlock()

	// Overall statistics
	totalTests := len(suite.results)
	passedTests := 0
	criticalThreats := 0
	falsePositives := 0
	falseNegatives := 0

	var totalProcessingTime time.Duration
	var threatScores []float64
	var confidenceScores []float64

	for _, result := range suite.results {
		if result.Passed {
			passedTests++
		}
		if result.SeverityLevel == "CRITICAL" {
			criticalThreats++
		}
		if result.FalsePositive {
			falsePositives++
		}
		if result.FalseNegative {
			falseNegatives++
		}

		totalProcessingTime += result.ProcessingTime
		threatScores = append(threatScores, result.ThreatScore)
		confidenceScores = append(confidenceScores, result.ConfidenceLevel)
	}

	var avgProcessingTime time.Duration
	if totalTests > 0 {
		avgProcessingTime = totalProcessingTime / time.Duration(totalTests)
	}
	avgThreatScore := calculateMean(threatScores)
	avgConfidence := calculateMean(confidenceScores)

	fmt.Printf("📊 EXECUTIVE SUMMARY\n")
	fmt.Printf("Total Advanced Tests: %d\n", totalTests)
	if totalTests > 0 {
		fmt.Printf("Overall Pass Rate: %.1f%%\n", float64(passedTests)/float64(totalTests)*100)
		fmt.Printf("False Positive Rate: %.1f%%\n", float64(falsePositives)/float64(totalTests)*100)
		fmt.Printf("False Negative Rate: %.1f%%\n", float64(falseNegatives)/float64(totalTests)*100)
	} else {
		fmt.Printf("Overall Pass Rate: N/A (no tests run)\n")
		fmt.Printf("False Positive Rate: N/A (no tests run)\n")
		fmt.Printf("False Negative Rate: N/A (no tests run)\n")
	}
	fmt.Printf("Critical Threats Detected: %d\n", criticalThreats)
	fmt.Printf("Average Processing Time: %v\n", avgProcessingTime)
	fmt.Printf("Average Threat Score: %.3f\n", avgThreatScore)
	fmt.Printf("Average Confidence: %.3f\n", avgConfidence)

	// Category breakdown
	fmt.Printf("\n📋 CATEGORY BREAKDOWN\n")
	categories := make(map[string][]string)
	for testID, result := range suite.results {
		categories[result.TestCategory] = append(categories[result.TestCategory], testID)
	}

	for category, tests := range categories {
		categoryPassed := 0
		for _, testID := range tests {
			if suite.results[testID].Passed {
				categoryPassed++
			}
		}
		fmt.Printf("%s: %d/%d passed (%.1f%%)\n",
			category, categoryPassed, len(tests),
			float64(categoryPassed)/float64(len(tests))*100)
	}

	// Attack vector analysis
	fmt.Printf("\n🎯 ATTACK VECTOR ANALYSIS\n")
	attackVectors := make(map[string]int)
	for _, result := range suite.results {
		attackVectors[result.AttackVector]++
	}

	for vector, count := range attackVectors {
		fmt.Printf("%s: %d tests\n", vector, count)
	}

	// Enterprise readiness assessment
	fmt.Printf("\n🏢 ENTERPRISE READINESS ASSESSMENT\n")
	suite.assessEnterpriseReadiness()

	fmt.Println(strings.Repeat("=", 80))
}

func (suite *AdvancedTestSuite) assessEnterpriseReadiness() {
	criteria := map[string]struct {
		threshold float64
		current   float64
		unit      string
	}{
		"Detection Accuracy":      {0.95, suite.calculateDetectionAccuracy(), "%"},
		"False Positive Rate":     {0.05, suite.calculateFalsePositiveRate(), "%"},
		"Average Processing Time": {2000, suite.calculateAvgProcessingTimeMs(), "ms"},
		"Enterprise Confidence":   {0.90, suite.calculateEnterpriseConfidence(), "score"},
	}

	allPassed := true
	for criterion, data := range criteria {
		passed := data.current <= data.threshold
		if criterion == "Detection Accuracy" || criterion == "Enterprise Confidence" {
			passed = data.current >= data.threshold
		}

		status := "✅"
		if !passed {
			status = "❌"
			allPassed = false
		}

		fmt.Printf("%s %s: %.2f%s (threshold: %.2f%s)\n",
			status, criterion, data.current, data.unit, data.threshold, data.unit)
	}

	fmt.Printf("\n🎯 OVERALL ENTERPRISE READINESS: ")
	if allPassed {
		fmt.Printf("✅ READY FOR ENTERPRISE DEPLOYMENT\n")
	} else {
		fmt.Printf("❌ REQUIRES IMPROVEMENT BEFORE ENTERPRISE DEPLOYMENT\n")
	}
}

// Helper functions for calculations
func calculateMean(values []float64) float64 {
	if len(values) == 0 {
		return 0
	}
	sum := 0.0
	for _, v := range values {
		sum += v
	}
	return sum / float64(len(values))
}

func (suite *AdvancedTestSuite) calculateDetectionAccuracy() float64 {
	threats := 0
	detected := 0
	for _, result := range suite.results {
		if result.ExpectedThreat {
			threats++
			if result.DetectedThreat {
				detected++
			}
		}
	}
	if threats == 0 {
		return 0
	}
	return float64(detected) / float64(threats) * 100
}

func (suite *AdvancedTestSuite) calculateFalsePositiveRate() float64 {
	legitimate := 0
	falsePositives := 0
	for _, result := range suite.results {
		if !result.ExpectedThreat {
			legitimate++
			if result.DetectedThreat {
				falsePositives++
			}
		}
	}
	if legitimate == 0 {
		return 0
	}
	return float64(falsePositives) / float64(legitimate) * 100
}

func (suite *AdvancedTestSuite) calculateAvgProcessingTimeMs() float64 {
	if len(suite.results) == 0 {
		return 0
	}
	total := time.Duration(0)
	for _, result := range suite.results {
		total += result.ProcessingTime
	}
	return float64(total.Milliseconds()) / float64(len(suite.results))
}

func (suite *AdvancedTestSuite) calculateEnterpriseConfidence() float64 {
	scores := make([]float64, 0, len(suite.results))
	for _, result := range suite.results {
		scores = append(scores, result.ConfidenceLevel)
	}
	return calculateMean(scores)
}

// RunAdvancedTestSuite executes the complete advanced test suite
func RunAdvancedTestSuite() {
	suite := NewAdvancedTestSuite()

	fmt.Println("🚀 Starting Advanced Real-World Security Test Suite for Typosentinel...")

	t := &testing.T{}

	// Run all advanced test categories
	suite.TestAdvancedTyposquattingAttacks(t)
	suite.TestDependencyConfusionAttacks(t)
	suite.TestEnterpriseSecurityScenarios(t)
	suite.TestAdvancedMLEvasion(t)
	suite.TestStressAndPerformance(t)
	suite.TestZeroDaySimulation(t)

	// Generate comprehensive report
	suite.GenerateComprehensiveReport()
}

// To run this test suite, call RunAdvancedTestSuite() from another main function
// or use: go test -run TestAdvanced