package security

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/Alivanroy/Typosentinel/pkg/logger"
	"github.com/Alivanroy/Typosentinel/pkg/types"
)

// TemporalDetector provides advanced temporal threat detection capabilities
// Addresses critical vulnerabilities identified in adversarial assessment:
// - Time-bomb malware with extended delays (18+ months)
// - Astronomical event triggers
// - Seasonal activation patterns
// - Gradual payload deployment across versions
type TemporalDetector struct {
	config                *TemporalDetectorConfig
	suspiciousPatterns    []TemporalPattern
	versionTracker        *VersionTracker
	activationPredictor   *ActivationPredictor
	behaviorBaseline      *BehaviorBaseline
	logger                logger.Logger
}

// TemporalDetectorConfig configures temporal detection parameters
type TemporalDetectorConfig struct {
	MaxAnalysisWindow     time.Duration `yaml:"max_analysis_window"`     // 24 months
	SuspicionThreshold    float64       `yaml:"suspicion_threshold"`     // 0.7
	VersionTrackingDepth  int           `yaml:"version_tracking_depth"`  // 50 versions
	AstronomicalChecks    bool          `yaml:"astronomical_checks"`     // true
	SeasonalAnalysis      bool          `yaml:"seasonal_analysis"`       // true
	GradualDeploymentScan bool          `yaml:"gradual_deployment_scan"` // true
	Enabled               bool          `yaml:"enabled"`                 // true
}

// TemporalPattern represents suspicious temporal patterns
type TemporalPattern struct {
	Name        string
	Pattern     *regexp.Regexp
	Severity    types.Severity
	Description string
	Indicators  []string
}

// VersionTracker tracks package versions for gradual deployment detection
type VersionTracker struct {
	packageHistory map[string][]VersionEntry
	maxEntries     int
}

// VersionEntry represents a package version entry
type VersionEntry struct {
	Version     string
	ReleaseDate time.Time
	CodeHash    string
	Suspicious  bool
	Changes     []CodeChange
}

// CodeChange represents changes between versions
type CodeChange struct {
	Type        string  // "addition", "modification", "deletion"
	Location    string
	Content     string
	Suspicion   float64
	Indicators  []string
}

// ActivationPredictor predicts potential activation triggers
type ActivationPredictor struct {
	astronomicalEvents map[string]time.Time
	seasonalPatterns   []SeasonalPattern
	marketEvents       []MarketEvent
}

// SeasonalPattern represents seasonal activation patterns
type SeasonalPattern struct {
	Name        string
	StartMonth  int
	EndMonth    int
	Probability float64
	Indicators  []string
}

// MarketEvent represents market-based triggers
type MarketEvent struct {
	Name        string
	Trigger     string
	Probability float64
	Indicators  []string
}

// BehaviorBaseline tracks normal behavior patterns
type BehaviorBaseline struct {
	normalPatterns    map[string]float64
	deviationThreshold float64
}

// TemporalThreat represents a detected temporal threat
type TemporalThreat struct {
	ThreatID          string                 `json:"threat_id"`
	PackageName       string                 `json:"package_name"`
	ThreatType        string                 `json:"threat_type"`
	Severity          types.Severity         `json:"severity"`
	ConfidenceScore   float64                `json:"confidence_score"`
	DetectedPatterns  []string               `json:"detected_patterns"`
	PredictedTriggers []PredictedTrigger     `json:"predicted_triggers"`
	VersionAnalysis   *VersionAnalysisResult `json:"version_analysis"`
	Recommendations   []string               `json:"recommendations"`
	Metadata          map[string]interface{} `json:"metadata"`
}

// PredictedTrigger represents a predicted activation trigger
type PredictedTrigger struct {
	Type        string    `json:"type"`
	Trigger     string    `json:"trigger"`
	Probability float64   `json:"probability"`
	EstimatedDate time.Time `json:"estimated_date,omitempty"`
}

// VersionAnalysisResult represents version analysis results
type VersionAnalysisResult struct {
	TotalVersions       int                    `json:"total_versions"`
	SuspiciousVersions  int                    `json:"suspicious_versions"`
	GradualDeployment   bool                   `json:"gradual_deployment"`
	PayloadAssembly     bool                   `json:"payload_assembly"`
	VersionProgression  []VersionProgression   `json:"version_progression"`
	SuspiciousChanges   []SuspiciousChange     `json:"suspicious_changes"`
}

// VersionProgression tracks progression across versions
type VersionProgression struct {
	Version     string    `json:"version"`
	Date        time.Time `json:"date"`
	Suspicion   float64   `json:"suspicion"`
	Changes     int       `json:"changes"`
	Indicators  []string  `json:"indicators"`
}

// SuspiciousChange represents a suspicious change across versions
type SuspiciousChange struct {
	FromVersion string   `json:"from_version"`
	ToVersion   string   `json:"to_version"`
	ChangeType  string   `json:"change_type"`
	Suspicion   float64  `json:"suspicion"`
	Indicators  []string `json:"indicators"`
}

// NewTemporalDetector creates a new temporal detector
func NewTemporalDetector(config *TemporalDetectorConfig, logger logger.Logger) *TemporalDetector {
	if config == nil {
		config = DefaultTemporalDetectorConfig()
	}

	detector := &TemporalDetector{
		config:              config,
		suspiciousPatterns:  initializeSuspiciousPatterns(),
		versionTracker:      NewVersionTracker(config.VersionTrackingDepth),
		activationPredictor: NewActivationPredictor(),
		behaviorBaseline:    NewBehaviorBaseline(),
		logger:              logger,
	}

	return detector
}

// DefaultTemporalDetectorConfig returns default configuration
func DefaultTemporalDetectorConfig() *TemporalDetectorConfig {
	return &TemporalDetectorConfig{
		MaxAnalysisWindow:     24 * 30 * 24 * time.Hour, // 24 months
		SuspicionThreshold:    0.7,
		VersionTrackingDepth:  50,
		AstronomicalChecks:    true,
		SeasonalAnalysis:      true,
		GradualDeploymentScan: true,
		Enabled:               true,
	}
}

// AnalyzeTemporalThreats performs comprehensive temporal threat analysis
func (td *TemporalDetector) AnalyzeTemporalThreats(ctx context.Context, pkg *types.Package) (*TemporalThreat, error) {
	if !td.config.Enabled {
		return nil, nil
	}

	td.logger.Info("Starting temporal threat analysis for package: " + pkg.Name)

	threat := &TemporalThreat{
		ThreatID:          generateThreatID(pkg.Name),
		PackageName:       pkg.Name,
		DetectedPatterns:  []string{},
		PredictedTriggers: []PredictedTrigger{},
		Recommendations:   []string{},
		Metadata:          make(map[string]interface{}),
	}

	// 1. Analyze code for temporal patterns
	patterns := td.analyzeTemporalPatterns(pkg)
	threat.DetectedPatterns = append(threat.DetectedPatterns, patterns...)

	// 2. Predict activation triggers
	triggers := td.predictActivationTriggers(pkg)
	threat.PredictedTriggers = triggers

	// 3. Analyze version progression for gradual deployment
	if td.config.GradualDeploymentScan {
		versionAnalysis := td.analyzeVersionProgression(pkg)
		threat.VersionAnalysis = versionAnalysis
	}

	// 4. Calculate overall confidence score
	threat.ConfidenceScore = td.calculateConfidenceScore(threat)

	// 5. Determine threat type and severity
	threat.ThreatType, threat.Severity = td.classifyThreat(threat)

	// 6. Generate recommendations
	threat.Recommendations = td.generateRecommendations(threat)

	td.logger.Info(fmt.Sprintf("Temporal threat analysis completed for %s: confidence=%.2f, threat_type=%s", 
		pkg.Name, threat.ConfidenceScore, threat.ThreatType))

	return threat, nil
}

// analyzeTemporalPatterns analyzes code for suspicious temporal patterns
func (td *TemporalDetector) analyzeTemporalPatterns(pkg *types.Package) []string {
	patterns := []string{}

	// Analyze package code for temporal indicators
	codeContent := td.extractCodeContent(pkg)
	
	for _, pattern := range td.suspiciousPatterns {
		if pattern.Pattern.MatchString(codeContent) {
			patterns = append(patterns, pattern.Name)
			td.logger.Debug(fmt.Sprintf("Detected temporal pattern %s in package %s", pattern.Name, pkg.Name))
		}
	}

	return patterns
}

// predictActivationTriggers predicts potential activation triggers
func (td *TemporalDetector) predictActivationTriggers(pkg *types.Package) []PredictedTrigger {
	triggers := []PredictedTrigger{}

	codeContent := td.extractCodeContent(pkg)

	// Check for astronomical event triggers
	if td.config.AstronomicalChecks {
		astroTriggers := td.detectAstronomicalTriggers(codeContent)
		triggers = append(triggers, astroTriggers...)
	}

	// Check for seasonal patterns
	if td.config.SeasonalAnalysis {
		seasonalTriggers := td.detectSeasonalTriggers(codeContent)
		triggers = append(triggers, seasonalTriggers...)
	}

	// Check for market-based triggers
	marketTriggers := td.detectMarketTriggers(codeContent)
	triggers = append(triggers, marketTriggers...)

	// Check for time-based delays
	delayTriggers := td.detectDelayTriggers(codeContent)
	triggers = append(triggers, delayTriggers...)

	return triggers
}

// analyzeVersionProgression analyzes version progression for gradual deployment
func (td *TemporalDetector) analyzeVersionProgression(pkg *types.Package) *VersionAnalysisResult {
	result := &VersionAnalysisResult{
		VersionProgression: []VersionProgression{},
		SuspiciousChanges:  []SuspiciousChange{},
	}

	// Get version history
	versions := td.versionTracker.GetVersionHistory(pkg.Name)
	result.TotalVersions = len(versions)

	// Analyze each version for suspicious changes
	for i, version := range versions {
		progression := VersionProgression{
			Version: version.Version,
			Date:    version.ReleaseDate,
			Changes: len(version.Changes),
		}

		// Calculate suspicion score for this version
		suspicion := td.calculateVersionSuspicion(version)
		progression.Suspicion = suspicion

		if suspicion > td.config.SuspicionThreshold {
			result.SuspiciousVersions++
			progression.Indicators = td.extractVersionIndicators(version)
		}

		result.VersionProgression = append(result.VersionProgression, progression)

		// Analyze changes between consecutive versions
		if i > 0 {
			suspiciousChange := td.analyzeVersionChanges(versions[i-1], version)
			if suspiciousChange != nil {
				result.SuspiciousChanges = append(result.SuspiciousChanges, *suspiciousChange)
			}
		}
	}

	// Detect gradual deployment patterns
	result.GradualDeployment = td.detectGradualDeployment(result.VersionProgression)
	result.PayloadAssembly = td.detectPayloadAssembly(result.SuspiciousChanges)

	return result
}

// initializeSuspiciousPatterns initializes temporal threat patterns
func initializeSuspiciousPatterns() []TemporalPattern {
	return []TemporalPattern{
		{
			Name:        "long_delay_timer",
			Pattern:     regexp.MustCompile(`(?i)(setTimeout|setInterval|sleep|delay).*(\d{7,}|365.*24.*60.*60)`),
			Severity:    types.SeverityHigh,
			Description: "Extremely long delay timers (months/years)",
			Indicators:  []string{"extended_delay", "time_bomb"},
		},
		{
			Name:        "astronomical_trigger",
			Pattern:     regexp.MustCompile(`(?i)(eclipse|solstice|equinox|lunar|solar|constellation|zodiac)`),
			Severity:    types.SeverityMedium,
			Description: "Astronomical event-based triggers",
			Indicators:  []string{"astronomical_event", "celestial_trigger"},
		},
		{
			Name:        "leap_year_trigger",
			Pattern:     regexp.MustCompile(`(?i)(leap.*year|february.*29|isLeapYear|%.*4.*==.*0)`),
			Severity:    types.SeverityMedium,
			Description: "Leap year activation triggers",
			Indicators:  []string{"leap_year", "calendar_trigger"},
		},
		{
			Name:        "market_volatility",
			Pattern:     regexp.MustCompile(`(?i)(stock.*price|market.*crash|volatility|dow.*jones|nasdaq|s&p.*500)`),
			Severity:    types.SeverityMedium,
			Description: "Market volatility-based triggers",
			Indicators:  []string{"market_trigger", "economic_event"},
		},
		{
			Name:        "gradual_assembly",
			Pattern:     regexp.MustCompile(`(?i)(assemble|construct|build).*payload|fragment.*\d+.*of.*\d+`),
			Severity:    types.SeverityHigh,
			Description: "Gradual payload assembly indicators",
			Indicators:  []string{"payload_assembly", "gradual_deployment"},
		},
		{
			Name:        "environment_detection",
			Pattern:     regexp.MustCompile(`(?i)(production|prod|live).*environment|NODE_ENV.*production`),
			Severity:    types.SeverityMedium,
			Description: "Production environment detection",
			Indicators:  []string{"environment_specific", "production_only"},
		},
	}
}

// Helper functions for temporal analysis
func (td *TemporalDetector) extractCodeContent(pkg *types.Package) string {
	// Extract and concatenate all code content from package
	// This would integrate with the actual package analysis system
	return fmt.Sprintf("%s %s", pkg.Name, pkg.Version)
}

func (td *TemporalDetector) detectAstronomicalTriggers(content string) []PredictedTrigger {
	triggers := []PredictedTrigger{}
	
	// Check for astronomical event references
	astronomicalPatterns := map[string]float64{
		"eclipse":    0.8,
		"solstice":   0.7,
		"equinox":    0.7,
		"lunar":      0.6,
		"solar":      0.6,
	}

	for event, probability := range astronomicalPatterns {
		if strings.Contains(strings.ToLower(content), event) {
			triggers = append(triggers, PredictedTrigger{
				Type:        "astronomical",
				Trigger:     event,
				Probability: probability,
			})
		}
	}

	return triggers
}

func (td *TemporalDetector) detectSeasonalTriggers(content string) []PredictedTrigger {
	triggers := []PredictedTrigger{}
	
	seasonalPatterns := map[string]float64{
		"christmas": 0.7,
		"halloween": 0.6,
		"easter":    0.6,
		"summer":    0.5,
		"winter":    0.5,
	}

	for season, probability := range seasonalPatterns {
		if strings.Contains(strings.ToLower(content), season) {
			triggers = append(triggers, PredictedTrigger{
				Type:        "seasonal",
				Trigger:     season,
				Probability: probability,
			})
		}
	}

	return triggers
}

func (td *TemporalDetector) detectMarketTriggers(content string) []PredictedTrigger {
	triggers := []PredictedTrigger{}
	
	marketPatterns := map[string]float64{
		"stock price": 0.8,
		"market crash": 0.9,
		"volatility": 0.7,
		"dow jones": 0.8,
		"nasdaq": 0.8,
	}

	for market, probability := range marketPatterns {
		if strings.Contains(strings.ToLower(content), market) {
			triggers = append(triggers, PredictedTrigger{
				Type:        "market",
				Trigger:     market,
				Probability: probability,
			})
		}
	}

	return triggers
}

func (td *TemporalDetector) detectDelayTriggers(content string) []PredictedTrigger {
	triggers := []PredictedTrigger{}
	
	// Look for extremely long delays
	delayPattern := regexp.MustCompile(`(\d+)\s*(month|year|day)s?`)
	matches := delayPattern.FindAllStringSubmatch(content, -1)
	
	for _, match := range matches {
		if len(match) >= 3 {
			triggers = append(triggers, PredictedTrigger{
				Type:        "delay",
				Trigger:     fmt.Sprintf("%s %s delay", match[1], match[2]),
				Probability: 0.8,
			})
		}
	}

	return triggers
}

func (td *TemporalDetector) calculateConfidenceScore(threat *TemporalThreat) float64 {
	score := 0.0
	
	// Weight patterns
	score += float64(len(threat.DetectedPatterns)) * 0.3
	
	// Weight triggers
	for _, trigger := range threat.PredictedTriggers {
		score += trigger.Probability * 0.2
	}
	
	// Weight version analysis
	if threat.VersionAnalysis != nil {
		if threat.VersionAnalysis.GradualDeployment {
			score += 0.4
		}
		if threat.VersionAnalysis.PayloadAssembly {
			score += 0.5
		}
	}
	
	return math.Min(score, 1.0)
}

func (td *TemporalDetector) classifyThreat(threat *TemporalThreat) (string, types.Severity) {
	if threat.ConfidenceScore > 0.8 {
		return "advanced_temporal_threat", types.SeverityCritical
	} else if threat.ConfidenceScore > 0.6 {
		return "temporal_threat", types.SeverityHigh
	} else if threat.ConfidenceScore > 0.4 {
		return "suspicious_temporal_pattern", types.SeverityMedium
	}
	return "temporal_anomaly", types.SeverityLow
}

func (td *TemporalDetector) generateRecommendations(threat *TemporalThreat) []string {
	recommendations := []string{}
	
	if threat.ConfidenceScore > 0.7 {
		recommendations = append(recommendations, "Immediate quarantine recommended")
		recommendations = append(recommendations, "Extended monitoring required (24+ months)")
	}
	
	if len(threat.PredictedTriggers) > 0 {
		recommendations = append(recommendations, "Monitor for predicted activation triggers")
	}
	
	if threat.VersionAnalysis != nil && threat.VersionAnalysis.GradualDeployment {
		recommendations = append(recommendations, "Review all package versions for gradual payload assembly")
	}
	
	return recommendations
}

// Helper functions for version tracking
func NewVersionTracker(maxEntries int) *VersionTracker {
	return &VersionTracker{
		packageHistory: make(map[string][]VersionEntry),
		maxEntries:     maxEntries,
	}
}

func (vt *VersionTracker) GetVersionHistory(packageName string) []VersionEntry {
	return vt.packageHistory[packageName]
}

func NewActivationPredictor() *ActivationPredictor {
	return &ActivationPredictor{
		astronomicalEvents: make(map[string]time.Time),
		seasonalPatterns:   []SeasonalPattern{},
		marketEvents:       []MarketEvent{},
	}
}

func NewBehaviorBaseline() *BehaviorBaseline {
	return &BehaviorBaseline{
		normalPatterns:     make(map[string]float64),
		deviationThreshold: 0.3,
	}
}

func (td *TemporalDetector) calculateVersionSuspicion(version VersionEntry) float64 {
	suspicion := 0.0
	
	// Check for suspicious timing patterns
	if version.ReleaseDate.Hour() < 6 || version.ReleaseDate.Hour() > 22 {
		suspicion += 0.2 // Off-hours deployment
	}
	
	// Check for weekend deployments
	if version.ReleaseDate.Weekday() == time.Saturday || version.ReleaseDate.Weekday() == time.Sunday {
		suspicion += 0.15
	}
	
	// Check for rapid version increments
	if strings.Contains(version.Version, "999") || strings.Contains(version.Version, "9999") {
		suspicion += 0.3
	}
	
	// Check for suspicious version patterns
	if matched, _ := regexp.MatchString(`\d+\.\d+\.\d+\.\d+`, version.Version); matched {
		suspicion += 0.2 // Unusual 4-part versioning
	}
	
	// Check for existing suspicious flag
	if version.Suspicious {
		suspicion += 0.4
	}
	
	// Check for code changes indicators
	for _, change := range version.Changes {
		if change.Suspicion > 0.5 {
			suspicion += 0.1
		}
	}
	
	return math.Min(suspicion, 1.0)
}

func (td *TemporalDetector) extractVersionIndicators(version VersionEntry) []string {
	indicators := []string{}
	
	// Time-based indicators
	if version.ReleaseDate.Hour() < 6 || version.ReleaseDate.Hour() > 22 {
		indicators = append(indicators, "off_hours_deployment")
	}
	
	if version.ReleaseDate.Weekday() == time.Saturday || version.ReleaseDate.Weekday() == time.Sunday {
		indicators = append(indicators, "weekend_deployment")
	}
	
	// Version pattern indicators
	if strings.Contains(version.Version, "999") {
		indicators = append(indicators, "suspicious_version_number")
	}
	
	if matched, _ := regexp.MatchString(`\d+\.\d+\.\d+\.\d+`, version.Version); matched {
		indicators = append(indicators, "unusual_version_format")
	}
	
	// Suspicious flag indicator
	if version.Suspicious {
		indicators = append(indicators, "marked_suspicious")
	}
	
	// Code changes indicators
	for _, change := range version.Changes {
		if change.Suspicion > 0.5 {
			indicators = append(indicators, "suspicious_code_change")
			break
		}
	}
	
	return indicators
}

func (td *TemporalDetector) analyzeVersionChanges(prev, current VersionEntry) *SuspiciousChange {
	if prev.Version == "" {
		return nil // No previous version to compare
	}
	
	change := &SuspiciousChange{
		FromVersion: prev.Version,
		ToVersion:   current.Version,
		ChangeType:  "version_update",
		Indicators:  []string{},
		Suspicion:   0.0,
	}
	
	// Analyze time gap between versions
	timeDiff := current.ReleaseDate.Sub(prev.ReleaseDate)
	if timeDiff < 5*time.Minute {
		change.Indicators = append(change.Indicators, "rapid_version_update")
		change.Suspicion += 0.3
	}
	
	// Analyze version number changes
	if td.isVersionDowngrade(prev.Version, current.Version) {
		change.Indicators = append(change.Indicators, "version_downgrade")
		change.Suspicion += 0.4
	}
	
	// Check for suspicious flags
	if current.Suspicious {
		change.Indicators = append(change.Indicators, "suspicious_version")
		change.Suspicion += 0.3
	}
	
	// Check for significant changes
	if len(current.Changes) > len(prev.Changes)*2 {
		change.Indicators = append(change.Indicators, "significant_changes")
		change.Suspicion += 0.2
	}
	
	change.Suspicion = math.Min(change.Suspicion, 1.0)
	
	if change.Suspicion > 0.1 {
		return change
	}
	
	return nil
}

func (td *TemporalDetector) detectGradualDeployment(progressions []VersionProgression) bool {
	if len(progressions) < 3 {
		return false
	}
	
	// Look for patterns indicating gradual payload assembly
	suspiciousPatterns := 0
	
	for _, progression := range progressions {
		// Check for incremental size increases
		if td.hasIncrementalSizeIncrease(progression) {
			suspiciousPatterns++
		}
		
		// Check for gradual complexity increase
		if td.hasGradualComplexityIncrease(progression) {
			suspiciousPatterns++
		}
		
		// Check for staged functionality introduction
		if td.hasStagedFunctionalityIntroduction(progression) {
			suspiciousPatterns++
		}
	}
	
	// If more than 60% of progressions show suspicious patterns
	return float64(suspiciousPatterns)/float64(len(progressions)) > 0.6
}

func (td *TemporalDetector) detectPayloadAssembly(changes []SuspiciousChange) bool {
	if len(changes) < 2 {
		return false
	}
	
	assemblyIndicators := 0
	
	for _, change := range changes {
		// Look for indicators of payload assembly
		for _, indicator := range change.Indicators {
			switch indicator {
			case "significant_metadata_change":
				assemblyIndicators++
			case "rapid_version_update":
				assemblyIndicators++
			case "author_change":
				assemblyIndicators += 2 // Higher weight
			}
		}
	}
	
	// Check for temporal clustering of changes
	if td.hasTemporalClustering(changes) {
		assemblyIndicators += 2
	}
	
	// Threshold for payload assembly detection
	return assemblyIndicators >= 4
}

// Helper methods for version analysis
func (td *TemporalDetector) isVersionDowngrade(prev, current string) bool {
	// Simple semantic version comparison
	prevParts := strings.Split(prev, ".")
	currentParts := strings.Split(current, ".")
	
	if len(prevParts) != len(currentParts) {
		return false
	}
	
	for i := 0; i < len(prevParts) && i < len(currentParts); i++ {
		prevNum, err1 := strconv.Atoi(prevParts[i])
		currentNum, err2 := strconv.Atoi(currentParts[i])
		
		if err1 != nil || err2 != nil {
			continue
		}
		
		if currentNum < prevNum {
			return true
		} else if currentNum > prevNum {
			return false
		}
	}
	
	return false
}

func (td *TemporalDetector) hasIncrementalSizeIncrease(progression VersionProgression) bool {
	// Simplified check based on suspicion score and changes
	return progression.Changes > 5 && progression.Suspicion > 0.5
}

func (td *TemporalDetector) hasGradualComplexityIncrease(progression VersionProgression) bool {
	// Simplified complexity analysis based on changes and suspicion
	return progression.Changes > 10 && progression.Suspicion > 0.6
}

func (td *TemporalDetector) hasStagedFunctionalityIntroduction(progression VersionProgression) bool {
	// Simplified check for staged functionality
	return progression.Changes > 3 && progression.Suspicion > 0.4
}

func (td *TemporalDetector) hasTemporalClustering(changes []SuspiciousChange) bool {
	if len(changes) < 2 {
		return false
	}
	
	// Simplified clustering check based on number of changes
	return len(changes) > 3
}

func generateThreatID(packageName string) string {
	hash := sha256.Sum256([]byte(packageName + time.Now().String()))
	return "temporal_" + hex.EncodeToString(hash[:8])
}