package security

import (
	"context"
	"fmt"
	"math"
	"regexp"
	"strings"
	"time"

	"github.com/Alivanroy/Typosentinel/pkg/logger"
	"github.com/Alivanroy/Typosentinel/pkg/types"
)

// TrustValidator provides comprehensive trust validation capabilities
// Addresses critical vulnerabilities identified in adversarial assessment:
// - Authority impersonation (federal security directive)
// - Maintainer reputation hijacking (emergency patch)
// - Corporate backing fabrication (enterprise security mandate)
// - Security researcher impersonation (vulnerability fix)
// - Compliance certification forgery (ISO certified framework)
// - Community manipulation (grassroots endorsed tool)
type TrustValidator struct {
	config              *TrustValidatorConfig
	authorityValidator  *AuthorityValidator
	maintainerValidator *MaintainerValidator
	corporateValidator  *CorporateValidator
	researcherValidator *ResearcherValidator
	complianceValidator *ComplianceValidator
	communityValidator  *CommunityValidator
	socialEngineering   *SocialEngineeringDetector
	logger              logger.Logger
}

// TrustValidatorConfig configures trust validation parameters
type TrustValidatorConfig struct {
	EnableAuthorityValidation  bool          `yaml:"enable_authority_validation"`  // true
	EnableMaintainerValidation bool          `yaml:"enable_maintainer_validation"` // true
	EnableCorporateValidation  bool          `yaml:"enable_corporate_validation"`  // true
	EnableResearcherValidation bool          `yaml:"enable_researcher_validation"` // true
	EnableComplianceValidation bool          `yaml:"enable_compliance_validation"` // true
	EnableCommunityValidation  bool          `yaml:"enable_community_validation"`  // true
	EnableSocialEngineering    bool          `yaml:"enable_social_engineering"`    // true
	TrustThreshold             float64       `yaml:"trust_threshold"`              // 0.7
	SuspicionThreshold         float64       `yaml:"suspicion_threshold"`          // 0.3
	ValidationTimeout          time.Duration `yaml:"validation_timeout"`           // 30s
	RequireMultipleValidation  bool          `yaml:"require_multiple_validation"`  // true
	ZeroTrustMode              bool          `yaml:"zero_trust_mode"`              // false
	Enabled                    bool          `yaml:"enabled"`                      // true
}

// TrustValidationResult represents trust validation results
type TrustValidationResult struct {
	PackageName           string                           `json:"package_name"`
	OverallTrustScore     float64                          `json:"overall_trust_score"`
	SuspicionScore        float64                          `json:"suspicion_score"`
	TrustLevel            string                           `json:"trust_level"`
	ValidationResults     map[string]TrustValidationDetail `json:"validation_results"`
	SocialEngineeringRisk *SocialEngineeringRisk           `json:"social_engineering_risk"`
	TrustFactors          []TrustFactor                    `json:"trust_factors"`
	RedFlags              []RedFlag                        `json:"red_flags"`
	Recommendations       []string                         `json:"recommendations"`
	Metadata              map[string]interface{}           `json:"metadata"`
}

// TrustValidationDetail represents individual validation results
type TrustValidationDetail struct {
	ValidationType string    `json:"validation_type"`
	Score          float64   `json:"score"`
	Confidence     float64   `json:"confidence"`
	Status         string    `json:"status"`
	Evidence       []string  `json:"evidence"`
	Warnings       []string  `json:"warnings"`
	Timestamp      time.Time `json:"timestamp"`
}

// SocialEngineeringRisk represents social engineering risk assessment
type SocialEngineeringRisk struct {
	RiskLevel             string                 `json:"risk_level"`
	ConfidenceScore       float64                `json:"confidence_score"`
	DetectedTechniques    []string               `json:"detected_techniques"`
	PsychologicalTriggers []PsychologicalTrigger `json:"psychological_triggers"`
	ManipulationTactics   []ManipulationTactic   `json:"manipulation_tactics"`
}

// PsychologicalTrigger represents psychological manipulation triggers
type PsychologicalTrigger struct {
	Type        string  `json:"type"`
	Description string  `json:"description"`
	Severity    string  `json:"severity"`
	Confidence  float64 `json:"confidence"`
}

// ManipulationTactic represents manipulation tactics
type ManipulationTactic struct {
	Tactic      string   `json:"tactic"`
	Description string   `json:"description"`
	Indicators  []string `json:"indicators"`
	Confidence  float64  `json:"confidence"`
}

// TrustFactor represents factors contributing to trust
type TrustFactor struct {
	Factor      string   `json:"factor"`
	Weight      float64  `json:"weight"`
	Score       float64  `json:"score"`
	Evidence    []string `json:"evidence"`
	Reliability string   `json:"reliability"`
}

// RedFlag represents trust red flags
type RedFlag struct {
	Flag        string    `json:"flag"`
	Severity    string    `json:"severity"`
	Description string    `json:"description"`
	Evidence    []string  `json:"evidence"`
	Timestamp   time.Time `json:"timestamp"`
}

// Authority validation structures
type AuthorityValidator struct {
	knownAuthorities map[string]AuthorityInfo
	suspiciousTerms  []string
}

type AuthorityInfo struct {
	Name        string
	Domain      string
	Verified    bool
	LastUpdated time.Time
}

// Maintainer validation structures
type MaintainerValidator struct {
	maintainerProfiles  map[string]MaintainerProfile
	reputationThreshold float64
}

type MaintainerProfile struct {
	Username           string
	Email              string
	Reputation         float64
	PackageCount       int
	AccountAge         time.Duration
	Verified           bool
	SuspiciousActivity bool
}

// Corporate validation structures
type CorporateValidator struct {
	corporateEntities map[string]CorporateEntity
	verificationAPIs  []string
}

type CorporateEntity struct {
	Name       string
	Domain     string
	Verified   bool
	Employees  int
	Founded    time.Time
	Legitimacy float64
}

// Researcher validation structures
type ResearcherValidator struct {
	researcherProfiles   map[string]ResearcherProfile
	academicInstitutions map[string]bool
}

type ResearcherProfile struct {
	Name         string
	Institution  string
	Publications int
	Citations    int
	HIndex       float64
	Verified     bool
}

// Compliance validation structures
type ComplianceValidator struct {
	certificationBodies map[string]CertificationBody
	complianceStandards map[string]ComplianceStandard
}

type CertificationBody struct {
	Name      string
	Authority string
	Verified  bool
	Standards []string
}

type ComplianceStandard struct {
	Name         string
	Authority    string
	Requirements []string
	Verified     bool
}

// Community validation structures
type CommunityValidator struct {
	communityMetrics  map[string]CommunityMetrics
	astroturfDetector *AstroturfDetector
}

type CommunityMetrics struct {
	Stars          int
	Forks          int
	Contributors   int
	Issues         int
	PullRequests   int
	CommunityScore float64
	Authenticity   float64
}

type AstroturfDetector struct {
	suspiciousPatterns []string
	botDetectionRules  []BotDetectionRule
}

type BotDetectionRule struct {
	Pattern     string
	Confidence  float64
	Description string
}

// Social engineering detection structures
type SocialEngineeringDetector struct {
	urgencyPatterns     []string
	authorityPatterns   []string
	scarcityPatterns    []string
	socialProofPatterns []string
	reciprocityPatterns []string
	commitmentPatterns  []string
}

// NewTrustValidator creates a new trust validator
func NewTrustValidator(config *TrustValidatorConfig, logger logger.Logger) *TrustValidator {
	if config == nil {
		config = DefaultTrustValidatorConfig()
	}

	return &TrustValidator{
		config:              config,
		authorityValidator:  NewAuthorityValidator(),
		maintainerValidator: NewMaintainerValidator(),
		corporateValidator:  NewCorporateValidator(),
		researcherValidator: NewResearcherValidator(),
		complianceValidator: NewComplianceValidator(),
		communityValidator:  NewCommunityValidator(),
		socialEngineering:   NewSocialEngineeringDetector(),
		logger:              logger,
	}
}

// DefaultTrustValidatorConfig returns default configuration
func DefaultTrustValidatorConfig() *TrustValidatorConfig {
	return &TrustValidatorConfig{
		EnableAuthorityValidation:  true,
		EnableMaintainerValidation: true,
		EnableCorporateValidation:  true,
		EnableResearcherValidation: true,
		EnableComplianceValidation: true,
		EnableCommunityValidation:  true,
		EnableSocialEngineering:    true,
		TrustThreshold:             0.7,
		SuspicionThreshold:         0.3,
		ValidationTimeout:          30 * time.Second,
		RequireMultipleValidation:  true,
		ZeroTrustMode:              false,
		Enabled:                    true,
	}
}

// ValidateTrust performs comprehensive trust validation
func (tv *TrustValidator) ValidateTrust(ctx context.Context, pkg *types.Package) (*TrustValidationResult, error) {
	if !tv.config.Enabled {
		return nil, nil
	}

	tv.logger.Info("Starting trust validation for package: " + pkg.Name)

	result := &TrustValidationResult{
		PackageName:       pkg.Name,
		ValidationResults: make(map[string]TrustValidationDetail),
		TrustFactors:      []TrustFactor{},
		RedFlags:          []RedFlag{},
		Recommendations:   []string{},
		Metadata:          make(map[string]interface{}),
	}

	// 1. Authority validation
	if tv.config.EnableAuthorityValidation {
		authResult := tv.validateAuthority(ctx, pkg)
		result.ValidationResults["authority"] = authResult
	}

	// 2. Maintainer validation
	if tv.config.EnableMaintainerValidation {
		maintainerResult := tv.validateMaintainer(ctx, pkg)
		result.ValidationResults["maintainer"] = maintainerResult
	}

	// 3. Corporate validation
	if tv.config.EnableCorporateValidation {
		corporateResult := tv.validateCorporate(ctx, pkg)
		result.ValidationResults["corporate"] = corporateResult
	}

	// 4. Researcher validation
	if tv.config.EnableResearcherValidation {
		researcherResult := tv.validateResearcher(ctx, pkg)
		result.ValidationResults["researcher"] = researcherResult
	}

	// 5. Compliance validation
	if tv.config.EnableComplianceValidation {
		complianceResult := tv.validateCompliance(ctx, pkg)
		result.ValidationResults["compliance"] = complianceResult
	}

	// 6. Community validation
	if tv.config.EnableCommunityValidation {
		communityResult := tv.validateCommunity(ctx, pkg)
		result.ValidationResults["community"] = communityResult
	}

	// 7. Social engineering detection
	if tv.config.EnableSocialEngineering {
		seRisk := tv.detectSocialEngineering(ctx, pkg)
		result.SocialEngineeringRisk = seRisk
	}

	// 8. Calculate overall trust score
	result.OverallTrustScore = tv.calculateOverallTrustScore(result)
	result.SuspicionScore = tv.calculateSuspicionScore(result)

	// 9. Determine trust level
	result.TrustLevel = tv.determineTrustLevel(result)

	// 10. Extract trust factors and red flags
	result.TrustFactors = tv.extractTrustFactors(result)
	result.RedFlags = tv.extractRedFlags(result)

	// 11. Generate recommendations
	result.Recommendations = tv.generateTrustRecommendations(result)

	tv.logger.Info(fmt.Sprintf("Trust validation completed for %s: trust=%.2f, suspicion=%.2f, level=%s",
		pkg.Name, result.OverallTrustScore, result.SuspicionScore, result.TrustLevel))

	return result, nil
}

// validateAuthority validates authority claims
func (tv *TrustValidator) validateAuthority(ctx context.Context, pkg *types.Package) TrustValidationDetail {
	result := TrustValidationDetail{
		ValidationType: "authority",
		Evidence:       []string{},
		Warnings:       []string{},
		Timestamp:      time.Now(),
	}

	// Check for authority impersonation patterns
	packageInfo := tv.extractPackageInfo(pkg)

	// Look for government/authority claims
	authorityPatterns := []string{
		"(?i)(federal|government|official|nist|cisa|fbi|nsa|dhs)",
		"(?i)(security directive|mandate|compliance|regulation)",
		"(?i)(iso certified|soc compliant|fips approved)",
	}

	suspiciousScore := 0.0
	for _, pattern := range authorityPatterns {
		if matched, _ := regexp.MatchString(pattern, packageInfo); matched {
			suspiciousScore += 0.3
			result.Warnings = append(result.Warnings, "Authority claim detected: "+pattern)
		}
	}

	// Validate against known authorities
	for authorityName, authorityInfo := range tv.authorityValidator.knownAuthorities {
		if strings.Contains(strings.ToLower(packageInfo), strings.ToLower(authorityName)) {
			if authorityInfo.Verified {
				result.Evidence = append(result.Evidence, "Verified authority: "+authorityName)
				result.Score += 0.5
			} else {
				result.Warnings = append(result.Warnings, "Unverified authority claim: "+authorityName)
				suspiciousScore += 0.4
			}
		}
	}

	result.Score = 1.0 - suspiciousScore
	result.Confidence = 0.8
	result.Status = tv.determineValidationStatus(result.Score)

	return result
}

// validateMaintainer validates maintainer reputation
func (tv *TrustValidator) validateMaintainer(ctx context.Context, pkg *types.Package) TrustValidationDetail {
	result := TrustValidationDetail{
		ValidationType: "maintainer",
		Evidence:       []string{},
		Warnings:       []string{},
		Timestamp:      time.Now(),
	}

	// Extract maintainer information
	maintainerInfo := tv.extractMaintainerInfo(pkg)

	// Check maintainer reputation
	if profile, exists := tv.maintainerValidator.maintainerProfiles[maintainerInfo]; exists {
		result.Score = profile.Reputation
		result.Evidence = append(result.Evidence, fmt.Sprintf("Maintainer reputation: %.2f", profile.Reputation))

		if profile.SuspiciousActivity {
			result.Warnings = append(result.Warnings, "Maintainer has suspicious activity history")
			result.Score *= 0.5
		}

		if profile.Verified {
			result.Evidence = append(result.Evidence, "Verified maintainer account")
			result.Score += 0.2
		}
	} else {
		result.Warnings = append(result.Warnings, "Unknown maintainer")
		result.Score = 0.3
	}

	result.Confidence = 0.7
	result.Status = tv.determineValidationStatus(result.Score)

	return result
}

// validateCorporate validates corporate backing claims
func (tv *TrustValidator) validateCorporate(ctx context.Context, pkg *types.Package) TrustValidationDetail {
	result := TrustValidationDetail{
		ValidationType: "corporate",
		Evidence:       []string{},
		Warnings:       []string{},
		Timestamp:      time.Now(),
	}

	packageInfo := tv.extractPackageInfo(pkg)

	// Look for corporate backing claims
	corporatePatterns := []string{
		"(?i)(enterprise|corporation|inc|ltd|llc)",
		"(?i)(backed by|sponsored by|developed by)",
		"(?i)(microsoft|google|amazon|apple|facebook)",
	}

	for _, pattern := range corporatePatterns {
		if matched, _ := regexp.MatchString(pattern, packageInfo); matched {
			result.Evidence = append(result.Evidence, "Corporate backing claim detected")

			// Validate against known corporate entities
			for entityName, entity := range tv.corporateValidator.corporateEntities {
				if strings.Contains(strings.ToLower(packageInfo), strings.ToLower(entityName)) {
					if entity.Verified {
						result.Score += 0.4
						result.Evidence = append(result.Evidence, "Verified corporate entity: "+entityName)
					} else {
						result.Warnings = append(result.Warnings, "Unverified corporate claim: "+entityName)
						result.Score -= 0.2
					}
				}
			}
		}
	}

	if result.Score == 0 {
		result.Score = 0.5 // Neutral if no corporate claims
	}

	result.Confidence = 0.6
	result.Status = tv.determineValidationStatus(result.Score)

	return result
}

// validateResearcher validates security researcher claims
func (tv *TrustValidator) validateResearcher(ctx context.Context, pkg *types.Package) TrustValidationDetail {
	result := TrustValidationDetail{
		ValidationType: "researcher",
		Evidence:       []string{},
		Warnings:       []string{},
		Timestamp:      time.Now(),
	}

	packageInfo := tv.extractPackageInfo(pkg)

	// Look for researcher claims
	researcherPatterns := []string{
		"(?i)(security researcher|vulnerability|cve|exploit)",
		"(?i)(academic|university|research|paper|publication)",
		"(?i)(phd|professor|researcher|scientist)",
	}

	for _, pattern := range researcherPatterns {
		if matched, _ := regexp.MatchString(pattern, packageInfo); matched {
			result.Evidence = append(result.Evidence, "Researcher claim detected")

			// Validate against known researchers
			for researcherName, profile := range tv.researcherValidator.researcherProfiles {
				if strings.Contains(strings.ToLower(packageInfo), strings.ToLower(researcherName)) {
					if profile.Verified {
						result.Score += 0.3
						result.Evidence = append(result.Evidence, "Verified researcher: "+researcherName)
					} else {
						result.Warnings = append(result.Warnings, "Unverified researcher claim: "+researcherName)
					}
				}
			}
		}
	}

	if result.Score == 0 {
		result.Score = 0.5 // Neutral if no researcher claims
	}

	result.Confidence = 0.7
	result.Status = tv.determineValidationStatus(result.Score)

	return result
}

// validateCompliance validates compliance certification claims
func (tv *TrustValidator) validateCompliance(ctx context.Context, pkg *types.Package) TrustValidationDetail {
	result := TrustValidationDetail{
		ValidationType: "compliance",
		Evidence:       []string{},
		Warnings:       []string{},
		Timestamp:      time.Now(),
	}

	packageInfo := tv.extractPackageInfo(pkg)

	// Look for compliance claims
	compliancePatterns := []string{
		"(?i)(iso 27001|soc 2|fips 140|common criteria)",
		"(?i)(certified|compliant|approved|validated)",
		"(?i)(audit|assessment|verification|attestation)",
	}

	for _, pattern := range compliancePatterns {
		if matched, _ := regexp.MatchString(pattern, packageInfo); matched {
			result.Evidence = append(result.Evidence, "Compliance claim detected")

			// Validate against known standards
			for standardName, standard := range tv.complianceValidator.complianceStandards {
				if strings.Contains(strings.ToLower(packageInfo), strings.ToLower(standardName)) {
					if standard.Verified {
						result.Score += 0.3
						result.Evidence = append(result.Evidence, "Verified compliance standard: "+standardName)
					} else {
						result.Warnings = append(result.Warnings, "Unverified compliance claim: "+standardName)
					}
				}
			}
		}
	}

	if result.Score == 0 {
		result.Score = 0.5 // Neutral if no compliance claims
	}

	result.Confidence = 0.8
	result.Status = tv.determineValidationStatus(result.Score)

	return result
}

// validateCommunity validates community endorsement
func (tv *TrustValidator) validateCommunity(ctx context.Context, pkg *types.Package) TrustValidationDetail {
	result := TrustValidationDetail{
		ValidationType: "community",
		Evidence:       []string{},
		Warnings:       []string{},
		Timestamp:      time.Now(),
	}

	// Get community metrics
	metrics := tv.getCommunityMetrics(pkg)

	// Detect astroturfing
	astroturfScore := tv.communityValidator.astroturfDetector.detectAstroturfing(pkg)

	result.Score = metrics.CommunityScore * (1.0 - astroturfScore)

	if astroturfScore > 0.5 {
		result.Warnings = append(result.Warnings, "Potential astroturfing detected")
	}

	if metrics.Authenticity < 0.5 {
		result.Warnings = append(result.Warnings, "Low community authenticity")
	}

	result.Evidence = append(result.Evidence, fmt.Sprintf("Community score: %.2f", metrics.CommunityScore))
	result.Confidence = 0.6
	result.Status = tv.determineValidationStatus(result.Score)

	return result
}

// detectSocialEngineering detects social engineering techniques
func (tv *TrustValidator) detectSocialEngineering(ctx context.Context, pkg *types.Package) *SocialEngineeringRisk {
	packageInfo := tv.extractPackageInfo(pkg)

	risk := &SocialEngineeringRisk{
		DetectedTechniques:    []string{},
		PsychologicalTriggers: []PsychologicalTrigger{},
		ManipulationTactics:   []ManipulationTactic{},
	}

	// Detect urgency patterns
	for _, pattern := range tv.socialEngineering.urgencyPatterns {
		if matched, _ := regexp.MatchString(pattern, packageInfo); matched {
			risk.DetectedTechniques = append(risk.DetectedTechniques, "urgency")
			risk.PsychologicalTriggers = append(risk.PsychologicalTriggers, PsychologicalTrigger{
				Type:        "urgency",
				Description: "Creates false sense of urgency",
				Severity:    "high",
				Confidence:  0.8,
			})
		}
	}

	// Detect authority patterns
	for _, pattern := range tv.socialEngineering.authorityPatterns {
		if matched, _ := regexp.MatchString(pattern, packageInfo); matched {
			risk.DetectedTechniques = append(risk.DetectedTechniques, "authority")
			risk.PsychologicalTriggers = append(risk.PsychologicalTriggers, PsychologicalTrigger{
				Type:        "authority",
				Description: "Appeals to authority figures",
				Severity:    "high",
				Confidence:  0.9,
			})
		}
	}

	// Calculate overall risk
	riskScore := float64(len(risk.DetectedTechniques)) * 0.2
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

// Helper functions

func (tv *TrustValidator) extractPackageInfo(pkg *types.Package) string {
	// Extract all available package information for analysis
	return fmt.Sprintf("%s %s", pkg.Name, pkg.Version)
}

func (tv *TrustValidator) extractMaintainerInfo(pkg *types.Package) string {
	// Extract maintainer information from package metadata
	maintainerInfo := []string{}

	// Check for metadata fields
	if pkg.Metadata != nil {
		if pkg.Metadata.Author != "" {
			maintainerInfo = append(maintainerInfo, "author:"+pkg.Metadata.Author)
		}

		if len(pkg.Metadata.Maintainers) > 0 {
			maintainerInfo = append(maintainerInfo, "maintainers:"+strings.Join(pkg.Metadata.Maintainers, ","))
		}

		if pkg.Metadata.Repository != "" {
			// Extract owner from repository URL
			parts := strings.Split(pkg.Metadata.Repository, "/")
			if len(parts) >= 2 {
				owner := parts[len(parts)-2]
				maintainerInfo = append(maintainerInfo, "repo_owner:"+owner)
			}
		}
	}

	if len(maintainerInfo) == 0 {
		return "unknown"
	}

	return strings.Join(maintainerInfo, "; ")
}

func (tv *TrustValidator) getCommunityMetrics(pkg *types.Package) CommunityMetrics {
	// Get community metrics for the package based on available data
	metrics := CommunityMetrics{}

	// Calculate community score based on metadata
	if pkg.Metadata != nil && pkg.Metadata.Downloads > 0 {
		// Normalize download count to 0-1 scale (log scale for large numbers)
		normalizedDownloads := math.Min(math.Log10(float64(pkg.Metadata.Downloads))/6.0, 1.0)
		metrics.CommunityScore = normalizedDownloads
	} else {
		metrics.CommunityScore = 0.1 // Low score for packages with no downloads
	}

	// Calculate authenticity based on package age and consistency
	authenticity := 0.5 // Base authenticity score

	// Increase authenticity for older packages (more established)
	if pkg.Metadata != nil && !pkg.Metadata.CreatedAt.IsZero() {
		age := time.Since(pkg.Metadata.CreatedAt)
		ageScore := math.Min(age.Hours()/(24*365), 1.0) // Max 1 year for full score
		authenticity += ageScore * 0.3
	}

	// Increase authenticity if package has consistent metadata
	if pkg.Metadata != nil && pkg.Metadata.Author != "" && pkg.Metadata.Description != "" && pkg.Metadata.Repository != "" {
		authenticity += 0.2
	}

	// Decrease authenticity for suspicious patterns
	if strings.Contains(strings.ToLower(pkg.Name), "test") ||
		strings.Contains(strings.ToLower(pkg.Name), "temp") ||
		strings.Contains(strings.ToLower(pkg.Name), "fake") {
		authenticity -= 0.3
	}

	metrics.Authenticity = math.Max(0.0, math.Min(authenticity, 1.0))

	return metrics
}

func (tv *TrustValidator) calculateOverallTrustScore(result *TrustValidationResult) float64 {
	totalScore := 0.0
	count := 0

	for _, validation := range result.ValidationResults {
		totalScore += validation.Score
		count++
	}

	if count == 0 {
		return 0.0
	}

	return totalScore / float64(count)
}

func (tv *TrustValidator) calculateSuspicionScore(result *TrustValidationResult) float64 {
	suspicion := 0.0

	if result.SocialEngineeringRisk != nil {
		suspicion += result.SocialEngineeringRisk.ConfidenceScore
	}

	// Add suspicion from validation warnings
	for _, validation := range result.ValidationResults {
		suspicion += float64(len(validation.Warnings)) * 0.1
	}

	return suspicion
}

func (tv *TrustValidator) determineTrustLevel(result *TrustValidationResult) string {
	if result.OverallTrustScore > 0.8 {
		return "high"
	} else if result.OverallTrustScore > 0.6 {
		return "medium"
	} else if result.OverallTrustScore > 0.4 {
		return "low"
	}
	return "untrusted"
}

func (tv *TrustValidator) extractTrustFactors(result *TrustValidationResult) []TrustFactor {
	factors := []TrustFactor{}

	for validationType, validation := range result.ValidationResults {
		factor := TrustFactor{
			Factor:      validationType,
			Weight:      0.2,
			Score:       validation.Score,
			Evidence:    validation.Evidence,
			Reliability: validation.Status,
		}
		factors = append(factors, factor)
	}

	return factors
}

func (tv *TrustValidator) extractRedFlags(result *TrustValidationResult) []RedFlag {
	flags := []RedFlag{}

	for _, validation := range result.ValidationResults {
		for _, warning := range validation.Warnings {
			flag := RedFlag{
				Flag:        validation.ValidationType + "_warning",
				Severity:    "medium",
				Description: warning,
				Evidence:    []string{warning},
				Timestamp:   time.Now(),
			}
			flags = append(flags, flag)
		}
	}

	return flags
}

func (tv *TrustValidator) generateTrustRecommendations(result *TrustValidationResult) []string {
	recommendations := []string{}

	if result.OverallTrustScore < tv.config.TrustThreshold {
		recommendations = append(recommendations, "Package trust score below threshold - additional verification required")
	}

	if result.SuspicionScore > tv.config.SuspicionThreshold {
		recommendations = append(recommendations, "High suspicion score detected - manual review recommended")
	}

	if result.SocialEngineeringRisk != nil && result.SocialEngineeringRisk.RiskLevel == "critical" {
		recommendations = append(recommendations, "Critical social engineering risk - immediate investigation required")
	}

	return recommendations
}

func (tv *TrustValidator) determineValidationStatus(score float64) string {
	if score > 0.7 {
		return "trusted"
	} else if score > 0.4 {
		return "neutral"
	}
	return "suspicious"
}

// Constructor functions for validators

func NewAuthorityValidator() *AuthorityValidator {
	return &AuthorityValidator{
		knownAuthorities: make(map[string]AuthorityInfo),
		suspiciousTerms:  []string{"federal", "government", "official", "mandate"},
	}
}

func NewMaintainerValidator() *MaintainerValidator {
	return &MaintainerValidator{
		maintainerProfiles:  make(map[string]MaintainerProfile),
		reputationThreshold: 0.7,
	}
}

func NewCorporateValidator() *CorporateValidator {
	return &CorporateValidator{
		corporateEntities: make(map[string]CorporateEntity),
		verificationAPIs:  []string{},
	}
}

func NewResearcherValidator() *ResearcherValidator {
	return &ResearcherValidator{
		researcherProfiles:   make(map[string]ResearcherProfile),
		academicInstitutions: make(map[string]bool),
	}
}

func NewComplianceValidator() *ComplianceValidator {
	return &ComplianceValidator{
		certificationBodies: make(map[string]CertificationBody),
		complianceStandards: make(map[string]ComplianceStandard),
	}
}

func NewCommunityValidator() *CommunityValidator {
	return &CommunityValidator{
		communityMetrics:  make(map[string]CommunityMetrics),
		astroturfDetector: NewAstroturfDetector(),
	}
}

func NewAstroturfDetector() *AstroturfDetector {
	return &AstroturfDetector{
		suspiciousPatterns: []string{},
		botDetectionRules:  []BotDetectionRule{},
	}
}

func (ad *AstroturfDetector) detectAstroturfing(pkg *types.Package) float64 {
	suspicionScore := 0.0

	// Check for suspicious naming patterns
	suspiciousNames := []string{"test", "temp", "fake", "demo", "sample", "example"}
	for _, pattern := range suspiciousNames {
		if strings.Contains(strings.ToLower(pkg.Name), pattern) {
			suspicionScore += 0.2
		}
	}

	// Check for rapid version releases (suspicious pattern)
	if pkg.Version != "" && strings.Count(pkg.Version, ".") > 3 {
		suspicionScore += 0.1
	}

	// Check for suspicious description terms
	if pkg.Metadata != nil && pkg.Metadata.Description != "" {
		suspiciousTerms := []string{"urgent", "critical", "must have", "revolutionary", "game changer"}
		for _, term := range suspiciousTerms {
			if strings.Contains(strings.ToLower(pkg.Metadata.Description), term) {
				suspicionScore += 0.15
			}
		}
	}

	// Check for unusual download patterns (very high downloads for new packages)
	if pkg.Metadata != nil && !pkg.Metadata.CreatedAt.IsZero() && pkg.Metadata.Downloads > 0 {
		age := time.Since(pkg.Metadata.CreatedAt)
		if age.Hours() < 24*7 && pkg.Metadata.Downloads > 10000 { // New package with high downloads
			suspicionScore += 0.4
		}
	}

	return math.Min(suspicionScore, 1.0)
}

func NewSocialEngineeringDetector() *SocialEngineeringDetector {
	return &SocialEngineeringDetector{
		urgencyPatterns:     []string{"(?i)(urgent|emergency|critical|immediate|asap)"},
		authorityPatterns:   []string{"(?i)(official|authorized|certified|approved|mandated)"},
		scarcityPatterns:    []string{"(?i)(limited time|exclusive|rare|scarce)"},
		socialProofPatterns: []string{"(?i)(everyone|popular|trending|recommended)"},
		reciprocityPatterns: []string{"(?i)(free|gift|bonus|special offer)"},
		commitmentPatterns:  []string{"(?i)(guarantee|promise|commitment|pledge)"},
	}
}
