package output

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/Alivanroy/Typosentinel/internal/analyzer"
	"github.com/Alivanroy/Typosentinel/pkg/types"
)

// SARIF represents the Static Analysis Results Interchange Format
type SARIF struct {
	Version string `json:"version"`
	Schema  string `json:"$schema"`
	Runs    []Run  `json:"runs"`
}

// Run represents a single run of the analysis tool
type Run struct {
	Tool        Tool         `json:"tool"`
	Results     []Result     `json:"results"`
	Artifacts   []Artifact   `json:"artifacts,omitempty"`
	Invocations []Invocation `json:"invocations,omitempty"`
	Properties  *Properties  `json:"properties,omitempty"`
}

// Tool represents the analysis tool information
type Tool struct {
	Driver Driver `json:"driver"`
}

// Driver represents the tool driver information
type Driver struct {
	Name            string `json:"name"`
	Version         string `json:"version"`
	InformationUri  string `json:"informationUri,omitempty"`
	Organization    string `json:"organization,omitempty"`
	SemanticVersion string `json:"semanticVersion,omitempty"`
	Rules           []Rule `json:"rules,omitempty"`
}

// Rule represents a rule definition
type Rule struct {
	ID                   string          `json:"id"`
	Name                 string          `json:"name,omitempty"`
	ShortDescription     *Message        `json:"shortDescription,omitempty"`
	FullDescription      *Message        `json:"fullDescription,omitempty"`
	Help                 *Message        `json:"help,omitempty"`
	HelpUri              string          `json:"helpUri,omitempty"`
	Properties           *RuleProperties `json:"properties,omitempty"`
	DefaultConfiguration *Configuration  `json:"defaultConfiguration,omitempty"`
}

// RuleProperties represents rule-specific properties
type RuleProperties struct {
	Severity    string   `json:"severity,omitempty"`
	Category    string   `json:"category,omitempty"`
	Tags        []string `json:"tags,omitempty"`
	Precision   string   `json:"precision,omitempty"`
	ProblemKind string   `json:"problem.kind,omitempty"`
}

// Configuration represents rule configuration
type Configuration struct {
	Level string `json:"level"`
}

// Result represents a single analysis result
type Result struct {
	RuleID              string               `json:"ruleId"`
	RuleIndex           int                  `json:"ruleIndex,omitempty"`
	Message             Message              `json:"message"`
	Level               string               `json:"level"`
	Locations           []Location           `json:"locations,omitempty"`
	PartialFingerprints *PartialFingerprints `json:"partialFingerprints,omitempty"`
	Properties          *ResultProperties    `json:"properties,omitempty"`
}

// Message represents a message with text
type Message struct {
	Text string `json:"text"`
}

// Location represents a location in the source code
type Location struct {
	PhysicalLocation *PhysicalLocation `json:"physicalLocation,omitempty"`
	LogicalLocations []LogicalLocation `json:"logicalLocations,omitempty"`
}

// PhysicalLocation represents a physical location in a file
type PhysicalLocation struct {
	ArtifactLocation *ArtifactLocation `json:"artifactLocation,omitempty"`
	Region           *Region           `json:"region,omitempty"`
}

// ArtifactLocation represents the location of an artifact
type ArtifactLocation struct {
	URI   string `json:"uri"`
	Index int    `json:"index,omitempty"`
}

// Region represents a region in a file
type Region struct {
	StartLine   int `json:"startLine,omitempty"`
	StartColumn int `json:"startColumn,omitempty"`
	EndLine     int `json:"endLine,omitempty"`
	EndColumn   int `json:"endColumn,omitempty"`
}

// LogicalLocation represents a logical location
type LogicalLocation struct {
	Name               string `json:"name,omitempty"`
	FullyQualifiedName string `json:"fullyQualifiedName,omitempty"`
	Kind               string `json:"kind,omitempty"`
}

// PartialFingerprints represents partial fingerprints for result matching
type PartialFingerprints struct {
	PrimaryLocationLineHash string `json:"primaryLocationLineHash,omitempty"`
}

// EvidenceInfo represents evidence supporting a threat detection
type EvidenceInfo struct {
	Type        string      `json:"type"`
	Description string      `json:"description"`
	Value       interface{} `json:"value"`
	Score       float64     `json:"score,omitempty"`
	Confidence  float64     `json:"confidence,omitempty"`
}

// ResultProperties represents result-specific properties
type ResultProperties struct {
	Severity        string                 `json:"severity,omitempty"`
	Confidence      string                 `json:"confidence,omitempty"`
	PackageName     string                 `json:"packageName,omitempty"`
	PackageVersion  string                 `json:"packageVersion,omitempty"`
	VulnerabilityID string                 `json:"vulnerabilityId,omitempty"`
	ThreatType      string                 `json:"threatType,omitempty"`
	Registry        string                 `json:"registry,omitempty"`
	DetectionMethod string                 `json:"detectionMethod,omitempty"`
	SimilarTo       string                 `json:"similarTo,omitempty"`
	Recommendation  string                 `json:"recommendation,omitempty"`
	CVEs            []string               `json:"cves,omitempty"`
	References      []string               `json:"references,omitempty"`
	Evidence        []EvidenceInfo         `json:"evidence,omitempty"`
	ThreatMetadata  map[string]interface{} `json:"threatMetadata,omitempty"`
	RiskScore       float64                `json:"riskScore,omitempty"`
}

// Artifact represents a file or other artifact
type Artifact struct {
	Location            *ArtifactLocation `json:"location"`
	Length              int64             `json:"length,omitempty"`
	MimeType            string            `json:"mimeType,omitempty"`
	Hashes              map[string]string `json:"hashes,omitempty"`
	LastModifiedTimeUtc string            `json:"lastModifiedTimeUtc,omitempty"`
}

// Invocation represents a tool invocation
type Invocation struct {
	ExecutionSuccessful bool              `json:"executionSuccessful"`
	StartTimeUtc        string            `json:"startTimeUtc,omitempty"`
	EndTimeUtc          string            `json:"endTimeUtc,omitempty"`
	ExitCode            int               `json:"exitCode,omitempty"`
	CommandLine         string            `json:"commandLine,omitempty"`
	Arguments           []string          `json:"arguments,omitempty"`
	WorkingDirectory    *ArtifactLocation `json:"workingDirectory,omitempty"`
}

// Properties represents additional properties
type Properties struct {
	RepositoryURL string                 `json:"repositoryUrl,omitempty"`
	Branch        string                 `json:"branch,omitempty"`
	CommitSHA     string                 `json:"commitSha,omitempty"`
	ScanType      string                 `json:"scanType,omitempty"`
	Metrics       map[string]interface{} `json:"metrics,omitempty"`
	// Enterprise metadata
	Enterprise *EnterpriseMetadata `json:"enterprise,omitempty"`
}

// EnterpriseMetadata represents enterprise-specific metadata
type EnterpriseMetadata struct {
	OrganizationID       string       `json:"organizationId,omitempty"`
	TenantID             string       `json:"tenantId,omitempty"`
	ScannerVersion       string       `json:"scannerVersion,omitempty"`
	PolicyVersion        string       `json:"policyVersion,omitempty"`
	ComplianceFrameworks []string     `json:"complianceFrameworks,omitempty"`
	RiskScore            float64      `json:"riskScore,omitempty"`
	ScanContext          *ScanContext `json:"scanContext,omitempty"`
	AuditTrail           *AuditTrail  `json:"auditTrail,omitempty"`
}

// ScanContext represents the context in which the scan was performed
type ScanContext struct {
	InitiatedBy   string `json:"initiatedBy,omitempty"`
	ScanReason    string `json:"scanReason,omitempty"`
	ScheduledScan bool   `json:"scheduledScan"`
	CICDPipeline  string `json:"cicdPipeline,omitempty"`
	Environment   string `json:"environment,omitempty"`
	ProjectID     string `json:"projectId,omitempty"`
}

// AuditTrail represents audit information for compliance
type AuditTrail struct {
	ScanID             string `json:"scanId,omitempty"`
	ApprovalStatus     string `json:"approvalStatus,omitempty"`
	ApprovedBy         string `json:"approvedBy,omitempty"`
	ApprovalTime       string `json:"approvalTime,omitempty"`
	RetentionPolicy    string `json:"retentionPolicy,omitempty"`
	DataClassification string `json:"dataClassification,omitempty"`
}

// SARIFFormatter implements SARIF output format
type SARIFFormatter struct {
	RepositoryURL string
	Branch        string
	CommitSHA     string
	ScanType      string
	// Enterprise fields
	EnterpriseMetadata *EnterpriseMetadata
}

// NewSARIFFormatter creates a new SARIF formatter
func NewSARIFFormatter(repoURL, branch, commitSHA, scanType string) *SARIFFormatter {
	return &SARIFFormatter{
		RepositoryURL: repoURL,
		Branch:        branch,
		CommitSHA:     commitSHA,
		ScanType:      scanType,
	}
}

// NewEnterpriseSARIFFormatter creates a new SARIF formatter with enterprise metadata
func NewEnterpriseSARIFFormatter(repoURL, branch, commitSHA, scanType string, enterpriseMetadata *EnterpriseMetadata) *SARIFFormatter {
	return &SARIFFormatter{
		RepositoryURL:      repoURL,
		Branch:             branch,
		CommitSHA:          commitSHA,
		ScanType:           scanType,
		EnterpriseMetadata: enterpriseMetadata,
	}
}

// Format converts scan results to SARIF format
func (f *SARIFFormatter) Format(results *analyzer.ScanResult) ([]byte, error) {
	startTime := time.Now().UTC()

	sarif := &SARIF{
		Version: "2.1.0",
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		Runs: []Run{
			{
				Tool: Tool{
					Driver: Driver{
						Name:            "TypoSentinel",
						Version:         "2.0.0",
						InformationUri:  "https://github.com/Alivanroy/Typosentinel",
						Organization:    "TypoSentinel Security",
						SemanticVersion: "2.0.0",
						Rules:           f.generateRules(),
					},
				},
				Results:   f.convertResults(results),
				Artifacts: f.generateArtifacts(results),
				Invocations: []Invocation{
					{
						ExecutionSuccessful: true,
						StartTimeUtc:        startTime.Format(time.RFC3339),
						EndTimeUtc:          time.Now().UTC().Format(time.RFC3339),
						ExitCode:            0,
						CommandLine:         "typosentinel scan",
					},
				},
				Properties: &Properties{
					RepositoryURL: f.RepositoryURL,
					Branch:        f.Branch,
					CommitSHA:     f.CommitSHA,
					ScanType:      f.ScanType,
					Metrics: map[string]interface{}{
						"totalPackages":  results.TotalPackages,
						"totalThreats":   len(results.Threats),
						"criticalIssues": f.countBySeverity(results, "critical"),
						"highIssues":     f.countBySeverity(results, "high"),
						"mediumIssues":   f.countBySeverity(results, "medium"),
						"lowIssues":      f.countBySeverity(results, "low"),
					},
					Enterprise: f.EnterpriseMetadata,
				},
			},
		},
	}

	return json.MarshalIndent(sarif, "", "  ")
}

// generateRules creates SARIF rules for different vulnerability types
func (f *SARIFFormatter) generateRules() []Rule {
	return []Rule{
		{
			ID:               "TYPO_SQUATTING",
			Name:             "Typosquatting Detection",
			ShortDescription: &Message{Text: "Potential typosquatting package detected"},
			FullDescription:  &Message{Text: "This package name is similar to a popular package and may be a typosquatting attempt"},
			Help:             &Message{Text: "Verify the package name and publisher before using. Consider using the official package instead."},
			HelpUri:          "https://github.com/Alivanroy/Typosentinel/blob/main/docs/typosquatting.md",
			Properties: &RuleProperties{
				Severity:    "high",
				Category:    "security",
				Tags:        []string{"security", "supply-chain", "typosquatting"},
				Precision:   "high",
				ProblemKind: "problem",
			},
			DefaultConfiguration: &Configuration{Level: "warning"},
		},
		{
			ID:               "MALICIOUS_PACKAGE",
			Name:             "Malicious Package Detection",
			ShortDescription: &Message{Text: "Potentially malicious package detected"},
			FullDescription:  &Message{Text: "This package has been identified as potentially malicious based on various indicators"},
			Help:             &Message{Text: "Remove this package immediately and scan your system for potential compromise."},
			HelpUri:          "https://github.com/Alivanroy/Typosentinel/blob/main/docs/malicious-packages.md",
			Properties: &RuleProperties{
				Severity:    "critical",
				Category:    "security",
				Tags:        []string{"security", "malware", "supply-chain"},
				Precision:   "high",
				ProblemKind: "problem",
			},
			DefaultConfiguration: &Configuration{Level: "error"},
		},
		{
			ID:               "VULNERABILITY",
			Name:             "Known Vulnerability",
			ShortDescription: &Message{Text: "Package contains known vulnerabilities"},
			FullDescription:  &Message{Text: "This package version contains known security vulnerabilities"},
			Help:             &Message{Text: "Update to a patched version or find an alternative package."},
			HelpUri:          "https://github.com/Alivanroy/Typosentinel/blob/main/docs/vulnerabilities.md",
			Properties: &RuleProperties{
				Severity:    "high",
				Category:    "security",
				Tags:        []string{"security", "vulnerability", "cve"},
				Precision:   "high",
				ProblemKind: "problem",
			},
			DefaultConfiguration: &Configuration{Level: "warning"},
		},
		{
			ID:               "SUSPICIOUS_BEHAVIOR",
			Name:             "Suspicious Package Behavior",
			ShortDescription: &Message{Text: "Package exhibits suspicious behavior"},
			FullDescription:  &Message{Text: "This package exhibits behavior patterns that may indicate malicious intent"},
			Help:             &Message{Text: "Review the package source code and consider alternatives."},
			HelpUri:          "https://github.com/Alivanroy/Typosentinel/blob/main/docs/suspicious-behavior.md",
			Properties: &RuleProperties{
				Severity:    "medium",
				Category:    "security",
				Tags:        []string{"security", "behavior", "analysis"},
				Precision:   "medium",
				ProblemKind: "problem",
			},
			DefaultConfiguration: &Configuration{Level: "note"},
		},
	}
}

// convertResults converts analyzer results to SARIF results
func (f *SARIFFormatter) convertResults(scanResult *analyzer.ScanResult) []Result {
	var results []Result
	ruleMap := map[string]int{
		"TYPO_SQUATTING":      0,
		"MALICIOUS_PACKAGE":   1,
		"VULNERABILITY":       2,
		"SUSPICIOUS_BEHAVIOR": 3,
	}

	// Convert threats to SARIF results
	for _, threat := range scanResult.Threats {
		ruleID := f.determineRuleIDFromThreat(threat)
		level := f.determineSeverityLevel(threat.Severity.String())

		result := Result{
			RuleID:    ruleID,
			RuleIndex: ruleMap[ruleID],
			Message: Message{
				Text: fmt.Sprintf("Package '%s' version '%s': %s", threat.Package, threat.Version, threat.Description),
			},
			Level: level,
			Locations: []Location{
				{
					LogicalLocations: []LogicalLocation{
						{
							Name:               threat.Package,
							FullyQualifiedName: fmt.Sprintf("%s@%s", threat.Package, threat.Version),
							Kind:               "package",
						},
					},
				},
			},
			PartialFingerprints: &PartialFingerprints{
				PrimaryLocationLineHash: fmt.Sprintf("%s:%s:%s", threat.Package, threat.Version, threat.ID),
			},
			Properties: &ResultProperties{
				Severity:        threat.Severity.String(),
				Confidence:      fmt.Sprintf("%.2f", threat.Confidence),
				PackageName:     threat.Package,
				PackageVersion:  threat.Version,
				VulnerabilityID: f.extractVulnerabilityID(threat),
				ThreatType:      string(threat.Type),
				Registry:        threat.Registry,
				DetectionMethod: threat.DetectionMethod,
				SimilarTo:       threat.SimilarTo,
				Recommendation:  threat.Recommendation,
				CVEs:            threat.CVEs,
				References:      threat.References,
				Evidence:        f.convertEvidence(threat.Evidence),
				ThreatMetadata:  threat.Metadata,
				RiskScore:       f.calculateRiskScore(threat),
			},
		}

		results = append(results, result)
	}

	return results
}

// generateArtifacts creates SARIF artifacts from scan results
func (f *SARIFFormatter) generateArtifacts(scanResult *analyzer.ScanResult) []Artifact {
	var artifacts []Artifact
	fileMap := make(map[string]bool)

	// Add the main scan path as an artifact
	if scanResult.Path != "" && !fileMap[scanResult.Path] {
		fileMap[scanResult.Path] = true
		artifacts = append(artifacts, Artifact{
			Location: &ArtifactLocation{
				URI: scanResult.Path,
			},
			MimeType: f.getMimeType(scanResult.Path),
		})
	}

	return artifacts
}

// determineRuleIDFromThreat determines the appropriate rule ID based on threat type
func (f *SARIFFormatter) determineRuleIDFromThreat(threat types.Threat) string {
	switch threat.Type {
	case types.ThreatTypeMaliciousPackage, types.ThreatTypeMalicious:
		return "MALICIOUS_PACKAGE"
	case types.ThreatTypeTyposquatting:
		return "TYPO_SQUATTING"
	case types.ThreatTypeVulnerable:
		return "VULNERABILITY"
	default:
		return "SUSPICIOUS_BEHAVIOR"
	}
}

// determineSeverityLevel converts severity to SARIF level
func (f *SARIFFormatter) determineSeverityLevel(severity string) string {
	switch severity {
	case "critical":
		return "error"
	case "high":
		return "error"
	case "medium":
		return "warning"
	case "low":
		return "note"
	default:
		return "info"
	}
}

// countBySeverity counts issues by severity level
func (f *SARIFFormatter) countBySeverity(scanResult *analyzer.ScanResult, severity string) int {
	count := 0
	for _, threat := range scanResult.Threats {
		if threat.Severity.String() == severity {
			count++
		}
	}
	return count
}

// getMimeType returns the MIME type for a file based on its extension
func (f *SARIFFormatter) getMimeType(filePath string) string {
	switch {
	case contains(filePath, ".json"):
		return "application/json"
	case contains(filePath, ".yaml") || contains(filePath, ".yml"):
		return "application/x-yaml"
	case contains(filePath, ".xml"):
		return "application/xml"
	case contains(filePath, ".toml"):
		return "application/toml"
	default:
		return "text/plain"
	}
}

// contains checks if a string contains a substring
func contains(s, substr string) bool {
	return len(s) >= len(substr) && s[len(s)-len(substr):] == substr
}

// extractVulnerabilityID extracts vulnerability ID from threat CVEs
func (f *SARIFFormatter) extractVulnerabilityID(threat types.Threat) string {
	if len(threat.CVEs) > 0 {
		return threat.CVEs[0]
	}
	return threat.ID
}

// convertEvidence converts threat evidence to SARIF evidence format
func (f *SARIFFormatter) convertEvidence(evidence []types.Evidence) []EvidenceInfo {
	var sarifEvidence []EvidenceInfo
	for _, e := range evidence {
		sarifEvidence = append(sarifEvidence, EvidenceInfo{
			Type:        e.Type,
			Description: e.Description,
			Value:       e.Value,
			Score:       e.Score,
		})
	}
	return sarifEvidence
}

// calculateRiskScore calculates a risk score based on threat properties
func (f *SARIFFormatter) calculateRiskScore(threat types.Threat) float64 {
	baseScore := threat.Confidence

	// Adjust score based on severity
	switch threat.Severity.String() {
	case "critical":
		baseScore *= 1.0
	case "high":
		baseScore *= 0.8
	case "medium":
		baseScore *= 0.6
	case "low":
		baseScore *= 0.4
	default:
		baseScore *= 0.2
	}

	// Adjust for CVEs
	if len(threat.CVEs) > 0 {
		baseScore *= 1.2
	}

	// Ensure score is between 0 and 1
	if baseScore > 1.0 {
		baseScore = 1.0
	}

	return baseScore
}
