package types

import (
	"time"
)

// SupplyChainScanRequest represents a request for supply chain security scanning
type SupplyChainScanRequest struct {
	Target      string                 `json:"target" binding:"required"`
	ScanType    SupplyChainScanType    `json:"scan_type"`
	Options     SupplyChainScanOptions `json:"options"`
	CallbackURL string                 `json:"callback_url,omitempty"`
}

// SupplyChainScanType defines the type of supply chain scan
type SupplyChainScanType string

const (
	ScanTypeAdvanced       SupplyChainScanType = "advanced"
	ScanTypeBuildIntegrity SupplyChainScanType = "build_integrity"
	ScanTypeGraphAnalysis  SupplyChainScanType = "graph_analysis"
	ScanTypeThreatIntel    SupplyChainScanType = "threat_intel"
	ScanTypeHoneypot       SupplyChainScanType = "honeypot"
	ScanTypeCompliance     SupplyChainScanType = "compliance"
)

// SupplyChainScanOptions contains options for supply chain scanning
type SupplyChainScanOptions struct {
	DeepAnalysis        bool                    `json:"deep_analysis"`
	IncludeDev          bool                    `json:"include_dev"`
	MaxDepth            int                     `json:"max_depth"`
	ThreatIntelEnabled  bool                    `json:"threat_intel_enabled"`
	BuildIntegrity      bool                    `json:"build_integrity"`
	GraphAnalysis       bool                    `json:"graph_analysis"`
	HoneypotDetection   bool                    `json:"honeypot_detection"`
	ComplianceCheck     bool                    `json:"compliance_check"`
	SensitivityLevel    SensitivityLevel        `json:"sensitivity_level"`
	CustomRules         []CustomDetectionRule  `json:"custom_rules,omitempty"`
	ExcludePatterns     []string                `json:"exclude_patterns,omitempty"`
	Timeout             time.Duration           `json:"timeout"`
}

// SensitivityLevel defines the sensitivity level for detection
type SensitivityLevel string

const (
	SensitivityLow      SensitivityLevel = "low"
	SensitivityMedium   SensitivityLevel = "medium"
	SensitivityHigh     SensitivityLevel = "high"
	SensitivityCritical SensitivityLevel = "critical"
)

// SupplyChainScanResult represents the result of a supply chain scan
type SupplyChainScanResult struct {
	ScanID           string                    `json:"scan_id"`
	Target           string                    `json:"target"`
	ScanType         SupplyChainScanType       `json:"scan_type"`
	Status           ScanStatus                `json:"status"`
	StartTime        time.Time                 `json:"start_time"`
	EndTime          *time.Time                `json:"end_time,omitempty"`
	Duration         time.Duration             `json:"duration"`
	RiskScore        float64                   `json:"risk_score"`
	RiskLevel        RiskLevel                 `json:"risk_level"`
	Findings         []SupplyChainFinding      `json:"findings"`
	DependencyGraph  *DependencyGraph          `json:"dependency_graph,omitempty"`
	BuildIntegrity   *BuildIntegrityResult     `json:"build_integrity,omitempty"`
	ThreatIntel      *ThreatIntelligenceResult `json:"threat_intel,omitempty"`
	Compliance       *ComplianceResult         `json:"compliance,omitempty"`
	Metadata         ScanMetadata              `json:"metadata"`
	Recommendations  []Recommendation          `json:"recommendations"`
}

// Note: ScanStatus and RiskLevel are already defined in types.go

// SupplyChainFinding represents a security finding in the supply chain
type SupplyChainFinding struct {
	ID              string                 `json:"id"`
	Type            FindingType            `json:"type"`
	Severity        RiskLevel              `json:"severity"`
	Title           string                 `json:"title"`
	Description     string                 `json:"description"`
	Package         PackageInfo            `json:"package"`
	Vulnerability   *VulnerabilityInfo     `json:"vulnerability,omitempty"`
	ThreatIntel     *ThreatIntelInfo       `json:"threat_intel,omitempty"`
	BuildIntegrity  *BuildIntegrityInfo    `json:"build_integrity,omitempty"`
	Evidence        []SupplyChainEvidence  `json:"evidence"`
	Remediation     RemediationAdvice      `json:"remediation"`
	CVSS            *CVSSScore             `json:"cvss,omitempty"`
	CWE             []string               `json:"cwe,omitempty"`
	References      []Reference            `json:"references"`
	FirstSeen       time.Time              `json:"first_seen"`
	LastUpdated     time.Time              `json:"last_updated"`
	Confidence      float64                `json:"confidence"`
	FalsePositive   bool                   `json:"false_positive"`
}

// FindingType represents the type of security finding
type FindingType string

const (
	FindingTypeVulnerability      FindingType = "vulnerability"
	FindingTypeMaliciousPackage   FindingType = "malicious_package"
	FindingTypeTyposquatting      FindingType = "typosquatting"
	FindingTypeDependencyConfusion FindingType = "dependency_confusion"
	FindingTypeBuildIntegrity     FindingType = "build_integrity"
	FindingTypeLicenseViolation   FindingType = "license_violation"
	FindingTypeOutdatedDependency FindingType = "outdated_dependency"
	FindingTypeSuspiciousMaintainer FindingType = "suspicious_maintainer"
	FindingTypeHoneypot           FindingType = "honeypot"
	FindingTypeSupplyChainAttack  FindingType = "supply_chain_attack"
	FindingTypeComplianceViolation FindingType = "compliance_violation"
)

// PackageInfo contains information about a package
type PackageInfo struct {
	Name         string            `json:"name"`
	Version      string            `json:"version"`
	Ecosystem    string            `json:"ecosystem"`
	PURL         string            `json:"purl,omitempty"`
	Repository   string            `json:"repository,omitempty"`
	Homepage     string            `json:"homepage,omitempty"`
	License      string            `json:"license,omitempty"`
	Maintainers  []Maintainer      `json:"maintainers,omitempty"`
	Dependencies []SupplyChainDependency `json:"dependencies,omitempty"`
	Metadata     map[string]interface{} `json:"metadata,omitempty"`
	Checksums    map[string]string `json:"checksums,omitempty"`
	Signatures   []Signature       `json:"signatures,omitempty"`
}

// Maintainer represents a package maintainer
type Maintainer struct {
	Name     string    `json:"name"`
	Email    string    `json:"email,omitempty"`
	Username string    `json:"username,omitempty"`
	URL      string    `json:"url,omitempty"`
	Since    time.Time `json:"since,omitempty"`
	Role     string    `json:"role,omitempty"`
	Verified bool      `json:"verified"`
}

// SupplyChainDependency extends the base Dependency type with supply chain specific fields
type SupplyChainDependency struct {
	Dependency   // Embed the existing Dependency type
	VersionRange string            `json:"version_range,omitempty"`
	Ecosystem    string            `json:"ecosystem"`
	Scope        DependencyScope   `json:"scope"`
	Optional     bool              `json:"optional"`
	Depth        int               `json:"depth"`
	PURL         string            `json:"purl,omitempty"`
	License      string            `json:"license,omitempty"`
	RiskScore    float64           `json:"risk_score"`
}

// DependencyScope represents the scope of a dependency
type DependencyScope string

const (
	ScopeRuntime     DependencyScope = "runtime"
	ScopeDevelopment DependencyScope = "development"
	ScopeTest        DependencyScope = "test"
	ScopeBuild       DependencyScope = "build"
	ScopeOptional    DependencyScope = "optional"
)

// Signature represents a cryptographic signature
type Signature struct {
	Algorithm   string    `json:"algorithm"`
	Value       string    `json:"value"`
	KeyID       string    `json:"key_id,omitempty"`
	Signer      string    `json:"signer,omitempty"`
	Timestamp   time.Time `json:"timestamp"`
	Valid       bool      `json:"valid"`
	TrustLevel  string    `json:"trust_level"`
}

// VulnerabilityInfo contains detailed vulnerability information
type VulnerabilityInfo struct {
	CVE         string              `json:"cve,omitempty"`
	GHSA        string              `json:"ghsa,omitempty"`
	OSV         string              `json:"osv,omitempty"`
	Title       string              `json:"title"`
	Description string              `json:"description"`
	Severity    RiskLevel           `json:"severity"`
	CVSS        *CVSSScore          `json:"cvss,omitempty"`
	CWE         []string            `json:"cwe,omitempty"`
	Affected    []AffectedVersion   `json:"affected"`
	Fixed       []string            `json:"fixed,omitempty"`
	Patched     []string            `json:"patched,omitempty"`
	Published   time.Time           `json:"published"`
	Modified    time.Time           `json:"modified"`
	Withdrawn   *time.Time          `json:"withdrawn,omitempty"`
	References  []Reference         `json:"references"`
	Credits     []Credit            `json:"credits,omitempty"`
	Exploits    []ExploitInfo       `json:"exploits,omitempty"`
}

// CVSSScore represents CVSS scoring information
type CVSSScore struct {
	Version string  `json:"version"`
	Vector  string  `json:"vector"`
	Score   float64 `json:"score"`
	Severity string `json:"severity"`
}

// AffectedVersion represents version ranges affected by a vulnerability
type AffectedVersion struct {
	Ecosystem string            `json:"ecosystem"`
	Package   string            `json:"package"`
	Ranges    []VersionRange    `json:"ranges"`
	Versions  []string          `json:"versions,omitempty"`
	Database  string            `json:"database,omitempty"`
}

// Note: VersionRange and VersionEvent are already defined in types.go

// Reference represents an external reference
type Reference struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}

// Credit represents credit information for vulnerability discovery
type Credit struct {
	Name    string   `json:"name"`
	Contact []string `json:"contact,omitempty"`
	Type    string   `json:"type,omitempty"`
}

// ExploitInfo contains information about known exploits
type ExploitInfo struct {
	Type        string    `json:"type"`
	Description string    `json:"description"`
	URL         string    `json:"url,omitempty"`
	Published   time.Time `json:"published"`
	Severity    string    `json:"severity"`
	InTheWild   bool      `json:"in_the_wild"`
}

// ThreatIntelInfo contains threat intelligence information
type ThreatIntelInfo struct {
	Source      string                 `json:"source"`
	ThreatType  string                 `json:"threat_type"`
	Confidence  float64                `json:"confidence"`
	Severity    RiskLevel              `json:"severity"`
	Description string                 `json:"description"`
	IOCs        []IndicatorOfCompromise `json:"iocs,omitempty"`
	TTP         []ThreatTactic         `json:"ttp,omitempty"`
	Attribution *ThreatAttribution     `json:"attribution,omitempty"`
	FirstSeen   time.Time              `json:"first_seen"`
	LastSeen    time.Time              `json:"last_seen"`
	Active      bool                   `json:"active"`
}

// IndicatorOfCompromise represents an IoC
type IndicatorOfCompromise struct {
	Type        string    `json:"type"`
	Value       string    `json:"value"`
	Description string    `json:"description,omitempty"`
	Confidence  float64   `json:"confidence"`
	FirstSeen   time.Time `json:"first_seen"`
	LastSeen    time.Time `json:"last_seen"`
}

// ThreatTactic represents threat tactics, techniques, and procedures
type ThreatTactic struct {
	Tactic     string `json:"tactic"`
	Technique  string `json:"technique"`
	Procedure  string `json:"procedure,omitempty"`
	MITREID    string `json:"mitre_id,omitempty"`
	Description string `json:"description"`
}

// ThreatAttribution contains threat attribution information
type ThreatAttribution struct {
	Actor       string   `json:"actor,omitempty"`
	Group       string   `json:"group,omitempty"`
	Campaign    string   `json:"campaign,omitempty"`
	Motivation  string   `json:"motivation,omitempty"`
	Country     string   `json:"country,omitempty"`
	Confidence  float64  `json:"confidence"`
	Aliases     []string `json:"aliases,omitempty"`
}

// BuildIntegrityInfo contains build integrity information
type BuildIntegrityInfo struct {
	Verified        bool                   `json:"verified"`
	ChecksumMatch   bool                   `json:"checksum_match"`
	SignatureValid  bool                   `json:"signature_valid"`
	Reproducible    bool                   `json:"reproducible"`
	BuildSystem     string                 `json:"build_system,omitempty"`
	BuildMetadata   map[string]interface{} `json:"build_metadata,omitempty"`
	Provenance      *BuildProvenance       `json:"provenance,omitempty"`
	Anomalies       []BuildAnomaly         `json:"anomalies,omitempty"`
	TrustScore      float64                `json:"trust_score"`
}

// BuildProvenance contains build provenance information
type BuildProvenance struct {
	Builder     string                 `json:"builder"`
	BuildID     string                 `json:"build_id"`
	Timestamp   time.Time              `json:"timestamp"`
	SourceRepo  string                 `json:"source_repo"`
	SourceRef   string                 `json:"source_ref"`
	SourceHash  string                 `json:"source_hash"`
	BuildConfig map[string]interface{} `json:"build_config,omitempty"`
	Materials   []BuildMaterial        `json:"materials,omitempty"`
	SLSALevel   int                    `json:"slsa_level"`
}

// BuildMaterial represents build materials/inputs
type BuildMaterial struct {
	URI    string            `json:"uri"`
	Digest map[string]string `json:"digest"`
}

// BuildAnomaly represents a build integrity anomaly
type BuildAnomaly struct {
	Type        string    `json:"type"`
	Description string    `json:"description"`
	Severity    RiskLevel `json:"severity"`
	Evidence    string    `json:"evidence,omitempty"`
}

// SupplyChainEvidence extends the base Evidence type with supply chain specific fields
type SupplyChainEvidence struct {
	Evidence    // Embed the existing Evidence type
	Data        map[string]interface{} `json:"data,omitempty"`
	Source      string                 `json:"source"`
	Timestamp   time.Time              `json:"timestamp"`
	Confidence  float64                `json:"confidence"`
}

// RemediationAdvice contains remediation advice for findings
type RemediationAdvice struct {
	Summary     string              `json:"summary"`
	Steps       []RemediationStep   `json:"steps"`
	Alternatives []string           `json:"alternatives,omitempty"`
	References  []Reference         `json:"references,omitempty"`
	Priority    RemediationPriority `json:"priority"`
	Effort      RemediationEffort   `json:"effort"`
	Impact      string              `json:"impact,omitempty"`
}

// RemediationStep represents a step in remediation
type RemediationStep struct {
	Order       int    `json:"order"`
	Description string `json:"description"`
	Command     string `json:"command,omitempty"`
	Automated   bool   `json:"automated"`
}

// RemediationPriority represents the priority of remediation
type RemediationPriority string

const (
	PriorityImmediate RemediationPriority = "immediate"
	PriorityHigh      RemediationPriority = "high"
	PriorityMedium    RemediationPriority = "medium"
	PriorityLow       RemediationPriority = "low"
)

// RemediationEffort represents the effort required for remediation
type RemediationEffort string

const (
	EffortMinimal   RemediationEffort = "minimal"
	EffortLow       RemediationEffort = "low"
	EffortMedium    RemediationEffort = "medium"
	EffortHigh      RemediationEffort = "high"
	EffortExtensive RemediationEffort = "extensive"
)

// DependencyGraph represents a dependency graph
type DependencyGraph struct {
	Nodes []GraphNode `json:"nodes"`
	Edges []GraphEdge `json:"edges"`
	Stats GraphStats  `json:"stats"`
}

// GraphNode represents a node in the dependency graph
type GraphNode struct {
	ID          string                 `json:"id"`
	Package     PackageInfo            `json:"package"`
	RiskScore   float64                `json:"risk_score"`
	Centrality  float64                `json:"centrality"`
	Depth       int                    `json:"depth"`
	Direct      bool                   `json:"direct"`
	Findings    []SupplyChainFinding   `json:"findings,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// GraphEdge represents an edge in the dependency graph
type GraphEdge struct {
	From         string          `json:"from"`
	To           string          `json:"to"`
	RelationType RelationType    `json:"relation_type"`
	VersionRange string          `json:"version_range,omitempty"`
	Scope        DependencyScope `json:"scope"`
	Optional     bool            `json:"optional"`
	Weight       float64         `json:"weight"`
}

// RelationType represents the type of relationship between packages
type RelationType string

const (
	RelationDependsOn RelationType = "depends_on"
	RelationDevDep    RelationType = "dev_dependency"
	RelationPeerDep   RelationType = "peer_dependency"
	RelationOptional  RelationType = "optional_dependency"
	RelationBundled   RelationType = "bundled_dependency"
)

// GraphStats contains statistics about the dependency graph
type GraphStats struct {
	TotalNodes      int     `json:"total_nodes"`
	TotalEdges      int     `json:"total_edges"`
	MaxDepth        int     `json:"max_depth"`
	DirectDeps      int     `json:"direct_deps"`
	TransitiveDeps  int     `json:"transitive_deps"`
	CyclicDeps      int     `json:"cyclic_deps"`
	AverageRisk     float64 `json:"average_risk"`
	HighRiskNodes   int     `json:"high_risk_nodes"`
}

// BuildIntegrityResult contains build integrity scan results
type BuildIntegrityResult struct {
	OverallScore    float64                    `json:"overall_score"`
	Verified        bool                       `json:"verified"`
	Checks          []BuildIntegrityCheck      `json:"checks"`
	Anomalies       []BuildAnomaly             `json:"anomalies"`
	Provenance      *BuildProvenance           `json:"provenance,omitempty"`
	Recommendations []Recommendation           `json:"recommendations"`
	Metadata        map[string]interface{}     `json:"metadata,omitempty"`
}

// BuildIntegrityCheck represents a build integrity check
type BuildIntegrityCheck struct {
	Name        string    `json:"name"`
	Type        string    `json:"type"`
	Status      string    `json:"status"`
	Score       float64   `json:"score"`
	Description string    `json:"description"`
	Details     string    `json:"details,omitempty"`
	Timestamp   time.Time `json:"timestamp"`
}

// ThreatIntelligenceResult contains threat intelligence results
type ThreatIntelligenceResult struct {
	OverallRisk     RiskLevel                  `json:"overall_risk"`
	ThreatScore     float64                    `json:"threat_score"`
	Threats         []ThreatIntelInfo          `json:"threats"`
	IOCs            []IndicatorOfCompromise    `json:"iocs"`
	Attribution     []ThreatAttribution        `json:"attribution,omitempty"`
	Recommendations []Recommendation           `json:"recommendations"`
	Sources         []string                   `json:"sources"`
	LastUpdated     time.Time                  `json:"last_updated"`
	Metadata        map[string]interface{}     `json:"metadata,omitempty"`
}

// ComplianceResult contains compliance check results
type ComplianceResult struct {
	OverallStatus   ComplianceStatus           `json:"overall_status"`
	Score           float64                    `json:"score"`
	Standards       []StandardCompliance       `json:"standards"`
	Violations      []ComplianceViolation      `json:"violations"`
	Recommendations []Recommendation           `json:"recommendations"`
	Metadata        map[string]interface{}     `json:"metadata,omitempty"`
}

// ComplianceStatus represents compliance status
type ComplianceStatus string

const (
	ComplianceStatusCompliant    ComplianceStatus = "compliant"
	ComplianceStatusNonCompliant ComplianceStatus = "non_compliant"
	ComplianceStatusPartial      ComplianceStatus = "partial"
	ComplianceStatusUnknown      ComplianceStatus = "unknown"
)

// StandardCompliance represents compliance with a specific standard
type StandardCompliance struct {
	Standard    string           `json:"standard"`
	Version     string           `json:"version"`
	Status      ComplianceStatus `json:"status"`
	Score       float64          `json:"score"`
	Controls    []ControlResult  `json:"controls"`
	LastChecked time.Time        `json:"last_checked"`
}

// ControlResult represents the result of a compliance control check
type ControlResult struct {
	ID          string           `json:"id"`
	Name        string           `json:"name"`
	Description string           `json:"description"`
	Status      ComplianceStatus `json:"status"`
	Evidence    []SupplyChainEvidence `json:"evidence,omitempty"`
	Remediation string           `json:"remediation,omitempty"`
}

// ComplianceViolation represents a compliance violation
type ComplianceViolation struct {
	Standard    string        `json:"standard"`
	Control     string        `json:"control"`
	Severity    RiskLevel     `json:"severity"`
	Description string        `json:"description"`
	Evidence    []SupplyChainEvidence `json:"evidence"`
	Remediation string        `json:"remediation"`
	Deadline    *time.Time    `json:"deadline,omitempty"`
}

// Recommendation represents a security recommendation
type Recommendation struct {
	ID          string                 `json:"id"`
	Type        RecommendationType     `json:"type"`
	Priority    RemediationPriority    `json:"priority"`
	Title       string                 `json:"title"`
	Description string                 `json:"description"`
	Actions     []RecommendationAction `json:"actions"`
	Impact      string                 `json:"impact"`
	Effort      RemediationEffort      `json:"effort"`
	References  []Reference            `json:"references,omitempty"`
}

// RecommendationType represents the type of recommendation
type RecommendationType string

const (
	RecommendationTypeUpdate      RecommendationType = "update"
	RecommendationTypeReplace     RecommendationType = "replace"
	RecommendationTypeRemove      RecommendationType = "remove"
	RecommendationTypeConfigure   RecommendationType = "configure"
	RecommendationTypeMonitor     RecommendationType = "monitor"
	RecommendationTypeInvestigate RecommendationType = "investigate"
)

// RecommendationAction represents an action within a recommendation
type RecommendationAction struct {
	Order       int    `json:"order"`
	Description string `json:"description"`
	Command     string `json:"command,omitempty"`
	Automated   bool   `json:"automated"`
	Required    bool   `json:"required"`
}

// ScanMetadata contains metadata about the scan
type ScanMetadata struct {
	ScannerVersion  string                 `json:"scanner_version"`
	RulesVersion    string                 `json:"rules_version"`
	DatabaseVersion string                 `json:"database_version"`
	ScanOptions     SupplyChainScanOptions `json:"scan_options"`
	Environment     map[string]string      `json:"environment,omitempty"`
	Statistics      ScanStatistics         `json:"statistics"`
}

// ScanStatistics contains scan statistics
type ScanStatistics struct {
	PackagesScanned     int           `json:"packages_scanned"`
	DependenciesFound   int           `json:"dependencies_found"`
	VulnerabilitiesFound int          `json:"vulnerabilities_found"`
	ThreatsDetected     int           `json:"threats_detected"`
	FindingsTotal       int           `json:"findings_total"`
	ScanDuration        time.Duration `json:"scan_duration"`
	CacheHits           int           `json:"cache_hits"`
	CacheMisses         int           `json:"cache_misses"`
	APICallsMade        int           `json:"api_calls_made"`
	ErrorsEncountered   int           `json:"errors_encountered"`
}

// CustomDetectionRule represents a custom detection rule
type CustomDetectionRule struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Type        string                 `json:"type"`
	Pattern     string                 `json:"pattern"`
	Severity    RiskLevel              `json:"severity"`
	Enabled     bool                   `json:"enabled"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// GraphAnalysisRequest represents a request for dependency graph analysis
type GraphAnalysisRequest struct {
	Target      string                    `json:"target" binding:"required"`
	Options     GraphAnalysisOptions      `json:"options"`
	Algorithms  []GraphAnalysisAlgorithm  `json:"algorithms"`
}

// GraphAnalysisOptions contains options for graph analysis
type GraphAnalysisOptions struct {
	MaxDepth        int  `json:"max_depth"`
	IncludeDev      bool `json:"include_dev"`
	IncludeOptional bool `json:"include_optional"`
	Visualization   bool `json:"visualization"`
	RiskPropagation bool `json:"risk_propagation"`
}

// GraphAnalysisAlgorithm represents a graph analysis algorithm
type GraphAnalysisAlgorithm string

const (
	AlgorithmShortestPath      GraphAnalysisAlgorithm = "shortest_path"
	AlgorithmCentrality        GraphAnalysisAlgorithm = "centrality"
	AlgorithmCommunityDetection GraphAnalysisAlgorithm = "community_detection"
	AlgorithmAnomalyDetection  GraphAnalysisAlgorithm = "anomaly_detection"
	AlgorithmRiskPropagation   GraphAnalysisAlgorithm = "risk_propagation"
)

// ThreatIntelRequest represents a request for threat intelligence
type ThreatIntelRequest struct {
	Target  string                 `json:"target" binding:"required"`
	Sources []string               `json:"sources,omitempty"`
	Options ThreatIntelOptions     `json:"options"`
}

// ThreatIntelOptions contains options for threat intelligence queries
type ThreatIntelOptions struct {
	IncludeIOCs     bool          `json:"include_iocs"`
	IncludeAttribution bool       `json:"include_attribution"`
	MaxAge          time.Duration `json:"max_age"`
	MinConfidence   float64       `json:"min_confidence"`
	ActiveOnly      bool          `json:"active_only"`
}

// BuildIntegrityRequest represents a request for build integrity checking
type BuildIntegrityRequest struct {
	Target  string                    `json:"target" binding:"required"`
	Options BuildIntegrityOptions    `json:"options"`
	Checks  []BuildIntegrityCheckType `json:"checks"`
}

// BuildIntegrityOptions contains options for build integrity checking
type BuildIntegrityOptions struct {
	VerifyChecksums   bool `json:"verify_checksums"`
	VerifySignatures  bool `json:"verify_signatures"`
	CheckReproducible bool `json:"check_reproducible"`
	ValidateProvenance bool `json:"validate_provenance"`
	DeepAnalysis      bool `json:"deep_analysis"`
}

// BuildIntegrityCheckType represents a type of build integrity check
type BuildIntegrityCheckType string

const (
	CheckTypeChecksum     BuildIntegrityCheckType = "checksum"
	CheckTypeSignature    BuildIntegrityCheckType = "signature"
	CheckTypeReproducible BuildIntegrityCheckType = "reproducible"
	CheckTypeProvenance   BuildIntegrityCheckType = "provenance"
	CheckTypeMetadata     BuildIntegrityCheckType = "metadata"
	CheckTypeAnomaly      BuildIntegrityCheckType = "anomaly"
)