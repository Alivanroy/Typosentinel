package campaign

import (
	"context"
	"time"
)

// Campaign represents a group of malicious packages that are related through
// common indicators such as author identity, code similarity, or network IOCs
type Campaign struct {
	ID          string    `json:"id" db:"id"`
	Name        string    `json:"name" db:"name"`
	Description string    `json:"description" db:"description"`
	Severity    string    `json:"severity" db:"severity"` // low, medium, high, critical
	Status      string    `json:"status" db:"status"`       // active, inactive, archived
	PackageIDs  []string  `json:"package_ids" db:"package_ids"`
	IOCs        IOCSet    `json:"iocs" db:"iocs"`
	Metadata    Metadata  `json:"metadata" db:"metadata"`
	CreatedAt   time.Time `json:"created_at" db:"created_at"`
	UpdatedAt   time.Time `json:"updated_at" db:"updated_at"`
}

// PackageSignature represents unique characteristics of a package that can be used
// for similarity analysis and campaign attribution
type PackageSignature struct {
	PackageID        string            `json:"package_id"`
	PackageName      string            `json:"package_name"`
	PackageVersion   string            `json:"package_version"`
	Ecosystem        string            `json:"ecosystem"`
	AuthorSignature  *AuthorSignature  `json:"author_signature"`
	CodeSignature    *CodeSignature    `json:"code_signature"`
	MetadataSignature *MetadataSignature `json:"metadata_signature"`
	NetworkSignature  *NetworkSignature `json:"network_signature"`
	BehaviorSignature *BehaviorSignature `json:"behavior_signature"`
	CreatedAt        time.Time         `json:"created_at"`
}

// AuthorSignature captures author/maintainer characteristics for similarity analysis
type AuthorSignature struct {
	AuthorName     string   `json:"author_name"`
	AuthorEmail    string   `json:"author_email"`
	AuthorUsername string   `json:"author_username"`
	Maintainers    []string `json:"maintainers"`
	Contributors   []string `json:"contributors"`
	RepositoryURL  string   `json:"repository_url"`
	HomepageURL    string   `json:"homepage_url"`
}

// CodeSignature captures code characteristics for similarity analysis
type CodeSignature struct {
	FileHashes      map[string]string `json:"file_hashes"`       // filename -> hash
	FunctionNames   []string          `json:"function_names"`    // Extracted function names
	VariableNames   []string          `json:"variable_names"`    // Extracted variable names
	StringLiterals  []string          `json:"string_literals"`   // String constants
	ImportPackages  []string          `json:"import_packages"`   // Imported packages/modules
	CodePatterns    []string          `json:"code_patterns"`     // Detected code patterns
	SimilarityHash  string            `json:"similarity_hash"`   // Perceptual hash for similarity
}

// MetadataSignature captures package metadata characteristics
type MetadataSignature struct {
	Description    string   `json:"description"`
	Keywords       []string `json:"keywords"`
	License        string   `json:"license"`
	READMEContent  string   `json:"readme_content"`
	READMEPatterns []string `json:"readme_patterns"` // Extracted patterns from README
	PackageSize    int64    `json:"package_size"`
	FileCount      int      `json:"file_count"`
}

// NetworkSignature captures network-related indicators
type NetworkSignature struct {
	Domains       []string `json:"domains"`        // Domains referenced in code
	IPAddresses   []string `json:"ip_addresses"`   // IP addresses referenced
	URLs          []string `json:"urls"`           // URLs referenced
	EmailDomains  []string `json:"email_domains"`  // Email domains in author/contact info
	C2Indicators  []string `json:"c2_indicators"`  // Command & control indicators
}

// BehaviorSignature captures behavioral characteristics from dynamic analysis
type BehaviorSignature struct {
	FilesystemPatterns []string `json:"filesystem_patterns"` // Files/directories accessed
	NetworkConnections []string `json:"network_connections"` // Network connections made
	ProcessSpawning    []string `json:"process_spawning"`    // Processes spawned
	SuspiciousCalls    []string `json:"suspicious_calls"`    // Suspicious API calls
	RiskScore          float64  `json:"risk_score"`          // Overall behavior risk score
}

// IOCSet represents a collection of indicators of compromise
type IOCSet struct {
	Domains       []string            `json:"domains"`
	IPAddresses   []string            `json:"ip_addresses"`
	FileHashes    []string            `json:"file_hashes"`
	URLs          []string            `json:"urls"`
	EmailAddresses []string           `json:"email_addresses"`
	CustomIOCs    map[string][]string `json:"custom_iocs"` // Custom IOC categories
}

// Metadata contains additional campaign metadata
type Metadata struct {
	Confidence     float64            `json:"confidence"`     // Confidence score (0-1)
	FirstSeen      time.Time          `json:"first_seen"`     // When campaign was first observed
	LastSeen       time.Time          `json:"last_seen"`      // When campaign was last observed
	CampaignType   string             `json:"campaign_type"`  // typosquatting, dependency-confusion, etc.
	ThreatActors   []string           `json:"threat_actors"`  // Associated threat actors
	TTPs           []string           `json:"ttps"`           // Tactics, Techniques, Procedures
	References     []string           `json:"references"`     // External references
	Tags           []string           `json:"tags"`           // Campaign tags
	CustomFields   map[string]interface{} `json:"custom_fields"` // Custom metadata fields
}

// SimilarityScore represents the similarity between two packages
type SimilarityScore struct {
	PackageID1     string             `json:"package_id1"`
	PackageID2     string             `json:"package_id2"`
	OverallScore   float64            `json:"overall_score"`   // 0-1 similarity score
	AuthorScore    float64            `json:"author_score"`    // Author similarity (0-1)
	CodeScore      float64            `json:"code_score"`      // Code similarity (0-1)
	MetadataScore  float64            `json:"metadata_score"`  // Metadata similarity (0-1)
	NetworkScore   float64            `json:"network_score"`   // Network IOC similarity (0-1)
	BehaviorScore  float64            `json:"behavior_score"`  // Behavior similarity (0-1)
	MatchingIOCs   []string           `json:"matching_iocs"`   // Specific IOCs that matched
	MatchingPatterns []string         `json:"matching_patterns"` // Patterns that matched
	CalculatedAt   time.Time          `json:"calculated_at"`
}

// CampaignMatch represents a potential campaign match for a package
type CampaignMatch struct {
	Campaign       *Campaign       `json:"campaign"`
	SimilarityScore *SimilarityScore `json:"similarity_score"`
	Confidence     float64         `json:"confidence"`     // Overall confidence in the match
	Reasoning      string          `json:"reasoning"`      // Explanation of why this match was made
	Evidence       []string        `json:"evidence"`       // Supporting evidence
}

// CampaignStore defines the interface for campaign data persistence
type CampaignStore interface {
	// Campaign management
	CreateCampaign(ctx context.Context, campaign *Campaign) error
	GetCampaign(ctx context.Context, id string) (*Campaign, error)
	UpdateCampaign(ctx context.Context, campaign *Campaign) error
	DeleteCampaign(ctx context.Context, id string) error
	ListCampaigns(ctx context.Context, filter CampaignFilter) ([]*Campaign, error)

	// Package signature management
	CreatePackageSignature(ctx context.Context, signature *PackageSignature) error
	GetPackageSignature(ctx context.Context, packageID string) (*PackageSignature, error)
	UpdatePackageSignature(ctx context.Context, signature *PackageSignature) error
	DeletePackageSignature(ctx context.Context, packageID string) error

	// Similarity and matching
	GetSimilarPackages(ctx context.Context, packageID string, threshold float64) ([]*SimilarityScore, error)
	GetCampaignMatches(ctx context.Context, packageID string) ([]*CampaignMatch, error)
	StoreSimilarityScore(ctx context.Context, score *SimilarityScore) error

	// Analytics and reporting
	GetCampaignStatistics(ctx context.Context) (*CampaignStatistics, error)
	GetPackageCampaigns(ctx context.Context, packageID string) ([]*Campaign, error)
}

// CampaignFilter contains filtering options for listing campaigns
type CampaignFilter struct {
	Status     string    `json:"status"`
	Severity   string    `json:"severity"`
	PackageID  string    `json:"package_id"`
	StartDate  time.Time `json:"start_date"`
	EndDate    time.Time `json:"end_date"`
	Limit      int       `json:"limit"`
	Offset     int       `json:"offset"`
}

// CampaignStatistics contains campaign analytics data
type CampaignStatistics struct {
	TotalCampaigns      int                    `json:"total_campaigns"`
	ActiveCampaigns     int                    `json:"active_campaigns"`
	HighSeverityCampaigns int                  `json:"high_severity_campaigns"`
	PackageCount        int                    `json:"package_count"`
	CampaignBreakdown   map[string]int         `json:"campaign_breakdown"` // severity -> count
	EcosystemBreakdown  map[string]int         `json:"ecosystem_breakdown"` // ecosystem -> count
	RecentCampaigns     []*Campaign            `json:"recent_campaigns"`
	TopIOCs             map[string]int         `json:"top_iocs"` // IOC -> occurrence count
}