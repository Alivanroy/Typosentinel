package orchestrator

import (
	"encoding/json"
	"fmt"
	"log"
	"sort"
	"strings"
	"time"

	"github.com/Alivanroy/Typosentinel/internal/repository"
)

// ComplianceReporter handles compliance reporting and assessment
type ComplianceReporter struct {
	config    ComplianceConfig
	logger    *log.Logger
	standards map[string]*ComplianceStandard
}

// ComplianceConfig holds compliance reporting configuration
type ComplianceConfig struct {
	Enabled          bool                     `json:"enabled"`
	Standards        []string                 `json:"standards"`      // SOX, PCI-DSS, HIPAA, etc.
	ReportFormats    []string                 `json:"report_formats"` // JSON, PDF, CSV, XML
	OutputDirectory  string                   `json:"output_directory"`
	Schedule         string                   `json:"schedule"` // cron expression
	RetentionDays    int                      `json:"retention_days"`
	Notifications    []ComplianceNotification `json:"notifications"`
	CustomPolicies   []CompliancePolicy       `json:"custom_policies"`
	Thresholds       ComplianceThresholds     `json:"thresholds"`
	IncludeMetadata  bool                     `json:"include_metadata"`
	EncryptReports   bool                     `json:"encrypt_reports"`
	DigitalSignature bool                     `json:"digital_signature"`
}

// ComplianceStandard defines a compliance standard
type ComplianceStandard struct {
	ID           string                  `json:"id"`
	Name         string                  `json:"name"`
	Version      string                  `json:"version"`
	Description  string                  `json:"description"`
	Requirements []ComplianceRequirement `json:"requirements"`
	Categories   []string                `json:"categories"`
	Severity     string                  `json:"severity"`
	Mandatory    bool                    `json:"mandatory"`
}

// ComplianceRequirement defines a specific compliance requirement
type ComplianceRequirement struct {
	ID          string   `json:"id"`
	Title       string   `json:"title"`
	Description string   `json:"description"`
	Category    string   `json:"category"`
	Severity    string   `json:"severity"`
	Criteria    []string `json:"criteria"`
	Mandatory   bool     `json:"mandatory"`
	Weight      float64  `json:"weight"`
}

// ComplianceNotification defines notification settings
type ComplianceNotification struct {
	Type     string   `json:"type"` // email, slack, webhook
	Targets  []string `json:"targets"`
	Events   []string `json:"events"` // violation, report_generated, threshold_exceeded
	Template string   `json:"template"`
	Enabled  bool     `json:"enabled"`
}

// CompliancePolicy defines custom compliance policies
type CompliancePolicy struct {
	ID          string             `json:"id"`
	Name        string             `json:"name"`
	Description string             `json:"description"`
	Rules       []ComplianceRule   `json:"rules"`
	Actions     []ComplianceAction `json:"actions"`
	Enabled     bool               `json:"enabled"`
	Priority    int                `json:"priority"`
}

// ComplianceRule defines a compliance rule
type ComplianceRule struct {
	ID        string                 `json:"id"`
	Type      string                 `json:"type"`     // threat_count, vulnerability_score, package_age
	Operator  string                 `json:"operator"` // gt, lt, eq, contains
	Value     interface{}            `json:"value"`
	Condition string                 `json:"condition"` // and, or
	Metadata  map[string]interface{} `json:"metadata"`
}

// ComplianceAction defines actions to take on rule violations
type ComplianceAction struct {
	Type       string                 `json:"type"` // block, warn, notify, quarantine
	Parameters map[string]interface{} `json:"parameters"`
	Enabled    bool                   `json:"enabled"`
}

// ComplianceThresholds defines compliance thresholds
type ComplianceThresholds struct {
	CriticalViolations int     `json:"critical_violations"`
	HighViolations     int     `json:"high_violations"`
	MediumViolations   int     `json:"medium_violations"`
	ComplianceScore    float64 `json:"compliance_score"`
	RiskScore          float64 `json:"risk_score"`
}

// ComplianceReport represents a compliance assessment report
type ComplianceReport struct {
	ID               string                     `json:"id"`
	Timestamp        time.Time                  `json:"timestamp"`
	Standard         string                     `json:"standard"`
	Version          string                     `json:"version"`
	Scope            ComplianceScope            `json:"scope"`
	Summary          ComplianceSummary          `json:"summary"`
	Findings         []ComplianceFinding        `json:"findings"`
	Recommendations  []ComplianceRecommendation `json:"recommendations"`
	Metadata         map[string]interface{}     `json:"metadata"`
	GeneratedBy      string                     `json:"generated_by"`
	ReportFormat     string                     `json:"report_format"`
	DigitalSignature string                     `json:"digital_signature,omitempty"`
}

// ComplianceScope defines the scope of compliance assessment
type ComplianceScope struct {
	Repositories  []string  `json:"repositories"`
	TimeRange     TimeRange `json:"time_range"`
	Platforms     []string  `json:"platforms"`
	Organizations []string  `json:"organizations"`
}

// TimeRange defines a time range for compliance assessment
type TimeRange struct {
	Start time.Time `json:"start"`
	End   time.Time `json:"end"`
}

// ComplianceSummary provides an overview of compliance status
type ComplianceSummary struct {
	OverallScore          float64 `json:"overall_score"`
	ComplianceLevel       string  `json:"compliance_level"`
	TotalRequirements     int     `json:"total_requirements"`
	MetRequirements       int     `json:"met_requirements"`
	FailedRequirements    int     `json:"failed_requirements"`
	CriticalViolations    int     `json:"critical_violations"`
	HighViolations        int     `json:"high_violations"`
	MediumViolations      int     `json:"medium_violations"`
	LowViolations         int     `json:"low_violations"`
	TotalRepositories     int     `json:"total_repositories"`
	CompliantRepositories int     `json:"compliant_repositories"`
	RiskScore             float64 `json:"risk_score"`
}

// ComplianceFinding represents a compliance finding
type ComplianceFinding struct {
	ID            string                 `json:"id"`
	RequirementID string                 `json:"requirement_id"`
	Repository    string                 `json:"repository"`
	Severity      string                 `json:"severity"`
	Status        string                 `json:"status"`
	Description   string                 `json:"description"`
	Evidence      []string               `json:"evidence"`
	Remediation   string                 `json:"remediation"`
	Timestamp     time.Time              `json:"timestamp"`
	Metadata      map[string]interface{} `json:"metadata"`
}

// ComplianceRecommendation provides remediation recommendations
type ComplianceRecommendation struct {
	ID          string   `json:"id"`
	Title       string   `json:"title"`
	Description string   `json:"description"`
	Priority    string   `json:"priority"`
	Category    string   `json:"category"`
	Actions     []string `json:"actions"`
	Resources   []string `json:"resources"`
	Timeline    string   `json:"timeline"`
}

// NewComplianceReporter creates a new compliance reporter
func NewComplianceReporter(config ComplianceConfig, logger *log.Logger) *ComplianceReporter {
	if logger == nil {
		logger = log.New(log.Writer(), "[ComplianceReporter] ", log.LstdFlags)
	}

	reporter := &ComplianceReporter{
		config:    config,
		logger:    logger,
		standards: make(map[string]*ComplianceStandard),
	}

	// Initialize built-in compliance standards
	reporter.initializeStandards()

	return reporter
}

// GenerateComplianceReport generates a compliance report for the given scan results
func (cr *ComplianceReporter) GenerateComplianceReport(scanResults []*repository.ScanResult, standard string) (*ComplianceReport, error) {
	if !cr.config.Enabled {
		return nil, fmt.Errorf("compliance reporting is disabled")
	}

	standardDef, exists := cr.standards[standard]
	if !exists {
		return nil, fmt.Errorf("compliance standard %s not found", standard)
	}

	report := &ComplianceReport{
		ID:           fmt.Sprintf("compliance_%s_%d", standard, time.Now().Unix()),
		Timestamp:    time.Now(),
		Standard:     standard,
		Version:      standardDef.Version,
		GeneratedBy:  "TypoSentinel Enterprise",
		ReportFormat: "JSON",
		Metadata:     make(map[string]interface{}),
	}

	// Set scope
	report.Scope = cr.buildScope(scanResults)

	// Assess compliance
	findings, err := cr.assessCompliance(scanResults, standardDef)
	if err != nil {
		return nil, fmt.Errorf("failed to assess compliance: %w", err)
	}
	report.Findings = findings

	// Generate summary
	report.Summary = cr.generateSummary(findings, standardDef)

	// Generate recommendations
	report.Recommendations = cr.generateRecommendations(findings)

	// Add metadata
	report.Metadata["scan_count"] = len(scanResults)
	report.Metadata["assessment_duration"] = time.Since(report.Timestamp).String()
	report.Metadata["standard_requirements"] = len(standardDef.Requirements)

	cr.logger.Printf("Generated compliance report %s for standard %s", report.ID, standard)
	return report, nil
}

// buildScope builds the compliance scope from scan results
func (cr *ComplianceReporter) buildScope(scanResults []*repository.ScanResult) ComplianceScope {
	var repositories []string
	var platforms []string
	var organizations []string
	var earliest, latest time.Time

	for i, result := range scanResults {
		if result.Repository != nil {
			repos := result.Repository.FullName
			if !containsString(repositories, repos) {
				repositories = append(repositories, repos)
			}

			platform := result.Repository.Platform
			if !containsString(platforms, platform) {
				platforms = append(platforms, platform)
			}

			org := strings.Split(result.Repository.FullName, "/")[0]
			if !containsString(organizations, org) {
				organizations = append(organizations, org)
			}
		}

		if i == 0 {
			earliest = result.StartTime
			latest = result.EndTime
		} else {
			if result.StartTime.Before(earliest) {
				earliest = result.StartTime
			}
			if result.EndTime.After(latest) {
				latest = result.EndTime
			}
		}
	}

	return ComplianceScope{
		Repositories:  repositories,
		TimeRange:     TimeRange{Start: earliest, End: latest},
		Platforms:     platforms,
		Organizations: organizations,
	}
}

// assessCompliance assesses compliance against the given standard
func (cr *ComplianceReporter) assessCompliance(scanResults []*repository.ScanResult, standard *ComplianceStandard) ([]ComplianceFinding, error) {
	var findings []ComplianceFinding

	for _, requirement := range standard.Requirements {
		for _, result := range scanResults {
			finding := cr.assessRequirement(result, requirement)
			if finding != nil {
				findings = append(findings, *finding)
			}
		}
	}

	return findings, nil
}

// assessRequirement assesses a single compliance requirement
func (cr *ComplianceReporter) assessRequirement(result *repository.ScanResult, requirement ComplianceRequirement) *ComplianceFinding {
	// This is a simplified assessment - in practice, this would be much more sophisticated
	finding := &ComplianceFinding{
		ID:            fmt.Sprintf("finding_%s_%s_%d", requirement.ID, result.ScanID, time.Now().Unix()),
		RequirementID: requirement.ID,
		Repository:    result.Repository.FullName,
		Severity:      requirement.Severity,
		Timestamp:     time.Now(),
		Metadata:      make(map[string]interface{}),
	}

	// Simple compliance check based on scan status and requirement
	switch requirement.Category {
	case "vulnerability_management":
		if result.Status == "failed" || result.Error != "" {
			finding.Status = "non_compliant"
			finding.Description = "Repository scan failed or encountered errors"
			finding.Evidence = []string{result.Error}
			finding.Remediation = "Review and fix scan errors, ensure repository is accessible"
		} else {
			finding.Status = "compliant"
			finding.Description = "Repository scan completed successfully"
		}

	case "dependency_management":
		if len(result.DependencyFiles) == 0 {
			finding.Status = "non_compliant"
			finding.Description = "No dependency files found in repository"
			finding.Remediation = "Ensure proper dependency management files are present"
		} else {
			finding.Status = "compliant"
			finding.Description = fmt.Sprintf("Found %d dependency files", len(result.DependencyFiles))
		}

	case "security_scanning":
		if result.Duration > 30*time.Minute {
			finding.Status = "warning"
			finding.Description = "Scan duration exceeded recommended threshold"
			finding.Remediation = "Optimize scan configuration or repository size"
		} else {
			finding.Status = "compliant"
			finding.Description = "Scan completed within acceptable time"
		}

	default:
		finding.Status = "not_assessed"
		finding.Description = "Requirement not assessed by current implementation"
	}

	return finding
}

// generateSummary generates a compliance summary
func (cr *ComplianceReporter) generateSummary(findings []ComplianceFinding, standard *ComplianceStandard) ComplianceSummary {
	summary := ComplianceSummary{
		TotalRequirements: len(standard.Requirements),
	}

	// Count findings by status and severity
	for _, finding := range findings {
		switch finding.Status {
		case "compliant":
			summary.MetRequirements++
		case "non_compliant":
			summary.FailedRequirements++
		}

		switch finding.Severity {
		case "critical":
			summary.CriticalViolations++
		case "high":
			summary.HighViolations++
		case "medium":
			summary.MediumViolations++
		case "low":
			summary.LowViolations++
		}
	}

	// Calculate compliance score
	if summary.TotalRequirements > 0 {
		summary.OverallScore = float64(summary.MetRequirements) / float64(summary.TotalRequirements) * 100
	}

	// Determine compliance level
	switch {
	case summary.OverallScore >= 95:
		summary.ComplianceLevel = "excellent"
	case summary.OverallScore >= 85:
		summary.ComplianceLevel = "good"
	case summary.OverallScore >= 70:
		summary.ComplianceLevel = "acceptable"
	case summary.OverallScore >= 50:
		summary.ComplianceLevel = "poor"
	default:
		summary.ComplianceLevel = "critical"
	}

	// Calculate risk score
	summary.RiskScore = float64(summary.CriticalViolations*10+summary.HighViolations*5+summary.MediumViolations*2+summary.LowViolations*1) / float64(len(findings)) * 10

	// Count unique repositories
	repoSet := make(map[string]bool)
	for _, finding := range findings {
		repoSet[finding.Repository] = true
	}
	summary.TotalRepositories = len(repoSet)

	// Count compliant repositories
	compliantRepos := make(map[string]bool)
	for _, finding := range findings {
		if finding.Status == "compliant" {
			compliantRepos[finding.Repository] = true
		}
	}
	summary.CompliantRepositories = len(compliantRepos)

	return summary
}

// generateRecommendations generates compliance recommendations
func (cr *ComplianceReporter) generateRecommendations(findings []ComplianceFinding) []ComplianceRecommendation {
	var recommendations []ComplianceRecommendation

	// Group findings by type for recommendations
	violationCounts := make(map[string]int)
	for _, finding := range findings {
		if finding.Status == "non_compliant" {
			violationCounts[finding.RequirementID]++
		}
	}

	// Generate recommendations based on common violations
	for reqID, count := range violationCounts {
		if count > 0 {
			recommendation := ComplianceRecommendation{
				ID:          fmt.Sprintf("rec_%s_%d", reqID, time.Now().Unix()),
				Title:       fmt.Sprintf("Address %s violations", reqID),
				Description: fmt.Sprintf("Found %d violations for requirement %s", count, reqID),
				Category:    "remediation",
				Actions:     []string{"Review findings", "Implement fixes", "Re-scan repositories"},
				Resources:   []string{"Compliance documentation", "Security guidelines"},
				Timeline:    "30 days",
			}

			if count >= 10 {
				recommendation.Priority = "high"
			} else if count >= 5 {
				recommendation.Priority = "medium"
			} else {
				recommendation.Priority = "low"
			}

			recommendations = append(recommendations, recommendation)
		}
	}

	// Sort recommendations by priority
	sort.Slice(recommendations, func(i, j int) bool {
		priorityOrder := map[string]int{"high": 3, "medium": 2, "low": 1}
		return priorityOrder[recommendations[i].Priority] > priorityOrder[recommendations[j].Priority]
	})

	return recommendations
}

// initializeStandards initializes built-in compliance standards
func (cr *ComplianceReporter) initializeStandards() {
	// SOX (Sarbanes-Oxley) compliance standard
	sox := &ComplianceStandard{
		ID:          "SOX",
		Name:        "Sarbanes-Oxley Act",
		Version:     "2002",
		Description: "Financial reporting and corporate governance compliance",
		Categories:  []string{"financial_reporting", "audit_trail", "access_control"},
		Severity:    "high",
		Mandatory:   true,
		Requirements: []ComplianceRequirement{
			{
				ID:          "SOX-404",
				Title:       "Internal Control Assessment",
				Description: "Assessment of internal control over financial reporting",
				Category:    "vulnerability_management",
				Severity:    "high",
				Mandatory:   true,
				Weight:      1.0,
			},
			{
				ID:          "SOX-302",
				Title:       "Corporate Responsibility",
				Description: "Corporate responsibility for financial reports",
				Category:    "dependency_management",
				Severity:    "high",
				Mandatory:   true,
				Weight:      1.0,
			},
		},
	}
	cr.standards["SOX"] = sox

	// PCI-DSS compliance standard
	pci := &ComplianceStandard{
		ID:          "PCI-DSS",
		Name:        "Payment Card Industry Data Security Standard",
		Version:     "4.0",
		Description: "Security standards for payment card data protection",
		Categories:  []string{"data_protection", "network_security", "access_control"},
		Severity:    "critical",
		Mandatory:   true,
		Requirements: []ComplianceRequirement{
			{
				ID:          "PCI-DSS-6.2",
				Title:       "Vulnerability Management",
				Description: "Ensure all system components are protected from known vulnerabilities",
				Category:    "vulnerability_management",
				Severity:    "critical",
				Mandatory:   true,
				Weight:      1.0,
			},
			{
				ID:          "PCI-DSS-6.3",
				Title:       "Secure Development",
				Description: "Develop software applications in accordance with PCI DSS",
				Category:    "security_scanning",
				Severity:    "high",
				Mandatory:   true,
				Weight:      0.8,
			},
		},
	}
	cr.standards["PCI-DSS"] = pci

	// HIPAA compliance standard
	hipaa := &ComplianceStandard{
		ID:          "HIPAA",
		Name:        "Health Insurance Portability and Accountability Act",
		Version:     "1996",
		Description: "Healthcare data privacy and security compliance",
		Categories:  []string{"data_privacy", "access_control", "audit_trail"},
		Severity:    "high",
		Mandatory:   true,
		Requirements: []ComplianceRequirement{
			{
				ID:          "HIPAA-164.308",
				Title:       "Administrative Safeguards",
				Description: "Administrative safeguards for PHI protection",
				Category:    "dependency_management",
				Severity:    "high",
				Mandatory:   true,
				Weight:      1.0,
			},
			{
				ID:          "HIPAA-164.312",
				Title:       "Technical Safeguards",
				Description: "Technical safeguards for PHI protection",
				Category:    "security_scanning",
				Severity:    "high",
				Mandatory:   true,
				Weight:      1.0,
			},
		},
	}
	cr.standards["HIPAA"] = hipaa

	cr.logger.Printf("Initialized %d compliance standards", len(cr.standards))
}

// ExportReport exports a compliance report in the specified format
func (cr *ComplianceReporter) ExportReport(report *ComplianceReport, format string) ([]byte, error) {
	switch strings.ToLower(format) {
	case "json":
		return json.MarshalIndent(report, "", "  ")
	case "csv":
		return cr.exportCSV(report)
	default:
		return nil, fmt.Errorf("unsupported export format: %s", format)
	}
}

// exportCSV exports a compliance report as CSV
func (cr *ComplianceReporter) exportCSV(report *ComplianceReport) ([]byte, error) {
	var csv strings.Builder

	// Header
	csv.WriteString("Finding ID,Requirement ID,Repository,Severity,Status,Description,Timestamp\n")

	// Data rows
	for _, finding := range report.Findings {
		csv.WriteString(fmt.Sprintf("%s,%s,%s,%s,%s,\"%s\",%s\n",
			finding.ID,
			finding.RequirementID,
			finding.Repository,
			finding.Severity,
			finding.Status,
			strings.ReplaceAll(finding.Description, "\"", "\\\""),
			finding.Timestamp.Format(time.RFC3339),
		))
	}

	return []byte(csv.String()), nil
}

// GetSupportedStandards returns a list of supported compliance standards
func (cr *ComplianceReporter) GetSupportedStandards() []string {
	var standards []string
	for id := range cr.standards {
		standards = append(standards, id)
	}
	sort.Strings(standards)
	return standards
}

// ValidateCompliance validates compliance against thresholds
func (cr *ComplianceReporter) ValidateCompliance(report *ComplianceReport) []string {
	var violations []string

	if report.Summary.CriticalViolations > cr.config.Thresholds.CriticalViolations {
		violations = append(violations, fmt.Sprintf("Critical violations (%d) exceed threshold (%d)",
			report.Summary.CriticalViolations, cr.config.Thresholds.CriticalViolations))
	}

	if report.Summary.HighViolations > cr.config.Thresholds.HighViolations {
		violations = append(violations, fmt.Sprintf("High violations (%d) exceed threshold (%d)",
			report.Summary.HighViolations, cr.config.Thresholds.HighViolations))
	}

	if report.Summary.OverallScore < cr.config.Thresholds.ComplianceScore {
		violations = append(violations, fmt.Sprintf("Compliance score (%.2f) below threshold (%.2f)",
			report.Summary.OverallScore, cr.config.Thresholds.ComplianceScore))
	}

	if report.Summary.RiskScore > cr.config.Thresholds.RiskScore {
		violations = append(violations, fmt.Sprintf("Risk score (%.2f) exceeds threshold (%.2f)",
			report.Summary.RiskScore, cr.config.Thresholds.RiskScore))
	}

	return violations
}

// containsString checks if a slice contains a string
func containsString(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}
