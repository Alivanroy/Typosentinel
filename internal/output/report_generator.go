package output

import (
	"fmt"
	"path/filepath"
	"time"


	"github.com/sirupsen/logrus"
)

// ReportGenerator manages the generation of various report types
type ReportGenerator struct {
	pdfGenerator *PDFGenerator
	templateDir  string
	outputDir    string
	logger       *logrus.Logger
}

// ReportType defines the type of report to generate
type ReportType string

const (
	ExecutiveReport  ReportType = "executive"
	TechnicalReport  ReportType = "technical"
	ComplianceReport ReportType = "compliance"
)

// ReportData contains common data for all report types
type ReportData struct {
	Organization string    `json:"organization"`
	ReportDate   string    `json:"report_date"`
	ReportID     string    `json:"report_id"`
	ReportType   string    `json:"report_type"`
	GeneratedBy  string    `json:"generated_by"`
	Version      string    `json:"version"`
	ScanPeriod   string    `json:"scan_period"`
	Timestamp    time.Time `json:"timestamp"`
}

// ExecutiveReportData contains data specific to executive reports
type ExecutiveReportData struct {
	ReportData
	ExecutiveSummary     string                 `json:"executive_summary"`
	TotalRepositories    int                    `json:"total_repositories"`
	ScannedRepositories  int                    `json:"scanned_repositories"`
	TotalVulnerabilities int                    `json:"total_vulnerabilities"`
	CriticalIssues       int                    `json:"critical_issues"`
	HighRiskIssues       int                    `json:"high_risk_issues"`
	MediumRiskIssues     int                    `json:"medium_risk_issues"`
	LowRiskIssues        int                    `json:"low_risk_issues"`
	ComplianceScore      float64                `json:"compliance_score"`
	SecurityTrend        string                 `json:"security_trend"`
	TopRisks             []RiskItem             `json:"top_risks"`
	Recommendations      []string               `json:"recommendations"`
	Metrics              map[string]interface{} `json:"metrics"`
}

// TechnicalReportData contains data specific to technical reports
type TechnicalReportData struct {
	ReportData
	ScanOverview        ScanOverview          `json:"scan_overview"`
	Vulnerabilities     []VulnerabilityDetail `json:"vulnerabilities"`
	RepositoryAnalysis  []RepositoryAnalysis  `json:"repository_analysis"`
	DetectionMethods    []DetectionMethod     `json:"detection_methods"`
	ScanTimeline        []ScanEvent           `json:"scan_timeline"`
	SystemConfiguration SystemConfig          `json:"system_configuration"`
	PerformanceMetrics  PerformanceMetrics    `json:"performance_metrics"`
}

// ComplianceReportData contains data specific to compliance reports
type ComplianceReportData struct {
	ReportData
	ExecutiveSummary      string                               `json:"executive_summary"`
	AssessmentPeriod      string                               `json:"assessment_period"`
	Assessor              string                               `json:"assessor"`
	ComplianceFramework   string                               `json:"compliance_framework"`
	AssessmentScope       string                               `json:"assessment_scope"`
	OverallScore          float64                              `json:"overall_score"`
	TotalRequirements     int                                  `json:"total_requirements"`
	CompliantRequirements int                                  `json:"compliant_requirements"`
	PartiallyCompliant    int                                  `json:"partially_compliant"`
	NonCompliant          int                                  `json:"non_compliant"`
	ComplianceStandards   []ComplianceStandard                 `json:"compliance_standards"`
	DetailedAssessment    []interface{} `json:"detailed_assessment"` // Removed orchestrator dependency
	SecurityControls      []SecurityControl                    `json:"security_controls"`
	HighRiskFindings      int                                  `json:"high_risk_findings"`
	MediumRiskFindings    int                                  `json:"medium_risk_findings"`
	LowRiskFindings       int                                  `json:"low_risk_findings"`
	OverallRiskScore      string                               `json:"overall_risk_score"`
	RemediationRoadmap    []RemediationPhase                   `json:"remediation_roadmap"`
	AuditTrail            []AuditEntry                         `json:"audit_trail"`
	ReportVersion         string                               `json:"report_version"`
}

// Supporting data structures
type RiskItem struct {
	Title       string `json:"title"`
	Description string `json:"description"`
	Severity    string `json:"severity"`
	Impact      string `json:"impact"`
	Count       int    `json:"count"`
}

type ScanOverview struct {
	TotalScans      int           `json:"total_scans"`
	SuccessfulScans int           `json:"successful_scans"`
	FailedScans     int           `json:"failed_scans"`
	AverageDuration time.Duration `json:"average_duration"`
	LastScanTime    time.Time     `json:"last_scan_time"`
}

type VulnerabilityDetail struct {
	ID          string `json:"id"`
	Title       string `json:"title"`
	Description string `json:"description"`
	Severity    string `json:"severity"`
	CVSS        string `json:"cvss"`
	Repository  string `json:"repository"`
	FilePath    string `json:"file_path"`
	LineNumber  int    `json:"line_number"`
	Status      string `json:"status"`
	FirstFound  string `json:"first_found"`
	LastSeen    string `json:"last_seen"`
}

type RepositoryAnalysis struct {
	Name            string `json:"name"`
	URL             string `json:"url"`
	Language        string `json:"language"`
	Vulnerabilities int    `json:"vulnerabilities"`
	RiskScore       string `json:"risk_score"`
	LastScanned     string `json:"last_scanned"`
	Status          string `json:"status"`
}

type DetectionMethod struct {
	Name        string `json:"name"`
	Type        string `json:"type"`
	Findings    int    `json:"findings"`
	Accuracy    string `json:"accuracy"`
	Description string `json:"description"`
}

type ScanEvent struct {
	Timestamp  string `json:"timestamp"`
	Event      string `json:"event"`
	Repository string `json:"repository"`
	Status     string `json:"status"`
	Duration   string `json:"duration"`
	Findings   int    `json:"findings"`
}

type SystemConfig struct {
	Version     string            `json:"version"`
	Environment string            `json:"environment"`
	Settings    map[string]string `json:"settings"`
	Plugins     []string          `json:"plugins"`
}

type PerformanceMetrics struct {
	ScanSpeed   string `json:"scan_speed"`
	MemoryUsage string `json:"memory_usage"`
	CPUUsage    string `json:"cpu_usage"`
	Throughput  string `json:"throughput"`
	ErrorRate   string `json:"error_rate"`
}

type ComplianceStandard struct {
	Name              string   `json:"name"`
	Score             float64  `json:"score"`
	ScoreClass        string   `json:"score_class"`
	Status            string   `json:"status"`
	StatusClass       string   `json:"status_class"`
	RequirementsMet   int      `json:"requirements_met"`
	TotalRequirements int      `json:"total_requirements"`
	LastAssessment    string   `json:"last_assessment"`
	CriticalGaps      []string `json:"critical_gaps,omitempty"`
}

type RemediationStep struct {
	Priority string `json:"priority"`
	Action   string `json:"action"`
	DueDate  string `json:"due_date"`
}

type SecurityControl struct {
	ControlID     string `json:"control_id"`
	ControlName   string `json:"control_name"`
	Status        string `json:"status"`
	StatusClass   string `json:"status_class"`
	Effectiveness string `json:"effectiveness"`
	LastTested    string `json:"last_tested"`
	RiskLevel     string `json:"risk_level"`
}

type RemediationPhase struct {
	Phase           string `json:"phase"`
	Title           string `json:"title"`
	Timeline        string `json:"timeline"`
	Priority        string `json:"priority"`
	Owner           string `json:"owner"`
	Description     string `json:"description"`
	SuccessCriteria string `json:"success_criteria"`
}

type AuditEntry struct {
	Timestamp   string `json:"timestamp"`
	Action      string `json:"action"`
	User        string `json:"user"`
	Description string `json:"description"`
}

// NewReportGenerator creates a new report generator
func NewReportGenerator(templateDir, outputDir string, pdfOptions *PDFOptions, logger *logrus.Logger) *ReportGenerator {
	if logger == nil {
		logger = logrus.New()
	}

	pdfGen := NewPDFGenerator(templateDir, outputDir, pdfOptions)

	return &ReportGenerator{
		pdfGenerator: pdfGen,
		templateDir:  templateDir,
		outputDir:    outputDir,
		logger:       logger,
	}
}

// GenerateExecutiveReport generates an executive report in PDF format
func (rg *ReportGenerator) GenerateExecutiveReport(data ExecutiveReportData, filename string) error {
	if filename == "" {
		filename = fmt.Sprintf("executive_report_%s_%s.pdf", data.Organization, data.ReportDate)
	}

	rg.logger.Infof("Generating executive report: %s", filename)
	return rg.pdfGenerator.GenerateExecutiveReport(data, filename)
}

// GenerateTechnicalReport generates a technical report in PDF format
func (rg *ReportGenerator) GenerateTechnicalReport(data TechnicalReportData, filename string) error {
	if filename == "" {
		filename = fmt.Sprintf("technical_report_%s_%s.pdf", data.Organization, data.ReportDate)
	}

	rg.logger.Infof("Generating technical report: %s", filename)
	return rg.pdfGenerator.GenerateTechnicalReport(data, filename)
}

// GenerateComplianceReport generates a compliance report in PDF format
func (rg *ReportGenerator) GenerateComplianceReport(data ComplianceReportData, filename string) error {
	if filename == "" {
		filename = fmt.Sprintf("compliance_report_%s_%s.pdf", data.Organization, data.ReportDate)
	}

	rg.logger.Infof("Generating compliance report: %s", filename)
	return rg.pdfGenerator.GenerateComplianceReport(data, filename)
}

// GenerateAllReports generates all three report types from the same base data
func (rg *ReportGenerator) GenerateAllReports(baseData ReportData, executiveData ExecutiveReportData, technicalData TechnicalReportData, complianceData ComplianceReportData) error {
	timestamp := time.Now().Format("20060102_150405")
	orgName := baseData.Organization

	// Generate executive report
	execFilename := fmt.Sprintf("%s_executive_report_%s.pdf", orgName, timestamp)
	if err := rg.GenerateExecutiveReport(executiveData, execFilename); err != nil {
		return fmt.Errorf("failed to generate executive report: %w", err)
	}

	// Generate technical report
	techFilename := fmt.Sprintf("%s_technical_report_%s.pdf", orgName, timestamp)
	if err := rg.GenerateTechnicalReport(technicalData, techFilename); err != nil {
		return fmt.Errorf("failed to generate technical report: %w", err)
	}

	// Generate compliance report
	compFilename := fmt.Sprintf("%s_compliance_report_%s.pdf", orgName, timestamp)
	if err := rg.GenerateComplianceReport(complianceData, compFilename); err != nil {
		return fmt.Errorf("failed to generate compliance report: %w", err)
	}

	rg.logger.Infof("Generated all reports for %s at %s", orgName, timestamp)
	return nil
}

// GenerateReportByType generates a report based on the specified type
func (rg *ReportGenerator) GenerateReportByType(reportType ReportType, data interface{}, filename string) error {
	switch reportType {
	case ExecutiveReport:
		execData, ok := data.(ExecutiveReportData)
		if !ok {
			return fmt.Errorf("invalid data type for executive report")
		}
		return rg.GenerateExecutiveReport(execData, filename)

	case TechnicalReport:
		techData, ok := data.(TechnicalReportData)
		if !ok {
			return fmt.Errorf("invalid data type for technical report")
		}
		return rg.GenerateTechnicalReport(techData, filename)

	case ComplianceReport:
		compData, ok := data.(ComplianceReportData)
		if !ok {
			return fmt.Errorf("invalid data type for compliance report")
		}
		return rg.GenerateComplianceReport(compData, filename)

	default:
		return fmt.Errorf("unsupported report type: %s", reportType)
	}
}

// GetReportPath returns the full path to a generated report
func (rg *ReportGenerator) GetReportPath(filename string) string {
	return filepath.Join(rg.outputDir, filename)
}

// ValidateReportData validates common report data fields
func (rg *ReportGenerator) ValidateReportData(data ReportData) error {
	if data.Organization == "" {
		return fmt.Errorf("organization is required")
	}
	if data.ReportDate == "" {
		return fmt.Errorf("report date is required")
	}
	if data.ReportID == "" {
		return fmt.Errorf("report ID is required")
	}
	return nil
}

// GetAvailableTemplates returns available report templates
func (rg *ReportGenerator) GetAvailableTemplates() ([]string, error) {
	return rg.pdfGenerator.GetAvailableTemplates()
}

// SetPDFOptions updates PDF generation options
func (rg *ReportGenerator) SetPDFOptions(options PDFOptions) {
	rg.pdfGenerator.SetCustomOptions(options)
}

// CleanupOldReports removes old report files
func (rg *ReportGenerator) CleanupOldReports(maxAge time.Duration) error {
	return rg.pdfGenerator.CleanupOldReports(maxAge)
}

// GetReportStats returns statistics about generated reports
func (rg *ReportGenerator) GetReportStats() (map[string]interface{}, error) {
	stats := make(map[string]interface{})

	templates, err := rg.GetAvailableTemplates()
	if err != nil {
		return nil, err
	}

	stats["available_templates"] = len(templates)
	stats["template_names"] = templates
	stats["output_directory"] = rg.outputDir
	stats["template_directory"] = rg.templateDir

	return stats, nil
}
