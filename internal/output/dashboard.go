package output

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html/template"
	"time"

	"github.com/Alivanroy/Typosentinel/internal/analyzer"
	"github.com/Alivanroy/Typosentinel/pkg/types"
)

// DashboardData represents data for the executive dashboard
type DashboardData struct {
	ScanResult      *analyzer.ScanResult `json:"scan_result"`
	RepositoryInfo  *RepositoryInfo      `json:"repository_info"`
	ExecutiveSummary *ExecutiveSummary    `json:"executive_summary"`
	RiskMetrics     *RiskMetrics         `json:"risk_metrics"`
	ThreatBreakdown *ThreatBreakdown     `json:"threat_breakdown"`
	Recommendations []Recommendation     `json:"recommendations"`
	TrendData       *TrendData           `json:"trend_data,omitempty"`
	ComplianceData  *ComplianceData      `json:"compliance_data,omitempty"`
	GeneratedAt     time.Time            `json:"generated_at"`
}

// RepositoryInfo contains repository metadata
type RepositoryInfo struct {
	URL         string `json:"url"`
	Branch      string `json:"branch"`
	CommitSHA   string `json:"commit_sha"`
	ScanType    string `json:"scan_type"`
	ProjectName string `json:"project_name"`
	Owner       string `json:"owner"`
	Languages   []string `json:"languages"`
}

// ExecutiveSummary provides high-level insights
type ExecutiveSummary struct {
	OverallRiskLevel    string  `json:"overall_risk_level"`
	RiskScore          float64 `json:"risk_score"`
	TotalPackages      int     `json:"total_packages"`
	VulnerablePackages int     `json:"vulnerable_packages"`
	CriticalIssues     int     `json:"critical_issues"`
	HighIssues         int     `json:"high_issues"`
	MediumIssues       int     `json:"medium_issues"`
	LowIssues          int     `json:"low_issues"`
	SecurityPosture    string  `json:"security_posture"`
	ComplianceStatus   string  `json:"compliance_status"`
}

// RiskMetrics contains detailed risk analysis
type RiskMetrics struct {
	SupplyChainRisk    float64            `json:"supply_chain_risk"`
	LicenseRisk        float64            `json:"license_risk"`
	MaintenanceRisk    float64            `json:"maintenance_risk"`
	VulnerabilityRisk  float64            `json:"vulnerability_risk"`
	RiskDistribution   map[string]int     `json:"risk_distribution"`
	TopRiskyPackages   []RiskyPackage     `json:"top_risky_packages"`
	RiskTrends         []RiskTrendPoint   `json:"risk_trends,omitempty"`
}

// ThreatBreakdown categorizes threats by type
type ThreatBreakdown struct {
	ByType     map[string]int `json:"by_type"`
	BySeverity map[string]int `json:"by_severity"`
	ByRegistry map[string]int `json:"by_registry"`
	Timeline   []ThreatPoint  `json:"timeline,omitempty"`
}

// RiskyPackage represents a high-risk package
type RiskyPackage struct {
	Name        string  `json:"name"`
	Version     string  `json:"version"`
	Registry    string  `json:"registry"`
	RiskScore   float64 `json:"risk_score"`
	Threats     []string `json:"threats"`
	Severity    string  `json:"severity"`
	Description string  `json:"description"`
}

// RiskTrendPoint represents a point in risk trend analysis
type RiskTrendPoint struct {
	Date      time.Time `json:"date"`
	RiskScore float64   `json:"risk_score"`
	Threats   int       `json:"threats"`
}

// ThreatPoint represents a threat occurrence point
type ThreatPoint struct {
	Date     time.Time `json:"date"`
	Type     string    `json:"type"`
	Severity string    `json:"severity"`
	Count    int       `json:"count"`
}

// Recommendation provides actionable security recommendations
type Recommendation struct {
	ID          string `json:"id"`
	Title       string `json:"title"`
	Description string `json:"description"`
	Priority    string `json:"priority"`
	Category    string `json:"category"`
	Action      string `json:"action"`
	Impact      string `json:"impact"`
	Effort      string `json:"effort"`
	Packages    []string `json:"packages,omitempty"`
}

// TrendData contains historical trend information
type TrendData struct {
	RiskTrends       []RiskTrendPoint `json:"risk_trends"`
	ThreatTrends     []ThreatPoint    `json:"threat_trends"`
	PackageGrowth    []GrowthPoint    `json:"package_growth"`
	VulnerabilityTrends []VulnTrendPoint `json:"vulnerability_trends"`
}

// GrowthPoint represents package growth over time
type GrowthPoint struct {
	Date     time.Time `json:"date"`
	Packages int       `json:"packages"`
	New      int       `json:"new"`
	Updated  int       `json:"updated"`
}

// VulnTrendPoint represents vulnerability trends
type VulnTrendPoint struct {
	Date            time.Time `json:"date"`
	NewVulns        int       `json:"new_vulns"`
	FixedVulns      int       `json:"fixed_vulns"`
	TotalVulns      int       `json:"total_vulns"`
}

// ComplianceData contains compliance-related information
type ComplianceData struct {
	Frameworks    []ComplianceFramework `json:"frameworks"`
	OverallScore  float64               `json:"overall_score"`
	Status        string                `json:"status"`
	Violations    []ComplianceViolation `json:"violations"`
	Recommendations []string            `json:"recommendations"`
}

// ComplianceFramework represents a compliance framework assessment
type ComplianceFramework struct {
	Name        string  `json:"name"`
	Version     string  `json:"version"`
	Score       float64 `json:"score"`
	Status      string  `json:"status"`
	Requirements []ComplianceRequirement `json:"requirements"`
}

// ComplianceRequirement represents a specific compliance requirement
type ComplianceRequirement struct {
	ID          string `json:"id"`
	Title       string `json:"title"`
	Status      string `json:"status"`
	Description string `json:"description"`
	Evidence    string `json:"evidence,omitempty"`
}

// ComplianceViolation represents a compliance violation
type ComplianceViolation struct {
	Framework   string `json:"framework"`
	Requirement string `json:"requirement"`
	Severity    string `json:"severity"`
	Description string `json:"description"`
	Remediation string `json:"remediation"`
}

// DashboardFormatter generates executive dashboard reports
type DashboardFormatter struct {
	RepositoryURL string
	Branch        string
	CommitSHA     string
	ScanType      string
	ProjectName   string
	Owner         string
	IncludeTrends bool
	IncludeCompliance bool
}

// NewDashboardFormatter creates a new dashboard formatter
func NewDashboardFormatter(repoURL, branch, commitSHA, scanType, projectName, owner string) *DashboardFormatter {
	return &DashboardFormatter{
		RepositoryURL: repoURL,
		Branch:        branch,
		CommitSHA:     commitSHA,
		ScanType:      scanType,
		ProjectName:   projectName,
		Owner:         owner,
		IncludeTrends: false,
		IncludeCompliance: false,
	}
}

// Format generates an executive dashboard HTML report
func (f *DashboardFormatter) Format(scanResult *analyzer.ScanResult) ([]byte, error) {
	dashboardData := f.generateDashboardData(scanResult)
	
	// Generate HTML report
	htmlReport, err := f.generateHTMLReport(dashboardData)
	if err != nil {
		return nil, fmt.Errorf("failed to generate HTML report: %w", err)
	}
	
	return htmlReport, nil
}

// FormatJSON generates dashboard data in JSON format
func (f *DashboardFormatter) FormatJSON(scanResult *analyzer.ScanResult) ([]byte, error) {
	dashboardData := f.generateDashboardData(scanResult)
	return json.MarshalIndent(dashboardData, "", "  ")
}

// generateDashboardData creates comprehensive dashboard data from scan results
func (f *DashboardFormatter) generateDashboardData(scanResult *analyzer.ScanResult) *DashboardData {
	return &DashboardData{
		ScanResult:      scanResult,
		RepositoryInfo:  f.generateRepositoryInfo(),
		ExecutiveSummary: f.generateExecutiveSummary(scanResult),
		RiskMetrics:     f.generateRiskMetrics(scanResult),
		ThreatBreakdown: f.generateThreatBreakdown(scanResult),
		Recommendations: f.generateRecommendations(scanResult),
		TrendData:       f.generateTrendData(scanResult),
		ComplianceData:  f.generateComplianceData(scanResult),
		GeneratedAt:     time.Now(),
	}
}

// generateRepositoryInfo creates repository information
func (f *DashboardFormatter) generateRepositoryInfo() *RepositoryInfo {
	return &RepositoryInfo{
		URL:         f.RepositoryURL,
		Branch:      f.Branch,
		CommitSHA:   f.CommitSHA,
		ScanType:    f.ScanType,
		ProjectName: f.ProjectName,
		Owner:       f.Owner,
		Languages:   []string{"JavaScript", "Go", "Python"}, // This should be detected from scan
	}
}

// generateExecutiveSummary creates executive summary
func (f *DashboardFormatter) generateExecutiveSummary(scanResult *analyzer.ScanResult) *ExecutiveSummary {
	criticalCount := f.countBySeverity(scanResult, "critical")
	highCount := f.countBySeverity(scanResult, "high")
	mediumCount := f.countBySeverity(scanResult, "medium")
	lowCount := f.countBySeverity(scanResult, "low")
	
	totalThreats := len(scanResult.Threats)
	riskScore := f.calculateRiskScore(scanResult)
	
	return &ExecutiveSummary{
		OverallRiskLevel:    f.determineRiskLevel(riskScore),
		RiskScore:          riskScore,
		TotalPackages:      scanResult.TotalPackages,
		VulnerablePackages: totalThreats,
		CriticalIssues:     criticalCount,
		HighIssues:         highCount,
		MediumIssues:       mediumCount,
		LowIssues:          lowCount,
		SecurityPosture:    f.determineSecurityPosture(riskScore),
		ComplianceStatus:   f.determineComplianceStatus(scanResult),
	}
}

// generateRiskMetrics creates detailed risk metrics
func (f *DashboardFormatter) generateRiskMetrics(scanResult *analyzer.ScanResult) *RiskMetrics {
	riskDistribution := make(map[string]int)
	for _, threat := range scanResult.Threats {
		riskDistribution[threat.Severity.String()]++
	}
	
	return &RiskMetrics{
		SupplyChainRisk:   f.calculateSupplyChainRisk(scanResult),
		LicenseRisk:       f.calculateLicenseRisk(scanResult),
		MaintenanceRisk:   f.calculateMaintenanceRisk(scanResult),
		VulnerabilityRisk: f.calculateVulnerabilityRisk(scanResult),
		RiskDistribution:  riskDistribution,
		TopRiskyPackages:  f.getTopRiskyPackages(scanResult, 10),
	}
}

// generateThreatBreakdown creates threat breakdown analysis
func (f *DashboardFormatter) generateThreatBreakdown(scanResult *analyzer.ScanResult) *ThreatBreakdown {
	byType := make(map[string]int)
	bySeverity := make(map[string]int)
	byRegistry := make(map[string]int)
	
	for _, threat := range scanResult.Threats {
		byType[string(threat.Type)]++
		bySeverity[threat.Severity.String()]++
		byRegistry[threat.Registry]++
	}
	
	return &ThreatBreakdown{
		ByType:     byType,
		BySeverity: bySeverity,
		ByRegistry: byRegistry,
	}
}

// generateRecommendations creates actionable recommendations
func (f *DashboardFormatter) generateRecommendations(scanResult *analyzer.ScanResult) []Recommendation {
	var recommendations []Recommendation
	
	// Generate recommendations based on threats found
	criticalCount := f.countBySeverity(scanResult, "critical")
	highCount := f.countBySeverity(scanResult, "high")
	
	if criticalCount > 0 {
		recommendations = append(recommendations, Recommendation{
			ID:          "CRITICAL_THREATS",
			Title:       "Address Critical Security Threats Immediately",
			Description: fmt.Sprintf("Found %d critical security threats that require immediate attention", criticalCount),
			Priority:    "Critical",
			Category:    "Security",
			Action:      "Review and remediate all critical threats within 24 hours",
			Impact:      "High",
			Effort:      "Medium",
		})
	}
	
	if highCount > 0 {
		recommendations = append(recommendations, Recommendation{
			ID:          "HIGH_THREATS",
			Title:       "Remediate High-Priority Security Issues",
			Description: fmt.Sprintf("Found %d high-priority security issues that should be addressed soon", highCount),
			Priority:    "High",
			Category:    "Security",
			Action:      "Plan remediation for high-priority threats within 1 week",
			Impact:      "Medium",
			Effort:      "Medium",
		})
	}
	
	// Add general recommendations
	recommendations = append(recommendations, Recommendation{
		ID:          "DEPENDENCY_UPDATES",
		Title:       "Regular Dependency Updates",
		Description: "Implement a regular dependency update schedule to stay current with security patches",
		Priority:    "Medium",
		Category:    "Maintenance",
		Action:      "Set up automated dependency update checks",
		Impact:      "High",
		Effort:      "Low",
	})
	
	recommendations = append(recommendations, Recommendation{
		ID:          "SECURITY_SCANNING",
		Title:       "Integrate Security Scanning in CI/CD",
		Description: "Add automated security scanning to your continuous integration pipeline",
		Priority:    "Medium",
		Category:    "DevSecOps",
		Action:      "Configure TypoSentinel in your CI/CD pipeline",
		Impact:      "High",
		Effort:      "Low",
	})
	
	return recommendations
}

// generateTrendData creates trend analysis (placeholder for future implementation)
func (f *DashboardFormatter) generateTrendData(scanResult *analyzer.ScanResult) *TrendData {
	if !f.IncludeTrends {
		return nil
	}
	
	// This would be populated from historical data in a real implementation
	return &TrendData{
		RiskTrends:   []RiskTrendPoint{},
		ThreatTrends: []ThreatPoint{},
		PackageGrowth: []GrowthPoint{},
		VulnerabilityTrends: []VulnTrendPoint{},
	}
}

// generateComplianceData creates compliance assessment (placeholder)
func (f *DashboardFormatter) generateComplianceData(scanResult *analyzer.ScanResult) *ComplianceData {
	if !f.IncludeCompliance {
		return nil
	}
	
	// This would be populated based on compliance frameworks in a real implementation
	return &ComplianceData{
		Frameworks:   []ComplianceFramework{},
		OverallScore: 0.0,
		Status:       "Not Assessed",
		Violations:   []ComplianceViolation{},
		Recommendations: []string{},
	}
}

// Helper functions

func (f *DashboardFormatter) countBySeverity(scanResult *analyzer.ScanResult, severity string) int {
	count := 0
	for _, threat := range scanResult.Threats {
		if threat.Severity.String() == severity {
			count++
		}
	}
	return count
}

func (f *DashboardFormatter) calculateRiskScore(scanResult *analyzer.ScanResult) float64 {
	if scanResult.TotalPackages == 0 {
		return 0.0
	}
	
	critical := float64(f.countBySeverity(scanResult, "critical"))
	high := float64(f.countBySeverity(scanResult, "high"))
	medium := float64(f.countBySeverity(scanResult, "medium"))
	low := float64(f.countBySeverity(scanResult, "low"))
	
	// Weighted risk score calculation
	weightedScore := (critical * 10) + (high * 7) + (medium * 4) + (low * 1)
	maxPossibleScore := float64(scanResult.TotalPackages) * 10
	
	if maxPossibleScore == 0 {
		return 0.0
	}
	
	return (weightedScore / maxPossibleScore) * 100
}

func (f *DashboardFormatter) determineRiskLevel(riskScore float64) string {
	switch {
	case riskScore >= 80:
		return "Critical"
	case riskScore >= 60:
		return "High"
	case riskScore >= 40:
		return "Medium"
	case riskScore >= 20:
		return "Low"
	default:
		return "Minimal"
	}
}

func (f *DashboardFormatter) determineSecurityPosture(riskScore float64) string {
	switch {
	case riskScore >= 80:
		return "Poor - Immediate action required"
	case riskScore >= 60:
		return "Concerning - Needs improvement"
	case riskScore >= 40:
		return "Fair - Some issues to address"
	case riskScore >= 20:
		return "Good - Minor improvements needed"
	default:
		return "Excellent - Well secured"
	}
}

func (f *DashboardFormatter) determineComplianceStatus(scanResult *analyzer.ScanResult) string {
	criticalCount := f.countBySeverity(scanResult, "critical")
	highCount := f.countBySeverity(scanResult, "high")
	
	if criticalCount > 0 {
		return "Non-Compliant"
	}
	if highCount > 5 {
		return "At Risk"
	}
	return "Compliant"
}

func (f *DashboardFormatter) calculateSupplyChainRisk(scanResult *analyzer.ScanResult) float64 {
	// Calculate supply chain risk based on threat types
	supplyChainThreats := 0
	for _, threat := range scanResult.Threats {
		if threat.Type == types.ThreatTypeSupplyChainRisk || 
		   threat.Type == types.ThreatTypeDependencyConfusion ||
		   threat.Type == types.ThreatTypeTyposquatting {
			supplyChainThreats++
		}
	}
	
	if scanResult.TotalPackages == 0 {
		return 0.0
	}
	
	return (float64(supplyChainThreats) / float64(scanResult.TotalPackages)) * 100
}

func (f *DashboardFormatter) calculateLicenseRisk(scanResult *analyzer.ScanResult) float64 {
	// Placeholder for license risk calculation
	return 15.0 // This would be calculated based on license analysis
}

func (f *DashboardFormatter) calculateMaintenanceRisk(scanResult *analyzer.ScanResult) float64 {
	// Placeholder for maintenance risk calculation
	return 25.0 // This would be calculated based on package age, update frequency, etc.
}

func (f *DashboardFormatter) calculateVulnerabilityRisk(scanResult *analyzer.ScanResult) float64 {
	vulnThreats := 0
	for _, threat := range scanResult.Threats {
		if threat.Type == types.ThreatTypeVulnerable {
			vulnThreats++
		}
	}
	
	if scanResult.TotalPackages == 0 {
		return 0.0
	}
	
	return (float64(vulnThreats) / float64(scanResult.TotalPackages)) * 100
}

func (f *DashboardFormatter) getTopRiskyPackages(scanResult *analyzer.ScanResult, limit int) []RiskyPackage {
	var riskyPackages []RiskyPackage
	
	// Group threats by package
	packageThreats := make(map[string][]types.Threat)
	for _, threat := range scanResult.Threats {
		key := fmt.Sprintf("%s@%s", threat.Package, threat.Version)
		packageThreats[key] = append(packageThreats[key], threat)
	}
	
	// Calculate risk score for each package
	for _, threats := range packageThreats {
		if len(threats) == 0 {
			continue
		}
		
		firstThreat := threats[0]
		riskScore := f.calculatePackageRiskScore(threats)
		
		var threatTypes []string
		for _, threat := range threats {
			threatTypes = append(threatTypes, string(threat.Type))
		}
		
		riskyPackages = append(riskyPackages, RiskyPackage{
			Name:        firstThreat.Package,
			Version:     firstThreat.Version,
			Registry:    firstThreat.Registry,
			RiskScore:   riskScore,
			Threats:     threatTypes,
			Severity:    f.getHighestSeverity(threats),
			Description: firstThreat.Description,
		})
	}
	
	// Sort by risk score and return top packages
	if len(riskyPackages) > limit {
		// Simple sort by risk score (descending)
		for i := 0; i < len(riskyPackages)-1; i++ {
			for j := i + 1; j < len(riskyPackages); j++ {
				if riskyPackages[i].RiskScore < riskyPackages[j].RiskScore {
					riskyPackages[i], riskyPackages[j] = riskyPackages[j], riskyPackages[i]
				}
			}
		}
		return riskyPackages[:limit]
	}
	
	return riskyPackages
}

func (f *DashboardFormatter) calculatePackageRiskScore(threats []types.Threat) float64 {
	score := 0.0
	for _, threat := range threats {
		switch threat.Severity {
		case types.SeverityCritical:
			score += 10.0
		case types.SeverityHigh:
			score += 7.0
		case types.SeverityMedium:
			score += 4.0
		case types.SeverityLow:
			score += 1.0
		}
		score += threat.Confidence * 2.0 // Factor in confidence
	}
	return score
}

func (f *DashboardFormatter) getHighestSeverity(threats []types.Threat) string {
	highestSeverity := types.SeverityLow
	for _, threat := range threats {
		if threat.Severity > highestSeverity {
			highestSeverity = threat.Severity
		}
	}
	return highestSeverity.String()
}

// generateHTMLReport creates an HTML dashboard report
func (f *DashboardFormatter) generateHTMLReport(data *DashboardData) ([]byte, error) {
	tmpl := template.Must(template.New("dashboard").Parse(dashboardTemplate))
	
	var buf bytes.Buffer
	err := tmpl.Execute(&buf, data)
	if err != nil {
		return nil, fmt.Errorf("failed to execute template: %w", err)
	}
	
	return buf.Bytes(), nil
}

// dashboardTemplate is the HTML template for the executive dashboard
const dashboardTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>TypoSentinel Security Dashboard - {{.RepositoryInfo.ProjectName}}</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background-color: #f8fafc;
            color: #334155;
            line-height: 1.6;
        }
        
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 2rem 0;
            text-align: center;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 0 1rem;
        }
        
        .dashboard-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 1.5rem;
            margin: 2rem 0;
        }
        
        .card {
            background: white;
            border-radius: 8px;
            padding: 1.5rem;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            border: 1px solid #e2e8f0;
        }
        
        .card h3 {
            color: #1e293b;
            margin-bottom: 1rem;
            font-size: 1.25rem;
        }
        
        .metric {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 0.75rem 0;
            border-bottom: 1px solid #f1f5f9;
        }
        
        .metric:last-child {
            border-bottom: none;
        }
        
        .metric-value {
            font-weight: 600;
            font-size: 1.1rem;
        }
        
        .risk-critical { color: #dc2626; }
        .risk-high { color: #ea580c; }
        .risk-medium { color: #d97706; }
        .risk-low { color: #65a30d; }
        .risk-minimal { color: #059669; }
        
        .recommendations {
            grid-column: 1 / -1;
        }
        
        .recommendation {
            background: #f8fafc;
            border-left: 4px solid #3b82f6;
            padding: 1rem;
            margin: 0.5rem 0;
            border-radius: 0 4px 4px 0;
        }
        
        .recommendation.critical {
            border-left-color: #dc2626;
            background: #fef2f2;
        }
        
        .recommendation.high {
            border-left-color: #ea580c;
            background: #fff7ed;
        }
        
        .chart-container {
            position: relative;
            height: 300px;
            margin: 1rem 0;
        }
        
        .repo-info {
            background: #f1f5f9;
            padding: 1rem;
            border-radius: 6px;
            margin: 1rem 0;
        }
        
        .repo-info strong {
            color: #475569;
        }
        
        .footer {
            text-align: center;
            padding: 2rem;
            color: #64748b;
            border-top: 1px solid #e2e8f0;
            margin-top: 3rem;
        }
        
        .status-badge {
            display: inline-block;
            padding: 0.25rem 0.75rem;
            border-radius: 9999px;
            font-size: 0.875rem;
            font-weight: 500;
        }
        
        .status-compliant {
            background: #dcfce7;
            color: #166534;
        }
        
        .status-at-risk {
            background: #fef3c7;
            color: #92400e;
        }
        
        .status-non-compliant {
            background: #fecaca;
            color: #991b1b;
        }
    </style>
</head>
<body>
    <div class="header">
        <div class="container">
            <h1>🛡️ TypoSentinel Security Dashboard</h1>
            <p>Comprehensive Security Analysis for {{.RepositoryInfo.ProjectName}}</p>
        </div>
    </div>
    
    <div class="container">
        <div class="repo-info">
            <strong>Repository:</strong> {{.RepositoryInfo.URL}} <br>
            <strong>Branch:</strong> {{.RepositoryInfo.Branch}} <br>
            <strong>Commit:</strong> {{.RepositoryInfo.CommitSHA}} <br>
            <strong>Scan Type:</strong> {{.RepositoryInfo.ScanType}} <br>
            <strong>Generated:</strong> {{.GeneratedAt.Format "2006-01-02 15:04:05 UTC"}}
        </div>
        
        <div class="dashboard-grid">
            <!-- Executive Summary -->
            <div class="card">
                <h3>📊 Executive Summary</h3>
                <div class="metric">
                    <span>Overall Risk Level</span>
                    <span class="metric-value risk-{{.ExecutiveSummary.OverallRiskLevel | lower}}">{{.ExecutiveSummary.OverallRiskLevel}}</span>
                </div>
                <div class="metric">
                    <span>Risk Score</span>
                    <span class="metric-value">{{printf "%.1f" .ExecutiveSummary.RiskScore}}/100</span>
                </div>
                <div class="metric">
                    <span>Total Packages</span>
                    <span class="metric-value">{{.ExecutiveSummary.TotalPackages}}</span>
                </div>
                <div class="metric">
                    <span>Vulnerable Packages</span>
                    <span class="metric-value risk-high">{{.ExecutiveSummary.VulnerablePackages}}</span>
                </div>
                <div class="metric">
                    <span>Security Posture</span>
                    <span class="metric-value">{{.ExecutiveSummary.SecurityPosture}}</span>
                </div>
                <div class="metric">
                    <span>Compliance Status</span>
                    <span class="status-badge status-{{.ExecutiveSummary.ComplianceStatus | lower | replace " " "-"}}">{{.ExecutiveSummary.ComplianceStatus}}</span>
                </div>
            </div>
            
            <!-- Threat Breakdown -->
            <div class="card">
                <h3>🚨 Threat Breakdown</h3>
                <div class="metric">
                    <span>Critical Issues</span>
                    <span class="metric-value risk-critical">{{.ExecutiveSummary.CriticalIssues}}</span>
                </div>
                <div class="metric">
                    <span>High Issues</span>
                    <span class="metric-value risk-high">{{.ExecutiveSummary.HighIssues}}</span>
                </div>
                <div class="metric">
                    <span>Medium Issues</span>
                    <span class="metric-value risk-medium">{{.ExecutiveSummary.MediumIssues}}</span>
                </div>
                <div class="metric">
                    <span>Low Issues</span>
                    <span class="metric-value risk-low">{{.ExecutiveSummary.LowIssues}}</span>
                </div>
                <div class="chart-container">
                    <canvas id="threatChart"></canvas>
                </div>
            </div>
            
            <!-- Risk Metrics -->
            <div class="card">
                <h3>📈 Risk Metrics</h3>
                <div class="metric">
                    <span>Supply Chain Risk</span>
                    <span class="metric-value">{{printf "%.1f" .RiskMetrics.SupplyChainRisk}}%</span>
                </div>
                <div class="metric">
                    <span>Vulnerability Risk</span>
                    <span class="metric-value">{{printf "%.1f" .RiskMetrics.VulnerabilityRisk}}%</span>
                </div>
                <div class="metric">
                    <span>License Risk</span>
                    <span class="metric-value">{{printf "%.1f" .RiskMetrics.LicenseRisk}}%</span>
                </div>
                <div class="metric">
                    <span>Maintenance Risk</span>
                    <span class="metric-value">{{printf "%.1f" .RiskMetrics.MaintenanceRisk}}%</span>
                </div>
                <div class="chart-container">
                    <canvas id="riskChart"></canvas>
                </div>
            </div>
            
            <!-- Top Risky Packages -->
            <div class="card">
                <h3>⚠️ Top Risky Packages</h3>
                {{range .RiskMetrics.TopRiskyPackages}}
                <div class="metric">
                    <div>
                        <strong>{{.Name}}@{{.Version}}</strong><br>
                        <small>{{.Description}}</small>
                    </div>
                    <span class="metric-value risk-{{.Severity | lower}}">{{printf "%.1f" .RiskScore}}</span>
                </div>
                {{end}}
            </div>
            
            <!-- Recommendations -->
            <div class="card recommendations">
                <h3>💡 Security Recommendations</h3>
                {{range .Recommendations}}
                <div class="recommendation {{.Priority | lower}}">
                    <h4>{{.Title}}</h4>
                    <p>{{.Description}}</p>
                    <p><strong>Action:</strong> {{.Action}}</p>
                    <p><strong>Impact:</strong> {{.Impact}} | <strong>Effort:</strong> {{.Effort}}</p>
                </div>
                {{end}}
            </div>
        </div>
    </div>
    
    <div class="footer">
        <p>Generated by TypoSentinel v2.0.0 | <a href="https://github.com/Alivanroy/Typosentinel">Learn More</a></p>
    </div>
    
    <script>
        // Threat Breakdown Chart
        const threatCtx = document.getElementById('threatChart').getContext('2d');
        new Chart(threatCtx, {
            type: 'doughnut',
            data: {
                labels: ['Critical', 'High', 'Medium', 'Low'],
                datasets: [{
                    data: [{{.ExecutiveSummary.CriticalIssues}}, {{.ExecutiveSummary.HighIssues}}, {{.ExecutiveSummary.MediumIssues}}, {{.ExecutiveSummary.LowIssues}}],
                    backgroundColor: ['#dc2626', '#ea580c', '#d97706', '#65a30d']
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'bottom'
                    }
                }
            }
        });
        
        // Risk Metrics Chart
        const riskCtx = document.getElementById('riskChart').getContext('2d');
        new Chart(riskCtx, {
            type: 'radar',
            data: {
                labels: ['Supply Chain', 'Vulnerability', 'License', 'Maintenance'],
                datasets: [{
                    label: 'Risk Level (%)',
                    data: [{{.RiskMetrics.SupplyChainRisk}}, {{.RiskMetrics.VulnerabilityRisk}}, {{.RiskMetrics.LicenseRisk}}, {{.RiskMetrics.MaintenanceRisk}}],
                    backgroundColor: 'rgba(59, 130, 246, 0.2)',
                    borderColor: 'rgba(59, 130, 246, 1)',
                    borderWidth: 2
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    r: {
                        beginAtZero: true,
                        max: 100
                    }
                }
            }
        });
        
        // Template helper functions
        function lower(str) {
            return str.toLowerCase();
        }
        
        function replace(str, old, newStr) {
            return str.replace(new RegExp(old, 'g'), newStr);
        }
    </script>
</body>
</html>`