package handlers

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/typosentinel/typosentinel/internal/analyzer"
	"github.com/typosentinel/typosentinel/internal/config"
	"github.com/typosentinel/typosentinel/internal/logger"
)

// IDEScanRequest represents the request payload for IDE scanning
type IDEScanRequest struct {
	Ecosystem string        `json:"ecosystem" binding:"required"`
	Packages  []PackageInfo `json:"packages" binding:"required"`
	Options   *ScanOptions  `json:"options,omitempty"`
}

// PackageInfo represents a package with name and version
type PackageInfo struct {
	Name    string `json:"name" binding:"required"`
	Version string `json:"version" binding:"required"`
}

// ScanOptions represents optional scanning parameters
type ScanOptions struct {
	ConfidenceThreshold    float64 `json:"confidence_threshold,omitempty"`
	IncludeRemediation     bool    `json:"include_remediation,omitempty"`
	IncludeTransitive      bool    `json:"include_transitive,omitempty"`
	IncludeLicenseAnalysis bool    `json:"include_license_analysis,omitempty"`
	IncludeProjectHealth   bool    `json:"include_project_health,omitempty"`
}

// IDEScanResponse represents the response payload for IDE scanning
type IDEScanResponse struct {
	Findings        []Finding         `json:"findings"`
	DependencyTree  *DependencyTree   `json:"dependency_tree,omitempty"`
	LicenseAnalysis *LicenseAnalysis  `json:"license_analysis,omitempty"`
	ProjectHealth   *ProjectHealth    `json:"project_health,omitempty"`
	ScanMetadata    ScanMetadata      `json:"scan_metadata"`
}

// Finding represents a security or quality finding
type Finding struct {
	PackageName  string       `json:"packageName"`
	Severity     string       `json:"severity"`
	Type         string       `json:"type"`
	Description  string       `json:"description"`
	CVE          *string      `json:"cve,omitempty"`
	Remediation  *Remediation `json:"remediation,omitempty"`
	Confidence   float64      `json:"confidence"`
	FirstSeen    time.Time    `json:"first_seen"`
	LastUpdated  time.Time    `json:"last_updated"`
}

// Remediation represents suggested fixes for a finding
type Remediation struct {
	Type               string  `json:"type"` // UPGRADE, REMOVE, REPLACE
	SafeVersion        *string `json:"safeVersion,omitempty"`
	AlternativePackage *string `json:"alternativePackage,omitempty"`
	Description        string  `json:"description"`
	Urgency           string  `json:"urgency"` // LOW, MEDIUM, HIGH, CRITICAL
}

// DependencyTree represents the dependency hierarchy (Phase 3)
type DependencyTree struct {
	Direct     []DependencyNode `json:"direct"`
	Transitive []DependencyNode `json:"transitive"`
	Depth      int              `json:"depth"`
	TotalCount int              `json:"total_count"`
}

// DependencyNode represents a single dependency in the tree
type DependencyNode struct {
	Name         string             `json:"name"`
	Version      string             `json:"version"`
	Children     []DependencyNode   `json:"children,omitempty"`
	Findings     []Finding          `json:"findings,omitempty"`
	Licenses     []string           `json:"licenses,omitempty"`
	Maintenance  *MaintenanceInfo   `json:"maintenance,omitempty"`
}

// LicenseAnalysis represents license compliance analysis (Phase 3)
type LicenseAnalysis struct {
	Violations      []LicenseViolation `json:"violations"`
	Compatibility   string             `json:"compatibility"` // COMPATIBLE, INCOMPATIBLE, UNKNOWN
	RiskLevel       string             `json:"risk_level"`    // LOW, MEDIUM, HIGH
	Recommendations []string           `json:"recommendations"`
}

// LicenseViolation represents a license compliance issue
type LicenseViolation struct {
	PackageName    string `json:"package_name"`
	License        string `json:"license"`
	ViolationType  string `json:"violation_type"`
	Severity       string `json:"severity"`
	Description    string `json:"description"`
	Recommendation string `json:"recommendation"`
}

// ProjectHealth represents overall project health metrics (Phase 3)
type ProjectHealth struct {
	Score              float64                `json:"score"` // 0-100
	Grade              string                 `json:"grade"` // A, B, C, D, F
	Metrics            ProjectHealthMetrics   `json:"metrics"`
	Recommendations    []string               `json:"recommendations"`
	Trends             *ProjectHealthTrends   `json:"trends,omitempty"`
}

// ProjectHealthMetrics represents detailed health metrics
type ProjectHealthMetrics struct {
	SecurityScore      float64 `json:"security_score"`
	MaintenanceScore   float64 `json:"maintenance_score"`
	LicenseScore       float64 `json:"license_score"`
	DependencyScore    float64 `json:"dependency_score"`
	VulnerabilityCount int     `json:"vulnerability_count"`
	OutdatedCount      int     `json:"outdated_count"`
	UnmaintainedCount  int     `json:"unmaintained_count"`
}

// ProjectHealthTrends represents health trends over time
type ProjectHealthTrends struct {
	ScoreChange        float64 `json:"score_change"`        // Change from last scan
	VulnerabilityTrend string  `json:"vulnerability_trend"` // IMPROVING, STABLE, DEGRADING
	MaintenanceTrend   string  `json:"maintenance_trend"`   // IMPROVING, STABLE, DEGRADING
}

// MaintenanceInfo represents package maintenance information
type MaintenanceInfo struct {
	LastRelease    *time.Time `json:"last_release,omitempty"`
	ReleaseFreq    string     `json:"release_frequency"`
	MaintainerInfo string     `json:"maintainer_info"`
	IsDeprecated   bool       `json:"is_deprecated"`
	IsArchived     bool       `json:"is_archived"`
}

// ScanMetadata represents metadata about the scan
type ScanMetadata struct {
	ScanID       string    `json:"scan_id"`
	Timestamp    time.Time `json:"timestamp"`
	Duration     string    `json:"duration"`
	Ecosystem    string    `json:"ecosystem"`
	PackageCount int       `json:"package_count"`
	EngineVersion string   `json:"engine_version"`
}

// IDEHandler handles IDE-specific scanning requests
type IDEHandler struct {
	analyzer *analyzer.Analyzer
	config   *config.Config
	logger   *logger.Logger
}

// NewIDEHandler creates a new IDE handler
func NewIDEHandler(analyzer *analyzer.Analyzer, config *config.Config, logger *logger.Logger) *IDEHandler {
	return &IDEHandler{
		analyzer: analyzer,
		config:   config,
		logger:   logger,
	}
}

// ScanDependencies handles POST /api/v1/scan/ide
// Phase 1 implementation: Real-time scanning with rich hover info
func (h *IDEHandler) ScanDependencies(c *gin.Context) {
	start := time.Now()
	h.logger.Info("IDE scan request received")

	var req IDEScanRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.logger.Error("Invalid request payload", "error", err)
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid request payload",
			"details": err.Error(),
		})
		return
	}

	// Validate ecosystem
	if !isValidEcosystem(req.Ecosystem) {
		h.logger.Error("Unsupported ecosystem", "ecosystem", req.Ecosystem)
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Unsupported ecosystem",
			"supported": []string{"npm", "pip", "go", "maven", "gradle", "composer", "cargo"},
		})
		return
	}

	// Validate package count
	if len(req.Packages) == 0 {
		h.logger.Error("No packages provided")
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "No packages provided",
		})
		return
	}

	if len(req.Packages) > 1000 {
		h.logger.Error("Too many packages", "count", len(req.Packages))
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Too many packages (max 1000)",
		})
		return
	}

	// Set default options
	options := req.Options
	if options == nil {
		options = &ScanOptions{}
	}
	if options.ConfidenceThreshold == 0 {
		options.ConfidenceThreshold = h.config.Analysis.ConfidenceThreshold
	}

	// Perform the scan
	response, err := h.performScan(req.Ecosystem, req.Packages, options)
	if err != nil {
		h.logger.Error("Scan failed", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Scan failed",
			"details": err.Error(),
		})
		return
	}

	// Add scan metadata
	response.ScanMetadata = ScanMetadata{
		ScanID:        generateScanID(),
		Timestamp:     start,
		Duration:      time.Since(start).String(),
		Ecosystem:     req.Ecosystem,
		PackageCount:  len(req.Packages),
		EngineVersion: h.config.Version,
	}

	h.logger.Info("IDE scan completed", 
		"duration", time.Since(start),
		"packages", len(req.Packages),
		"findings", len(response.Findings),
	)

	c.JSON(http.StatusOK, response)
}

// performScan executes the actual scanning logic
func (h *IDEHandler) performScan(ecosystem string, packages []PackageInfo, options *ScanOptions) (*IDEScanResponse, error) {
	response := &IDEScanResponse{
		Findings: []Finding{},
	}

	// Scan each package
	for _, pkg := range packages {
		findings, err := h.scanPackage(ecosystem, pkg, options)
		if err != nil {
			h.logger.Warn("Failed to scan package", "package", pkg.Name, "error", err)
			continue
		}
		response.Findings = append(response.Findings, findings...)
	}

	// Phase 3: Add transitive dependency analysis if requested
	if options.IncludeTransitive {
		depTree, err := h.buildDependencyTree(ecosystem, packages)
		if err != nil {
			h.logger.Warn("Failed to build dependency tree", "error", err)
		} else {
			response.DependencyTree = depTree
		}
	}

	// Phase 3: Add license analysis if requested
	if options.IncludeLicenseAnalysis {
		licenseAnalysis, err := h.analyzeLicenses(ecosystem, packages)
		if err != nil {
			h.logger.Warn("Failed to analyze licenses", "error", err)
		} else {
			response.LicenseAnalysis = licenseAnalysis
		}
	}

	// Phase 3: Add project health if requested
	if options.IncludeProjectHealth {
		projectHealth, err := h.calculateProjectHealth(response)
		if err != nil {
			h.logger.Warn("Failed to calculate project health", "error", err)
		} else {
			response.ProjectHealth = projectHealth
		}
	}

	return response, nil
}

// scanPackage scans a single package for issues
func (h *IDEHandler) scanPackage(ecosystem string, pkg PackageInfo, options *ScanOptions) ([]Finding, error) {
	var findings []Finding

	// Use the existing analyzer to scan the package
	result, err := h.analyzer.AnalyzePackage(pkg.Name, pkg.Version, ecosystem)
	if err != nil {
		return nil, err
	}

	// Convert analyzer results to IDE findings
	for _, threat := range result.Threats {
		// Skip findings below confidence threshold
		if threat.Confidence < options.ConfidenceThreshold {
			continue
		}

		finding := Finding{
			PackageName: pkg.Name,
			Severity:    threat.Severity,
			Type:        threat.Type,
			Description: h.generateDescription(threat),
			Confidence:  threat.Confidence,
			FirstSeen:   threat.FirstSeen,
			LastUpdated: threat.LastUpdated,
		}

		// Add CVE if available
		if threat.CVE != "" {
			finding.CVE = &threat.CVE
		}

		// Add remediation if requested
		if options.IncludeRemediation {
			remediation := h.generateRemediation(threat, pkg)
			if remediation != nil {
				finding.Remediation = remediation
			}
		}

		findings = append(findings, finding)
	}

	return findings, nil
}

// generateDescription creates a detailed description for a threat
func (h *IDEHandler) generateDescription(threat analyzer.Threat) string {
	switch threat.Type {
	case "Typosquatting":
		return fmt.Sprintf("The package '%s' is a suspected typosquat of a popular package. "+
			"Typosquatting attacks exploit common typing mistakes to distribute malicious code. "+
			"This package may contain malware, steal credentials, or perform other malicious activities.",
			threat.PackageName)
	case "Known Vulnerability":
		return fmt.Sprintf("The package '%s' contains a known security vulnerability (%s). "+
			"This vulnerability could be exploited by attackers to compromise your application. "+
			"Consider upgrading to a patched version or applying the recommended mitigation.",
			threat.PackageName, threat.CVE)
	case "Malicious Code":
		return fmt.Sprintf("The package '%s' has been identified as containing malicious code. "+
			"This package may perform unauthorized actions such as data exfiltration, "+
			"cryptocurrency mining, or system compromise. Remove this package immediately.",
			threat.PackageName)
	case "Suspicious Behavior":
		return fmt.Sprintf("The package '%s' exhibits suspicious behavior patterns. "+
			"This may include unusual network activity, file system access, or code obfuscation. "+
			"Review the package source code and consider alternatives.",
			threat.PackageName)
	default:
		return fmt.Sprintf("Security issue detected in package '%s': %s",
			threat.PackageName, threat.Description)
	}
}

// generateRemediation creates remediation advice for a threat
func (h *IDEHandler) generateRemediation(threat analyzer.Threat, pkg PackageInfo) *Remediation {
	switch threat.Type {
	case "Known Vulnerability":
		// Try to find a safe version
		safeVersion := h.findSafeVersion(pkg.Name, pkg.Version, threat.CVE)
		if safeVersion != "" {
			return &Remediation{
				Type:        "UPGRADE",
				SafeVersion: &safeVersion,
				Description: fmt.Sprintf("Upgrade to version %s which fixes %s", safeVersion, threat.CVE),
				Urgency:     h.getUrgencyFromSeverity(threat.Severity),
			}
		}
	case "Typosquatting":
		// Try to find the legitimate package
		legitPackage := h.findLegitimatePackage(pkg.Name)
		if legitPackage != "" {
			return &Remediation{
				Type:               "REPLACE",
				AlternativePackage: &legitPackage,
				Description:        fmt.Sprintf("Replace with the legitimate package '%s'", legitPackage),
				Urgency:           "HIGH",
			}
		}
	case "Malicious Code":
		return &Remediation{
			Type:        "REMOVE",
			Description: "Remove this malicious package immediately",
			Urgency:     "CRITICAL",
		}
	}

	return nil
}

// buildDependencyTree builds the dependency tree (Phase 3)
func (h *IDEHandler) buildDependencyTree(ecosystem string, packages []PackageInfo) (*DependencyTree, error) {
	// Placeholder for Phase 3 implementation
	// This would integrate with package manager APIs to resolve transitive dependencies
	return &DependencyTree{
		Direct:     []DependencyNode{},
		Transitive: []DependencyNode{},
		Depth:      0,
		TotalCount: len(packages),
	}, nil
}

// analyzeLicenses performs license compliance analysis (Phase 3)
func (h *IDEHandler) analyzeLicenses(ecosystem string, packages []PackageInfo) (*LicenseAnalysis, error) {
	// Placeholder for Phase 3 implementation
	return &LicenseAnalysis{
		Violations:      []LicenseViolation{},
		Compatibility:   "UNKNOWN",
		RiskLevel:       "LOW",
		Recommendations: []string{},
	}, nil
}

// calculateProjectHealth calculates overall project health (Phase 3)
func (h *IDEHandler) calculateProjectHealth(response *IDEScanResponse) (*ProjectHealth, error) {
	// Placeholder for Phase 3 implementation
	// This would analyze all findings and calculate health metrics
	vulnCount := 0
	for _, finding := range response.Findings {
		if finding.Severity == "Critical" || finding.Severity == "High" {
			vulnCount++
		}
	}

	// Simple scoring based on vulnerability count
	score := 100.0
	if vulnCount > 0 {
		score = max(0, 100-float64(vulnCount*20))
	}

	grade := "A"
	if score < 80 {
		grade = "B"
	}
	if score < 60 {
		grade = "C"
	}
	if score < 40 {
		grade = "D"
	}
	if score < 20 {
		grade = "F"
	}

	return &ProjectHealth{
		Score: score,
		Grade: grade,
		Metrics: ProjectHealthMetrics{
			SecurityScore:      score,
			VulnerabilityCount: vulnCount,
		},
		Recommendations: []string{},
	}, nil
}

// Helper functions

func isValidEcosystem(ecosystem string) bool {
	valid := []string{"npm", "pip", "go", "maven", "gradle", "composer", "cargo", "nuget"}
	for _, v := range valid {
		if v == ecosystem {
			return true
		}
	}
	return false
}

func generateScanID() string {
	return fmt.Sprintf("ide_%d", time.Now().UnixNano())
}

func (h *IDEHandler) findSafeVersion(packageName, currentVersion, cve string) string {
	// Placeholder: In a real implementation, this would query a vulnerability database
	// to find the first version that fixes the given CVE
	return ""
}

func (h *IDEHandler) findLegitimatePackage(typosquatName string) string {
	// Placeholder: In a real implementation, this would use fuzzy matching
	// to find the most likely legitimate package name
	commonTypos := map[string]string{
		"lodahs":    "lodash",
		"reqeust":   "request",
		"expres":    "express",
		"momnet":    "moment",
		"chokidra":  "chokidar",
		"colros":    "colors",
	}
	return commonTypos[typosquatName]
}

func (h *IDEHandler) getUrgencyFromSeverity(severity string) string {
	switch severity {
	case "Critical":
		return "CRITICAL"
	case "High":
		return "HIGH"
	case "Medium":
		return "MEDIUM"
	default:
		return "LOW"
	}
}

func max(a, b float64) float64 {
	if a > b {
		return a
	}
	return b
}