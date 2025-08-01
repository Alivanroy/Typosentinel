package handlers

import (
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/Alivanroy/Typosentinel/internal/config"
	"github.com/Alivanroy/Typosentinel/internal/scanner"
	"github.com/Alivanroy/Typosentinel/pkg/logger"
	"github.com/Alivanroy/Typosentinel/pkg/types"
)

// SupplyChainHandlers contains handlers for supply chain security endpoints
type SupplyChainHandlers struct {
	scanner  *scanner.Scanner
	config   *config.Config
	logger   *logger.Logger
	analyses map[string]*SupplyChainScanResult // In-memory storage for demo
}

// NewSupplyChainHandlers creates a new supply chain handlers instance
func NewSupplyChainHandlers(scanner *scanner.Scanner, cfg *config.Config, logger *logger.Logger) *SupplyChainHandlers {
	return &SupplyChainHandlers{
		scanner:  scanner,
		config:   cfg,
		logger:   logger,
		analyses: make(map[string]*SupplyChainScanResult),
	}
}

// SupplyChainScanResult represents enhanced scan results with supply chain analysis
type SupplyChainScanResult struct {
	*types.ScanResult
	BuildIntegrityFindings []BuildIntegrityFinding `json:"build_integrity_findings"`
	ZeroDayFindings        []ZeroDayFinding        `json:"zero_day_findings"`
	ThreatIntelFindings    []ThreatIntelFinding    `json:"threat_intel_findings"`
	HoneypotDetections     []HoneypotDetection     `json:"honeypot_detections"`
	SupplyChainRisk        SupplyChainRiskScore    `json:"supply_chain_risk"`
	ScanMetadata           SupplyChainScanMetadata `json:"scan_metadata"`
}

// Request/Response types
type ScanRequest struct {
	PackageName    string            `json:"package_name"`
	Version        string            `json:"version,omitempty"`
	Registry       string            `json:"registry,omitempty"`
	ScanOptions    ScanOptions       `json:"scan_options,omitempty"`
	Metadata       map[string]string `json:"metadata,omitempty"`
}

type ScanOptions struct {
	BuildIntegrity    bool `json:"build_integrity"`
	ZeroDayDetection  bool `json:"zero_day_detection"`
	DependencyGraph   bool `json:"dependency_graph"`
	ThreatIntel       bool `json:"threat_intel"`
	HoneypotDetection bool `json:"honeypot_detection"`
	DeepScan          bool `json:"deep_scan"`
}

type ScanResponse struct {
	AnalysisID    string                  `json:"analysis_id"`
	Status        string                  `json:"status"`
	StartTime     time.Time               `json:"start_time"`
	Result        *SupplyChainScanResult  `json:"result,omitempty"`
	Message       string                  `json:"message,omitempty"`
}

type GraphAnalyzeRequest struct {
	Packages    []PackageInfo `json:"packages"`
	Depth       int           `json:"depth,omitempty"`
	IncludeDevs bool          `json:"include_devs,omitempty"`
}

type PackageInfo struct {
	Name     string `json:"name"`
	Version  string `json:"version"`
	Registry string `json:"registry,omitempty"`
}

type ThreatIntelQuery struct {
	PackageName string   `json:"package_name,omitempty"`
	Indicators  []string `json:"indicators,omitempty"`
	ThreatTypes []string `json:"threat_types,omitempty"`
	Limit       int      `json:"limit,omitempty"`
}

// Supply chain specific types
type BuildIntegrityFinding struct {
	ID          string                 `json:"id"`
	Type        string                 `json:"type"`
	Severity    types.Severity         `json:"severity"`
	Description string                 `json:"description"`
	Confidence  float64                `json:"confidence"`
	Metadata    map[string]interface{} `json:"metadata"`
	DetectedAt  time.Time              `json:"detected_at"`
}

type ZeroDayFinding struct {
	ID             string                 `json:"id"`
	Type           string                 `json:"type"`
	Severity       types.Severity         `json:"severity"`
	Description    string                 `json:"description"`
	BehaviorType   string                 `json:"behavior_type"`
	AnomalyScore   float64                `json:"anomaly_score"`
	Confidence     float64                `json:"confidence"`
	Recommendation string                 `json:"recommendation"`
	Metadata       map[string]interface{} `json:"metadata"`
	DetectedAt     time.Time              `json:"detected_at"`
}

type ThreatIntelFinding struct {
	ID          string                 `json:"id"`
	Source      string                 `json:"source"`
	Type        string                 `json:"type"`
	Severity    types.Severity         `json:"severity"`
	Description string                 `json:"description"`
	Confidence  float64                `json:"confidence"`
	References  []string               `json:"references"`
	Metadata    map[string]interface{} `json:"metadata"`
	DetectedAt  time.Time              `json:"detected_at"`
}

type HoneypotDetection struct {
	ID          string                 `json:"id"`
	Type        string                 `json:"type"`
	Description string                 `json:"description"`
	Confidence  float64                `json:"confidence"`
	Metadata    map[string]interface{} `json:"metadata"`
	DetectedAt  time.Time              `json:"detected_at"`
}

type SupplyChainRiskScore struct {
	OverallScore    float64                `json:"overall_score"`
	RiskLevel       types.Severity         `json:"risk_level"`
	Factors         []RiskFactor           `json:"factors"`
	Recommendations []string               `json:"recommendations"`
	Metadata        map[string]interface{} `json:"metadata"`
	CalculatedAt    time.Time              `json:"calculated_at"`
}

type SupplyChainScanMetadata struct {
	ScanID           string                 `json:"scan_id"`
	ScanType         string                 `json:"scan_type"`
	DetectorsUsed    []string               `json:"detectors_used"`
	ScanDuration     time.Duration          `json:"scan_duration"`
	PackagesScanned  int                    `json:"packages_scanned"`
	FindingsCount    map[string]int         `json:"findings_count"`
	Configuration    map[string]interface{} `json:"configuration"`
	Timestamp        time.Time              `json:"timestamp"`
}

type RiskFactor struct {
	Type  string  `json:"type"`
	Score float64 `json:"score"`
}

// Handler methods

// HandleScan processes supply chain scan requests
// POST /v1/supply-chain/scan
func (h *SupplyChainHandlers) HandleScan(c *gin.Context) {
	var req ScanRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.writeError(c, http.StatusBadRequest, "Invalid request body", err)
		return
	}

	// Validate request
	if req.PackageName == "" {
		h.writeError(c, http.StatusBadRequest, "Package name is required", nil)
		return
	}

	// Generate analysis ID
	analysisID := fmt.Sprintf("sc_%d", time.Now().UnixNano())

	// Create scan metadata
	metadata := SupplyChainScanMetadata{
		ScanID:        analysisID,
		ScanType:      "enhanced_supply_chain",
		DetectorsUsed: []string{"build_integrity", "zero_day", "dependency_graph", "threat_intel"},
		Timestamp:     time.Now(),
		Configuration: map[string]interface{}{
			"package_name":       req.PackageName,
			"version":            req.Version,
			"registry":           req.Registry,
			"build_integrity":    req.ScanOptions.BuildIntegrity,
			"zero_day_detection": req.ScanOptions.ZeroDayDetection,
			"dependency_graph":   req.ScanOptions.DependencyGraph,
			"threat_intel":       req.ScanOptions.ThreatIntel,
			"honeypot_detection": req.ScanOptions.HoneypotDetection,
			"deep_scan":          req.ScanOptions.DeepScan,
		},
	}

	// Create enhanced scan result with sample data
	result := &SupplyChainScanResult{
		BuildIntegrityFindings: h.generateSampleBuildFindings(req.PackageName),
		ZeroDayFindings:        h.generateSampleZeroDayFindings(req.PackageName),
		ThreatIntelFindings:    h.generateSampleThreatIntelFindings(req.PackageName),
		HoneypotDetections:     h.generateSampleHoneypotDetections(req.PackageName),
		SupplyChainRisk:        h.calculateSupplyChainRisk(req.PackageName),
		ScanMetadata:           metadata,
	}

	// Store result for later retrieval
	h.analyses[analysisID] = result

	// Prepare response
	response := ScanResponse{
		AnalysisID: analysisID,
		Status:     "completed",
		StartTime:  metadata.Timestamp,
		Result:     result,
		Message:    "Supply chain scan completed successfully",
	}

	c.JSON(http.StatusOK, response)
}

// HandleGetAnalysis retrieves supply chain analysis results
// GET /v1/supply-chain/analysis/:id
func (h *SupplyChainHandlers) HandleGetAnalysis(c *gin.Context) {
	analysisID := c.Param("id")

	if analysisID == "" {
		h.writeError(c, http.StatusBadRequest, "Analysis ID is required", nil)
		return
	}

	// Retrieve analysis result
	result, exists := h.analyses[analysisID]
	if !exists {
		h.writeError(c, http.StatusNotFound, "Analysis not found", nil)
		return
	}

	response := ScanResponse{
		AnalysisID: analysisID,
		Status:     "completed",
		Result:     result,
		Message:    "Analysis retrieved successfully",
	}

	c.JSON(http.StatusOK, response)
}

// HandleGraphAnalyze processes dependency graph analysis requests
// POST /v1/supply-chain/graph/analyze
func (h *SupplyChainHandlers) HandleGraphAnalyze(c *gin.Context) {
	var req GraphAnalyzeRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.writeError(c, http.StatusBadRequest, "Invalid request body", err)
		return
	}

	// Validate request
	if len(req.Packages) == 0 {
		h.writeError(c, http.StatusBadRequest, "At least one package is required", nil)
		return
	}

	// Set default depth if not specified
	if req.Depth == 0 {
		req.Depth = 5
	}

	// Perform dependency graph analysis for each package
	var results []*SupplyChainScanResult
	for _, pkg := range req.Packages {
		// Create mock result for demo
		result := &SupplyChainScanResult{
			BuildIntegrityFindings: h.generateSampleBuildFindings(pkg.Name),
			ZeroDayFindings:        h.generateSampleZeroDayFindings(pkg.Name),
			ThreatIntelFindings:    h.generateSampleThreatIntelFindings(pkg.Name),
			HoneypotDetections:     h.generateSampleHoneypotDetections(pkg.Name),
			SupplyChainRisk:        h.calculateSupplyChainRisk(pkg.Name),
			ScanMetadata: SupplyChainScanMetadata{
				ScanID:    fmt.Sprintf("graph_%s_%d", pkg.Name, time.Now().Unix()),
				ScanType:  "dependency_graph",
				Timestamp: time.Now(),
				Configuration: map[string]interface{}{
					"package_name": pkg.Name,
					"version":      pkg.Version,
					"registry":     pkg.Registry,
					"depth":        req.Depth,
				},
			},
		}
		results = append(results, result)
	}

	response := map[string]interface{}{
		"analysis_count": len(results),
		"results":        results,
		"depth":          req.Depth,
		"include_devs":   req.IncludeDevs,
		"timestamp":      time.Now(),
	}

	c.JSON(http.StatusOK, response)
}

// HandleThreatIntel processes threat intelligence queries
// GET /v1/supply-chain/threats/intel
func (h *SupplyChainHandlers) HandleThreatIntel(c *gin.Context) {
	// Parse query parameters
	packageName := c.Query("package")
	threatType := c.Query("type")
	limitStr := c.Query("limit")

	limit := 10 // default limit
	if limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 {
			limit = l
		}
	}

	// Create threat intelligence query
	query := ThreatIntelQuery{
		PackageName: packageName,
		Limit:       limit,
	}

	if threatType != "" {
		query.ThreatTypes = []string{threatType}
	}

	// Generate threat intelligence data
	response := map[string]interface{}{
		"query":     query,
		"threats":   h.generateSampleThreats(packageName, threatType, limit),
		"timestamp": time.Now(),
		"source":    "TypoSentinel Threat Intelligence",
	}

	c.JSON(http.StatusOK, response)
}

// Helper methods for generating sample data

func (h *SupplyChainHandlers) generateSampleBuildFindings(packageName string) []BuildIntegrityFinding {
	if packageName == "" {
		return []BuildIntegrityFinding{}
	}

	return []BuildIntegrityFinding{
		{
			ID:          fmt.Sprintf("build_%s_%d", packageName, time.Now().Unix()),
			Type:        "unsigned_package",
			Severity:    types.SeverityMedium,
			Description: fmt.Sprintf("Package %s is not digitally signed", packageName),
			Confidence:  0.8,
			Metadata:    map[string]interface{}{"package": packageName},
			DetectedAt:  time.Now(),
		},
	}
}

func (h *SupplyChainHandlers) generateSampleZeroDayFindings(packageName string) []ZeroDayFinding {
	if packageName == "" {
		return []ZeroDayFinding{}
	}

	return []ZeroDayFinding{
		{
			ID:             fmt.Sprintf("zeroday_%s_%d", packageName, time.Now().Unix()),
			Type:           "behavioral_anomaly",
			Severity:       types.SeverityLow,
			Description:    fmt.Sprintf("Unusual behavior detected in package %s", packageName),
			BehaviorType:   "network_activity",
			AnomalyScore:   0.3,
			Confidence:     0.6,
			Recommendation: "Monitor package behavior during runtime",
			Metadata:       map[string]interface{}{"package": packageName},
			DetectedAt:     time.Now(),
		},
	}
}

func (h *SupplyChainHandlers) generateSampleThreatIntelFindings(packageName string) []ThreatIntelFinding {
	if packageName == "" {
		return []ThreatIntelFinding{}
	}

	return []ThreatIntelFinding{
		{
			ID:          fmt.Sprintf("threat_%s_%d", packageName, time.Now().Unix()),
			Source:      "TypoSentinel Intelligence",
			Type:        "typosquatting",
			Severity:    types.SeverityMedium,
			Description: fmt.Sprintf("Potential typosquatting detected for package %s", packageName),
			Confidence:  0.75,
			References:  []string{"https://example.com/threat-report"},
			Metadata:    map[string]interface{}{"package": packageName},
			DetectedAt:  time.Now(),
		},
	}
}

func (h *SupplyChainHandlers) generateSampleHoneypotDetections(packageName string) []HoneypotDetection {
	if packageName == "" {
		return []HoneypotDetection{}
	}

	return []HoneypotDetection{
		{
			ID:          fmt.Sprintf("honeypot_%s_%d", packageName, time.Now().Unix()),
			Type:        "package_trap",
			Description: fmt.Sprintf("Package %s may be a honeypot or trap", packageName),
			Confidence:  0.4,
			Metadata:    map[string]interface{}{"package": packageName},
			DetectedAt:  time.Now(),
		},
	}
}

func (h *SupplyChainHandlers) calculateSupplyChainRisk(packageName string) SupplyChainRiskScore {
	return SupplyChainRiskScore{
		OverallScore: 0.6,
		RiskLevel:    types.SeverityMedium,
		Factors: []RiskFactor{
			{Type: "build_integrity", Score: 0.7},
			{Type: "threat_intelligence", Score: 0.5},
			{Type: "zero_day_risk", Score: 0.3},
		},
		Recommendations: []string{
			"Verify package signatures",
			"Monitor for suspicious behavior",
			"Review dependency chain",
		},
		Metadata:     map[string]interface{}{"package": packageName},
		CalculatedAt: time.Now(),
	}
}

func (h *SupplyChainHandlers) generateSampleThreats(packageName, threatType string, limit int) []map[string]interface{} {
	threats := []map[string]interface{}{}

	if packageName != "" {
		threats = append(threats, map[string]interface{}{
			"id":          fmt.Sprintf("threat_%s_%d", packageName, time.Now().Unix()),
			"package":     packageName,
			"type":        "typosquatting",
			"severity":    "medium",
			"description": fmt.Sprintf("Potential typosquatting detected for package %s", packageName),
			"indicators":  []string{"suspicious_name", "low_download_count"},
			"confidence":  0.75,
			"timestamp":   time.Now(),
		})
	}

	// Add more sample threats based on type
	if threatType == "" || threatType == "malware" {
		threats = append(threats, map[string]interface{}{
			"id":          fmt.Sprintf("malware_%d", time.Now().Unix()),
			"type":        "malware",
			"severity":    "high",
			"description": "Known malicious package detected in ecosystem",
			"indicators":  []string{"malicious_code", "data_exfiltration"},
			"confidence":  0.95,
			"timestamp":   time.Now(),
		})
	}

	if len(threats) > limit {
		threats = threats[:limit]
	}

	return threats
}

// writeError writes an error response
func (h *SupplyChainHandlers) writeError(c *gin.Context, status int, message string, err error) {
	h.logger.Error(message)

	errorResponse := map[string]interface{}{
		"error":     message,
		"status":    status,
		"timestamp": time.Now(),
	}

	if err != nil {
		errorResponse["details"] = err.Error()
	}

	c.JSON(status, errorResponse)
}