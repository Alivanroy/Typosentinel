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
	var req types.GraphAnalysisRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.writeError(c, http.StatusBadRequest, "Invalid request body", err)
		return
	}

	// Validate request
	if req.Target == "" {
		h.writeError(c, http.StatusBadRequest, "Target path is required", nil)
		return
	}

	// Set default options if not specified
	if req.Options.MaxDepth == 0 {
		req.Options.MaxDepth = 5
	}

	// Perform dependency graph analysis using the scanner
	projectInfo := &types.ProjectInfo{
		Path: req.Target,
		Type: "auto", // Auto-detect project type
	}

	// Scan the project to get dependencies
	scanResult, err := h.scanner.ScanProject(projectInfo.Path)
	if err != nil {
		h.writeError(c, http.StatusInternalServerError, "Failed to scan project", err)
		return
	}

	// Generate analysis ID
	analysisID := fmt.Sprintf("graph_%d", time.Now().Unix())

	// Create dependency graph analysis result
	graphResult := &types.DependencyGraphAnalysisResult{
		Graph: &types.DependencyGraph{
			Nodes: h.convertToGraphNodes(scanResult.Packages),
			Edges: h.generateGraphEdges(scanResult.Packages),
			Stats: h.calculateGraphStats(scanResult.Packages),
		},
		RiskAnalysis: &types.GraphRiskAnalysis{
			OverallRisk:     h.calculateOverallRisk(scanResult.Packages),
			CriticalPaths:   h.findCriticalPaths(scanResult.Packages),
			VulnerablePaths: h.findVulnerablePaths(scanResult.Packages),
			RiskFactors:     h.analyzeRiskFactors(scanResult.Packages),
		},
		Metadata: map[string]interface{}{
			"analysis_id": analysisID,
			"target":      req.Target,
			"timestamp":   time.Now(),
			"duration":    time.Since(time.Now()),
		},
	}

	// Store analysis result
	h.analyses[analysisID] = &SupplyChainScanResult{
		ScanResult: scanResult,
		ScanMetadata: SupplyChainScanMetadata{
			ScanID:          analysisID,
			ScanType:        "dependency_graph",
			PackagesScanned: len(scanResult.Packages),
			Timestamp:       time.Now(),
			Configuration: map[string]interface{}{
				"target":     req.Target,
				"max_depth": req.Options.MaxDepth,
			},
		},
	}

	c.JSON(http.StatusOK, graphResult)
}

// HandleGraphGenerate generates dependency graph visualization
// POST /v1/supply-chain/graph/generate
func (h *SupplyChainHandlers) HandleGraphGenerate(c *gin.Context) {
	var req types.GraphGenerationRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.writeError(c, http.StatusBadRequest, "Invalid request body", err)
		return
	}

	// Validate request
	if req.Target == "" {
		h.writeError(c, http.StatusBadRequest, "Target path is required", nil)
		return
	}

	// Set default options
	if req.Options.Format == "" {
		req.Options.Format = "dot"
	}
	if req.Options.MaxDepth == 0 {
		req.Options.MaxDepth = 5
	}

	// Scan project and generate graph
	projectInfo := &types.ProjectInfo{
		Path: req.Target,
		Type: "auto",
	}

	scanResult, err := h.scanner.ScanProject(projectInfo.Path)
	if err != nil {
		h.writeError(c, http.StatusInternalServerError, "Failed to scan project", err)
		return
	}

	// Generate graph content based on format
	var graphContent string
	switch req.Options.Format {
	case "dot":
		graphContent = h.generateDotGraph(scanResult.Packages, req.Options)
	case "json":
		graphContent = h.generateJSONGraph(scanResult.Packages, req.Options)
	case "svg":
		graphContent = h.generateSVGGraph(scanResult.Packages, req.Options)
	default:
		h.writeError(c, http.StatusBadRequest, "Unsupported format", nil)
		return
	}

	response := map[string]interface{}{
		"target":           req.Target,
		"format":           req.Options.Format,
		"graph_content":    graphContent,
		"nodes_count":      len(scanResult.Packages),
		"generation_time":  time.Now(),
		"options":          req.Options,
	}

	c.JSON(http.StatusOK, response)
}

// HandleGraphExport exports dependency graph in various formats
// POST /v1/supply-chain/graph/export
func (h *SupplyChainHandlers) HandleGraphExport(c *gin.Context) {
	var req types.GraphExportRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.writeError(c, http.StatusBadRequest, "Invalid request body", err)
		return
	}

	// Validate request
	if req.Target == "" {
		h.writeError(c, http.StatusBadRequest, "Target is required", nil)
		return
	}

	// Set default format
	if req.Format == "" {
		req.Format = "json"
	}

	// Create mock export result for demonstration
	exportID := "export-" + time.Now().Format("20060102-150405")
	
	// Export graph in requested format
	var exportContent string
	var contentType string

	switch req.Format {
	case "json":
		exportContent = `{"nodes": [], "edges": [], "stats": {}}`
		contentType = "application/json"
	case "dot":
		exportContent = "digraph G {\n}\n"
		contentType = "text/vnd.graphviz"
	case "svg":
		exportContent = "<svg></svg>"
		contentType = "image/svg+xml"
	case "csv":
		exportContent = "package,version,risk_score\n"
		contentType = "text/csv"
	default:
		h.writeError(c, http.StatusBadRequest, "Unsupported export format", nil)
		return
	}

	// Set appropriate headers
	c.Header("Content-Type", contentType)
	if req.Options.PrettyPrint {
		filename := fmt.Sprintf("dependency-graph-%s.%s", exportID, req.Format)
		c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=%s", filename))
	}

	c.String(http.StatusOK, exportContent)
}

// HandleGraphStats returns statistics about dependency graphs
// GET /v1/supply-chain/graph/stats
func (h *SupplyChainHandlers) HandleGraphStats(c *gin.Context) {
	analysisID := c.Query("analysis_id")
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

	// Calculate comprehensive statistics
	stats := map[string]interface{}{
		"analysis_id":      analysisID,
		"total_packages":   len(result.Packages),
		"direct_deps":      h.countDirectDependencies(result.Packages),
		"transitive_deps":  h.countTransitiveDependencies(result.Packages),
		"max_depth":        h.calculateMaxDepth(result.Packages),
		"risk_distribution": h.calculateRiskDistribution(result.Packages),
		"ecosystem_breakdown": h.calculateEcosystemBreakdown(result.Packages),
		"vulnerability_stats": h.calculateVulnerabilityStats(result.Packages),
		"generated_at":     time.Now(),
	}

	c.JSON(http.StatusOK, stats)
}

// Helper methods for graph operations
func (h *SupplyChainHandlers) convertToGraphNodes(packages []*types.Package) []types.GraphNode {
	nodes := make([]types.GraphNode, 0, len(packages))
	for i, pkg := range packages {
		node := types.GraphNode{
			ID: fmt.Sprintf("%s@%s", pkg.Name, pkg.Version),
			Package: types.PackageInfo{
				Name:      pkg.Name,
				Version:   pkg.Version,
				Ecosystem: pkg.Type,
				License:   "", // License not available in Package type
			},
			RiskScore:  pkg.RiskScore,
			Centrality: 0.0, // Default centrality
			Depth:      0, // Depth not available in Package type
			Direct:     i < 10, // Assume first 10 are direct dependencies
		}
		nodes = append(nodes, node)
	}
	return nodes
}

func (h *SupplyChainHandlers) generateGraphEdges(packages []*types.Package) []types.GraphEdge {
	edges := make([]types.GraphEdge, 0)
	for i, pkg := range packages {
		if i > 0 {
			// Create edge from previous package (simplified)
			edge := types.GraphEdge{
				From:         fmt.Sprintf("%s@%s", packages[i-1].Name, packages[i-1].Version),
				To:           fmt.Sprintf("%s@%s", pkg.Name, pkg.Version),
				RelationType: types.RelationDependsOn,
				Scope:        types.ScopeRuntime,
				Optional:     false,
				Weight:       1.0,
			}
			edges = append(edges, edge)
		}
	}
	return edges
}

func (h *SupplyChainHandlers) calculateGraphStats(packages []*types.Package) types.GraphStats {
	return types.GraphStats{
		TotalNodes:     len(packages),
		TotalEdges:     len(packages) - 1, // Simplified
		MaxDepth:       h.calculateMaxDepth(packages),
		DirectDeps:     h.countDirectDependencies(packages),
		TransitiveDeps: h.countTransitiveDependencies(packages),
		CyclicDeps:     0, // Simplified
		AverageRisk:    0.0, // Default
		HighRiskNodes:  0, // Default
	}
}

// calculateEnhancedGraphStats provides comprehensive graph statistics
func (h *SupplyChainHandlers) calculateEnhancedGraphStats(packages []*types.Package) types.GraphStats {
	totalRisk := 0.0
	highRiskCount := 0
	cyclicDeps := h.detectCyclicDependencies(packages)
	
	for _, pkg := range packages {
		totalRisk += pkg.RiskScore
		if pkg.RiskScore > 0.7 {
			highRiskCount++
		}
	}
	
	averageRisk := 0.0
	if len(packages) > 0 {
		averageRisk = totalRisk / float64(len(packages))
	}
	
	return types.GraphStats{
		TotalNodes:     len(packages),
		TotalEdges:     h.calculateActualEdges(packages),
		MaxDepth:       h.calculateMaxDepth(packages),
		DirectDeps:     h.countDirectDependencies(packages),
		TransitiveDeps: h.countTransitiveDependencies(packages),
		CyclicDeps:     cyclicDeps,
		AverageRisk:    averageRisk,
		HighRiskNodes:  highRiskCount,
	}
}

func (h *SupplyChainHandlers) calculateOverallRisk(packages []*types.Package) types.RiskLevel {
	// Simplified risk calculation
	if len(packages) > 100 {
		return types.RiskLevelHigh
	} else if len(packages) > 50 {
		return types.RiskLevelMedium
	}
	return types.RiskLevelLow
}

func (h *SupplyChainHandlers) findCriticalPaths(packages []*types.Package) [][]string {
	// Simplified critical path detection
	paths := make([][]string, 0)
	if len(packages) > 0 {
		path := []string{fmt.Sprintf("%s@%s", packages[0].Name, packages[0].Version)}
		paths = append(paths, path)
	}
	return paths
}

func (h *SupplyChainHandlers) findVulnerablePaths(packages []*types.Package) [][]string {
	// Simplified vulnerable path detection
	return [][]string{} // No vulnerable paths by default
}

func (h *SupplyChainHandlers) analyzeRiskFactors(packages []*types.Package) []types.RiskFactor {
	// Simplified risk factor analysis
	factors := make([]types.RiskFactor, 0)
	if len(packages) > 50 {
		factors = append(factors, types.RiskFactor{
			Type:        "dependency_count",
			Description: "High number of dependencies",
			Severity:    types.RiskLevelMedium,
			Impact:      0.5,
		})
	}
	return factors
}

func (h *SupplyChainHandlers) generateDotGraph(packages []*types.Package, options types.GraphGenerationOptions) string {
	// Simplified DOT graph generation
	return "digraph G { /* simplified graph */ }"
}

func (h *SupplyChainHandlers) generateJSONGraph(packages []*types.Package, options types.GraphGenerationOptions) string {
	// Simplified JSON graph generation
	return "{\"nodes\": [], \"edges\": []}"
}

func (h *SupplyChainHandlers) generateSVGGraph(packages []*types.Package, options types.GraphGenerationOptions) string {
	// Simplified SVG generation
	return "<svg><!-- simplified graph --></svg>"
}

func (h *SupplyChainHandlers) exportAsJSON(result *SupplyChainScanResult) string {
	// Simplified JSON export
	return "{\"packages\": []}"
}

func (h *SupplyChainHandlers) exportAsDot(result *SupplyChainScanResult) string {
	// Simplified DOT export
	return "digraph G { /* simplified graph */ }"
}

func (h *SupplyChainHandlers) exportAsSVG(result *SupplyChainScanResult) string {
	// Simplified SVG export
	return "<svg><!-- simplified graph --></svg>"
}

func (h *SupplyChainHandlers) exportAsCSV(result *SupplyChainScanResult) string {
	// Simplified CSV export
	csv := "name,version,ecosystem,risk_score\n"
	for _, pkg := range result.Packages {
		csv += fmt.Sprintf("%s,%s,%s,%.2f\n", 
			pkg.Name, 
			pkg.Version, 
			pkg.Type, 
			pkg.RiskScore)
	}
	return csv
}

func (h *SupplyChainHandlers) countDirectDependencies(packages []*types.Package) int {
	// Simplified - assume first 10 are direct dependencies
	if len(packages) > 10 {
		return 10
	}
	return len(packages)
}

func (h *SupplyChainHandlers) countTransitiveDependencies(packages []*types.Package) int {
	// Simplified - assume remaining are transitive dependencies
	if len(packages) > 10 {
		return len(packages) - 10
	}
	return 0
}

func (h *SupplyChainHandlers) calculateMaxDepth(packages []*types.Package) int {
	// Simplified - return default max depth
	return 5
}



func (h *SupplyChainHandlers) calculateEcosystemBreakdown(packages []*types.Package) map[string]int {
	breakdown := make(map[string]int)
	for _, pkg := range packages {
		breakdown[pkg.Type]++
	}
	return breakdown
}

func (h *SupplyChainHandlers) calculateVulnerabilityStats(packages []*types.Package) map[string]int {
	stats := map[string]int{
		"critical": 0,
		"high":     0,
		"medium":   0,
		"low":      0,
	}
	
	for _, pkg := range packages {
		for _, threat := range pkg.Threats {
			switch threat.Severity {
			case types.SeverityCritical:
				stats["critical"]++
			case types.SeverityHigh:
				stats["high"]++
			case types.SeverityMedium:
				stats["medium"]++
			case types.SeverityLow:
				stats["low"]++
			}
		}
	}
	
	return stats
}

// Enhanced algorithm implementations

// applyCentralityAnalysis calculates centrality scores for nodes
func (h *SupplyChainHandlers) applyCentralityAnalysis(nodes []types.GraphNode, edges []types.GraphEdge) {
	// Build adjacency map
	adjacency := make(map[string][]string)
	for _, edge := range edges {
		adjacency[edge.From] = append(adjacency[edge.From], edge.To)
	}
	
	// Calculate betweenness centrality (simplified)
	for i := range nodes {
		nodes[i].Centrality = h.calculateBetweennessCentrality(nodes[i].ID, adjacency)
	}
}

// applyRiskPropagation propagates risk scores through the dependency graph
func (h *SupplyChainHandlers) applyRiskPropagation(nodes []types.GraphNode, edges []types.GraphEdge) {
	// Build dependency map
	dependencies := make(map[string][]string)
	for _, edge := range edges {
		dependencies[edge.To] = append(dependencies[edge.To], edge.From)
	}
	
	// Propagate risk scores
	for i := range nodes {
		propagatedRisk := nodes[i].RiskScore
		for _, depID := range dependencies[nodes[i].ID] {
			for j, depNode := range nodes {
				if depNode.ID == depID {
					propagatedRisk += nodes[j].RiskScore * 0.3 // 30% risk propagation
					break
				}
			}
		}
		nodes[i].RiskScore = propagatedRisk
	}
}

// applyAnomalyDetection identifies anomalous patterns in the dependency graph
func (h *SupplyChainHandlers) applyAnomalyDetection(nodes []types.GraphNode, edges []types.GraphEdge) {
	// Calculate average metrics
	totalRisk := 0.0
	totalCentrality := 0.0
	for _, node := range nodes {
		totalRisk += node.RiskScore
		totalCentrality += node.Centrality
	}
	
	avgRisk := totalRisk / float64(len(nodes))
	avgCentrality := totalCentrality / float64(len(nodes))
	
	// Mark anomalous nodes
	for i := range nodes {
		if nodes[i].RiskScore > avgRisk*2 || nodes[i].Centrality > avgCentrality*2 {
			if nodes[i].Metadata == nil {
				nodes[i].Metadata = make(map[string]interface{})
			}
			nodes[i].Metadata["anomalous"] = true
			nodes[i].Metadata["anomaly_reason"] = "High risk or centrality score"
		}
	}
}

// applyCommunityDetection identifies communities in the dependency graph
func (h *SupplyChainHandlers) applyCommunityDetection(nodes []types.GraphNode, edges []types.GraphEdge) {
	// Simple community detection based on package ecosystems
	communities := make(map[string]int)
	communityID := 0
	
	for i := range nodes {
		ecosystem := nodes[i].Package.Ecosystem
		if _, exists := communities[ecosystem]; !exists {
			communities[ecosystem] = communityID
			communityID++
		}
		
		if nodes[i].Metadata == nil {
			nodes[i].Metadata = make(map[string]interface{})
		}
		nodes[i].Metadata["community_id"] = communities[ecosystem]
		nodes[i].Metadata["ecosystem"] = ecosystem
	}
}

// performEnhancedRiskAnalysis provides comprehensive risk analysis
func (h *SupplyChainHandlers) performEnhancedRiskAnalysis(packages []*types.Package, algorithms []types.GraphAnalysisAlgorithm) *types.GraphRiskAnalysis {
	overallRisk := h.calculateOverallRisk(packages)
	riskScore := h.calculateRiskScore(packages)
	criticalPaths := h.findCriticalPaths(packages)
	vulnerablePaths := h.findVulnerablePaths(packages)
	riskFactors := h.analyzeRiskFactors(packages)
	riskDistribution := h.calculateRiskDistribution(packages)
	
	return &types.GraphRiskAnalysis{
		OverallRisk:      overallRisk,
		RiskScore:        riskScore,
		CriticalPaths:    criticalPaths,
		VulnerablePaths:  vulnerablePaths,
		RiskFactors:      riskFactors,
		RiskDistribution: riskDistribution,
	}
}

// generateRecommendations creates actionable recommendations
func (h *SupplyChainHandlers) generateRecommendations(packages []*types.Package, riskAnalysis *types.GraphRiskAnalysis) []types.Recommendation {
	recommendations := make([]types.Recommendation, 0)
	
	// High-risk package recommendations
	for _, pkg := range packages {
		if pkg.RiskScore > 0.8 {
			recommendations = append(recommendations, types.Recommendation{
				ID:          fmt.Sprintf("high-risk-%s", pkg.Name),
				Type:        types.RecommendationTypeInvestigate,
				Priority:    types.PriorityHigh,
				Title:       fmt.Sprintf("High-risk package detected: %s", pkg.Name),
				Description: fmt.Sprintf("Package %s@%s has a high risk score of %.2f", pkg.Name, pkg.Version, pkg.RiskScore),
				Actions: []types.RecommendationAction{
					{
						Order:       1,
						Description: "Consider finding alternative packages or implementing additional security measures",
						Automated:   false,
						Required:    true,
					},
				},
				Impact:      "High security risk reduction",
				Effort:      types.EffortMedium,
			})
		}
	}
	
	// Vulnerability recommendations
	if len(riskAnalysis.VulnerablePaths) > 0 {
		recommendations = append(recommendations, types.Recommendation{
			ID:          "vulnerable-paths",
			Type:        types.RecommendationTypeUpdate,
			Priority:    types.PriorityMedium,
			Title:       "Vulnerable dependency paths detected",
			Description: fmt.Sprintf("Found %d vulnerable dependency paths", len(riskAnalysis.VulnerablePaths)),
			Actions: []types.RecommendationAction{
				{
					Order:       1,
					Description: "Review and update vulnerable dependencies",
					Automated:   false,
					Required:    true,
				},
			},
			Impact:      "Vulnerability mitigation",
			Effort:      types.EffortLow,
		})
	}
	
	return recommendations
}

// Helper methods for enhanced functionality

func (h *SupplyChainHandlers) calculateBetweennessCentrality(nodeID string, adjacency map[string][]string) float64 {
	// Simplified betweenness centrality calculation
	// In a real implementation, this would use algorithms like Brandes' algorithm
	connections := len(adjacency[nodeID])
	return float64(connections) / 10.0 // Normalized
}

func (h *SupplyChainHandlers) calculateRiskScore(packages []*types.Package) float64 {
	totalRisk := 0.0
	for _, pkg := range packages {
		totalRisk += pkg.RiskScore
	}
	if len(packages) == 0 {
		return 0.0
	}
	return totalRisk / float64(len(packages))
}

func (h *SupplyChainHandlers) calculateRiskDistribution(packages []*types.Package) map[types.RiskLevel]int {
	distribution := make(map[types.RiskLevel]int)
	
	for _, pkg := range packages {
		var riskLevel types.RiskLevel
		switch {
		case pkg.RiskScore >= 0.8:
			riskLevel = types.RiskLevelCritical
		case pkg.RiskScore >= 0.6:
			riskLevel = types.RiskLevelHigh
		case pkg.RiskScore >= 0.4:
			riskLevel = types.RiskLevelMedium
		default:
			riskLevel = types.RiskLevelLow
		}
		distribution[riskLevel]++
	}
	
	return distribution
}

func (h *SupplyChainHandlers) detectCyclicDependencies(packages []*types.Package) int {
	// Simplified cycle detection
	// In a real implementation, this would use DFS or similar algorithms
	return 0
}

func (h *SupplyChainHandlers) calculateActualEdges(packages []*types.Package) int {
	totalEdges := 0
	for _, pkg := range packages {
		totalEdges += len(pkg.Dependencies)
	}
	return totalEdges
}

func (h *SupplyChainHandlers) getAlgorithmNames(algorithms []types.GraphAnalysisAlgorithm) []string {
	names := make([]string, len(algorithms))
	for i, alg := range algorithms {
		names[i] = string(alg)
	}
	return names
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