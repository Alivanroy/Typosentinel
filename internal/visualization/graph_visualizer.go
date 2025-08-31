package visualization

import (
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/Alivanroy/Typosentinel/internal/analyzer"
	"github.com/Alivanroy/Typosentinel/pkg/types"
)

// GraphVisualizer provides advanced dependency graph visualization capabilities
type GraphVisualizer struct {
	config *VisualizationConfig
}

// VisualizationConfig contains configuration for graph visualization
type VisualizationConfig struct {
	Interactive     bool    `json:"interactive"`
	ShowRiskScores  bool    `json:"show_risk_scores"`
	ShowMetadata    bool    `json:"show_metadata"`
	ColorScheme     string  `json:"color_scheme"`
	Layout          string  `json:"layout"`
	MaxNodes        int     `json:"max_nodes"`
	MinRiskScore    float64 `json:"min_risk_score"`
	OutputDirectory string  `json:"output_directory"`
}

// InteractiveGraphData represents data for interactive visualization
type InteractiveGraphData struct {
	Nodes     []GraphNodeData `json:"nodes"`
	Edges     []GraphEdgeData `json:"edges"`
	Metadata  GraphMetadata   `json:"metadata"`
	Filters   FilterOptions   `json:"filters"`
	Timestamp time.Time       `json:"timestamp"`
}

// GraphNodeData represents a node in the interactive graph
type GraphNodeData struct {
	ID          string                 `json:"id"`
	Label       string                 `json:"label"`
	PackageName string                 `json:"package_name"`
	Version     string                 `json:"version"`
	RiskScore   float64                `json:"risk_score"`
	Severity    string                 `json:"severity"`
	Threats     []types.Threat         `json:"threats"`
	Direct      bool                   `json:"direct"`
	Depth       int                    `json:"depth"`
	Size        float64                `json:"size"`
	Color       string                 `json:"color"`
	Group       string                 `json:"group"`
	Metadata    map[string]interface{} `json:"metadata"`
	Coordinates *NodeCoordinates       `json:"coordinates,omitempty"`
}

// GraphEdgeData represents an edge in the interactive graph
type GraphEdgeData struct {
	ID     string  `json:"id"`
	Source string  `json:"source"`
	Target string  `json:"target"`
	Weight float64 `json:"weight"`
	Type   string  `json:"type"`
	Color  string  `json:"color"`
	Width  float64 `json:"width"`
	Dashed bool    `json:"dashed"`
}

// NodeCoordinates represents the position of a node
type NodeCoordinates struct {
	X float64 `json:"x"`
	Y float64 `json:"y"`
}

// GraphMetadata contains metadata about the graph
type GraphMetadata struct {
	Title           string    `json:"title"`
	ScanPath        string    `json:"scan_path"`
	TotalNodes      int       `json:"total_nodes"`
	TotalEdges      int       `json:"total_edges"`
	MaxDepth        int       `json:"max_depth"`
	HighRiskNodes   int       `json:"high_risk_nodes"`
	CriticalThreats int       `json:"critical_threats"`
	GeneratedAt     time.Time `json:"generated_at"`
	ScanDuration    string    `json:"scan_duration"`
}

// FilterOptions contains available filter options
type FilterOptions struct {
	SeverityLevels []string   `json:"severity_levels"`
	PackageTypes   []string   `json:"package_types"`
	RiskRange      RiskRange  `json:"risk_range"`
	DepthRange     DepthRange `json:"depth_range"`
}

// RiskRange represents the range of risk scores
type RiskRange struct {
	Min float64 `json:"min"`
	Max float64 `json:"max"`
}

// DepthRange represents the range of dependency depths
type DepthRange struct {
	Min int `json:"min"`
	Max int `json:"max"`
}

// NewGraphVisualizer creates a new graph visualizer instance
func NewGraphVisualizer(config *VisualizationConfig) *GraphVisualizer {
	if config == nil {
		config = &VisualizationConfig{
			Interactive:     true,
			ShowRiskScores:  true,
			ShowMetadata:    true,
			ColorScheme:     "risk",
			Layout:          "force",
			MaxNodes:        1000,
			MinRiskScore:    0.0,
			OutputDirectory: "./output",
		}
	}
	return &GraphVisualizer{config: config}
}

// GenerateInteractiveGraph creates an interactive HTML visualization
func (gv *GraphVisualizer) GenerateInteractiveGraph(result *analyzer.ScanResult, outputPath string) error {
	// Convert scan result to graph data
	graphData := gv.convertToGraphData(result)

	// Generate HTML file
	htmlContent := gv.generateHTMLVisualization(graphData)

	// Ensure output directory exists
	if err := os.MkdirAll(filepath.Dir(outputPath), 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	// Write HTML file
	if err := os.WriteFile(outputPath, []byte(htmlContent), 0644); err != nil {
		return fmt.Errorf("failed to write HTML file: %w", err)
	}

	fmt.Printf("✅ Interactive dependency graph generated: %s\n", outputPath)
	return nil
}

// GenerateAdvancedSVG creates an enhanced SVG visualization
func (gv *GraphVisualizer) GenerateAdvancedSVG(result *analyzer.ScanResult, outputPath string) error {
	graphData := gv.convertToGraphData(result)

	// Calculate layout
	gv.calculateForceLayout(graphData)

	// Generate SVG content
	svgContent := gv.generateAdvancedSVGContent(graphData)

	// Write SVG file
	if err := os.WriteFile(outputPath, []byte(svgContent), 0644); err != nil {
		return fmt.Errorf("failed to write SVG file: %w", err)
	}

	fmt.Printf("✅ Advanced SVG graph generated: %s\n", outputPath)
	return nil
}

// convertToGraphData converts analyzer result to graph visualization data
func (gv *GraphVisualizer) convertToGraphData(result *analyzer.ScanResult) *InteractiveGraphData {
	nodes := make([]GraphNodeData, 0)
	edges := make([]GraphEdgeData, 0)

	// Create root node
	rootNode := GraphNodeData{
		ID:          "root",
		Label:       filepath.Base(result.Path),
		PackageName: filepath.Base(result.Path),
		Version:     "root",
		RiskScore:   gv.calculateOverallRiskScore(result),
		Severity:    gv.calculateOverallSeverity(result),
		Direct:      true,
		Depth:       0,
		Size:        gv.calculateNodeSize(0, len(result.Threats)),
		Color:       gv.getNodeColor(gv.calculateOverallRiskScore(result)),
		Group:       "root",
		Metadata: map[string]interface{}{
			"total_packages": result.TotalPackages,
			"scan_duration":  result.Duration.String(),
		},
	}
	nodes = append(nodes, rootNode)

	// Create threat nodes
	for i, threat := range result.Threats {
		if i >= gv.config.MaxNodes-1 { // Reserve space for root node
			break
		}

		riskScore := gv.calculateThreatRiskScore(threat)
		if riskScore < gv.config.MinRiskScore {
			continue
		}

		nodeID := fmt.Sprintf("threat_%d", i)
		threatNode := GraphNodeData{
			ID:          nodeID,
			Label:       threat.Package,
			PackageName: threat.Package,
			Version:     threat.Version,
			RiskScore:   riskScore,
			Severity:    threat.Severity.String(),
			Threats:     []types.Threat{threat},
			Direct:      i < 10, // Assume first 10 are direct dependencies
			Depth:       gv.calculateDepth(threat),
			Size:        gv.calculateNodeSize(1, 1),
			Color:       gv.getNodeColor(riskScore),
			Group:       gv.getNodeGroup(threat),
			Metadata:    gv.extractThreatMetadata(threat),
		}
		nodes = append(nodes, threatNode)

		// Create edge from root to threat
		edgeID := fmt.Sprintf("edge_root_%d", i)
		edge := GraphEdgeData{
			ID:     edgeID,
			Source: "root",
			Target: nodeID,
			Weight: riskScore,
			Type:   "dependency",
			Color:  gv.getEdgeColor(riskScore),
			Width:  gv.calculateEdgeWidth(riskScore),
			Dashed: !threatNode.Direct,
		}
		edges = append(edges, edge)
	}

	// Calculate metadata
	metadata := GraphMetadata{
		Title:           fmt.Sprintf("Dependency Graph - %s", filepath.Base(result.Path)),
		ScanPath:        result.Path,
		TotalNodes:      len(nodes),
		TotalEdges:      len(edges),
		MaxDepth:        gv.calculateMaxDepth(nodes),
		HighRiskNodes:   gv.countHighRiskNodes(nodes),
		CriticalThreats: result.Summary.CriticalThreats,
		GeneratedAt:     time.Now(),
		ScanDuration:    result.Duration.String(),
	}

	// Calculate filter options
	filters := gv.calculateFilterOptions(nodes)

	return &InteractiveGraphData{
		Nodes:     nodes,
		Edges:     edges,
		Metadata:  metadata,
		Filters:   filters,
		Timestamp: time.Now(),
	}
}

// Helper methods for calculations

func (gv *GraphVisualizer) calculateOverallRiskScore(result *analyzer.ScanResult) float64 {
	if len(result.Threats) == 0 {
		return 0.0
	}

	totalRisk := 0.0
	for _, threat := range result.Threats {
		totalRisk += gv.calculateThreatRiskScore(threat)
	}
	return totalRisk / float64(len(result.Threats))
}

func (gv *GraphVisualizer) calculateOverallSeverity(result *analyzer.ScanResult) string {
	if result.Summary.CriticalThreats > 0 {
		return "critical"
	}
	if result.Summary.HighThreats > 0 {
		return "high"
	}
	if result.Summary.MediumThreats > 0 {
		return "medium"
	}
	return "low"
}

func (gv *GraphVisualizer) calculateThreatRiskScore(threat types.Threat) float64 {
	switch threat.Severity {
	case types.SeverityCritical:
		return 1.0
	case types.SeverityHigh:
		return 0.8
	case types.SeverityMedium:
		return 0.5
	case types.SeverityLow:
		return 0.2
	default:
		return 0.1
	}
}

func (gv *GraphVisualizer) calculateDepth(threat types.Threat) int {
	// Simple heuristic based on package name complexity
	parts := strings.Split(threat.Package, "/")
	return len(parts)
}

func (gv *GraphVisualizer) calculateNodeSize(baseSize int, threatCount int) float64 {
	size := float64(baseSize + threatCount*2)
	return math.Max(10, math.Min(50, size))
}

func (gv *GraphVisualizer) getNodeColor(riskScore float64) string {
	switch gv.config.ColorScheme {
	case "risk":
		if riskScore >= 0.8 {
			return "#dc3545" // Red
		} else if riskScore >= 0.5 {
			return "#fd7e14" // Orange
		} else if riskScore >= 0.2 {
			return "#ffc107" // Yellow
		}
		return "#28a745" // Green
	default:
		return "#007bff" // Blue
	}
}

func (gv *GraphVisualizer) getNodeGroup(threat types.Threat) string {
	switch threat.Severity {
	case types.SeverityCritical:
		return "critical"
	case types.SeverityHigh:
		return "high"
	case types.SeverityMedium:
		return "medium"
	default:
		return "low"
	}
}

func (gv *GraphVisualizer) getEdgeColor(riskScore float64) string {
	if riskScore >= 0.8 {
		return "#dc3545"
	} else if riskScore >= 0.5 {
		return "#fd7e14"
	}
	return "#6c757d"
}

func (gv *GraphVisualizer) calculateEdgeWidth(riskScore float64) float64 {
	return math.Max(1, riskScore*5)
}

func (gv *GraphVisualizer) extractThreatMetadata(threat types.Threat) map[string]interface{} {
	return map[string]interface{}{
		"type":        threat.Type,
		"description": threat.Description,
		"confidence":  threat.Confidence,
		"package":     threat.Package,
	}
}

func (gv *GraphVisualizer) calculateMaxDepth(nodes []GraphNodeData) int {
	maxDepth := 0
	for _, node := range nodes {
		if node.Depth > maxDepth {
			maxDepth = node.Depth
		}
	}
	return maxDepth
}

func (gv *GraphVisualizer) countHighRiskNodes(nodes []GraphNodeData) int {
	count := 0
	for _, node := range nodes {
		if node.RiskScore >= 0.7 {
			count++
		}
	}
	return count
}

func (gv *GraphVisualizer) calculateFilterOptions(nodes []GraphNodeData) FilterOptions {
	severityLevels := make(map[string]bool)
	packageTypes := make(map[string]bool)
	minRisk, maxRisk := 1.0, 0.0
	minDepth, maxDepth := 1000, 0

	for _, node := range nodes {
		severityLevels[node.Severity] = true
		packageTypes[node.Group] = true

		if node.RiskScore < minRisk {
			minRisk = node.RiskScore
		}
		if node.RiskScore > maxRisk {
			maxRisk = node.RiskScore
		}

		if node.Depth < minDepth {
			minDepth = node.Depth
		}
		if node.Depth > maxDepth {
			maxDepth = node.Depth
		}
	}

	severities := make([]string, 0, len(severityLevels))
	for severity := range severityLevels {
		severities = append(severities, severity)
	}
	sort.Strings(severities)

	types := make([]string, 0, len(packageTypes))
	for pkgType := range packageTypes {
		types = append(types, pkgType)
	}
	sort.Strings(types)

	return FilterOptions{
		SeverityLevels: severities,
		PackageTypes:   types,
		RiskRange:      RiskRange{Min: minRisk, Max: maxRisk},
		DepthRange:     DepthRange{Min: minDepth, Max: maxDepth},
	}
}

// generateHTMLVisualization creates interactive HTML content
func (gv *GraphVisualizer) generateHTMLVisualization(data *InteractiveGraphData) string {
	return fmt.Sprintf(`<!DOCTYPE html>
<html>
<head>
    <title>%s</title>
    <script src="https://d3js.org/d3.v7.min.js"></script>
    <style>
        body { font-family: Arial, sans-serif; margin: 0; padding: 20px; }
        .graph-container { width: 100%%; height: 600px; border: 1px solid #ccc; }
        .controls { margin-bottom: 20px; }
        .node { cursor: pointer; }
        .tooltip { position: absolute; background: rgba(0,0,0,0.8); color: white; padding: 10px; border-radius: 5px; pointer-events: none; }
    </style>
</head>
<body>
    <h1>%s</h1>
    <div class="controls">
        <label>Filter by Risk: <input type="range" id="riskFilter" min="0" max="1" step="0.1" value="0"></label>
        <label>Show Direct Only: <input type="checkbox" id="directFilter"></label>
    </div>
    <div id="graph" class="graph-container"></div>
    <script>
        const data = %s;
        // D3.js visualization code would go here
        console.log('Graph data loaded:', data);
    </script>
</body>
</html>`, data.Metadata.Title, data.Metadata.Title, gv.dataToJSON(data))
}

// calculateForceLayout calculates positions for nodes using force-directed layout
func (gv *GraphVisualizer) calculateForceLayout(data *InteractiveGraphData) {
	// Simple circular layout for demonstration
	centerX, centerY := 400.0, 300.0
	radius := 200.0

	for i := range data.Nodes {
		if data.Nodes[i].ID == "root" {
			data.Nodes[i].Coordinates = &NodeCoordinates{X: centerX, Y: centerY}
		} else {
			angle := 2 * math.Pi * float64(i-1) / float64(len(data.Nodes)-1)
			x := centerX + radius*math.Cos(angle)
			y := centerY + radius*math.Sin(angle)
			data.Nodes[i].Coordinates = &NodeCoordinates{X: x, Y: y}
		}
	}
}

// generateAdvancedSVGContent creates enhanced SVG visualization
func (gv *GraphVisualizer) generateAdvancedSVGContent(data *InteractiveGraphData) string {
	svg := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" width="800" height="600">
  <title>%s</title>
  <defs>
    <filter id="shadow">
      <feDropShadow dx="2" dy="2" stdDeviation="3" flood-opacity="0.3"/>
    </filter>
  </defs>
  <rect width="100%%" height="100%%" fill="#f8f9fa"/>
  <text x="400" y="30" text-anchor="middle" font-size="20" font-weight="bold">%s</text>
`, data.Metadata.Title, data.Metadata.Title)

	// Add edges
	for _, edge := range data.Edges {
		sourceNode := gv.findNodeByID(data.Nodes, edge.Source)
		targetNode := gv.findNodeByID(data.Nodes, edge.Target)
		if sourceNode != nil && targetNode != nil && sourceNode.Coordinates != nil && targetNode.Coordinates != nil {
			strokeStyle := "solid"
			if edge.Dashed {
				strokeStyle = "5,5"
			}
			svg += fmt.Sprintf(`  <line x1="%.1f" y1="%.1f" x2="%.1f" y2="%.1f" stroke="%s" stroke-width="%.1f" stroke-dasharray="%s"/>
`,
				sourceNode.Coordinates.X, sourceNode.Coordinates.Y,
				targetNode.Coordinates.X, targetNode.Coordinates.Y,
				edge.Color, edge.Width, strokeStyle)
		}
	}

	// Add nodes
	for _, node := range data.Nodes {
		if node.Coordinates != nil {
			svg += fmt.Sprintf(`  <circle cx="%.1f" cy="%.1f" r="%.1f" fill="%s" stroke="#333" stroke-width="1" filter="url(#shadow)"/>
`,
				node.Coordinates.X, node.Coordinates.Y, node.Size, node.Color)
			svg += fmt.Sprintf(`  <text x="%.1f" y="%.1f" text-anchor="middle" font-size="10" fill="white">%s</text>
`,
				node.Coordinates.X, node.Coordinates.Y+3, gv.truncateLabel(node.Label, 10))
		}
	}

	// Add legend
	svg += `  <g transform="translate(50, 500)">
    <text x="0" y="0" font-size="12" font-weight="bold">Legend:</text>
    <circle cx="15" cy="20" r="8" fill="#dc3545"/>
    <text x="30" y="25" font-size="10">High Risk</text>
    <circle cx="15" cy="40" r="8" fill="#ffc107"/>
    <text x="30" y="45" font-size="10">Medium Risk</text>
    <circle cx="15" cy="60" r="8" fill="#28a745"/>
    <text x="30" y="65" font-size="10">Low Risk</text>
  </g>
`

	svg += "</svg>"
	return svg
}

// Helper methods

func (gv *GraphVisualizer) dataToJSON(data *InteractiveGraphData) string {
	// Simple JSON serialization for demonstration
	return fmt.Sprintf(`{"nodes":%d,"edges":%d,"metadata":%s}`,
		len(data.Nodes), len(data.Edges), gv.metadataToJSON(data.Metadata))
}

func (gv *GraphVisualizer) metadataToJSON(metadata GraphMetadata) string {
	return fmt.Sprintf(`{"title":"%s","total_nodes":%d,"total_edges":%d}`,
		metadata.Title, metadata.TotalNodes, metadata.TotalEdges)
}

func (gv *GraphVisualizer) findNodeByID(nodes []GraphNodeData, id string) *GraphNodeData {
	for i := range nodes {
		if nodes[i].ID == id {
			return &nodes[i]
		}
	}
	return nil
}

func (gv *GraphVisualizer) truncateLabel(label string, maxLen int) string {
	if len(label) <= maxLen {
		return label
	}
	return label[:maxLen-3] + "..."
}
