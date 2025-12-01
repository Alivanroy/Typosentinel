package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/Alivanroy/Typosentinel/internal/analyzer"
	"github.com/Alivanroy/Typosentinel/internal/config"
	"github.com/Alivanroy/Typosentinel/internal/database"
	"github.com/Alivanroy/Typosentinel/internal/detector"
	"github.com/Alivanroy/Typosentinel/internal/output"
	"github.com/Alivanroy/Typosentinel/internal/scanner"
	"github.com/Alivanroy/Typosentinel/pkg/types"
)

// createDefaultConfig creates a default configuration
func createDefaultConfig() *config.Config {
	return &config.Config{
		TypoDetection: &config.TypoDetectionConfig{
			Enabled:           true,
			Threshold:         0.8,
			MaxDistance:       3,
			CheckSimilarNames: true,
			CheckHomoglyphs:   true,
		},
		SupplyChain: &config.SupplyChainConfig{
			Enabled: true,
			DependencyGraph: config.DependencyGraphConfig{
				Enabled:                 true,
				MaxDepth:                8,
				TransitiveAnalysis:      true,
				ConfusionDetection:      true,
				SupplyChainRiskAnalysis: true,
			},
			BuildIntegrity: config.BuildIntegrityConfig{
				Enabled:        true,
				SignatureCheck: false,
				Timeout:        time.Second * 30,
			},
			ZeroDayDetection: config.ZeroDayDetectionConfig{
				Enabled:            false,
				BehavioralAnalysis: false,
				Timeout:            time.Second * 30,
			},
			HoneypotDetection: config.HoneypotDetectionConfig{
				Enabled:             false,
				ConfidenceThreshold: 0.6,
				Timeout:             time.Second * 30,
			},
			RiskCalculation: config.RiskCalculationConfig{
				Enabled: true,
				Thresholds: config.RiskThresholds{
					Low:      0.2,
					Medium:   0.5,
					High:     0.7,
					Critical: 0.9,
				},
			},
		},
	}
}

// outputScanResult outputs the scan result in the specified format
func outputScanResult(result *analyzer.ScanResult, format string) {
	switch format {
	case "json":
		data, _ := json.MarshalIndent(result, "", "  ")
		fmt.Println(string(data))
	case "sarif":
		f := output.NewSARIFFormatter("", "", "", "cli")
		b, err := f.Format(result)
		if err != nil {
			data, _ := json.MarshalIndent(result, "", "  ")
			fmt.Println(string(data))
			return
		}
		fmt.Println(string(b))
	case "table":
		outputScanResultTable(result)
	case "spdx":
		outputSBOM(result, "spdx")
	case "cyclonedx":
		outputSBOM(result, "cyclonedx")
	case "dot":
		outputDependencyGraphDOT(result, "modern", "LR", false)
	case "svg":
		outputDependencyGraphSVG(result, false)
	case "mermaid":
		outputDependencyGraphMermaid(result, false)
	case "futuristic":
		formatter := output.NewFuturisticFormatter(true, false)
		formatter.PrintBanner()
		formatter.PrintScanStart(result.Path)
		formatter.PrintScanResults(result)
	default:
		formatter := output.NewFuturisticFormatter(true, false)
		formatter.PrintBanner()
		formatter.PrintScanStart(result.Path)
		formatter.PrintScanResults(result)
	}
}

// outputScanResultTable outputs scan results in table format
func outputScanResultTable(result *analyzer.ScanResult) {
	fmt.Printf("Scan Results for: %s\n", result.Path)
	fmt.Printf("Scan ID: %s\n", result.ScanID)
	fmt.Printf("Duration: %v\n", result.Duration)
	fmt.Printf("Total Packages: %d\n", result.TotalPackages)
	fmt.Println()

	fmt.Printf("Summary:\n")
	fmt.Printf("  Critical: %d\n", result.Summary.CriticalThreats)
	fmt.Printf("  High: %d\n", result.Summary.HighThreats)
	fmt.Printf("  Medium: %d\n", result.Summary.MediumThreats)
	fmt.Printf("  Low: %d\n", result.Summary.LowThreats)
	fmt.Printf("  Warnings: %d\n", result.Summary.TotalWarnings)
	fmt.Printf("  Clean: %d\n", result.Summary.CleanPackages)
	fmt.Println()

	if len(result.Threats) > 0 {
		fmt.Println("Threats Found:")
		for _, threat := range result.Threats {
			fmt.Printf("  [%s] %s: %s (Confidence: %.2f)\n",
				strings.ToUpper(threat.Severity.String()),
				threat.Package,
				threat.Description,
				threat.Confidence)
		}
		fmt.Println()
	}

	if len(result.Warnings) > 0 {
		fmt.Println("Warnings:")
		for _, warning := range result.Warnings {
			fmt.Printf("  %s: %s\n", warning.Package, warning.Message)
		}
	}
}

// outputAnalysisResult outputs the analysis result
func outputAnalysisResult(result *detector.CheckPackageResult, format string) {
	switch format {
	case "json":
		data, _ := json.MarshalIndent(result, "", "  ")
		fmt.Println(string(data))
	case "table":
		outputAnalysisResultTable(result)
	case "futuristic":
		formatter := output.NewFuturisticFormatter(true, false)
		formatter.PrintBanner()
		formatter.PrintAnalysisResults(result)
	default:
		formatter := output.NewFuturisticFormatter(true, false)
		formatter.PrintBanner()
		formatter.PrintAnalysisResults(result)
	}
}

// outputAnalysisResultTable outputs analysis results in table format
func outputAnalysisResultTable(result *detector.CheckPackageResult) {
	fmt.Printf("Package Analysis\n")
	fmt.Println()

	if len(result.Threats) > 0 {
		fmt.Println("Threats:")
		for _, threat := range result.Threats {
			fmt.Printf("  [%s] %s (Confidence: %.2f)\n",
				strings.ToUpper(threat.Severity.String()),
				threat.Description,
				threat.Confidence)
			if threat.SimilarTo != "" {
				fmt.Printf("    Similar to: %s\n", threat.SimilarTo)
			}
		}
		fmt.Println()
	}

	if len(result.Warnings) > 0 {
		fmt.Println("Warnings:")
		for _, warning := range result.Warnings {
			fmt.Printf("  %s\n", warning.Message)
		}
		fmt.Println()
	}
}

// saveScanToDatabase saves scan results to the  database
func saveScanToDatabase(result *analyzer.ScanResult, scanPath string) error {
	dbConfig := &config.DatabaseConfig{
		Type:     getEnvOrDefault("TYPOSENTINEL_DB_TYPE", "sqlite"),
		Host:     getEnvOrDefault("TYPOSENTINEL_DB_HOST", "localhost"),
		Port:     getEnvIntOrDefault("TYPOSENTINEL_DB_PORT", 5432),
		Username: getEnvOrDefault("TYPOSENTINEL_DB_USER", "typosentinel"),
		Password: getEnvOrDefault("TYPOSENTINEL_DB_PASSWORD", ""),
		Database: getEnvOrDefault("TYPOSENTINEL_DB_NAME", "./data/typosentinel.db"),
		SSLMode:  getEnvOrDefault("TYPOSENTINEL_DB_SSLMODE", "disable"),
	}

	if dbConfig.Type == "" {
		return fmt.Errorf("database not configured")
	}

	ossService, err := database.NewOSSService(dbConfig)
	if err != nil {
		return fmt.Errorf("failed to initialize OSS service: %v", err)
	}
	defer ossService.Close()

	packageScan := &database.PackageScan{
		ID:          result.ScanID,
		PackageName: extractPackageNameFromPath(scanPath),
		Version:     "unknown",
		Registry:    "npm",
		StartedAt:   result.Timestamp,
		Status:      "completed",
		Threats:     convertThreatsToDatabase(result.Threats),
		Duration:    int64(result.Duration.Seconds()),
		Metadata: map[string]interface{}{
			"path":           scanPath,
			"total_packages": result.TotalPackages,
			"warnings":       len(result.Warnings),
		},
	}

	completedAt := result.Timestamp.Add(result.Duration)
	packageScan.CompletedAt = &completedAt

	ctx := context.Background()
	if err := ossService.CreateScan(ctx, packageScan); err != nil {
		return fmt.Errorf("failed to save scan to database: %v", err)
	}

	return nil
}

// Helper environment variable functions
func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getEnvIntOrDefault(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		if intVal, err := strconv.Atoi(value); err == nil {
			return intVal
		}
	}
	return defaultValue
}

func extractPackageNameFromPath(path string) string {
	return strings.TrimPrefix(path, "./")
}

func convertThreatsToDatabase(threats []types.Threat) []database.ThreatResult {
	dbThreats := make([]database.ThreatResult, len(threats))
	for i, threat := range threats {
		dbThreats[i] = database.ThreatResult{
			Type:        string(threat.Type),
			Description: threat.Description,
			Severity:    threat.Severity.String(),
			Confidence:  threat.Confidence,
		}
	}
	return dbThreats
}

// outputSBOM outputs scan results in SBOM format
func outputSBOM(result *analyzer.ScanResult, format string) {
	scanResults := convertToScannerResults(result)

	options := output.FormatterOptions{
		Format:      output.OutputFormat(format),
		ColorOutput: false,
		Quiet:       false,
		Verbose:     false,
		Indent:      "  ",
	}

	var sbomData []byte
	var err error

	switch format {
	case "spdx":
		formatter := output.NewSPDXFormatter()
		sbomData, err = formatter.Format(scanResults, options)
	case "cyclonedx":
		formatter := output.NewCycloneDXFormatter()
		sbomData, err = formatter.Format(scanResults, &options)
	default:
		fmt.Printf("Unsupported SBOM format: %s\n", format)
		return
	}

	if err != nil {
		fmt.Printf("Error generating %s SBOM: %v\n", format, err)
		return
	}

	fmt.Println(string(sbomData))
}

// outputSBOMWithFile outputs scan results in SBOM format with optional file output
func outputSBOMWithFile(result *analyzer.ScanResult, format, outputFile string) {
	scanResults := convertToScannerResults(result)

	options := output.FormatterOptions{
		Format:      output.OutputFormat(format),
		ColorOutput: false,
		Quiet:       false,
		Verbose:     false,
		Indent:      "  ",
	}

	var sbomData []byte
	var err error

	switch format {
	case "spdx":
		formatter := output.NewSPDXFormatter()
		sbomData, err = formatter.Format(scanResults, options)
	case "cyclonedx":
		formatter := output.NewCycloneDXFormatter()
		sbomData, err = formatter.Format(scanResults, &options)
	default:
		fmt.Printf("Unsupported SBOM format: %s\n", format)
		return
	}

	if err != nil {
		fmt.Printf("Error generating %s SBOM: %v\n", format, err)
		return
	}

	if outputFile != "" {
		err = os.WriteFile(outputFile, sbomData, 0644)
		if err != nil {
			fmt.Printf("Error writing SBOM to file %s: %v\n", outputFile, err)
			return
		}
		fmt.Printf("SBOM written to: %s\n", outputFile)
	} else {
		fmt.Println(string(sbomData))
	}
}

// convertToScannerResults converts analyzer.ScanResult to scanner.ScanResults
func convertToScannerResults(result *analyzer.ScanResult) *scanner.ScanResults {
	var scanResults []scanner.ScanResult

	packageThreats := make(map[string][]scanner.Threat)
	packageMap := make(map[string]*types.Package)

	for _, threat := range result.Threats {
		packageName := threat.Package

		if _, exists := packageMap[packageName]; !exists {
			packageMap[packageName] = &types.Package{
				Name:     packageName,
				Version:  threat.Version,
				Registry: threat.Registry,
				Metadata: &types.PackageMetadata{
					Name:     packageName,
					Version:  threat.Version,
					Registry: threat.Registry,
				},
			}
		}

		scannerThreat := scanner.Threat{
			Type:           string(threat.Type),
			Severity:       threat.Severity.String(),
			Score:          threat.Confidence,
			Description:    threat.Description,
			Recommendation: threat.Recommendation,
			Evidence:       threat.SimilarTo,
			Source:         threat.DetectionMethod,
			Confidence:     threat.Confidence,
		}

		packageThreats[packageName] = append(packageThreats[packageName], scannerThreat)
	}

	for packageName, threats := range packageThreats {
		scanResult := scanner.ScanResult{
			Package: packageMap[packageName],
			Threats: threats,
		}
		scanResults = append(scanResults, scanResult)
	}

	if len(scanResults) == 0 {
		scanResult := scanner.ScanResult{
			Package: &types.Package{
				Name:    result.Path,
				Version: "unknown",
				Metadata: &types.PackageMetadata{
					Name:    result.Path,
					Version: "unknown",
				},
			},
			Threats: []scanner.Threat{},
		}
		scanResults = append(scanResults, scanResult)
	}

	return &scanner.ScanResults{
		Results: scanResults,
	}
}

// Graph visualization functions (DOT, SVG, Mermaid)
func outputDependencyGraphDOT(result *analyzer.ScanResult, style string, rankdir string, verbose bool) error {
	fmt.Print(generateDOTContentFromResult(result, style, rankdir))
	return nil
}

func generateDOTContentFromResult(result *analyzer.ScanResult, style string, rankdir string) string {
	var content strings.Builder
	content.WriteString("digraph DependencyGraph {\n")
	content.WriteString(fmt.Sprintf("  rankdir=%s;\n", rankdir))
	content.WriteString("  graph [bgcolor=white, pad=0.5, fontname=\"Arial\"];\n")
	content.WriteString("  node [fontname=\"Arial\", fontsize=10];\n")
	content.WriteString("  edge [fontname=\"Arial\"];\n\n")

	// Root project
	content.WriteString("  // Root project\n")
	content.WriteString("  subgraph cluster_root {\n")
	content.WriteString(fmt.Sprintf("    label=\"Project: %s\";\n", result.Path))
	content.WriteString("    style=rounded; color=blue;\n")
	content.WriteString(fmt.Sprintf("    root [label=\"%s\\n%d packages\", shape=folder, style=filled, fillcolor=lightblue];\n", result.Path, result.TotalPackages))
	content.WriteString("  }\n\n")

	// Metadata
	content.WriteString("  // Metadata\n")
	content.WriteString("  subgraph cluster_metadata {\n")
	content.WriteString("    label=\"Scan Metadata\";\n")
	content.WriteString("    style=rounded; color=gray;\n")
	content.WriteString(fmt.Sprintf("    metadata [label=\"Scan Time: %s\\nDuration: %v\\nThreats: %d | Warnings: %d\", shape=note];\n",
		result.Timestamp.Format("2006-01-02 15:04:05"), result.Duration, len(result.Threats), len(result.Warnings)))
	content.WriteString("  }\n\n")

	// Threats
	if len(result.Threats) > 0 {
		content.WriteString("  // Threats\n")
		for i, threat := range result.Threats {
			shape := "ellipse"
			color := "#fff176" // yellow/low
			switch threat.Severity {
			case types.SeverityCritical:
				shape = "hexagon"
				color = "#d32f2f"
			case types.SeverityHigh:
				shape = "box"
				color = "#ff6b6b"
			case types.SeverityMedium:
				color = "#ffb74d"
			}
			content.WriteString(fmt.Sprintf("  threat_%d [label=\"%s\\n%s\\n%s\", shape=%s, style=filled, fillcolor=\"%s\"];\n",
				i, threat.Package, threat.Severity, threat.Type, shape, color))
			content.WriteString(fmt.Sprintf("  root -> threat_%d [color=\"%s\", penwidth=2];\n", i, color))
		}
		content.WriteString("\n")
	}

	// Legend
	content.WriteString("  // Legend\n")
	content.WriteString("  subgraph cluster_legend {\n")
	content.WriteString("    label=\"Legend\"; style=rounded; color=black;\n")
	content.WriteString("    legend_critical [label=\"Critical\", shape=hexagon, style=filled, fillcolor=\"#d32f2f\", fontcolor=white];\n")
	content.WriteString("    legend_high [label=\"High\", shape=box, style=filled, fillcolor=\"#ff6b6b\"];\n")
	content.WriteString("    legend_medium [label=\"Medium\", shape=ellipse, style=filled, fillcolor=\"#ffb74d\"];\n")
	content.WriteString("    legend_low [label=\"Low\", shape=ellipse, style=filled, fillcolor=\"#aed581\"];\n")
	content.WriteString("    legend_warning [label=\"Warning\", shape=ellipse, style=\"filled,dashed\", fillcolor=\"#fff9c4\"];\n")
	content.WriteString("    legend_critical -> legend_high -> legend_medium -> legend_low -> legend_warning [style=invis];\n")
	content.WriteString("  } // Invisible edges for layout\n")

	content.WriteString("}\n")
	return content.String()
}

func outputDependencyGraphSVG(result *analyzer.ScanResult, verbose bool) error {
	fmt.Println("<?xml version=\"1.0\" encoding=\"UTF-8\"?>")
	fmt.Println("<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"1200\" height=\"800\" viewBox=\"0 0 1200 800\">")

	// Shadow filter
	fmt.Println("  <defs>")
	fmt.Println("    <filter id=\"shadow\" x=\"-50%\" y=\"-50%\" width=\"200%\" height=\"200%\">")
	fmt.Println("      <feGaussianBlur in=\"SourceAlpha\" stdDeviation=\"3\"/>")
	fmt.Println("      <feOffset dx=\"2\" dy=\"2\" result=\"offsetblur\"/>")
	fmt.Println("      <feMerge>")
	fmt.Println("        <feMergeNode/>")
	fmt.Println("        <feMergeNode in=\"SourceGraphic\"/>")
	fmt.Println("      </feMerge>")
	fmt.Println("    </filter>")
	fmt.Println("  </defs>")

	// Background
	fmt.Println("  <rect width=\"100%\" height=\"100%\" fill=\"#f5f5f5\"/>")

	// Title
	fmt.Printf("  <text x=\"600\" y=\"30\" font-size=\"20\" font-weight=\"bold\" text-anchor=\"middle\" font-family=\"Arial\">Dependency Graph: %s</text>\n", result.Path)
	fmt.Printf("  <text x=\"600\" y=\"55\" font-size=\"12\" text-anchor=\"middle\" font-family=\"Arial\">Scan: %s | Duration: %v | Threats: %d | Warnings: %d</text>\n",
		result.Timestamp.Format("2006-01-02 15:04:05"), result.Duration, len(result.Threats), len(result.Warnings))

	// Root node
	rootX, rootY := 600, 400
	fmt.Println("  <g id=\"root\">")
	fmt.Printf("    <circle cx=\"%d\" cy=\"%d\" r=\"60\" fill=\"#e3f2fd\" stroke=\"#1976d2\" stroke-width=\"3\" filter=\"url(#shadow)\"/>\n", rootX, rootY)
	fmt.Printf("    <text x=\"%d\" y=\"%d\" font-size=\"14\" font-weight=\"bold\" text-anchor=\"middle\" font-family=\"Arial\">%s</text>\n", rootX, rootY-5, result.Path)
	fmt.Printf("    <text x=\"%d\" y=\"%d\" font-size=\"11\" text-anchor=\"middle\" font-family=\"Arial\">%d packages</text>\n", rootX, rootY+10, result.TotalPackages)
	fmt.Printf("    <title>Project: %s&#10;Total Packages: %d&#10;Threats: %d&#10;Warnings: %d</title>\n",
		result.Path, result.TotalPackages, len(result.Threats), len(result.Warnings))
	fmt.Println("  </g>")

	// Threats in circular layout
	threatCount := len(result.Threats)
	if threatCount > 0 {
		fmt.Println("  <g id=\"threats\">")
		radius := 280.0
		angleStep := 360.0 / float64(threatCount)

		for i, threat := range result.Threats {
			angle := (float64(i)*angleStep - 90) * (3.14159 / 180.0)
			tx := int(float64(rootX) + radius*math.Cos(angle))
			ty := int(float64(rootY) + radius*math.Sin(angle))

			color := "#fff176" // yellow
			stroke := "#fbc02d"
			switch threat.Severity {
			case types.SeverityCritical:
				color = "#d32f2f"
				stroke = "#b71c1c"
			case types.SeverityHigh:
				color = "#ff6b6b"
				stroke = "#d32f2f"
			case types.SeverityMedium:
				color = "#ffb74d"
				stroke = "#f57c00"
			}

			// Edge
			fmt.Printf("    <line x1=\"%d\" y1=\"%d\" x2=\"%d\" y2=\"%d\" stroke=\"%s\" stroke-width=\"2\" marker-end=\"url(#arrowhead)\"/>\n",
				rootX, rootY, tx, ty, stroke)
			// Node
			fmt.Printf("    <circle cx=\"%d\" cy=\"%d\" r=\"40\" fill=\"%s\" stroke=\"%s\" stroke-width=\"2\" filter=\"url(#shadow)\"/>\n",
				tx, ty, color, stroke)
			fmt.Printf("    <text x=\"%d\" y=\"%d\" font-size=\"10\" text-anchor=\"middle\" font-family=\"Arial\">%s</text>\n", tx, ty, threat.Package)
			fmt.Printf("    <title>%s&#10;%s&#10;%s</title>\n", threat.Package, threat.Severity, threat.Type)
		}
		fmt.Println("  </g>")
	}

	// Legend
	legendX, legendY := 50, 100
	fmt.Println("  <g id=\"legend\">")
	fmt.Println("    <text x=\"50\" y=\"80\" font-size=\"12\" font-weight=\"bold\" font-family=\"Arial\">Legend:</text>")
	severities := []struct{ name, color, stroke string }{
		{"Critical", "#d32f2f", "#b71c1c"},
		{"High", "#ff6b6b", "#d32f2f"},
		{"Medium", "#ffb74d", "#f57c00"},
		{"Low", "#fff176", "#fbc02d"},
		{"Warning", "#fff9c4", "#f57c00"},
	}
	for i, s := range severities {
		y := legendY + i*25
		fmt.Printf("    <rect x=\"%d\" y=\"%d\" width=\"20\" height=\"15\" rx=\"3\" fill=\"%s\" stroke=\"%s\"/>\n",
			legendX, y, s.color, s.stroke)
		fmt.Printf("    <text x=\"%d\" y=\"%d\" font-size=\"10\" font-family=\"Arial\">%s</text>\n",
			legendX+25, y+12, s.name)
	}
	fmt.Println("  </g>")

	fmt.Println("</svg>")
	return nil
}

func outputDependencyGraphMermaid(result *analyzer.ScanResult, verbose bool) error {
	fmt.Print(generateMermaidContentFromResult(result))
	return nil
}

func generateMermaidContentFromResult(result *analyzer.ScanResult) string {
	var content strings.Builder
	content.WriteString("graph LR\n")

	// Styling
	content.WriteString("  %% Styles\n")
	content.WriteString("  classDef critical fill:#d32f2f,stroke:#b71c1c,color:white,stroke-width:2px;\n")
	content.WriteString("  classDef high fill:#ff6b6b,stroke:#d32f2f,color:black,stroke-width:2px;\n")
	content.WriteString("  classDef medium fill:#ffb74d,stroke:#f57c00,color:black,stroke-width:1px;\n")
	content.WriteString("  classDef low fill:#fff176,stroke:#fbc02d,color:black,stroke-width:1px;\n")
	content.WriteString("  classDef warning fill:#fff9c4,stroke:#f57c00,color:black,stroke-dasharray: 5 5;\n")
	content.WriteString("  classDef root fill:#e3f2fd,stroke:#1976d2,color:black,stroke-width:2px;\n\n")

	// Root node
	content.WriteString(fmt.Sprintf("  root(\"%s<br/>%d packages\"):::root\n", result.Path, result.TotalPackages))

	// Threats
	if len(result.Threats) > 0 {
		content.WriteString("  subgraph Threats\n")
		content.WriteString("    direction TB\n")
		for i, threat := range result.Threats {
			styleClass := "low"
			switch threat.Severity {
			case types.SeverityCritical:
				styleClass = "critical"
			case types.SeverityHigh:
				styleClass = "high"
			case types.SeverityMedium:
				styleClass = "medium"
			}

			nodeID := fmt.Sprintf("threat_%d", i)
			label := fmt.Sprintf("%s<br/>%s<br/>%s", threat.Package, threat.Severity, threat.Type)
			content.WriteString(fmt.Sprintf("    %s[\"%s\"]:::%s\n", nodeID, label, styleClass))
			content.WriteString(fmt.Sprintf("    root --> %s\n", nodeID))
		}
		content.WriteString("  end\n")
	}

	// Warnings
	if len(result.Warnings) > 0 {
		content.WriteString("  subgraph Warnings\n")
		content.WriteString("    direction TB\n")
		for i, w := range result.Warnings {
			nodeID := fmt.Sprintf("warn_%d", i)
			label := fmt.Sprintf("%s<br/>Warning", w.Package)
			content.WriteString(fmt.Sprintf("    %s[\"%s\"]:::warning\n", nodeID, label))
			content.WriteString(fmt.Sprintf("    root -.-> %s\n", nodeID))
		}
		content.WriteString("  end\n")
	}

	// Metadata
	content.WriteString(fmt.Sprintf("\n  %% Scan: %s | Duration: %v\n",
		result.Timestamp.Format("2006-01-02 15:04:05"), result.Duration))

	return content.String()
}
