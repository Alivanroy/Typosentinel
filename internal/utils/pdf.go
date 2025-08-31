package utils

import (
	"bytes"
	"fmt"
	"strings"
	"time"
)

// ScanReportData represents the data structure for PDF reports
type ScanReportData struct {
	ScanID      string                 `json:"scan_id"`
	Repository  string                 `json:"repository"`
	Platform    string                 `json:"platform"`
	Status      string                 `json:"status"`
	StartedAt   time.Time              `json:"started_at"`
	CompletedAt time.Time              `json:"completed_at"`
	Duration    string                 `json:"duration"`
	Threats     []ThreatInfo           `json:"threats"`
	Summary     ScanSummary            `json:"summary"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// ThreatInfo represents threat information
type ThreatInfo struct {
	Type        string `json:"type"`
	Severity    string `json:"severity"`
	Package     string `json:"package"`
	Description string `json:"description"`
	Remediation string `json:"remediation"`
}

// ScanSummary represents scan summary statistics
type ScanSummary struct {
	TotalPackages      int `json:"total_packages"`
	VulnerablePackages int `json:"vulnerable_packages"`
	CriticalThreats    int `json:"critical_threats"`
	HighThreats        int `json:"high_threats"`
	MediumThreats      int `json:"medium_threats"`
	LowThreats         int `json:"low_threats"`
}

// GenerateSimplePDF generates a simple text-based PDF content
// Note: This is a basic implementation. For production use, consider using a proper PDF library
func GenerateSimplePDF(data ScanReportData) ([]byte, error) {
	var buf bytes.Buffer

	// PDF Header (simplified)
	buf.WriteString("%PDF-1.4\n")
	buf.WriteString("1 0 obj\n")
	buf.WriteString("<<\n")
	buf.WriteString("/Type /Catalog\n")
	buf.WriteString("/Pages 2 0 R\n")
	buf.WriteString(">>\n")
	buf.WriteString("endobj\n\n")

	// Pages object
	buf.WriteString("2 0 obj\n")
	buf.WriteString("<<\n")
	buf.WriteString("/Type /Pages\n")
	buf.WriteString("/Kids [3 0 R]\n")
	buf.WriteString("/Count 1\n")
	buf.WriteString(">>\n")
	buf.WriteString("endobj\n\n")

	// Generate content stream
	content := generateReportContent(data)
	contentLength := len(content)

	// Page object
	buf.WriteString("3 0 obj\n")
	buf.WriteString("<<\n")
	buf.WriteString("/Type /Page\n")
	buf.WriteString("/Parent 2 0 R\n")
	buf.WriteString("/MediaBox [0 0 612 792]\n")
	buf.WriteString("/Contents 4 0 R\n")
	buf.WriteString("/Resources <<\n")
	buf.WriteString("  /Font <<\n")
	buf.WriteString("    /F1 <<\n")
	buf.WriteString("      /Type /Font\n")
	buf.WriteString("      /Subtype /Type1\n")
	buf.WriteString("      /BaseFont /Helvetica\n")
	buf.WriteString("    >>\n")
	buf.WriteString("  >>\n")
	buf.WriteString(">>\n")
	buf.WriteString(">>\n")
	buf.WriteString("endobj\n\n")

	// Content stream
	buf.WriteString("4 0 obj\n")
	buf.WriteString("<<\n")
	buf.WriteString(fmt.Sprintf("/Length %d\n", contentLength))
	buf.WriteString(">>\n")
	buf.WriteString("stream\n")
	buf.WriteString(content)
	buf.WriteString("\nendstream\n")
	buf.WriteString("endobj\n\n")

	// Cross-reference table
	buf.WriteString("xref\n")
	buf.WriteString("0 5\n")
	buf.WriteString("0000000000 65535 f \n")
	buf.WriteString("0000000009 65535 n \n")
	buf.WriteString("0000000074 65535 n \n")
	buf.WriteString("0000000120 65535 n \n")
	buf.WriteString("0000000274 65535 n \n")

	// Trailer
	buf.WriteString("trailer\n")
	buf.WriteString("<<\n")
	buf.WriteString("/Size 5\n")
	buf.WriteString("/Root 1 0 R\n")
	buf.WriteString(">>\n")
	buf.WriteString("startxref\n")
	buf.WriteString("380\n")
	buf.WriteString("%%EOF\n")

	return buf.Bytes(), nil
}

// generateReportContent generates the PDF content stream
func generateReportContent(data ScanReportData) string {
	var content strings.Builder

	content.WriteString("BT\n")
	content.WriteString("/F1 16 Tf\n")
	content.WriteString("50 750 Td\n")
	content.WriteString("(TypoSentinel Security Scan Report) Tj\n")
	content.WriteString("0 -30 Td\n")

	// Basic information
	content.WriteString("/F1 12 Tf\n")
	content.WriteString(fmt.Sprintf("(Scan ID: %s) Tj\n", escapePDFString(data.ScanID)))
	content.WriteString("0 -20 Td\n")
	content.WriteString(fmt.Sprintf("(Repository: %s) Tj\n", escapePDFString(data.Repository)))
	content.WriteString("0 -20 Td\n")
	content.WriteString(fmt.Sprintf("(Platform: %s) Tj\n", escapePDFString(data.Platform)))
	content.WriteString("0 -20 Td\n")
	content.WriteString(fmt.Sprintf("(Status: %s) Tj\n", escapePDFString(data.Status)))
	content.WriteString("0 -20 Td\n")
	content.WriteString(fmt.Sprintf("(Duration: %s) Tj\n", escapePDFString(data.Duration)))
	content.WriteString("0 -30 Td\n")

	// Summary section
	content.WriteString("/F1 14 Tf\n")
	content.WriteString("(Summary) Tj\n")
	content.WriteString("0 -25 Td\n")
	content.WriteString("/F1 10 Tf\n")
	content.WriteString(fmt.Sprintf("(Total Packages: %d) Tj\n", data.Summary.TotalPackages))
	content.WriteString("0 -15 Td\n")
	content.WriteString(fmt.Sprintf("(Vulnerable Packages: %d) Tj\n", data.Summary.VulnerablePackages))
	content.WriteString("0 -15 Td\n")
	content.WriteString(fmt.Sprintf("(Critical Threats: %d) Tj\n", data.Summary.CriticalThreats))
	content.WriteString("0 -15 Td\n")
	content.WriteString(fmt.Sprintf("(High Threats: %d) Tj\n", data.Summary.HighThreats))
	content.WriteString("0 -15 Td\n")
	content.WriteString(fmt.Sprintf("(Medium Threats: %d) Tj\n", data.Summary.MediumThreats))
	content.WriteString("0 -15 Td\n")
	content.WriteString(fmt.Sprintf("(Low Threats: %d) Tj\n", data.Summary.LowThreats))
	content.WriteString("0 -30 Td\n")

	// Threats section
	if len(data.Threats) > 0 {
		content.WriteString("/F1 14 Tf\n")
		content.WriteString("(Detected Threats) Tj\n")
		content.WriteString("0 -25 Td\n")
		content.WriteString("/F1 10 Tf\n")

		for i, threat := range data.Threats {
			if i >= 10 { // Limit to first 10 threats for space
				content.WriteString("(... and more threats) Tj\n")
				break
			}
			content.WriteString(fmt.Sprintf("(%d. %s - %s) Tj\n", i+1, escapePDFString(threat.Type), escapePDFString(threat.Severity)))
			content.WriteString("0 -15 Td\n")
			if threat.Package != "" {
				content.WriteString(fmt.Sprintf("(   Package: %s) Tj\n", escapePDFString(threat.Package)))
				content.WriteString("0 -15 Td\n")
			}
		}
	} else {
		content.WriteString("/F1 14 Tf\n")
		content.WriteString("(No threats detected) Tj\n")
		content.WriteString("0 -25 Td\n")
	}

	// Footer
	content.WriteString("0 -50 Td\n")
	content.WriteString("/F1 8 Tf\n")
	content.WriteString(fmt.Sprintf("(Generated on: %s) Tj\n", time.Now().Format("2006-01-02 15:04:05")))
	content.WriteString("0 -15 Td\n")
	content.WriteString("(Powered by TypoSentinel) Tj\n")

	content.WriteString("ET\n")

	return content.String()
}

// escapePDFString escapes special characters in PDF strings
func escapePDFString(s string) string {
	s = strings.ReplaceAll(s, "\\", "\\\\")
	s = strings.ReplaceAll(s, "(", "\\(")
	s = strings.ReplaceAll(s, ")", "\\)")
	return s
}

// GenerateHTMLToPDF generates HTML content that can be converted to PDF
func GenerateHTMLToPDF(data ScanReportData) string {
	var html strings.Builder

	html.WriteString(`<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>TypoSentinel Security Scan Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .header { text-align: center; border-bottom: 2px solid #333; padding-bottom: 20px; margin-bottom: 30px; }
        .section { margin-bottom: 30px; }
        .section h2 { color: #333; border-bottom: 1px solid #ccc; padding-bottom: 5px; }
        .info-table { width: 100%; border-collapse: collapse; margin-bottom: 20px; }
        .info-table td { padding: 8px; border: 1px solid #ddd; }
        .info-table td:first-child { font-weight: bold; background-color: #f5f5f5; width: 150px; }
        .threat { margin-bottom: 15px; padding: 10px; border-left: 4px solid #ff6b6b; background-color: #fff5f5; }
        .threat.critical { border-left-color: #d63031; }
        .threat.high { border-left-color: #e17055; }
        .threat.medium { border-left-color: #fdcb6e; }
        .threat.low { border-left-color: #00b894; }
        .summary-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 15px; }
        .summary-card { padding: 15px; border: 1px solid #ddd; border-radius: 5px; text-align: center; }
        .no-threats { text-align: center; color: #00b894; font-size: 18px; padding: 20px; }
        .footer { margin-top: 50px; text-align: center; font-size: 12px; color: #666; }
    </style>
</head>
<body>`)

	// Header
	html.WriteString(`
    <div class="header">
        <h1>TypoSentinel Security Scan Report</h1>
    </div>`)

	// Basic Information
	html.WriteString(`
    <div class="section">
        <h2>Scan Information</h2>
        <table class="info-table">`)
	html.WriteString(fmt.Sprintf(`
            <tr><td>Scan ID</td><td>%s</td></tr>
            <tr><td>Repository</td><td>%s</td></tr>
            <tr><td>Platform</td><td>%s</td></tr>
            <tr><td>Status</td><td>%s</td></tr>
            <tr><td>Duration</td><td>%s</td></tr>
            <tr><td>Completed At</td><td>%s</td></tr>`,
		data.ScanID, data.Repository, data.Platform, data.Status, data.Duration,
		data.CompletedAt.Format("2006-01-02 15:04:05")))
	html.WriteString(`
        </table>
    </div>`)

	// Summary
	html.WriteString(`
    <div class="section">
        <h2>Summary</h2>
        <div class="summary-grid">`)
	html.WriteString(fmt.Sprintf(`
            <div class="summary-card">
                <h3>%d</h3>
                <p>Total Packages</p>
            </div>
            <div class="summary-card">
                <h3>%d</h3>
                <p>Vulnerable Packages</p>
            </div>
            <div class="summary-card">
                <h3>%d</h3>
                <p>Total Threats</p>
            </div>
            <div class="summary-card">
                <h3 style="color: #d63031;">%d</h3>
                <p>Critical</p>
            </div>
            <div class="summary-card">
                <h3 style="color: #e17055;">%d</h3>
                <p>High</p>
            </div>
            <div class="summary-card">
                <h3 style="color: #fdcb6e;">%d</h3>
                <p>Medium</p>
            </div>`,
		data.Summary.TotalPackages, data.Summary.VulnerablePackages,
		data.Summary.CriticalThreats+data.Summary.HighThreats+data.Summary.MediumThreats+data.Summary.LowThreats,
		data.Summary.CriticalThreats, data.Summary.HighThreats, data.Summary.MediumThreats))
	html.WriteString(`
        </div>
    </div>`)

	// Threats
	html.WriteString(`
    <div class="section">
        <h2>Detected Threats</h2>`)

	if len(data.Threats) > 0 {
		for _, threat := range data.Threats {
			severityClass := strings.ToLower(threat.Severity)
			html.WriteString(fmt.Sprintf(`
        <div class="threat %s">
            <h4>%s - %s</h4>
            <p><strong>Package:</strong> %s</p>
            <p><strong>Description:</strong> %s</p>
            <p><strong>Remediation:</strong> %s</p>
        </div>`, severityClass, threat.Type, threat.Severity, threat.Package, threat.Description, threat.Remediation))
		}
	} else {
		html.WriteString(`
        <div class="no-threats">
            <p>✅ No threats detected in this scan</p>
        </div>`)
	}

	html.WriteString(`
    </div>`)

	// Footer
	html.WriteString(fmt.Sprintf(`
    <div class="footer">
        <p>Generated on: %s</p>
        <p>Powered by TypoSentinel</p>
    </div>
</body>
</html>`, time.Now().Format("2006-01-02 15:04:05")))

	return html.String()
}
