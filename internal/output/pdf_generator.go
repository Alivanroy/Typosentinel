package output

import (
	"bytes"
	"context"
	"fmt"
	"html/template"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/chromedp"
)

// PDFGenerator handles PDF generation from HTML templates
type PDFGenerator struct {
	TemplateDir string
	OutputDir   string
	Options     PDFOptions
}

// PDFOptions configures PDF generation settings
type PDFOptions struct {
	PaperWidth      float64 `json:"paper_width"`       // in inches
	PaperHeight     float64 `json:"paper_height"`      // in inches
	MarginTop       float64 `json:"margin_top"`        // in inches
	MarginBottom    float64 `json:"margin_bottom"`     // in inches
	MarginLeft      float64 `json:"margin_left"`       // in inches
	MarginRight     float64 `json:"margin_right"`      // in inches
	PrintBackground bool    `json:"print_background"`  // include background graphics
	Landscape       bool    `json:"landscape"`          // page orientation
	Scale           float64 `json:"scale"`             // page scale (0.1 to 2.0)
	DisplayHeaderFooter bool `json:"display_header_footer"`
	HeaderTemplate  string  `json:"header_template"`
	FooterTemplate  string  `json:"footer_template"`
	PreferCSSPageSize bool  `json:"prefer_css_page_size"`
}

// DefaultPDFOptions returns sensible default PDF generation options
func DefaultPDFOptions() PDFOptions {
	return PDFOptions{
		PaperWidth:      8.5,  // US Letter width
		PaperHeight:     11.0, // US Letter height
		MarginTop:       1.0,
		MarginBottom:    1.0,
		MarginLeft:      1.0,
		MarginRight:     1.0,
		PrintBackground: true,
		Landscape:       false,
		Scale:           1.0,
		DisplayHeaderFooter: true,
		HeaderTemplate: `<div style="font-size: 10px; text-align: center; width: 100%; margin: 0 auto;"><span class="title"></span></div>`,
		FooterTemplate: `<div style="font-size: 10px; text-align: center; width: 100%; margin: 0 auto;">Page <span class="pageNumber"></span> of <span class="totalPages"></span></div>`,
		PreferCSSPageSize: false,
	}
}

// NewPDFGenerator creates a new PDF generator instance
func NewPDFGenerator(templateDir, outputDir string, options *PDFOptions) *PDFGenerator {
	if options == nil {
		defaultOpts := DefaultPDFOptions()
		options = &defaultOpts
	}
	
	return &PDFGenerator{
		TemplateDir: templateDir,
		OutputDir:   outputDir,
		Options:     *options,
	}
}

// GenerateReportPDF generates a PDF from an HTML template with data
func (pg *PDFGenerator) GenerateReportPDF(templateName string, data interface{}, outputFilename string) error {
	// Load and parse the HTML template
	tmplPath := filepath.Join(pg.TemplateDir, templateName)
	tmpl, err := template.ParseFiles(tmplPath)
	if err != nil {
		return fmt.Errorf("failed to parse template %s: %w", templateName, err)
	}

	// Execute template with data
	var htmlBuffer bytes.Buffer
	if err := tmpl.Execute(&htmlBuffer, data); err != nil {
		return fmt.Errorf("failed to execute template: %w", err)
	}

	// Generate PDF from HTML
	pdfBytes, err := pg.htmlToPDF(htmlBuffer.String())
	if err != nil {
		return fmt.Errorf("failed to generate PDF: %w", err)
	}

	// Ensure output directory exists
	if err := os.MkdirAll(pg.OutputDir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	// Write PDF to file
	outputPath := filepath.Join(pg.OutputDir, outputFilename)
	if err := os.WriteFile(outputPath, pdfBytes, 0644); err != nil {
		return fmt.Errorf("failed to write PDF file: %w", err)
	}

	return nil
}

// GenerateExecutiveReport generates an executive report PDF
func (pg *PDFGenerator) GenerateExecutiveReport(data interface{}, outputFilename string) error {
	return pg.GenerateReportPDF("executive.html", data, outputFilename)
}

// GenerateTechnicalReport generates a technical report PDF
func (pg *PDFGenerator) GenerateTechnicalReport(data interface{}, outputFilename string) error {
	return pg.GenerateReportPDF("technical.html", data, outputFilename)
}

// GenerateComplianceReport generates a compliance report PDF
func (pg *PDFGenerator) GenerateComplianceReport(data interface{}, outputFilename string) error {
	return pg.GenerateReportPDF("compliance.html", data, outputFilename)
}

// htmlToPDF converts HTML content to PDF using Chrome DevTools Protocol
func (pg *PDFGenerator) htmlToPDF(htmlContent string) ([]byte, error) {
	// Create context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Create Chrome context
	chromeCtx, cancel := chromedp.NewContext(ctx)
	defer cancel()

	// Create a data URL from HTML content
	dataURL := "data:text/html;charset=utf-8," + htmlContent

	var pdfBytes []byte

	// Navigate to the HTML content and generate PDF
	err := chromedp.Run(chromeCtx,
		chromedp.Navigate(dataURL),
		chromedp.WaitReady("body"),
		chromedp.ActionFunc(func(ctx context.Context) error {
			// Wait a bit for any dynamic content to load
			time.Sleep(2 * time.Second)
			return nil
		}),
		chromedp.ActionFunc(func(ctx context.Context) error {
			var err error
			pdfBytes, _, err = page.PrintToPDF().
				WithPrintBackground(pg.Options.PrintBackground).
				WithLandscape(pg.Options.Landscape).
				WithPaperWidth(pg.Options.PaperWidth).
				WithPaperHeight(pg.Options.PaperHeight).
				WithMarginTop(pg.Options.MarginTop).
				WithMarginBottom(pg.Options.MarginBottom).
				WithMarginLeft(pg.Options.MarginLeft).
				WithMarginRight(pg.Options.MarginRight).
				WithScale(pg.Options.Scale).
				WithDisplayHeaderFooter(pg.Options.DisplayHeaderFooter).
				WithHeaderTemplate(pg.Options.HeaderTemplate).
				WithFooterTemplate(pg.Options.FooterTemplate).
				WithPreferCSSPageSize(pg.Options.PreferCSSPageSize).
				Do(ctx)
			return err
		}),
	)

	if err != nil {
		return nil, fmt.Errorf("failed to generate PDF with Chrome: %w", err)
	}

	return pdfBytes, nil
}

// GeneratePDFFromHTML generates PDF directly from HTML string
func (pg *PDFGenerator) GeneratePDFFromHTML(htmlContent string, outputFilename string) error {
	pdfBytes, err := pg.htmlToPDF(htmlContent)
	if err != nil {
		return err
	}

	// Ensure output directory exists
	if err := os.MkdirAll(pg.OutputDir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	// Write PDF to file
	outputPath := filepath.Join(pg.OutputDir, outputFilename)
	if err := os.WriteFile(outputPath, pdfBytes, 0644); err != nil {
		return fmt.Errorf("failed to write PDF file: %w", err)
	}

	return nil
}

// GeneratePDFStream generates PDF and returns it as a byte stream
func (pg *PDFGenerator) GeneratePDFStream(templateName string, data interface{}) ([]byte, error) {
	// Load and parse the HTML template
	tmplPath := filepath.Join(pg.TemplateDir, templateName)
	tmpl, err := template.ParseFiles(tmplPath)
	if err != nil {
		return nil, fmt.Errorf("failed to parse template %s: %w", templateName, err)
	}

	// Execute template with data
	var htmlBuffer bytes.Buffer
	if err := tmpl.Execute(&htmlBuffer, data); err != nil {
		return nil, fmt.Errorf("failed to execute template: %w", err)
	}

	// Generate PDF from HTML
	return pg.htmlToPDF(htmlBuffer.String())
}

// BatchGenerateReports generates multiple reports in batch
func (pg *PDFGenerator) BatchGenerateReports(reports []ReportRequest) error {
	for i, report := range reports {
		if err := pg.GenerateReportPDF(report.TemplateName, report.Data, report.OutputFilename); err != nil {
			return fmt.Errorf("failed to generate report %d (%s): %w", i+1, report.OutputFilename, err)
		}
	}
	return nil
}

// ReportRequest represents a single report generation request
type ReportRequest struct {
	TemplateName   string      `json:"template_name"`
	Data           interface{} `json:"data"`
	OutputFilename string      `json:"output_filename"`
}

// ValidateTemplate checks if a template file exists and is valid
func (pg *PDFGenerator) ValidateTemplate(templateName string) error {
	tmplPath := filepath.Join(pg.TemplateDir, templateName)
	
	// Check if file exists
	if _, err := os.Stat(tmplPath); os.IsNotExist(err) {
		return fmt.Errorf("template file does not exist: %s", tmplPath)
	}

	// Try to parse the template
	_, err := template.ParseFiles(tmplPath)
	if err != nil {
		return fmt.Errorf("invalid template syntax in %s: %w", templateName, err)
	}

	return nil
}

// GetAvailableTemplates returns a list of available HTML templates
func (pg *PDFGenerator) GetAvailableTemplates() ([]string, error) {
	var templates []string
	
	entries, err := os.ReadDir(pg.TemplateDir)
	if err != nil {
		return nil, fmt.Errorf("failed to read template directory: %w", err)
	}

	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".html") {
			templates = append(templates, entry.Name())
		}
	}

	return templates, nil
}

// SetCustomOptions allows updating PDF generation options
func (pg *PDFGenerator) SetCustomOptions(options PDFOptions) {
	pg.Options = options
}

// GetPDFInfo returns information about a generated PDF file
func GetPDFInfo(filePath string) (*PDFInfo, error) {
	stat, err := os.Stat(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to get file info: %w", err)
	}

	return &PDFInfo{
		FilePath:    filePath,
		FileName:    stat.Name(),
		FileSize:    stat.Size(),
		CreatedAt:   stat.ModTime(),
		IsReadable:  true, // Basic check, could be enhanced
	}, nil
}

// PDFInfo contains information about a generated PDF
type PDFInfo struct {
	FilePath   string    `json:"file_path"`
	FileName   string    `json:"file_name"`
	FileSize   int64     `json:"file_size"`
	CreatedAt  time.Time `json:"created_at"`
	IsReadable bool      `json:"is_readable"`
}

// CleanupOldReports removes PDF files older than the specified duration
func (pg *PDFGenerator) CleanupOldReports(maxAge time.Duration) error {
	entries, err := os.ReadDir(pg.OutputDir)
	if err != nil {
		return fmt.Errorf("failed to read output directory: %w", err)
	}

	cutoff := time.Now().Add(-maxAge)
	var deletedCount int

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".pdf") {
			continue
		}

		filePath := filepath.Join(pg.OutputDir, entry.Name())
		stat, err := entry.Info()
		if err != nil {
			continue
		}

		if stat.ModTime().Before(cutoff) {
			if err := os.Remove(filePath); err == nil {
				deletedCount++
			}
		}
	}

	return nil
}

// StreamPDFToWriter generates PDF and writes it directly to an io.Writer
func (pg *PDFGenerator) StreamPDFToWriter(templateName string, data interface{}, writer io.Writer) error {
	pdfBytes, err := pg.GeneratePDFStream(templateName, data)
	if err != nil {
		return err
	}

	_, err = writer.Write(pdfBytes)
	return err
}