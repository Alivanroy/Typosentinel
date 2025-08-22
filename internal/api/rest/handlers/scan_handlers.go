package handlers

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/Alivanroy/Typosentinel/internal/database"
	"github.com/Alivanroy/Typosentinel/internal/detector"
	"github.com/gin-gonic/gin"
)

// ScanHandlers provides HTTP handlers for package scanning
type ScanHandlers struct {
	db       *database.OSSService
	detector *detector.Engine
}

// NewScanHandlers creates a new scan handlers instance
func NewScanHandlers(db *database.OSSService, detector *detector.Engine) *ScanHandlers {
	return &ScanHandlers{
		db:       db,
		detector: detector,
	}
}

// PackageScanRequest represents a package scan request
type PackageScanRequest struct {
	PackageName string `json:"package_name" binding:"required"`
	Registry    string `json:"registry" binding:"required"`
	Version     string `json:"version,omitempty"`
}

// PackageScanResponse represents a scan response
type PackageScanResponse struct {
	ID      string `json:"id"`
	Status  string `json:"status"`
	Message string `json:"message"`
}

// StartScan initiates a new package scan
func (h *ScanHandlers) StartScan(c *gin.Context) {
	var req PackageScanRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "Invalid request",
			"details": err.Error(),
		})
		return
	}

	// Validate registry
	validRegistries := []string{"npm", "pypi", "maven", "nuget", "rubygems", "packagist"}
	isValidRegistry := false
	for _, registry := range validRegistries {
		if strings.EqualFold(req.Registry, registry) {
			req.Registry = strings.ToLower(registry)
			isValidRegistry = true
			break
		}
	}

	if !isValidRegistry {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid registry",
			"valid_registries": validRegistries,
		})
		return
	}

	// Create scan record
	scan := &database.PackageScan{
		PackageName: req.PackageName,
		Registry:    req.Registry,
		Version:     req.Version,
		Status:      "pending",
		StartedAt:   time.Now(),
		Metadata: map[string]interface{}{
			"user_agent": c.GetHeader("User-Agent"),
			"ip":         c.ClientIP(),
		},
	}

	if err := h.db.CreateScan(c.Request.Context(), scan); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to create scan",
		})
		return
	}

	// Start scan asynchronously
	go h.performScan(scan)

	c.JSON(http.StatusAccepted, PackageScanResponse{
		ID:      scan.ID,
		Status:  "pending",
		Message: "Scan initiated successfully",
	})
}

// GetScanResults returns paginated scan results
func (h *ScanHandlers) GetScanResults(c *gin.Context) {
	// Parse pagination parameters
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "20"))
	
	if page < 1 {
		page = 1
	}
	if limit < 1 || limit > 100 {
		limit = 20
	}

	// Get recent scans
	scans, err := h.db.GetRecentScans(c.Request.Context(), limit)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to retrieve scan results",
		})
		return
	}

	// Convert scans to frontend format
	var scanResults []gin.H
	for _, scan := range scans {
		scanResult := gin.H{
			"id":           scan.ID,
			"target":       scan.PackageName,
			"status":       scan.Status,
			"threatsFound": scan.ThreatCount,
			"createdAt":    scan.StartedAt,
			"duration":     fmt.Sprintf("%ds", scan.Duration),
		}
		scanResults = append(scanResults, scanResult)
	}

	c.JSON(http.StatusOK, gin.H{
		"data": scanResults,
		"pagination": gin.H{
			"page":  page,
			"limit": limit,
			"total": len(scans),
		},
	})
}

// GetScanByID returns a specific scan by ID
func (h *ScanHandlers) GetScanByID(c *gin.Context) {
	scanID := c.Param("id")
	if scanID == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Scan ID is required",
		})
		return
	}

	scan, err := h.db.GetScan(c.Request.Context(), scanID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to retrieve scan",
		})
		return
	}

	if scan == nil {
		c.JSON(http.StatusNotFound, gin.H{
			"error": "Scan not found",
		})
		return
	}

	c.JSON(http.StatusOK, scan)
}

// SearchPackages searches for scanned packages
func (h *ScanHandlers) SearchPackages(c *gin.Context) {
	query := c.Query("q")
	if query == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Search query is required",
		})
		return
	}

	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "20"))
	if limit < 1 || limit > 100 {
		limit = 20
	}

	scans, err := h.db.SearchScans(c.Request.Context(), query, limit)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to search packages",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"results": scans,
		"query":   query,
		"count":   len(scans),
	})
}

// GetScanStats returns scan statistics
func (h *ScanHandlers) GetScanStats(c *gin.Context) {
	stats, err := h.db.GetScanStats(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to retrieve scan statistics",
		})
		return
	}

	c.JSON(http.StatusOK, stats)
}

// performScan performs the actual package scanning
func (h *ScanHandlers) performScan(scan *database.PackageScan) {
	ctx := context.Background()

	// Update status to running
	scan.Status = "running"
	h.db.UpdateScan(ctx, scan)

	startTime := time.Now()

	// Perform the actual scan using the detector
	threats, riskLevel, summary, err := h.scanPackage(scan.PackageName, scan.Registry, scan.Version)
	
	duration := time.Since(startTime)
	completedAt := time.Now()

	if err != nil {
		// Update scan with error
		scan.Status = "failed"
		scan.Summary = fmt.Sprintf("Scan failed: %v", err)
		scan.CompletedAt = &completedAt
		scan.Duration = int64(duration.Seconds())
	} else {
		// Update scan with results
		scan.Status = "completed"
		scan.RiskLevel = riskLevel
		scan.Threats = threats
		scan.Summary = summary
		scan.CompletedAt = &completedAt
		scan.Duration = int64(duration.Seconds())
	}

	// Save final results
	h.db.UpdateScan(ctx, scan)
}

// scanPackage performs the actual package analysis
func (h *ScanHandlers) scanPackage(packageName, registry, version string) ([]database.ThreatResult, string, string, error) {
	var threats []database.ThreatResult
	var riskLevel string
	var summary string

	// Use the detector if available
	if h.detector != nil {
		// Perform package analysis using the detector engine
		result, err := h.detector.CheckPackage(context.Background(), packageName, registry)
		if err != nil {
			return nil, "", "", fmt.Errorf("detector analysis failed: %w", err)
		}

		// Convert detector results to threat results
		if result.ThreatLevel != "low" && result.ThreatLevel != "" && result.ThreatLevel != "none" {
			threat := database.ThreatResult{
				Type:        "typosquatting",
				Severity:    result.ThreatLevel,
				Confidence:  result.Confidence,
				Description: fmt.Sprintf("Threat detected with confidence %.2f", result.Confidence),
				Source:      "typosentinel-detector",
			}
			threats = append(threats, threat)
		}

		// Add any additional threats from the result
		for _, detectedThreat := range result.Threats {
			threat := database.ThreatResult{
				Type:        string(detectedThreat.Type),
				Severity:    detectedThreat.Severity.String(),
				Confidence:  detectedThreat.Confidence,
				Description: detectedThreat.Description,
				Source:      "typosentinel-detector",
			}
			threats = append(threats, threat)
		}
	} else {
		// Fallback: Basic pattern-based detection
		threats = h.performBasicScan(packageName, registry)
	}

	// Determine risk level based on threats
	riskLevel = h.calculateRiskLevel(threats)

	// Generate summary
	if len(threats) == 0 {
		summary = "No threats detected. Package appears to be safe."
	} else {
		summary = fmt.Sprintf("Found %d potential threat(s). Risk level: %s", len(threats), riskLevel)
	}

	return threats, riskLevel, summary, nil
}

// performBasicScan performs basic pattern-based scanning
func (h *ScanHandlers) performBasicScan(packageName, registry string) []database.ThreatResult {
	var threats []database.ThreatResult

	// Check for common typosquatting patterns
	suspiciousPatterns := []string{
		"lodash", "express", "react", "angular", "vue", "jquery", "bootstrap",
		"numpy", "pandas", "requests", "django", "flask", "tensorflow",
		"spring", "hibernate", "junit", "maven", "gradle",
	}

	for _, pattern := range suspiciousPatterns {
		if strings.Contains(strings.ToLower(packageName), pattern) && packageName != pattern {
			// Check for character substitution
			if h.isLikelyTyposquatting(packageName, pattern) {
				threat := database.ThreatResult{
					Type:        "typosquatting",
					Severity:    "high",
					Confidence:  0.8,
					Description: fmt.Sprintf("Potential typosquatting of popular package '%s'", pattern),
					Source:      "basic-pattern-detector",
				}
				threats = append(threats, threat)
			}
		}
	}

	// Check for suspicious characters
	if strings.ContainsAny(packageName, "0123456789") && len(packageName) > 10 {
		threat := database.ThreatResult{
			Type:        "suspicious_name",
			Severity:    "low",
			Confidence:  0.5,
			Description: "Package name contains numbers and is unusually long",
			Source:      "basic-pattern-detector",
		}
		threats = append(threats, threat)
	}

	return threats
}

// isLikelyTyposquatting checks if a package name is likely typosquatting another
func (h *ScanHandlers) isLikelyTyposquatting(packageName, target string) bool {
	// Simple Levenshtein distance check
	distance := h.levenshteinDistance(strings.ToLower(packageName), strings.ToLower(target))
	return distance > 0 && distance <= 3 && len(packageName) > 3
}

// levenshteinDistance calculates the Levenshtein distance between two strings
func (h *ScanHandlers) levenshteinDistance(s1, s2 string) int {
	if len(s1) == 0 {
		return len(s2)
	}
	if len(s2) == 0 {
		return len(s1)
	}

	matrix := make([][]int, len(s1)+1)
	for i := range matrix {
		matrix[i] = make([]int, len(s2)+1)
		matrix[i][0] = i
	}
	for j := range matrix[0] {
		matrix[0][j] = j
	}

	for i := 1; i <= len(s1); i++ {
		for j := 1; j <= len(s2); j++ {
			cost := 0
			if s1[i-1] != s2[j-1] {
				cost = 1
			}
			matrix[i][j] = min(
				matrix[i-1][j]+1,      // deletion
				matrix[i][j-1]+1,      // insertion
				matrix[i-1][j-1]+cost, // substitution
			)
		}
	}

	return matrix[len(s1)][len(s2)]
}

// calculateRiskLevel determines the overall risk level based on threats
func (h *ScanHandlers) calculateRiskLevel(threats []database.ThreatResult) string {
	if len(threats) == 0 {
		return "low"
	}

	highCount := 0
	mediumCount := 0

	for _, threat := range threats {
		switch threat.Severity {
		case "critical":
			return "critical"
		case "high":
			highCount++
		case "medium":
			mediumCount++
		}
	}

	if highCount > 0 {
		return "high"
	}
	if mediumCount > 1 {
		return "medium"
	}
	return "low"
}

// min returns the minimum of three integers
func min(a, b, c int) int {
	if a < b && a < c {
		return a
	}
	if b < c {
		return b
	}
	return c
}