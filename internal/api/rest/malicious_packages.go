package rest

import (
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/Alivanroy/Typosentinel/internal/behavior"
	"github.com/Alivanroy/Typosentinel/pkg/logger"
)

// MaliciousPackageHandler handles malicious package and campaign related endpoints
type MaliciousPackageHandler struct {
	behaviorService *behavior.BehaviorService
	logger         *logger.Logger
}

// NewMaliciousPackageHandler creates a new malicious package handler
func NewMaliciousPackageHandler(behaviorService *behavior.BehaviorService) *MaliciousPackageHandler {
	return &MaliciousPackageHandler{
		behaviorService: behaviorService,
		logger:         logger.New(),
	}
}

// MaliciousPackageResponse represents a malicious package in the API response
type MaliciousPackageResponse struct {
	ID              string    `json:"id"`
	Name            string    `json:"name"`
	Ecosystem       string    `json:"ecosystem"`
	Version         string    `json:"version"`
	RiskScore       float64   `json:"riskScore"`
	RiskLevel       string    `json:"riskLevel"`
	BehaviorScore   float64   `json:"behaviorScore"`
	CampaignScore   float64   `json:"campaignScore"`
	BaseScore       float64   `json:"baseScore"`
	Threats         []ThreatResponse `json:"threats"`
	BehaviorSummary struct {
		FilesystemActions  int `json:"filesystemActions"`
		NetworkAttempts    int `json:"networkAttempts"`
		SuspiciousPatterns int `json:"suspiciousPatterns"`
		ProcessBehavior    int `json:"processBehavior"`
	} `json:"behaviorSummary"`
	CampaignID   string    `json:"campaignId,omitempty"`
	CampaignName string    `json:"campaignName,omitempty"`
	FirstSeen    time.Time `json:"firstSeen"`
	LastSeen     time.Time `json:"lastSeen"`
	Status       string    `json:"status"`
}

// ThreatResponse represents a threat in the API response
type ThreatResponse struct {
	Type        string  `json:"type"`
	Severity    string  `json:"severity"`
	Description string  `json:"description"`
	Confidence  float64 `json:"confidence"`
}

// CampaignResponse represents a campaign in the API response
type CampaignResponse struct {
	ID                  string    `json:"id"`
	Name                string    `json:"name"`
	Description         string    `json:"description"`
	Ecosystem           string    `json:"ecosystem"`
	PackageCount        int       `json:"packageCount"`
	AffectedEcosystems    []string  `json:"affectedEcosystems"`
	Severity            string    `json:"severity"`
	RiskScore            float64   `json:"riskScore"`
	FirstSeen           time.Time `json:"firstSeen"`
	LastSeen            time.Time `json:"lastSeen"`
	Status              string    `json:"status"`
	Packages            []PackageResponse `json:"packages"`
	Indicators          []IndicatorResponse `json:"indicators"`
	NetworkIOCs         []string  `json:"networkIOCs"`
	FileIOCs            []string  `json:"fileIOCs"`
	AuthorSignatures    []AuthorSignatureResponse `json:"authorSignatures"`
}

// PackageResponse represents a package in a campaign
type PackageResponse struct {
	Name      string  `json:"name"`
	Version   string  `json:"version"`
	Ecosystem string  `json:"ecosystem"`
	RiskScore float64 `json:"riskScore"`
}

// IndicatorResponse represents a threat indicator
type IndicatorResponse struct {
	Type        string  `json:"type"`
	Description string  `json:"description"`
	Confidence  float64 `json:"confidence"`
}

// AuthorSignatureResponse represents an author signature
type AuthorSignatureResponse struct {
	Name       string  `json:"name"`
	Email      string  `json:"email"`
	Confidence float64 `json:"confidence"`
}

// MaliciousPackageStatsResponse represents statistics about malicious packages
type MaliciousPackageStatsResponse struct {
	TotalMaliciousPackages int `json:"totalMaliciousPackages"`
	ActiveCampaigns        int `json:"activeCampaigns"`
	HighRiskPackages       int `json:"highRiskPackages"`
	QuarantinedPackages    int `json:"quarantinedPackages"`
	TopThreatTypes         []struct {
		Type  string `json:"type"`
		Count int    `json:"count"`
	} `json:"topThreatTypes"`
	EcosystemDistribution []struct {
		Ecosystem string `json:"ecosystem"`
		Count     int    `json:"count"`
	} `json:"ecosystemDistribution"`
}

// GetMaliciousPackages returns a list of malicious packages with optional filtering
func (h *MaliciousPackageHandler) GetMaliciousPackages(c *gin.Context) {
	riskLevel := c.Query("riskLevel")
	ecosystem := c.Query("ecosystem")
	campaignID := c.Query("campaignId")
	status := c.Query("status")
	limitStr := c.Query("limit")
	
	limit := 50 // default limit
	if limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 {
			limit = l
		}
	}

	// For now, return mock data. In a real implementation, this would query the database
	packages := []MaliciousPackageResponse{
		{
			ID:        "pkg-001",
			Name:      "malicious-package-1",
			Ecosystem: "npm",
			Version:   "1.0.0",
			RiskScore: 8.5,
			RiskLevel: "high",
			BehaviorScore: 7.2,
			CampaignScore: 6.8,
			BaseScore: 5.5,
			Threats: []ThreatResponse{
				{
					Type:        "typosquatting",
					Severity:    "high",
					Description: "Package name is similar to popular package 'express'",
					Confidence:  0.85,
				},
				{
					Type:        "suspicious_behavior",
					Severity:    "medium",
					Description: "Attempts to access sensitive files during installation",
					Confidence:  0.72,
				},
			},
			BehaviorSummary: struct {
				FilesystemActions  int `json:"filesystemActions"`
				NetworkAttempts    int `json:"networkAttempts"`
				SuspiciousPatterns int `json:"suspiciousPatterns"`
				ProcessBehavior    int `json:"processBehavior"`
			}{
				FilesystemActions:  12,
				NetworkAttempts:    3,
				SuspiciousPatterns: 7,
				ProcessBehavior:    2,
			},
			CampaignID:   "campaign-001",
			CampaignName: "Fake Express Campaign",
			FirstSeen:    time.Now().AddDate(0, -1, 0),
			LastSeen:     time.Now().AddDate(0, 0, -1),
			Status:       "active",
		},
		{
			ID:        "pkg-002",
			Name:      "suspicious-loader",
			Ecosystem: "pypi",
			Version:   "2.1.0",
			RiskScore: 9.2,
			RiskLevel: "critical",
			BehaviorScore: 8.5,
			CampaignScore: 7.1,
			BaseScore: 6.8,
			Threats: []ThreatResponse{
				{
					Type:        "crypto_mining",
					Severity:    "critical",
					Description: "Contains cryptocurrency mining payload",
					Confidence:  0.92,
				},
				{
					Type:        "network_exfiltration",
					Severity:    "high",
					Description: "Attempts to exfiltrate data to external servers",
					Confidence:  0.78,
				},
			},
			BehaviorSummary: struct {
				FilesystemActions  int `json:"filesystemActions"`
				NetworkAttempts    int `json:"networkAttempts"`
				SuspiciousPatterns int `json:"suspiciousPatterns"`
				ProcessBehavior    int `json:"processBehavior"`
			}{
				FilesystemActions:  18,
				NetworkAttempts:    7,
				SuspiciousPatterns: 12,
				ProcessBehavior:    5,
			},
			CampaignID:   "campaign-002",
			CampaignName: "Crypto Mining Network",
			FirstSeen:    time.Now().AddDate(0, -2, 0),
			LastSeen:     time.Now().AddDate(0, 0, -2),
			Status:       "quarantined",
		},
	}

	// Apply filters
	filteredPackages := make([]MaliciousPackageResponse, 0)
	for _, pkg := range packages {
		if riskLevel != "" && pkg.RiskLevel != riskLevel {
			continue
		}
		if ecosystem != "" && pkg.Ecosystem != ecosystem {
			continue
		}
		if campaignID != "" && pkg.CampaignID != campaignID {
			continue
		}
		if status != "" && pkg.Status != status {
			continue
		}
		filteredPackages = append(filteredPackages, pkg)
	}

	// Apply limit
	if len(filteredPackages) > limit {
		filteredPackages = filteredPackages[:limit]
	}

	c.JSON(http.StatusOK, gin.H{
		"packages": filteredPackages,
		"total":    len(filteredPackages),
		"filters": gin.H{
			"riskLevel":  riskLevel,
			"ecosystem":  ecosystem,
			"campaignId": campaignID,
			"status":     status,
			"limit":      limit,
		},
	})
}

// GetCampaigns returns a list of threat campaigns with optional filtering
func (h *MaliciousPackageHandler) GetCampaigns(c *gin.Context) {
	severity := c.Query("severity")
	ecosystem := c.Query("ecosystem")
	status := c.Query("status")
	limitStr := c.Query("limit")
	
	limit := 50 // default limit
	if limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 {
			limit = l
		}
	}

	// For now, return mock data. In a real implementation, this would query the database
	campaigns := []CampaignResponse{
		{
			ID:          "campaign-001",
			Name:        "Fake Express Campaign",
			Description: "Campaign targeting Node.js developers with fake express packages",
			Ecosystem:   "npm",
			PackageCount: 23,
			AffectedEcosystems: []string{"npm", "yarn"},
			Severity:    "high",
			RiskScore:   7.8,
			FirstSeen:   time.Now().AddDate(0, -2, 0),
			LastSeen:    time.Now().AddDate(0, 0, -1),
			Status:      "active",
			Packages: []PackageResponse{
				{Name: "malicious-package-1", Version: "1.0.0", Ecosystem: "npm", RiskScore: 8.5},
				{Name: "fake-express-loader", Version: "2.0.1", Ecosystem: "npm", RiskScore: 7.9},
			},
			Indicators: []IndicatorResponse{
				{Type: "typosquatting", Description: "Similar names to popular packages", Confidence: 0.85},
				{Type: "behavioral_pattern", Description: "Consistent malicious behavior patterns", Confidence: 0.78},
			},
			NetworkIOCs: []string{"suspicious-domain.com", "malware-c2.net"},
			FileIOCs:    []string{"malicious-script.js", "backdoor.py"},
			AuthorSignatures: []AuthorSignatureResponse{
				{Name: "John Doe", Email: "john@example.com", Confidence: 0.72},
			},
		},
		{
			ID:          "campaign-002",
			Name:        "Crypto Mining Network",
			Description: "Network of packages containing cryptocurrency mining payloads",
			Ecosystem:   "pypi",
			PackageCount: 47,
			AffectedEcosystems: []string{"pypi", "conda"},
			Severity:    "critical",
			RiskScore:   8.9,
			FirstSeen:   time.Now().AddDate(0, -3, 0),
			LastSeen:    time.Now().AddDate(0, 0, -2),
			Status:      "active",
			Packages: []PackageResponse{
				{Name: "suspicious-loader", Version: "2.1.0", Ecosystem: "pypi", RiskScore: 9.2},
				{Name: "crypto-miner", Version: "1.5.0", Ecosystem: "pypi", RiskScore: 8.7},
			},
			Indicators: []IndicatorResponse{
				{Type: "crypto_mining", Description: "Contains mining algorithms", Confidence: 0.92},
				{Type: "network_exfiltration", Description: "Data exfiltration capabilities", Confidence: 0.81},
			},
			NetworkIOCs: []string{"mining-pool.com", "crypto-wallet.net"},
			FileIOCs:    []string{"miner.py", "wallet.dat"},
			AuthorSignatures: []AuthorSignatureResponse{
				{Name: "Jane Smith", Email: "jane@example.com", Confidence: 0.68},
			},
		},
	}

	// Apply filters
	filteredCampaigns := make([]CampaignResponse, 0)
	for _, campaign := range campaigns {
		if severity != "" && campaign.Severity != severity {
			continue
		}
		if ecosystem != "" && campaign.Ecosystem != ecosystem {
			continue
		}
		if status != "" && campaign.Status != status {
			continue
		}
		filteredCampaigns = append(filteredCampaigns, campaign)
	}

	// Apply limit
	if len(filteredCampaigns) > limit {
		filteredCampaigns = filteredCampaigns[:limit]
	}

	c.JSON(http.StatusOK, gin.H{
		"campaigns": filteredCampaigns,
		"total":      len(filteredCampaigns),
		"filters": gin.H{
			"severity":  severity,
			"ecosystem": ecosystem,
			"status":    status,
			"limit":     limit,
		},
	})
}

// GetCampaignDetails returns detailed information about a specific campaign
func (h *MaliciousPackageHandler) GetCampaignDetails(c *gin.Context) {
	campaignID := c.Param("id")
	
	// For now, return mock data. In a real implementation, this would query the database
	campaign := CampaignResponse{
		ID:          campaignID,
		Name:        "Fake Express Campaign",
		Description: "Campaign targeting Node.js developers with fake express packages",
		Ecosystem:   "npm",
		PackageCount: 23,
		AffectedEcosystems: []string{"npm", "yarn"},
		Severity:    "high",
		RiskScore:   7.8,
		FirstSeen:   time.Now().AddDate(0, -2, 0),
		LastSeen:    time.Now().AddDate(0, 0, -1),
		Status:      "active",
		Packages: []PackageResponse{
			{Name: "malicious-package-1", Version: "1.0.0", Ecosystem: "npm", RiskScore: 8.5},
			{Name: "fake-express-loader", Version: "2.0.1", Ecosystem: "npm", RiskScore: 7.9},
			{Name: "express-malware", Version: "1.5.0", Ecosystem: "npm", RiskScore: 8.1},
		},
		Indicators: []IndicatorResponse{
			{Type: "typosquatting", Description: "Similar names to popular packages", Confidence: 0.85},
			{Type: "behavioral_pattern", Description: "Consistent malicious behavior patterns", Confidence: 0.78},
			{Type: "network_ioc", Description: "Shared network infrastructure", Confidence: 0.72},
		},
		NetworkIOCs: []string{"suspicious-domain.com", "malware-c2.net", "evil-server.org"},
		FileIOCs:    []string{"malicious-script.js", "backdoor.py", "trojan.exe"},
		AuthorSignatures: []AuthorSignatureResponse{
			{Name: "John Doe", Email: "john@example.com", Confidence: 0.72},
			{Name: "Jane Smith", Email: "jane@example.com", Confidence: 0.65},
		},
	}

	c.JSON(http.StatusOK, campaign)
}

// GetBehaviorProfile returns the behavior profile for a specific package
func (h *MaliciousPackageHandler) GetBehaviorProfile(c *gin.Context) {
	packageID := c.Param("id")
	
	// For now, return mock data. In a real implementation, this would query the behavior service
	behaviorProfile := gin.H{
		"packageId":   packageID,
		"packageName": "malicious-package-1",
		"ecosystem":   "npm",
		"filesystemActions": []gin.H{
			{"action": "write", "path": "/etc/passwd", "timestamp": time.Now().AddDate(0, 0, -1), "risk": "critical"},
			{"action": "read", "path": "/home/user/.ssh/id_rsa", "timestamp": time.Now().AddDate(0, 0, -1), "risk": "high"},
		},
		"networkAttempts": []gin.H{
			{"domain": "evil-server.com", "ip": "192.168.1.100", "port": 8080, "protocol": "http", "timestamp": time.Now().AddDate(0, 0, -1), "risk": "high"},
			{"domain": "malware-c2.net", "ip": "10.0.0.50", "port": 443, "protocol": "https", "timestamp": time.Now().AddDate(0, 0, -2), "risk": "critical"},
		},
		"suspiciousPatterns": []gin.H{
			{"pattern": "eval() usage", "description": "Uses eval() function for code execution", "severity": "high", "confidence": 0.85},
			{"pattern": "Base64 encoding", "description": "Heavy use of base64 encoding for obfuscation", "severity": "medium", "confidence": 0.72},
		},
		"processBehavior": []gin.H{
			{"action": "spawn", "target": "cmd.exe", "timestamp": time.Now().AddDate(0, 0, -1), "risk": "critical"},
			{"action": "inject", "target": "system process", "timestamp": time.Now().AddDate(0, 0, -1), "risk": "critical"},
		},
		"riskAssessment": gin.H{
			"overallScore": 8.5,
			"confidence":   0.89,
			"riskLevel":    "high",
		},
	}

	c.JSON(http.StatusOK, behaviorProfile)
}

// GetMaliciousPackageStats returns statistics about malicious packages
func (h *MaliciousPackageHandler) GetMaliciousPackageStats(c *gin.Context) {
	stats := MaliciousPackageStatsResponse{
		TotalMaliciousPackages: 156,
		ActiveCampaigns:        12,
		HighRiskPackages:       43,
		QuarantinedPackages:    28,
		TopThreatTypes: []struct {
			Type  string `json:"type"`
			Count int    `json:"count"`
		}{
			{Type: "typosquatting", Count: 67},
			{Type: "crypto_mining", Count: 34},
			{Type: "data_exfiltration", Count: 28},
			{Type: "backdoor", Count: 19},
			{Type: "trojan", Count: 8},
		},
		EcosystemDistribution: []struct {
			Ecosystem string `json:"ecosystem"`
			Count     int    `json:"count"`
		}{
			{Ecosystem: "npm", Count: 89},
			{Ecosystem: "pypi", Count: 45},
			{Ecosystem: "maven", Count: 15},
			{Ecosystem: "go", Count: 7},
		},
	}

	c.JSON(http.StatusOK, stats)
}