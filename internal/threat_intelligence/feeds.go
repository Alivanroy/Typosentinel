package threat_intelligence

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/Alivanroy/Typosentinel/pkg/logger"
)

// OSVFeed implements ThreatFeed interface for OSV database
type OSVFeed struct {
	logger         *logger.Logger
	updateInterval time.Duration
	status         FeedStatus
	baseURL        string
	client         *http.Client
}

// NewOSVFeed creates a new OSV threat feed
func NewOSVFeed(logger *logger.Logger) *OSVFeed {
	return &OSVFeed{
		logger:  logger,
		baseURL: "https://api.osv.dev/v1",
		client:  &http.Client{Timeout: 30 * time.Second},
		status: FeedStatus{
			Name:    "osv",
			State:   "inactive",
			Healthy: true,
		},
	}
}

// GetName returns the feed name
func (f *OSVFeed) GetName() string {
	return "osv"
}

// GetType returns the feed type
func (f *OSVFeed) GetType() string {
	return "osv"
}

// Initialize sets up the OSV feed
func (f *OSVFeed) Initialize(ctx context.Context, config map[string]interface{}) error {
	f.logger.Info("Initializing OSV threat feed")

	// Set update interval from config
	if interval, ok := config["update_interval"]; ok {
		if duration, ok := interval.(time.Duration); ok {
			f.updateInterval = duration
		} else {
			f.updateInterval = 1 * time.Hour // Default
		}
	} else {
		f.updateInterval = 1 * time.Hour // Default
	}

	f.status.State = "active"
	f.status.UpdateInterval = f.updateInterval
	f.status.LastUpdate = time.Now()

	return nil
}

// FetchThreats retrieves latest threats from OSV
func (f *OSVFeed) FetchThreats(ctx context.Context, since time.Time) ([]ThreatIntelligence, error) {
	f.logger.Debug("Fetching threats from OSV feed", map[string]interface{}{
		"since": since,
	})

	// Query OSV API for vulnerabilities since the given time
	url := fmt.Sprintf("%s/query", f.baseURL)

	// Create query payload
	queryPayload := map[string]interface{}{
		"version": "1",
		"query": map[string]interface{}{
			"modified_after": since.Format(time.RFC3339),
		},
	}

	payloadBytes, err := json.Marshal(queryPayload)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal query payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(payloadBytes))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "Typosentinel/1.0")

	resp, err := f.client.Do(req)
	if err != nil {
		f.status.LastError = err.Error()
		f.status.State = "error"
		f.status.Healthy = false
		return nil, fmt.Errorf("failed to fetch from OSV API: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		errorMsg := fmt.Sprintf("OSV API returned status %d", resp.StatusCode)
		f.status.LastError = errorMsg
		f.status.State = "error"
		f.status.Healthy = false
		return nil, fmt.Errorf(errorMsg)
	}

	var osvResponse struct {
		Vulns []struct {
			ID       string `json:"id"`
			Summary  string `json:"summary"`
			Details  string `json:"details"`
			Modified string `json:"modified"`
			Affected []struct {
				Package struct {
					Name      string `json:"name"`
					Ecosystem string `json:"ecosystem"`
				} `json:"package"`
				Severity []struct {
					Type  string `json:"type"`
					Score string `json:"score"`
				} `json:"severity"`
			} `json:"affected"`
			References []struct {
				Type string `json:"type"`
				URL  string `json:"url"`
			} `json:"references"`
		} `json:"vulns"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&osvResponse); err != nil {
		f.status.LastError = err.Error()
		f.status.State = "error"
		f.status.Healthy = false
		return nil, fmt.Errorf("failed to decode OSV response: %w", err)
	}

	// Convert OSV vulnerabilities to ThreatIntelligence format
	var threats []ThreatIntelligence
	for _, vuln := range osvResponse.Vulns {
		modified, _ := time.Parse(time.RFC3339, vuln.Modified)

		for _, affected := range vuln.Affected {
			severity := "medium"
			if len(affected.Severity) > 0 {
				severity = f.mapSeverity(affected.Severity[0].Score)
			}

			references := make([]string, len(vuln.References))
			for i, ref := range vuln.References {
				references[i] = ref.URL
			}

			threats = append(threats, ThreatIntelligence{
				ID:              vuln.ID,
				Source:          "OSV",
				Type:            "vulnerability",
				Severity:        severity,
				PackageName:     affected.Package.Name,
				Ecosystem:       affected.Package.Ecosystem,
				Description:     vuln.Summary,
				References:      references,
				Tags:            []string{"osv", "vulnerability"},
				ConfidenceLevel: 0.95,
				FirstSeen:       modified,
				LastSeen:        time.Now(),
				Metadata: map[string]interface{}{
					"details": vuln.Details,
					"osv_id":  vuln.ID,
				},
			})
		}
	}

	// Update status
	f.status.LastUpdate = time.Now()
	f.status.ThreatCount = len(threats)
	f.status.State = "active"
	f.status.Healthy = true
	f.status.LastError = ""

	return threats, nil
}

// GetStatus returns feed status
func (f *OSVFeed) GetStatus() FeedStatus {
	return f.status
}

// Close closes the OSV feed connection
func (f *OSVFeed) Close() error {
	f.status.State = "inactive"
	return nil
}

// mapSeverity converts OSV severity scores to standard severity levels
func (f *OSVFeed) mapSeverity(score string) string {
	switch {
	case strings.Contains(strings.ToLower(score), "critical"):
		return "critical"
	case strings.Contains(strings.ToLower(score), "high"):
		return "high"
	case strings.Contains(strings.ToLower(score), "medium"):
		return "medium"
	case strings.Contains(strings.ToLower(score), "low"):
		return "low"
	default:
		return "medium"
	}
}

// GitHubAdvisoryFeed implements ThreatFeed interface for GitHub Advisory database
type GitHubAdvisoryFeed struct {
	logger         *logger.Logger
	token          string
	updateInterval time.Duration
	status         FeedStatus
	baseURL        string
	apiKey         string
	client         *http.Client
}

// NewGitHubAdvisoryFeed creates a new GitHub Advisory threat feed
func NewGitHubAdvisoryFeed(logger *logger.Logger) *GitHubAdvisoryFeed {
	return &GitHubAdvisoryFeed{
		logger:  logger,
		baseURL: "https://api.github.com",
		client:  &http.Client{Timeout: 30 * time.Second},
		status: FeedStatus{
			Name:    "github_advisory",
			State:   "inactive",
			Healthy: true,
		},
	}
}

// GetName returns the feed name
func (f *GitHubAdvisoryFeed) GetName() string {
	return "github_advisory"
}

// GetType returns the feed type
func (f *GitHubAdvisoryFeed) GetType() string {
	return "github_advisory"
}

// Initialize sets up the GitHub Advisory feed
func (f *GitHubAdvisoryFeed) Initialize(ctx context.Context, config map[string]interface{}) error {
	f.logger.Info("Initializing GitHub Advisory threat feed")

	// Set token from config
	if token, ok := config["token"]; ok {
		if tokenStr, ok := token.(string); ok {
			f.token = tokenStr
		}
	}

	// Set update interval from config
	if interval, ok := config["update_interval"]; ok {
		if duration, ok := interval.(time.Duration); ok {
			f.updateInterval = duration
		} else {
			f.updateInterval = 1 * time.Hour // Default
		}
	} else {
		f.updateInterval = 1 * time.Hour // Default
	}

	f.status.State = "active"
	f.status.UpdateInterval = f.updateInterval
	f.status.LastUpdate = time.Now()

	return nil
}

// FetchThreats retrieves latest threats from GitHub Advisory
func (f *GitHubAdvisoryFeed) FetchThreats(ctx context.Context, since time.Time) ([]ThreatIntelligence, error) {
	f.logger.Debug("Fetching threats from GitHub Advisory feed", map[string]interface{}{
		"since": since,
	})

	// TODO: Implement actual GitHub Advisory API integration
	// For now, return empty slice to avoid build errors
	var threats []ThreatIntelligence

	f.status.LastUpdate = time.Now()
	f.status.ThreatCount = len(threats)

	return threats, nil
}

// GetStatus returns feed status
func (f *GitHubAdvisoryFeed) GetStatus() FeedStatus {
	return f.status
}

// Close closes the GitHub Advisory feed connection
func (f *GitHubAdvisoryFeed) Close() error {
	f.status.State = "inactive"
	return nil
}

// CustomFeed implements ThreatFeed interface for custom threat feeds
type CustomFeed struct {
	name           string
	logger         *logger.Logger
	updateInterval time.Duration
	status         FeedStatus
	url            string
	apiKey         string
	client         *http.Client
}

// NewCustomFeed creates a new custom threat feed
func NewCustomFeed(name string, logger *logger.Logger) *CustomFeed {
	return &CustomFeed{
		name:   name,
		logger: logger,
		client: &http.Client{Timeout: 30 * time.Second},
		status: FeedStatus{
			Name:    name,
			State:   "inactive",
			Healthy: true,
		},
	}
}

// GetName returns the feed name
func (f *CustomFeed) GetName() string {
	return f.name
}

// GetType returns the feed type
func (f *CustomFeed) GetType() string {
	return "custom"
}

// Initialize sets up the custom feed
func (f *CustomFeed) Initialize(ctx context.Context, config map[string]interface{}) error {
	f.logger.Info("Initializing custom threat feed", map[string]interface{}{
		"name": f.name,
	})

	// Set update interval from config
	if interval, ok := config["update_interval"]; ok {
		if duration, ok := interval.(time.Duration); ok {
			f.updateInterval = duration
		} else {
			f.updateInterval = 1 * time.Hour // Default
		}
	} else {
		f.updateInterval = 1 * time.Hour // Default
	}

	f.status.State = "active"
	f.status.UpdateInterval = f.updateInterval
	f.status.LastUpdate = time.Now()

	return nil
}

// FetchThreats retrieves latest threats from custom feed
func (f *CustomFeed) FetchThreats(ctx context.Context, since time.Time) ([]ThreatIntelligence, error) {
	f.logger.Debug("Fetching threats from custom feed", map[string]interface{}{
		"name":  f.name,
		"since": since,
	})

	// TODO: Implement custom feed integration based on feed configuration
	// This could support various formats like JSON, XML, CSV, etc.
	return []ThreatIntelligence{
		{
			ID:              "custom-001",
			Source:          f.name,
			Type:            "typosquatting",
			Severity:        "high",
			PackageName:     "suspicious-package",
			Ecosystem:       "npm",
			Description:     "Mock custom feed threat",
			ConfidenceLevel: 0.8,
			FirstSeen:       time.Now().Add(-6 * time.Hour),
			LastSeen:        time.Now(),
		},
	}, nil
}

// GetStatus returns feed status
func (f *CustomFeed) GetStatus() FeedStatus {
	return f.status
}

// Close closes the custom feed connection
func (f *CustomFeed) Close() error {
	f.status.State = "inactive"
	return nil
}

// Helper methods for CustomFeed to parse generic data
func (f *CustomFeed) getStringValue(data map[string]interface{}, key, defaultValue string) string {
	if val, ok := data[key]; ok {
		if str, ok := val.(string); ok {
			return str
		}
	}
	return defaultValue
}

func (f *CustomFeed) getFloatValue(data map[string]interface{}, key string, defaultValue float64) float64 {
	if val, ok := data[key]; ok {
		switch v := val.(type) {
		case float64:
			return v
		case float32:
			return float64(v)
		case int:
			return float64(v)
		case int64:
			return float64(v)
		}
	}
	return defaultValue
}

func (f *CustomFeed) getTimeValue(data map[string]interface{}, key string, defaultValue time.Time) time.Time {
	if val, ok := data[key]; ok {
		if str, ok := val.(string); ok {
			if t, err := time.Parse(time.RFC3339, str); err == nil {
				return t
			}
			// Try alternative formats
			if t, err := time.Parse("2006-01-02T15:04:05Z", str); err == nil {
				return t
			}
			if t, err := time.Parse("2006-01-02 15:04:05", str); err == nil {
				return t
			}
		}
	}
	return defaultValue
}
