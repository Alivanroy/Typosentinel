package threat_intelligence

import (
    "bytes"
    "context"
    "encoding/csv"
    "encoding/json"
    "fmt"
    "io"
    "net/http"
    "os"
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
    apiKey         string
    rateRPS        int
    lastCall       time.Time
    cacheTTL       time.Duration
    cacheSince     time.Time
    cacheThreats   []ThreatIntelligence
}

// NewOSVFeed creates a new OSV threat feed
func NewOSVFeed(logger *logger.Logger) *OSVFeed {
    return &OSVFeed{
        logger:  logger,
        baseURL: "https://api.osv.dev/v1",
        client:  &http.Client{Timeout: 30 * time.Second},
        rateRPS: 2,
        cacheTTL: 10 * time.Minute,
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
    if f.logger != nil { f.logger.Info("Initializing OSV threat feed") }

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
    if f.cacheThreats != nil && time.Since(f.cacheSince) < f.cacheTTL && (since.IsZero() || !f.cacheSince.Before(since)) {
        return f.cacheThreats, nil
    }
    minInterval := time.Second / time.Duration(func() int { if f.rateRPS < 1 { return 1 }; return f.rateRPS }())
    if time.Since(f.lastCall) < minInterval {
        time.Sleep(minInterval - time.Since(f.lastCall))
    }
    if f.logger != nil { f.logger.Debug("Fetching threats from OSV feed", map[string]interface{}{
        "since": since,
    }) }

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
    if f.apiKey != "" {
        req.Header.Set("Authorization", "Bearer "+f.apiKey)
    }

    resp, err := doWithRetry(f.client, req, 3)
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
        Next string `json:"next"`
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

    // Pagination: follow next token if present
    token := strings.TrimSpace(osvResponse.Next)
    for token != "" {
        nextPayload := map[string]interface{}{"version": "1", "query": map[string]interface{}{"token": token}}
        nb, _ := json.Marshal(nextPayload)
        req2, _ := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(nb))
        req2.Header.Set("Content-Type", "application/json")
        req2.Header.Set("User-Agent", "Typosentinel/1.0")
        if f.apiKey != "" { req2.Header.Set("Authorization", "Bearer "+f.apiKey) }
        resp2, err2 := doWithRetry(f.client, req2, 3)
        if err2 != nil { break }
        defer resp2.Body.Close()
        if resp2.StatusCode != http.StatusOK { break }
        var page struct {
            Vulns []struct {
                ID string `json:"id"`
                Summary string `json:"summary"`
                Details string `json:"details"`
                Modified string `json:"modified"`
                Affected []struct { Package struct { Name, Ecosystem string } `json:"package"`; Severity []struct { Type, Score string } `json:"severity"` } `json:"affected"`
                References []struct { Type, URL string } `json:"references"`
            } `json:"vulns"`
            Next string `json:"next"`
        }
        if err := json.NewDecoder(resp2.Body).Decode(&page); err != nil { break }
        for _, v := range page.Vulns {
            modified, _ := time.Parse(time.RFC3339, v.Modified)
            for _, affected := range v.Affected {
                severity := "medium"
                if len(affected.Severity) > 0 { severity = f.mapSeverity(affected.Severity[0].Score) }
                references := make([]string, len(v.References))
                for i, ref := range v.References { references[i] = ref.URL }
                threats = append(threats, ThreatIntelligence{ ID: v.ID, Source: "OSV", Type: "vulnerability", Severity: severity, PackageName: affected.Package.Name, Ecosystem: affected.Package.Ecosystem, Description: v.Summary, References: references, Tags: []string{"osv","vulnerability"}, ConfidenceLevel: 0.95, FirstSeen: modified, LastSeen: time.Now(), Metadata: map[string]interface{}{ "details": v.Details, "osv_id": v.ID } })
            }
        }
        token = strings.TrimSpace(page.Next)
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
    rateRPS        int
    lastCall       time.Time
    cacheTTL       time.Duration
    cacheSince     time.Time
    cacheThreats   []ThreatIntelligence
}

// NewGitHubAdvisoryFeed creates a new GitHub Advisory threat feed
func NewGitHubAdvisoryFeed(logger *logger.Logger) *GitHubAdvisoryFeed {
    return &GitHubAdvisoryFeed{
        logger:  logger,
        baseURL: "https://api.github.com",
        client:  &http.Client{Timeout: 30 * time.Second},
        rateRPS: 2,
        cacheTTL: 10 * time.Minute,
        status: FeedStatus{
            Name:    "github_advisory",
            State:   "inactive",
            Healthy: true,
        },
    }
}

type NVDFeed struct {
    logger         *logger.Logger
    updateInterval time.Duration
    status         FeedStatus
    mode           string
}

func NewNVDFeed(logger *logger.Logger) *NVDFeed {
    return &NVDFeed{
        logger: logger,
        status: FeedStatus{Name: "nvd", State: "inactive", Healthy: true},
        mode:   "stub",
    }
}

func (f *NVDFeed) GetName() string { return "nvd" }
func (f *NVDFeed) GetType() string { return "nvd" }

func (f *NVDFeed) Initialize(ctx context.Context, config map[string]interface{}) error {
    _ = ctx
    if interval, ok := config["update_interval"]; ok {
        if d, ok := interval.(time.Duration); ok {
            f.updateInterval = d
        } else {
            f.updateInterval = 2 * time.Hour
        }
    } else {
        f.updateInterval = 2 * time.Hour
    }
    if v, ok := config["mode"].(string); ok && v != "" {
        f.mode = strings.ToLower(v)
    }
    f.status.State = "active"
    f.status.UpdateInterval = f.updateInterval
    f.status.LastUpdate = time.Now()
    return nil
}

func (f *NVDFeed) FetchThreats(ctx context.Context, since time.Time) ([]ThreatIntelligence, error) {
    if f.mode != "real" {
        return f.fetchStub(since)
    }
    th, err := f.fetchStub(since)
    if err != nil || len(th) == 0 {
        return f.fetchStub(since)
    }
    return th, nil
}

func (f *NVDFeed) GetStatus() FeedStatus { return f.status }
func (f *NVDFeed) Close() error { f.status.State = "inactive"; return nil }

func (f *NVDFeed) fetchStub(since time.Time) ([]ThreatIntelligence, error) {
    data := []map[string]interface{}{
        {
            "cve": map[string]interface{}{
                "id": "CVE-2025-0001",
                "description": "Example buffer overflow in sample package",
                "published": time.Now().Add(-72 * time.Hour).Format(time.RFC3339),
                "severity": "HIGH",
                "package": map[string]interface{}{"name": "samplepkg", "ecosystem": "npm"},
                "references": []interface{}{"https://example.com/advisory/1"},
            },
        },
        {
            "cve": map[string]interface{}{
                "id": "CVE-2025-0002",
                "description": "Dependency confusion risk for org namespace",
                "published": time.Now().Add(-24 * time.Hour).Format(time.RFC3339),
                "severity": "MEDIUM",
                "package": map[string]interface{}{"name": "org-lib", "ecosystem": "pypi"},
                "references": []interface{}{"https://example.com/advisory/2"},
            },
        },
    }
    var threats []ThreatIntelligence
    for _, item := range data {
        if !f.validateStub(item) {
            continue
        }
        cve := item["cve"].(map[string]interface{})
        published, _ := time.Parse(time.RFC3339, cve["published"].(string))
        if !since.IsZero() && published.Before(since) {
            continue
        }
        pkg := cve["package"].(map[string]interface{})
        refs := cve["references"].([]interface{})
        r := make([]string, len(refs))
        for i := range refs { r[i] = fmt.Sprintf("%v", refs[i]) }
        sev := strings.ToLower(cve["severity"].(string))
        threats = append(threats, ThreatIntelligence{
            ID:              cve["id"].(string),
            Source:          "NVD",
            Type:            "vulnerability",
            Severity:        sev,
            PackageName:     fmt.Sprintf("%v", pkg["name"]),
            Ecosystem:       fmt.Sprintf("%v", pkg["ecosystem"]),
            Description:     fmt.Sprintf("%v", cve["description"]),
            References:      r,
            Tags:            []string{"nvd", "vulnerability"},
            ConfidenceLevel: 0.9,
            FirstSeen:       published,
            LastSeen:        time.Now(),
            Metadata:        map[string]interface{}{"schema": "stub"},
        })
    }
    f.status.LastUpdate = time.Now()
    f.status.ThreatCount = len(threats)
    f.status.State = "active"
    f.status.Healthy = true
    f.status.LastError = ""
    return threats, nil
}

func (f *NVDFeed) validateStub(item map[string]interface{}) bool {
    cveRaw, ok := item["cve"].(map[string]interface{})
    if !ok { return false }
    required := []string{"id", "description", "published", "severity", "package", "references"}
    for _, k := range required {
        if _, ok := cveRaw[k]; !ok { return false }
    }
    pkg, ok := cveRaw["package"].(map[string]interface{})
    if !ok { return false }
    if _, ok := pkg["name"]; !ok { return false }
    if _, ok := pkg["ecosystem"]; !ok { return false }
    refs, ok := cveRaw["references"].([]interface{})
    if !ok || len(refs) == 0 { return false }
    return true
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
    if f.logger != nil { f.logger.Info("Initializing GitHub Advisory threat feed") }

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

    if f.token == "" {
        if t := strings.TrimSpace(os.Getenv("GITHUB_TOKEN")); t != "" { f.token = t }
    }
    if r, ok := config["rps"].(int); ok && r > 0 { f.rateRPS = r }
    if ttl, ok := config["cache_ttl"].(time.Duration); ok && ttl > 0 { f.cacheTTL = ttl }

    return nil
}

// FetchThreats retrieves latest threats from GitHub Advisory
func (f *GitHubAdvisoryFeed) FetchThreats(ctx context.Context, since time.Time) ([]ThreatIntelligence, error) {
    if f.cacheThreats != nil && time.Since(f.cacheSince) < f.cacheTTL && (since.IsZero() || !f.cacheSince.Before(since)) {
        return f.cacheThreats, nil
    }
    minInterval := time.Second / time.Duration(func() int { if f.rateRPS < 1 { return 1 }; return f.rateRPS }())
    if time.Since(f.lastCall) < minInterval {
        time.Sleep(minInterval - time.Since(f.lastCall))
    }
    if f.logger != nil { f.logger.Debug("Fetching threats from GitHub Advisory feed", map[string]interface{}{
        "since": since,
    }) }
    return f.fetchGitHubPaged(ctx, since)
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

	// If no URL configured, return empty results
	if f.url == "" {
		f.logger.Debug("No URL configured for custom feed", map[string]interface{}{
			"name": f.name,
		})
		return []ThreatIntelligence{}, nil
	}

	// Create HTTP request
	req, err := http.NewRequestWithContext(ctx, "GET", f.url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Add API key if configured
	if f.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+f.apiKey)
	}

	// Add since parameter if supported
	if !since.IsZero() {
		q := req.URL.Query()
		q.Add("since", since.Format(time.RFC3339))
		req.URL.RawQuery = q.Encode()
	}

	// Make request
	resp, err := f.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch custom feed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("custom feed returned status %d", resp.StatusCode)
	}

	// Parse response based on content type
	contentType := resp.Header.Get("Content-Type")
	var threats []ThreatIntelligence

	if strings.Contains(contentType, "application/json") {
		threats, err = f.parseJSONFeed(resp.Body)
	} else if strings.Contains(contentType, "text/csv") {
		threats, err = f.parseCSVFeed(resp.Body)
	} else {
		// Default to JSON parsing
		threats, err = f.parseJSONFeed(resp.Body)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to parse custom feed: %w", err)
	}

	f.status.LastUpdate = time.Now()
	f.status.ThreatCount = len(threats)

	f.logger.Info("Successfully fetched custom feed threats", map[string]interface{}{
		"name":  f.name,
		"count": len(threats),
	})

	return threats, nil
}

// parseJSONFeed parses JSON format threat feed
func (f *CustomFeed) parseJSONFeed(body io.Reader) ([]ThreatIntelligence, error) {
	var data struct {
		Threats []map[string]interface{} `json:"threats"`
	}

	if err := json.NewDecoder(body).Decode(&data); err != nil {
		return nil, fmt.Errorf("failed to decode JSON: %w", err)
	}

	var threats []ThreatIntelligence
	for _, item := range data.Threats {
		threat := ThreatIntelligence{
			ID:              f.getStringValue(item, "id", ""),
			Source:          f.name,
			Type:            f.getStringValue(item, "type", "unknown"),
			Severity:        f.getStringValue(item, "severity", "medium"),
			PackageName:     f.getStringValue(item, "package_name", ""),
			Ecosystem:       f.getStringValue(item, "ecosystem", "unknown"),
			Description:     f.getStringValue(item, "description", ""),
			ConfidenceLevel: f.getFloatValue(item, "confidence", 0.5),
			FirstSeen:       f.getTimeValue(item, "first_seen", time.Now()),
			LastSeen:        f.getTimeValue(item, "last_seen", time.Now()),
			Metadata:        make(map[string]interface{}),
		}

		// Copy additional metadata
		for key, value := range item {
			if !isStandardField(key) {
				threat.Metadata[key] = value
			}
		}

		threats = append(threats, threat)
	}

	return threats, nil
}

// parseCSVFeed parses CSV format threat feed
func (f *CustomFeed) parseCSVFeed(body io.Reader) ([]ThreatIntelligence, error) {
	reader := csv.NewReader(body)
	records, err := reader.ReadAll()
	if err != nil {
		return nil, fmt.Errorf("failed to read CSV: %w", err)
	}

	if len(records) == 0 {
		return []ThreatIntelligence{}, nil
	}

	// First row should be headers
	headers := records[0]
	var threats []ThreatIntelligence

	for i := 1; i < len(records); i++ {
		record := records[i]
		if len(record) != len(headers) {
			continue // Skip malformed rows
		}

		// Create map from headers and values
		data := make(map[string]interface{})
		for j, header := range headers {
			data[header] = record[j]
		}

		threat := ThreatIntelligence{
			ID:              f.getStringValue(data, "id", ""),
			Source:          f.name,
			Type:            f.getStringValue(data, "type", "unknown"),
			Severity:        f.getStringValue(data, "severity", "medium"),
			PackageName:     f.getStringValue(data, "package_name", ""),
			Ecosystem:       f.getStringValue(data, "ecosystem", "unknown"),
			Description:     f.getStringValue(data, "description", ""),
			ConfidenceLevel: f.getFloatValue(data, "confidence", 0.5),
			FirstSeen:       f.getTimeValue(data, "first_seen", time.Now()),
			LastSeen:        f.getTimeValue(data, "last_seen", time.Now()),
			Metadata:        make(map[string]interface{}),
		}

		// Copy additional metadata
		for key, value := range data {
			if !isStandardField(key) {
				threat.Metadata[key] = value
			}
		}

		threats = append(threats, threat)
	}

	return threats, nil
}

// isStandardField checks if a field is a standard threat intelligence field
func isStandardField(field string) bool {
	standardFields := []string{
		"id", "type", "severity", "package_name", "ecosystem",
		"description", "confidence", "first_seen", "last_seen",
	}
	for _, std := range standardFields {
		if field == std {
			return true
		}
	}
	return false
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

// HTTP retry helper with exponential backoff
func doWithRetry(client *http.Client, req *http.Request, retries int) (*http.Response, error) {
    var resp *http.Response
    var err error
    backoff := 500 * time.Millisecond
    for i := 0; i <= retries; i++ {
        resp, err = client.Do(req)
        if err == nil && resp != nil {
            if resp.StatusCode == 429 || resp.StatusCode >= 500 {
                time.Sleep(backoff)
                backoff *= 2
                continue
            }
            return resp, nil
        }
        time.Sleep(backoff)
        backoff *= 2
    }
    return resp, err
}
func (f *GitHubAdvisoryFeed) fetchGitHubPaged(ctx context.Context, since time.Time) ([]ThreatIntelligence, error) {
    url := f.baseURL + "/graphql"
    query := `query($cursor: String){
        securityAdvisories(first: 100, after: $cursor, orderBy: {field: UPDATED_AT, direction: DESC}) {
            pageInfo { hasNextPage endCursor }
            nodes {
                ghsaId summary description severity updatedAt publishedAt
                vulnerabilities(first: 10) { nodes { package { name ecosystem } vulnerableVersionRange firstPatchedVersion { identifier } } }
            }
        }
    }`
    var threats []ThreatIntelligence
    cursor := ""
    for {
        reqBody := map[string]interface{}{ "query": query, "variables": map[string]interface{}{"cursor": func() interface{} { if cursor == "" { return nil }; return cursor }()}, }
        jsonData, err := json.Marshal(reqBody)
        if err != nil { return nil, fmt.Errorf("failed to marshal GraphQL query: %w", err) }
        req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(jsonData))
        if err != nil { return nil, fmt.Errorf("failed to create request: %w", err) }
        req.Header.Set("Content-Type", "application/json")
        req.Header.Set("User-Agent", "TypoSentinel/1.0")
        if f.token != "" { req.Header.Set("Authorization", "Bearer "+f.token) }
        client := &http.Client{Timeout: 30 * time.Second}
        resp, err := doWithRetry(client, req, 3)
        if err != nil { return nil, fmt.Errorf("failed to fetch GitHub advisories: %w", err) }
        defer resp.Body.Close()
        if resp.StatusCode != http.StatusOK { return nil, fmt.Errorf("GitHub API returned status %d", resp.StatusCode) }
        var response struct { Data struct { SecurityAdvisories struct { PageInfo struct { HasNextPage bool `json:"hasNextPage"`; EndCursor string `json:"endCursor"` } `json:"pageInfo"`; Nodes []struct { GhsaId string `json:"ghsaId"`; Summary string `json:"summary"`; Description string `json:"description"`; Severity string `json:"severity"`; UpdatedAt string `json:"updatedAt"`; PublishedAt string `json:"publishedAt"`; Vulnerabilities struct { Nodes []struct { Package struct { Name string `json:"name"`; Ecosystem string `json:"ecosystem"` } `json:"package"`; VulnerableVersionRange string `json:"vulnerableVersionRange"`; FirstPatchedVersion struct { Identifier string `json:"identifier"` } `json:"firstPatchedVersion"` } `json:"nodes"` } `json:"vulnerabilities"` } `json:"nodes"` } `json:"securityAdvisories"` } `json:"data"`; Errors []struct { Message string `json:"message"` } `json:"errors"` }
        if err := json.NewDecoder(resp.Body).Decode(&response); err != nil { return nil, fmt.Errorf("failed to decode GitHub API response: %w", err) }
        if len(response.Errors) > 0 { return nil, fmt.Errorf("GitHub API errors: %v", response.Errors) }
        for _, advisory := range response.Data.SecurityAdvisories.Nodes {
            updatedAt, err := time.Parse(time.RFC3339, advisory.UpdatedAt); if err != nil { continue }
            if updatedAt.Before(since) { continue }
            publishedAt, _ := time.Parse(time.RFC3339, advisory.PublishedAt)
            for _, vuln := range advisory.Vulnerabilities.Nodes {
                ecosystem := strings.ToLower(vuln.Package.Ecosystem)
                switch ecosystem { case "npm": ecosystem = "npm"; case "pip": ecosystem = "pypi"; case "rubygems": ecosystem = "rubygems"; case "nuget": ecosystem = "nuget"; case "maven": ecosystem = "maven"; case "go": ecosystem = "go"; default: ecosystem = "unknown" }
                threatType := "vulnerability"
                descLower := strings.ToLower(advisory.Description + " " + advisory.Summary)
                if strings.Contains(descLower, "typosquat") || strings.Contains(descLower, "malicious") { threatType = "typosquatting" } else if strings.Contains(descLower, "dependency confusion") { threatType = "dependency_confusion" }
                severity := strings.ToLower(advisory.Severity); if severity == "" { severity = "medium" }
                threats = append(threats, ThreatIntelligence{ ID: advisory.GhsaId, Source: "github_advisory", Type: threatType, Severity: severity, PackageName: vuln.Package.Name, Ecosystem: ecosystem, Description: advisory.Summary, ConfidenceLevel: 0.9, FirstSeen: publishedAt, LastSeen: updatedAt, Metadata: map[string]interface{}{ "vulnerable_range": vuln.VulnerableVersionRange, "patched_version": vuln.FirstPatchedVersion.Identifier, "full_description": advisory.Description } })
            }
        }
        pi := response.Data.SecurityAdvisories.PageInfo
        if !pi.HasNextPage || pi.EndCursor == "" { break }
        cursor = pi.EndCursor
    }
    f.status.LastUpdate = time.Now()
    f.status.ThreatCount = len(threats)
    if f.logger != nil { f.logger.Info("Successfully fetched GitHub Advisory threats", map[string]interface{}{"count": len(threats), "since": since}) }
    f.cacheThreats = threats
    f.cacheSince = time.Now()
    f.lastCall = time.Now()
    return threats, nil
}
