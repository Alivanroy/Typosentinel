package scanner

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/Alivanroy/Typosentinel/pkg/types"
	"github.com/sirupsen/logrus"
)

// RegistryMetadataFetcher fetches package metadata from registries
type RegistryMetadataFetcher struct {
	client      *http.Client
	cacheExpiry time.Duration
	cache       map[string]*RegistryMetadata
}

// RegistryMetadata contains package metadata from the registry
type RegistryMetadata struct {
	Name          string
	Version       string
	CreatedAt     time.Time
	UpdatedAt     time.Time
	DownloadCount int64
	Author        string
	AuthorEmail   string
	Maintainers   []string
	Description   string
	Repository    string
	Homepage      string
	License       string
	Dependencies  map[string]string
	FetchedAt     time.Time
}

// NPMRegistryResponse represents the npm registry API response
type NPMRegistryResponse struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Time        struct {
		Created  string `json:"created"`
		Modified string `json:"modified"`
	} `json:"time"`
	Versions map[string]struct {
		Name         string            `json:"name"`
		Version      string            `json:"version"`
		Description  string            `json:"description"`
		Dependencies map[string]string `json:"dependencies,omitempty"`
		Author       struct {
			Name  string `json:"name"`
			Email string `json:"email,omitempty"`
		} `json:"author,omitempty"`
		Repository struct {
			Type string `json:"type"`
			URL  string `json:"url"`
		} `json:"repository,omitempty"`
		Homepage string `json:"homepage,omitempty"`
		License  string `json:"license,omitempty"`
	} `json:"versions"`
	Maintainers []struct {
		Name  string `json:"name"`
		Email string `json:"email,omitempty"`
	} `json:"maintainers,omitempty"`
}

// NewRegistryMetadataFetcher creates a new metadata fetcher
func NewRegistryMetadataFetcher() *RegistryMetadataFetcher {
	return &RegistryMetadataFetcher{
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
		cacheExpiry: 24 * time.Hour,
		cache:       make(map[string]*RegistryMetadata),
	}
}

// FetchNPMMetadata fetches metadata for an npm package
func (f *RegistryMetadataFetcher) FetchNPMMetadata(packageName string, version string) (*RegistryMetadata, error) {
	// Check cache first
	cacheKey := fmt.Sprintf("npm:%s@%s", packageName, version)
	if cached, ok := f.cache[cacheKey]; ok {
		if time.Since(cached.FetchedAt) < f.cacheExpiry {
			logrus.Debugf("Cache hit for package metadata: %s", cacheKey)
			return cached, nil
		}
	}

	// Fetch from npm registry
	url := fmt.Sprintf("https://registry.npmjs.org/%s", packageName)
	resp, err := f.client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch metadata: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("registry returned status %d", resp.StatusCode)
	}

	var npmResp NPMRegistryResponse
	if err := json.NewDecoder(resp.Body).Decode(&npmResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	// Extract metadata
	metadata := &RegistryMetadata{
		Name:        npmResp.Name,
		Version:     version,
		Description: npmResp.Description,
		FetchedAt:   time.Now(),
	}

	// Parse creation time
	if created, err := time.Parse(time.RFC3339, npmResp.Time.Created); err == nil {
		metadata.CreatedAt = created
	}

	// Parse update time
	if modified, err := time.Parse(time.RFC3339, npmResp.Time.Modified); err == nil {
		metadata.UpdatedAt = modified
	}

	// Get version-specific data
	if versionData, ok := npmResp.Versions[version]; ok {
		metadata.Dependencies = versionData.Dependencies
		metadata.Author = versionData.Author.Name
		metadata.AuthorEmail = versionData.Author.Email
		metadata.Repository = versionData.Repository.URL
		metadata.Homepage = versionData.Homepage
		metadata.License = versionData.License
	}

	// Get maintainers
	for _, m := range npmResp.Maintainers {
		metadata.Maintainers = append(metadata.Maintainers, m.Name)
	}

	// Note: Download count requires a separate API call to npm download stats
	// We'll implement this as a separate feature to avoid rate limiting
	metadata.DownloadCount = -1 // -1 indicates not fetched

	// Cache the result
	f.cache[cacheKey] = metadata
	logrus.Debugf("Fetched and cached metadata for: %s", cacheKey)

	return metadata, nil
}

// AnalyzePackageAge analyzes package age and creates threats if suspicious
func (f *RegistryMetadataFetcher) AnalyzePackageAge(pkg *types.Package, metadata *RegistryMetadata) []types.Threat {
	var threats []types.Threat

	if metadata.CreatedAt.IsZero() {
		return threats
	}

	packageAge := time.Since(metadata.CreatedAt)
	ageDays := int(packageAge.Hours() / 24)

	// Thresholds for suspicious packages
	const (
		criticalAgeDays = 7  // Less than 1 week
		highAgeDays     = 30 // Less than 1 month
		mediumAgeDays   = 90 // Less than 3 months
	)

	var severity types.Severity
	var description string

	if ageDays < criticalAgeDays {
		severity = types.SeverityCritical
		description = fmt.Sprintf("Package is extremely new (%d days old). New packages are high-risk for typosquatting and malware.", ageDays)
	} else if ageDays < highAgeDays {
		severity = types.SeverityHigh
		description = fmt.Sprintf("Package is very new (%d days old). Exercise caution with recently published packages.", ageDays)
	} else if ageDays < mediumAgeDays {
		severity = types.SeverityMedium
		description = fmt.Sprintf("Package is relatively new (%d days old). Verify legitimacy before use.", ageDays)
	} else {
		// Package is old enough, no threat
		return threats
	}

	threat := types.Threat{
		Package:         pkg.Name,
		Version:         pkg.Version,
		Registry:        "npm",
		Type:            types.ThreatTypeNewPackage,
		Severity:        severity,
		Confidence:      0.85,
		Description:     description,
		DetectionMethod: "package_age_analysis",
		Recommendation:  "Verify package legitimacy, check maintainer reputation, and review package code before installation. New packages are statistically higher risk.",
		Evidence: []types.Evidence{
			{
				Type:        "package_age",
				Description: "Package creation date",
				Value:       metadata.CreatedAt.Format("2006-01-02"),
			},
			{
				Type:        "age_days",
				Description: "Days since creation",
				Value:       fmt.Sprintf("%d", ageDays),
			},
		},
		DetectedAt: time.Now(),
	}

	threats = append(threats, threat)
	return threats
}

// AnalyzeDownloadCount analyzes download counts (stub for future implementation)
func (f *RegistryMetadataFetcher) AnalyzeDownloadCount(pkg *types.Package, metadata *RegistryMetadata) []types.Threat {
	var threats []types.Threat

	// This would require calling npm download stats API
	// Stubbed for now to avoid rate limiting issues
	// Implementation: https://api.npmjs.org/downloads/point/last-month/package-name

	return threats
}
