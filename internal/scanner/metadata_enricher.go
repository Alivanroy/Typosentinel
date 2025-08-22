package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/Alivanroy/Typosentinel/pkg/types"
)

// MetadataEnricher enriches package metadata by fetching information from registries
type MetadataEnricher struct {
	client *http.Client
}

// NewMetadataEnricher creates a new metadata enricher
func NewMetadataEnricher() *MetadataEnricher {
	return &MetadataEnricher{
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// EnrichPackages enriches package metadata by fetching from registries
func (e *MetadataEnricher) EnrichPackages(ctx context.Context, packages []*types.Package) error {
	for _, pkg := range packages {
		if err := e.enrichPackage(ctx, pkg); err != nil {
			// Log error but continue with other packages
			continue
		}
	}
	return nil
}

// enrichPackage enriches a single package's metadata
func (e *MetadataEnricher) enrichPackage(ctx context.Context, pkg *types.Package) error {
	switch pkg.Registry {
	case "npm":
		return e.enrichNPMPackage(ctx, pkg)
	case "pypi":
		return e.enrichPyPIPackage(ctx, pkg)
	default:
		return nil // Skip unknown registries
	}
}

// enrichNPMPackage enriches NPM package metadata
func (e *MetadataEnricher) enrichNPMPackage(ctx context.Context, pkg *types.Package) error {
	url := fmt.Sprintf("https://registry.npmjs.org/%s", pkg.Name)
	
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return err
	}
	
	resp, err := e.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("npm registry returned status %d", resp.StatusCode)
	}
	
	var npmData struct {
		Description string `json:"description"`
		Author      struct {
			Name  string `json:"name"`
			Email string `json:"email"`
		} `json:"author"`
		Maintainers []struct {
			Name  string `json:"name"`
			Email string `json:"email"`
		} `json:"maintainers"`
		Homepage   string `json:"homepage"`
		Repository struct {
			Type string `json:"type"`
			URL  string `json:"url"`
		} `json:"repository"`
		License interface{} `json:"license"`
		Time    struct {
			Created  string `json:"created"`
			Modified string `json:"modified"`
		} `json:"time"`
	}
	
	if err := json.NewDecoder(resp.Body).Decode(&npmData); err != nil {
		return err
	}
	
	// Initialize metadata if nil
	if pkg.Metadata == nil {
		pkg.Metadata = &types.PackageMetadata{}
	}
	
	// Update metadata with fetched information
	pkg.Metadata.Description = npmData.Description
	pkg.Metadata.Homepage = npmData.Homepage
	pkg.Metadata.Repository = npmData.Repository.URL
	
	// Handle license (can be string or object)
	if license, ok := npmData.License.(string); ok {
		pkg.Metadata.License = license
	} else if licenseObj, ok := npmData.License.(map[string]interface{}); ok {
		if licenseType, exists := licenseObj["type"]; exists {
			pkg.Metadata.License = fmt.Sprintf("%v", licenseType)
		}
	}
	
	// Parse creation time
	if npmData.Time.Created != "" {
		if createdTime, err := time.Parse(time.RFC3339, npmData.Time.Created); err == nil {
			pkg.Metadata.CreatedAt = createdTime
		}
	}
	
	// Parse modification time
	if npmData.Time.Modified != "" {
		if modifiedTime, err := time.Parse(time.RFC3339, npmData.Time.Modified); err == nil {
			pkg.Metadata.UpdatedAt = modifiedTime
		}
	}
	
	// Set maintainers
	var maintainers []string
	for _, maintainer := range npmData.Maintainers {
		if maintainer.Name != "" {
			maintainers = append(maintainers, maintainer.Name)
		}
	}
	pkg.Metadata.Maintainers = maintainers
	
	return nil
}

// enrichPyPIPackage enriches PyPI package metadata
func (e *MetadataEnricher) enrichPyPIPackage(ctx context.Context, pkg *types.Package) error {
	url := fmt.Sprintf("https://pypi.org/pypi/%s/json", pkg.Name)
	
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return err
	}
	
	resp, err := e.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("pypi registry returned status %d", resp.StatusCode)
	}
	
	var pypiData struct {
		Info struct {
			Description string `json:"description"`
			Summary     string `json:"summary"`
			Homepage    string `json:"home_page"`
			Author      string `json:"author"`
			License     string `json:"license"`
		} `json:"info"`
	}
	
	if err := json.NewDecoder(resp.Body).Decode(&pypiData); err != nil {
		return err
	}
	
	// Initialize metadata if nil
	if pkg.Metadata == nil {
		pkg.Metadata = &types.PackageMetadata{}
	}
	
	// Update metadata with fetched information
	if pypiData.Info.Description != "" {
		pkg.Metadata.Description = pypiData.Info.Description
	} else if pypiData.Info.Summary != "" {
		pkg.Metadata.Description = pypiData.Info.Summary
	}
	
	pkg.Metadata.Homepage = pypiData.Info.Homepage
	pkg.Metadata.License = pypiData.Info.License
	
	if pypiData.Info.Author != "" {
		pkg.Metadata.Maintainers = []string{pypiData.Info.Author}
	}
	
	return nil
}