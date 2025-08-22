package registry

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/Alivanroy/Typosentinel/pkg/types"
)

// MavenClient handles interactions with Maven Central repository
type MavenClient struct {
	baseURL    string
	httpClient *http.Client
	cache      map[string]*CacheEntry
	cacheTTL   time.Duration
}

// MavenSearchResponse represents Maven Central search API response
type MavenSearchResponse struct {
	Response struct {
		NumFound int `json:"numFound"`
		Start    int `json:"start"`
		Docs     []struct {
			ID           string   `json:"id"`
			GroupID      string   `json:"g"`
			ArtifactID   string   `json:"a"`
			Version      string   `json:"v"`
			Packaging    string   `json:"p"`
			Timestamp    int64    `json:"timestamp"`
			VersionCount int      `json:"versionCount"`
			Text         []string `json:"text"`
		} `json:"docs"`
	} `json:"response"`
}

// MavenMetadata represents Maven artifact metadata
type MavenMetadata struct {
	XMLName    xml.Name `xml:"metadata"`
	GroupID    string   `xml:"groupId"`
	ArtifactID string   `xml:"artifactId"`
	Versioning struct {
		Latest   string `xml:"latest"`
		Release  string `xml:"release"`
		Versions struct {
			Version []string `xml:"version"`
		} `xml:"versions"`
		LastUpdated string `xml:"lastUpdated"`
	} `xml:"versioning"`
}

// MavenPOM represents Maven POM file structure
type MavenPOM struct {
	XMLName     xml.Name `xml:"project"`
	GroupID     string   `xml:"groupId"`
	ArtifactID  string   `xml:"artifactId"`
	Version     string   `xml:"version"`
	Packaging   string   `xml:"packaging"`
	Name        string   `xml:"name"`
	Description string   `xml:"description"`
	URL         string   `xml:"url"`
	Licenses    struct {
		License []struct {
			Name string `xml:"name"`
			URL  string `xml:"url"`
		} `xml:"license"`
	} `xml:"licenses"`
	Developers struct {
		Developer []struct {
			ID    string `xml:"id"`
			Name  string `xml:"name"`
			Email string `xml:"email"`
		} `xml:"developer"`
	} `xml:"developers"`
}

// NewMavenClient creates a new Maven client
func NewMavenClient() *MavenClient {
	return &MavenClient{
		baseURL: "https://search.maven.org",
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		cache:    make(map[string]*CacheEntry),
		cacheTTL: 5 * time.Minute,
	}
}

// GetPackageInfo retrieves package information from Maven Central
func (c *MavenClient) GetPackageInfo(ctx context.Context, groupID, artifactID, version string) (*types.PackageMetadata, error) {
	cacheKey := fmt.Sprintf("%s:%s:%s", groupID, artifactID, version)
	
	// Check cache first
	if entry, exists := c.cache[cacheKey]; exists {
		if time.Since(entry.Timestamp) < c.cacheTTL {
			if metadata, ok := entry.Data.(*types.PackageMetadata); ok {
				return metadata, nil
			}
		}
	}

	// Construct POM URL
	pomURL := fmt.Sprintf("https://repo1.maven.org/maven2/%s/%s/%s/%s-%s.pom",
		strings.ReplaceAll(groupID, ".", "/"),
		artifactID,
		version,
		artifactID,
		version)

	req, err := http.NewRequestWithContext(ctx, "GET", pomURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch POM: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("POM not found: %s", resp.Status)
	}

	var pom MavenPOM
	if err := xml.NewDecoder(resp.Body).Decode(&pom); err != nil {
		return nil, fmt.Errorf("failed to parse POM: %w", err)
	}

	// Convert to PackageMetadata
	metadata := &types.PackageMetadata{
		Name:        fmt.Sprintf("%s:%s", groupID, artifactID),
		Version:     version,
		Description: pom.Description,
		Homepage:    pom.URL,
		Registry:    "maven",
		Author:      "", // Maven doesn't have a single author field
		License:     "", // Will be populated from licenses
		Keywords:    []string{},
		Dependencies: []string{},
		Maintainers: []string{},
		Downloads:   0, // Maven Central doesn't provide download stats easily
		LastUpdated: &[]time.Time{time.Now()}[0], // Use current time as approximation
	}

	// Extract license information
	if len(pom.Licenses.License) > 0 {
		metadata.License = pom.Licenses.License[0].Name
	}

	// Extract maintainer information
	for _, dev := range pom.Developers.Developer {
		if dev.Name != "" {
			metadata.Maintainers = append(metadata.Maintainers, dev.Name)
		}
	}

	// Cache the result
	c.cache[cacheKey] = &CacheEntry{
		Data:      metadata,
		Timestamp: time.Now(),
	}

	return metadata, nil
}

// SearchPackages searches for packages in Maven Central
func (c *MavenClient) SearchPackages(ctx context.Context, query string) ([]*types.PackageMetadata, error) {
	// Construct search URL
	searchURL := fmt.Sprintf("%s/solrsearch/select?q=%s&rows=20&wt=json",
		c.baseURL, url.QueryEscape(query))

	req, err := http.NewRequestWithContext(ctx, "GET", searchURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create search request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to search packages: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("search failed: %s", resp.Status)
	}

	var searchResp MavenSearchResponse
	if err := json.NewDecoder(resp.Body).Decode(&searchResp); err != nil {
		return nil, fmt.Errorf("failed to parse search response: %w", err)
	}

	var packages []*types.PackageMetadata
	for _, doc := range searchResp.Response.Docs {
		pkg := &types.PackageMetadata{
			Name:        fmt.Sprintf("%s:%s", doc.GroupID, doc.ArtifactID),
			Version:     doc.Version,
			Description: "", // Search API doesn't provide description
			Registry:    "maven",
			Homepage:    "",
			Author:      "",
			License:     "",
			Keywords:    []string{},
			Dependencies: []string{},
			Maintainers: []string{},
			Downloads:   0,
			LastUpdated: &[]time.Time{time.Unix(doc.Timestamp/1000, 0)}[0],
		}
		packages = append(packages, pkg)
	}

	return packages, nil
}

// GetPopularPackages returns a list of popular Maven packages
func (c *MavenClient) GetPopularPackages(limit int) ([]string, error) {
	// Return a curated list of popular Maven packages
	popularPackages := []string{
		"org.springframework:spring-core",
		"org.springframework:spring-boot-starter",
		"junit:junit",
		"org.apache.commons:commons-lang3",
		"com.google.guava:guava",
		"org.slf4j:slf4j-api",
		"ch.qos.logback:logback-classic",
		"com.fasterxml.jackson.core:jackson-core",
		"org.apache.httpcomponents:httpclient",
		"org.hibernate:hibernate-core",
		"org.mockito:mockito-core",
		"org.apache.maven.plugins:maven-compiler-plugin",
		"org.springframework.boot:spring-boot-starter-web",
		"org.springframework.boot:spring-boot-starter-data-jpa",
		"mysql:mysql-connector-java",
		"org.postgresql:postgresql",
		"redis.clients:jedis",
		"org.apache.kafka:kafka-clients",
		"com.amazonaws:aws-java-sdk",
		"org.elasticsearch.client:elasticsearch-rest-high-level-client",
	}

	if limit > 0 && limit < len(popularPackages) {
		return popularPackages[:limit], nil
	}
	return popularPackages, nil
}

// ClearCache clears the client cache
func (c *MavenClient) ClearCache() {
	c.cache = make(map[string]*CacheEntry)
}

// SetCacheTTL sets the cache TTL
func (c *MavenClient) SetCacheTTL(ttl time.Duration) {
	c.cacheTTL = ttl
}