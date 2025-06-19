package registry

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"typosentinel/pkg/types"
)

func TestNewPyPIClient(t *testing.T) {
	client := NewPyPIClient()
	if client == nil {
		t.Fatal("Expected non-nil client")
	}
	if client.baseURL != "https://pypi.org/pypi" {
		t.Errorf("Expected baseURL to be https://pypi.org/pypi, got %s", client.baseURL)
	}
	if client.client.Timeout != 30*time.Second {
		t.Errorf("Expected timeout to be 30s, got %v", client.client.Timeout)
	}
}

func TestGetPackageInfo_Success(t *testing.T) {
	// Create mock response
	mockResponse := PyPIPackageInfo{
		Info: struct {
			Name        string            `json:"name"`
			Version     string            `json:"version"`
			Summary     string            `json:"summary"`
			Description string            `json:"description"`
			Author      string            `json:"author"`
			AuthorEmail string            `json:"author_email"`
			Maintainer  string            `json:"maintainer"`
			HomePage    string            `json:"home_page"`
			License     string            `json:"license"`
			Keywords    string            `json:"keywords"`
			Classifiers []string          `json:"classifiers"`
			ProjectURLs map[string]string `json:"project_urls"`
		}{
			Name:        "requests",
			Version:     "2.28.1",
			Summary:     "Python HTTP for Humans.",
			Author:      "Kenneth Reitz",
			AuthorEmail: "me@kennethreitz.org",
			License:     "Apache 2.0",
			HomePage:    "https://requests.readthedocs.io",
			Classifiers: []string{"Development Status :: 5 - Production/Stable"},
		},
	}

	// Create test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/requests/json" {
			t.Errorf("Expected path /requests/json, got %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(mockResponse)
	}))
	defer server.Close()

	// Create client with test server URL
	client := &PyPIClient{
		client:  &http.Client{Timeout: 30 * time.Second},
		baseURL: server.URL,
	}

	// Test GetPackageInfo
	packageInfo, err := client.GetPackageInfo("requests")
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if packageInfo.Info.Name != "requests" {
		t.Errorf("Expected name 'requests', got %s", packageInfo.Info.Name)
	}
	if packageInfo.Info.Version != "2.28.1" {
		t.Errorf("Expected version '2.28.1', got %s", packageInfo.Info.Version)
	}
	if packageInfo.Info.Author != "Kenneth Reitz" {
		t.Errorf("Expected author 'Kenneth Reitz', got %s", packageInfo.Info.Author)
	}
}

func TestGetPackageInfo_NotFound(t *testing.T) {
	// Create test server that returns 404
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	// Create client with test server URL
	client := &PyPIClient{
		client:  &http.Client{Timeout: 30 * time.Second},
		baseURL: server.URL,
	}

	// Test GetPackageInfo with non-existent package
	_, err := client.GetPackageInfo("nonexistent-package")
	if err == nil {
		t.Fatal("Expected error for non-existent package")
	}
	if err.Error() != "package not found: nonexistent-package" {
		t.Errorf("Expected 'package not found' error, got %v", err)
	}
}

func TestGetPackageVersion_Success(t *testing.T) {
	// Create mock response
	mockResponse := PyPIPackageInfo{
		Info: struct {
			Name        string            `json:"name"`
			Version     string            `json:"version"`
			Summary     string            `json:"summary"`
			Description string            `json:"description"`
			Author      string            `json:"author"`
			AuthorEmail string            `json:"author_email"`
			Maintainer  string            `json:"maintainer"`
			HomePage    string            `json:"home_page"`
			License     string            `json:"license"`
			Keywords    string            `json:"keywords"`
			Classifiers []string          `json:"classifiers"`
			ProjectURLs map[string]string `json:"project_urls"`
		}{
			Name:    "requests",
			Version: "2.25.1",
			Summary: "Python HTTP for Humans.",
			Author:  "Kenneth Reitz",
		},
	}

	// Create test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/requests/2.25.1/json" {
			t.Errorf("Expected path /requests/2.25.1/json, got %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(mockResponse)
	}))
	defer server.Close()

	// Create client with test server URL
	client := &PyPIClient{
		client:  &http.Client{Timeout: 30 * time.Second},
		baseURL: server.URL,
	}

	// Test GetPackageVersion
	packageInfo, err := client.GetPackageVersion("requests", "2.25.1")
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if packageInfo.Info.Version != "2.25.1" {
		t.Errorf("Expected version '2.25.1', got %s", packageInfo.Info.Version)
	}
}

func TestEnrichPackage_Success(t *testing.T) {
	// Create mock response
	mockResponse := PyPIPackageInfo{
		Info: struct {
			Name        string            `json:"name"`
			Version     string            `json:"version"`
			Summary     string            `json:"summary"`
			Description string            `json:"description"`
			Author      string            `json:"author"`
			AuthorEmail string            `json:"author_email"`
			Maintainer  string            `json:"maintainer"`
			HomePage    string            `json:"home_page"`
			License     string            `json:"license"`
			Keywords    string            `json:"keywords"`
			Classifiers []string          `json:"classifiers"`
			ProjectURLs map[string]string `json:"project_urls"`
		}{
			Name:        "requests",
			Version:     "2.28.1",
			Summary:     "Python HTTP for Humans.",
			Author:      "Kenneth Reitz",
			AuthorEmail: "me@kennethreitz.org",
			License:     "Apache 2.0",
			HomePage:    "https://requests.readthedocs.io",
			Keywords:    "http,requests",
			Classifiers: []string{"Development Status :: 5 - Production/Stable"},
			ProjectURLs: map[string]string{"Homepage": "https://requests.readthedocs.io"},
		},
		URLs: []PyPIRelease{
			{
				Filename:    "requests-2.28.1-py3-none-any.whl",
				PackageType: "bdist_wheel",
				UploadTime:  time.Now(),
			},
		},
		Releases: map[string][]PyPIRelease{
			"2.28.1": {},
			"2.28.0": {},
		},
	}

	// Create test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(mockResponse)
	}))
	defer server.Close()

	// Create client with test server URL
	client := &PyPIClient{
		client:  &http.Client{Timeout: 30 * time.Second},
		baseURL: server.URL,
	}

	// Create test package
	pkg := &types.Package{
		Name:     "requests",
		Version:  "2.28.1",
		Registry: "pypi",
		Type:     "production",
	}

	// Test EnrichPackage
	err := client.EnrichPackage(pkg)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	// Verify enrichment
	if pkg.Description != "Python HTTP for Humans." {
		t.Errorf("Expected description 'Python HTTP for Humans.', got %s", pkg.Description)
	}
	if pkg.Author != "Kenneth Reitz" {
		t.Errorf("Expected author 'Kenneth Reitz', got %s", pkg.Author)
	}
	if pkg.License != "Apache 2.0" {
		t.Errorf("Expected license 'Apache 2.0', got %s", pkg.License)
	}
	if pkg.Homepage != "https://requests.readthedocs.io" {
		t.Errorf("Expected homepage 'https://requests.readthedocs.io', got %s", pkg.Homepage)
	}

	// Verify metadata
	if pkg.Metadata == nil {
		t.Fatal("Expected metadata to be set")
	}
	if pkg.Metadata["author_email"] != "me@kennethreitz.org" {
		t.Errorf("Expected author_email 'me@kennethreitz.org', got %v", pkg.Metadata["author_email"])
	}
	if pkg.Metadata["keywords"] != "http,requests" {
		t.Errorf("Expected keywords 'http,requests', got %v", pkg.Metadata["keywords"])
	}
	if pkg.Metadata["available_versions"] != 2 {
		t.Errorf("Expected 2 available versions, got %v", pkg.Metadata["available_versions"])
	}
}

func TestEnrichPackage_WithWildcardVersion(t *testing.T) {
	// Create mock response
	mockResponse := PyPIPackageInfo{
		Info: struct {
			Name        string            `json:"name"`
			Version     string            `json:"version"`
			Summary     string            `json:"summary"`
			Description string            `json:"description"`
			Author      string            `json:"author"`
			AuthorEmail string            `json:"author_email"`
			Maintainer  string            `json:"maintainer"`
			HomePage    string            `json:"home_page"`
			License     string            `json:"license"`
			Keywords    string            `json:"keywords"`
			Classifiers []string          `json:"classifiers"`
			ProjectURLs map[string]string `json:"project_urls"`
		}{
			Name:    "numpy",
			Version: "1.24.0",
			Summary: "Fundamental package for array computing",
			Author:  "NumPy Developers",
		},
	}

	// Create test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/numpy/json" {
			t.Errorf("Expected path /numpy/json, got %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(mockResponse)
	}))
	defer server.Close()

	// Create client with test server URL
	client := &PyPIClient{
		client:  &http.Client{Timeout: 30 * time.Second},
		baseURL: server.URL,
	}

	// Create test package with wildcard version
	pkg := &types.Package{
		Name:     "numpy",
		Version:  "*",
		Registry: "pypi",
		Type:     "production",
	}

	// Test EnrichPackage
	err := client.EnrichPackage(pkg)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	// Verify enrichment
	if pkg.Description != "Fundamental package for array computing" {
		t.Errorf("Expected description 'Fundamental package for array computing', got %s", pkg.Description)
	}
}

func TestGetPopularPackages(t *testing.T) {
	client := NewPyPIClient()

	// Test without limit
	packages, err := client.GetPopularPackages(0)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if len(packages) == 0 {
		t.Error("Expected some popular packages")
	}

	// Test with limit
	packages, err = client.GetPopularPackages(5)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if len(packages) != 5 {
		t.Errorf("Expected 5 packages, got %d", len(packages))
	}

	// Verify some expected packages are in the list
	expected := []string{"requests", "numpy", "pandas"}
	allPackages, _ := client.GetPopularPackages(0)
	for _, exp := range expected {
		found := false
		for _, pkg := range allPackages {
			if pkg == exp {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected to find %s in popular packages", exp)
		}
	}
}