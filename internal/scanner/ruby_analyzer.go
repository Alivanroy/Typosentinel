package scanner

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"typosentinel/internal/config"
	"typosentinel/pkg/types"
)

// RubyPackageAnalyzer analyzes Ruby projects with enhanced Bundler integration
type RubyPackageAnalyzer struct {
	*BaseAnalyzer
	config     *config.Config
	httpClient *http.Client
	apiURL     string
}

// NewRubyPackageAnalyzer creates a new Ruby analyzer with RubyGems API integration
func NewRubyPackageAnalyzer(cfg *config.Config) *RubyPackageAnalyzer {
	metadata := &AnalyzerMetadata{
		Name:        "ruby",
		Version:     "1.0.0",
		Description: "Analyzes Ruby projects using Gemfile, Gemfile.lock, and .gemspec files with RubyGems API integration",
		Author:      "TypoSentinel",
		Languages:   []string{"ruby"},
		Capabilities: []string{"dependency_extraction", "bundler_integration", "rubygems_api", "gemspec_parsing", "lock_file_parsing"},
		Requirements: []string{"Gemfile"},
	}
	
	baseAnalyzer := NewBaseAnalyzer(
		"ruby",
		[]string{".rb", ".gemspec"},
		[]string{"Gemfile", "Gemfile.lock", "*.gemspec"},
		metadata,
		cfg,
	)
	
	return &RubyPackageAnalyzer{
		BaseAnalyzer: baseAnalyzer,
		config: cfg,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		apiURL: "https://rubygems.org/api/v1",
	}
}

// GemfileLock represents the structure of Gemfile.lock
type GemfileLock struct {
	Gems []GemLockEntry `json:"gems"`
}

type GemLockEntry struct {
	Name         string   `json:"name"`
	Version      string   `json:"version"`
	Dependencies []string `json:"dependencies"`
	Source       string   `json:"source"`
}

// GemSpec represents basic gem specification
type GemSpec struct {
	Name         string            `json:"name"`
	Version      string            `json:"version"`
	Description  string            `json:"description"`
	Authors      []string          `json:"authors"`
	Dependencies map[string]string `json:"dependencies"`
}

// RubyGemsAPIResponse represents the response from RubyGems API
type RubyGemsAPIResponse struct {
	Name            string    `json:"name"`
	Version         string    `json:"version"`
	Authors         string    `json:"authors"`
	Info            string    `json:"info"`
	Licenses        []string  `json:"licenses"`
	Metadata        map[string]interface{} `json:"metadata"`
	SHA             string    `json:"sha"`
	ProjectURI      string    `json:"project_uri"`
	GemURI          string    `json:"gem_uri"`
	HomepageURI     string    `json:"homepage_uri"`
	WikiURI         string    `json:"wiki_uri"`
	DocumentationURI string   `json:"documentation_uri"`
	MailingListURI  string    `json:"mailing_list_uri"`
	SourceCodeURI   string    `json:"source_code_uri"`
	BugTrackerURI   string    `json:"bug_tracker_uri"`
	ChangelogURI    string    `json:"changelog_uri"`
	Dependencies    struct {
		Development []RubyGemDependency `json:"development"`
		Runtime     []RubyGemDependency `json:"runtime"`
	} `json:"dependencies"`
	BuiltAt         time.Time `json:"built_at"`
	CreatedAt       time.Time `json:"created_at"`
	Description     string    `json:"description"`
	Downloads       int       `json:"downloads"`
	Number          string    `json:"number"`
	Summary         string    `json:"summary"`
	Platform        string    `json:"platform"`
	RubyVersion     string    `json:"ruby_version"`
	Prerelease      bool      `json:"prerelease"`
	Requirements    []string  `json:"requirements"`
}

// RubyGemDependency represents a gem dependency
type RubyGemDependency struct {
	Name         string `json:"name"`
	Requirements string `json:"requirements"`
}

// BundlerLockInfo represents parsed Bundler lock information
type BundlerLockInfo struct {
	BundlerVersion string
	RubyVersion    string
	Gems           map[string]*BundlerGemInfo
	Platforms      []string
	Sources        []string
}

// BundlerGemInfo represents gem information from Bundler
type BundlerGemInfo struct {
	Name         string
	Version      string
	Dependencies []string
	Source       string
	Platforms    []string
}

func (a *RubyPackageAnalyzer) ExtractPackages(projectInfo *ProjectInfo) ([]*types.Package, error) {
	var packages []*types.Package

	// Parse Gemfile for dependency information
	gemfilePath := filepath.Join(projectInfo.Path, "Gemfile")
	if _, err := os.Stat(gemfilePath); err == nil {
		gemfilePackages, err := a.parseGemfile(gemfilePath)
		if err != nil {
			return nil, fmt.Errorf("failed to parse Gemfile: %w", err)
		}
		packages = append(packages, gemfilePackages...)
	}

	// Parse Gemfile.lock for exact versions using enhanced parser
	gemfileLockPath := filepath.Join(projectInfo.Path, "Gemfile.lock")
	var lockInfo *BundlerLockInfo
	if _, err := os.Stat(gemfileLockPath); err == nil {
		lockInfo, err = a.parseBundlerLockEnhanced(gemfileLockPath)
		if err != nil {
			return nil, fmt.Errorf("failed to parse Gemfile.lock: %w", err)
		}
	}

	// Parse .gemspec files if present
	gemspecFiles, err := filepath.Glob(filepath.Join(projectInfo.Path, "*.gemspec"))
	if err == nil && len(gemspecFiles) > 0 {
		for _, gemspecFile := range gemspecFiles {
			gemspecPackages, err := a.parseGemspec(gemspecFile)
			if err != nil {
				continue // Skip invalid gemspec files
			}
			packages = append(packages, gemspecPackages...)
		}
	}

	// Enhance packages with lock file information
	if lockInfo != nil {
		packages = a.enhanceWithLockInfo(packages, lockInfo)
	}

	// Enhance packages with RubyGems API information (if enabled)
	if a.config != nil && a.config.Scanner.EnrichMetadata {
		for _, pkg := range packages {
			if err := a.enhancePackageWithAPIInfo(pkg); err != nil {
				// Log error but don't fail the entire analysis
				fmt.Printf("Warning: failed to enhance package %s with API info: %v\n", pkg.Name, err)
			}
		}
	}

	return packages, nil
}

func (a *RubyPackageAnalyzer) parseGemfile(filePath string) ([]*types.Package, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var packages []*types.Package
	scanner := bufio.NewScanner(file)
	currentGroup := "production"

	// Regex patterns for parsing Gemfile
	gemRegex := regexp.MustCompile(`^\s*gem\s+['"]([^'"]+)['"](?:\s*,\s*['"]([^'"]+)['"])?`)
	groupRegex := regexp.MustCompile(`^\s*group\s+:([a-zA-Z_]+)`)
	endRegex := regexp.MustCompile(`^\s*end\s*$`)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip comments and empty lines
		if strings.HasPrefix(line, "#") || line == "" {
			continue
		}

		// Check for group declarations
		if matches := groupRegex.FindStringSubmatch(line); len(matches) >= 2 {
			currentGroup = matches[1]
			if currentGroup == "development" || currentGroup == "test" {
				currentGroup = "development"
			} else {
				currentGroup = "production"
			}
			continue
		}

		// Check for end of group
		if endRegex.MatchString(line) {
			currentGroup = "production"
			continue
		}

		// Parse gem declarations
		if matches := gemRegex.FindStringSubmatch(line); len(matches) >= 2 {
			name := matches[1]
			version := "*"
			if len(matches) >= 3 && matches[2] != "" {
				version = matches[2]
			}

			pkg := &types.Package{
				Name:     name,
				Version:  version,
				Registry: "rubygems.org",
				Type:     currentGroup,
				Metadata: &types.PackageMetadata{
					Name:     name,
					Version:  version,
					Registry: "rubygems.org",
					Metadata: map[string]interface{}{
						"ecosystem": "ruby",
						"source":    "Gemfile",
					},
				},
			}
			packages = append(packages, pkg)
		}
	}

	return packages, nil
}

func (a *RubyPackageAnalyzer) parseGemfileLock(filePath string) (map[string]*types.Package, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	packages := make(map[string]*types.Package)
	scanner := bufio.NewScanner(file)
	inSpecsSection := false

	// Regex for parsing gem entries in Gemfile.lock
	gemRegex := regexp.MustCompile(`^\s{4}([a-zA-Z0-9_-]+)\s+\(([^)]+)\)`)
	depRegex := regexp.MustCompile(`^\s{6}([a-zA-Z0-9_-]+)`)

	var currentGem *types.Package

	for scanner.Scan() {
		line := scanner.Text()

		// Check for specs section
		if strings.Contains(line, "specs:") {
			inSpecsSection = true
			continue
		}

		// Exit specs section
		if inSpecsSection && strings.HasPrefix(line, "PLATFORMS") {
			inSpecsSection = false
			continue
		}

		if !inSpecsSection {
			continue
		}

		// Parse gem entries
		if matches := gemRegex.FindStringSubmatch(line); len(matches) >= 3 {
			name := matches[1]
			version := matches[2]

			currentGem = &types.Package{
				Name:     name,
				Version:  version,
				Registry: "rubygems.org",
				Type:     "production",
				Metadata: &types.PackageMetadata{
					Name:     name,
					Version:  version,
					Registry: "rubygems.org",
					Metadata: map[string]interface{}{
						"ecosystem":    "ruby",
						"source":       "Gemfile.lock",
						"dependencies": []string{},
					},
				},
			}
			packages[name] = currentGem
			continue
		}

		// Parse dependencies
		if currentGem != nil {
			if matches := depRegex.FindStringSubmatch(line); len(matches) >= 2 {
				depName := matches[1]
				if deps, ok := currentGem.Metadata.Metadata["dependencies"].([]string); ok {
				currentGem.Metadata.Metadata["dependencies"] = append(deps, depName)
			}
			}
		}
	}

	return packages, nil
}

func (a *RubyPackageAnalyzer) parseGemspec(filePath string) ([]*types.Package, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	content := string(data)
	var packages []*types.Package

	// Parse add_dependency and add_development_dependency calls
	depRegex := regexp.MustCompile(`s\.add_(?:(development_|runtime_))?dependency\s+['"]([^'"]+)['"](?:\s*,\s*['"]([^'"]+)['"])?`)
	matches := depRegex.FindAllStringSubmatch(content, -1)

	for _, match := range matches {
		if len(match) >= 3 {
			depType := "production"
			if match[1] == "development_" {
				depType = "development"
			}

			name := match[2]
			version := "*"
			if len(match) >= 4 && match[3] != "" {
				version = match[3]
			}

			pkg := &types.Package{
				Name:     name,
				Version:  version,
				Registry: "rubygems.org",
				Type:     depType,
				Metadata: &types.PackageMetadata{
					Name:     name,
					Version:  version,
					Registry: "rubygems.org",
					Metadata: map[string]interface{}{
						"ecosystem": "ruby",
						"source":    "gemspec",
					},
				},
			}
			packages = append(packages, pkg)
		}
	}

	return packages, nil
}

func (a *RubyPackageAnalyzer) enhanceWithLockInfo(gemfilePackages []*types.Package, lockInfo *BundlerLockInfo) []*types.Package {
	// Update Gemfile packages with exact versions from lock file
	for _, pkg := range gemfilePackages {
		if lockGem, exists := lockInfo.Gems[pkg.Name]; exists {
			pkg.Version = lockGem.Version
			if pkg.Metadata == nil {
				pkg.Metadata = &types.PackageMetadata{
					Name:     pkg.Name,
					Version:  pkg.Version,
					Registry: pkg.Registry,
					Metadata: make(map[string]interface{}),
				}
			}
			pkg.Metadata.Metadata["exact_version"] = lockGem.Version
			pkg.Metadata.Metadata["dependencies"] = lockGem.Dependencies
			pkg.Metadata.Metadata["source"] = lockGem.Source
			pkg.Metadata.Metadata["platforms"] = lockGem.Platforms
			pkg.Metadata.Metadata["bundler_version"] = lockInfo.BundlerVersion
			pkg.Metadata.Metadata["ruby_version"] = lockInfo.RubyVersion
		}
	}

	// Add any packages from lock file that weren't in Gemfile (transitive dependencies)
	gemfilePackageNames := make(map[string]bool)
	for _, pkg := range gemfilePackages {
		gemfilePackageNames[pkg.Name] = true
	}

	for name, lockGem := range lockInfo.Gems {
		if !gemfilePackageNames[name] {
			transitivePkg := &types.Package{
				Name:     name,
				Version:  lockGem.Version,
				Registry: "rubygems.org",
				Type:     "transitive",
				Metadata: &types.PackageMetadata{
					Name:     name,
					Version:  lockGem.Version,
					Registry: "rubygems.org",
					Metadata: map[string]interface{}{
						"ecosystem":       "ruby",
						"source":          "Gemfile.lock",
						"dependencies":    lockGem.Dependencies,
						"platforms":       lockGem.Platforms,
						"bundler_version": lockInfo.BundlerVersion,
						"ruby_version":    lockInfo.RubyVersion,
					},
				},
			}
			gemfilePackages = append(gemfilePackages, transitivePkg)
		}
	}

	return gemfilePackages
}

// fetchGemInfo fetches gem information from RubyGems API
func (a *RubyPackageAnalyzer) fetchGemInfo(name, version string) (*RubyGemsAPIResponse, error) {
	url := fmt.Sprintf("%s/gems/%s.json", a.apiURL, name)
	if version != "" && version != "*" {
		url = fmt.Sprintf("%s/versions/%s.json", url, version)
	}

	resp, err := a.httpClient.Get(url)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch gem info for %s: %w", name, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("RubyGems API returned status %d for gem %s", resp.StatusCode, name)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	var gemInfo RubyGemsAPIResponse
	if err := json.Unmarshal(body, &gemInfo); err != nil {
		return nil, fmt.Errorf("failed to parse gem info: %w", err)
	}

	return &gemInfo, nil
}

// enhancePackageWithAPIInfo enhances package information with RubyGems API data
func (a *RubyPackageAnalyzer) enhancePackageWithAPIInfo(pkg *types.Package) error {
	gemInfo, err := a.fetchGemInfo(pkg.Name, pkg.Version)
	if err != nil {
		// Don't fail the entire analysis if API call fails
		return nil
	}

	if pkg.Metadata == nil {
		pkg.Metadata = &types.PackageMetadata{
			Name:     pkg.Name,
			Version:  pkg.Version,
			Registry: pkg.Registry,
			Metadata: make(map[string]interface{}),
		}
	}

	// Enhance metadata with API information
	pkg.Metadata.Metadata["description"] = gemInfo.Description
	pkg.Metadata.Metadata["summary"] = gemInfo.Summary
	pkg.Metadata.Metadata["authors"] = gemInfo.Authors
	pkg.Metadata.Metadata["licenses"] = gemInfo.Licenses
	pkg.Metadata.Metadata["homepage_uri"] = gemInfo.HomepageURI
	pkg.Metadata.Metadata["source_code_uri"] = gemInfo.SourceCodeURI
	pkg.Metadata.Metadata["bug_tracker_uri"] = gemInfo.BugTrackerURI
	pkg.Metadata.Metadata["documentation_uri"] = gemInfo.DocumentationURI
	pkg.Metadata.Metadata["downloads"] = gemInfo.Downloads
	pkg.Metadata.Metadata["built_at"] = gemInfo.BuiltAt
	pkg.Metadata.Metadata["created_at"] = gemInfo.CreatedAt
	pkg.Metadata.Metadata["sha"] = gemInfo.SHA
	pkg.Metadata.Metadata["platform"] = gemInfo.Platform
	pkg.Metadata.Metadata["ruby_version"] = gemInfo.RubyVersion
	pkg.Metadata.Metadata["prerelease"] = gemInfo.Prerelease
	pkg.Metadata.Metadata["requirements"] = gemInfo.Requirements

	// Add dependency information
	var allDeps []string
	for _, dep := range gemInfo.Dependencies.Runtime {
		allDeps = append(allDeps, dep.Name)
	}
	for _, dep := range gemInfo.Dependencies.Development {
		allDeps = append(allDeps, dep.Name)
	}
	pkg.Metadata.Metadata["api_dependencies"] = allDeps

	return nil
}

// parseBundlerLockEnhanced provides enhanced parsing of Gemfile.lock with more details
func (a *RubyPackageAnalyzer) parseBundlerLockEnhanced(filePath string) (*BundlerLockInfo, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	lockInfo := &BundlerLockInfo{
		Gems: make(map[string]*BundlerGemInfo),
	}

	scanner := bufio.NewScanner(file)
	currentSection := ""
	var currentGem *BundlerGemInfo

	// Regex patterns
	gemRegex := regexp.MustCompile(`^\s{4}([a-zA-Z0-9_-]+)\s+\(([^)]+)\)`)
	depRegex := regexp.MustCompile(`^\s{6}([a-zA-Z0-9_-]+)`)
	bundlerVersionRegex := regexp.MustCompile(`^BUNDLED WITH\s*$`)
	rubyVersionRegex := regexp.MustCompile(`^RUBY VERSION\s*$`)
	platformRegex := regexp.MustCompile(`^PLATFORMS\s*$`)
	sourceRegex := regexp.MustCompile(`^\s{2}remote:\s+(.+)$`)

	for scanner.Scan() {
		line := scanner.Text()

		// Detect sections
		if strings.Contains(line, "GEM") {
			currentSection = "GEM"
			continue
		} else if strings.Contains(line, "specs:") {
			currentSection = "specs"
			continue
		} else if platformRegex.MatchString(line) {
			currentSection = "PLATFORMS"
			continue
		} else if strings.Contains(line, "DEPENDENCIES") {
			currentSection = "DEPENDENCIES"
			continue
		} else if rubyVersionRegex.MatchString(line) {
			currentSection = "RUBY VERSION"
			continue
		} else if bundlerVersionRegex.MatchString(line) {
			currentSection = "BUNDLED WITH"
			continue
		}

		switch currentSection {
		case "GEM":
			if matches := sourceRegex.FindStringSubmatch(line); len(matches) >= 2 {
				lockInfo.Sources = append(lockInfo.Sources, matches[1])
			}
		case "specs":
			if matches := gemRegex.FindStringSubmatch(line); len(matches) >= 3 {
				name := matches[1]
				version := matches[2]
				currentGem = &BundlerGemInfo{
					Name:    name,
					Version: version,
				}
				lockInfo.Gems[name] = currentGem
			} else if currentGem != nil {
				if matches := depRegex.FindStringSubmatch(line); len(matches) >= 2 {
					currentGem.Dependencies = append(currentGem.Dependencies, matches[1])
				}
			}
		case "PLATFORMS":
			platform := strings.TrimSpace(line)
			if platform != "" {
				lockInfo.Platforms = append(lockInfo.Platforms, platform)
			}
		case "RUBY VERSION":
			if strings.Contains(line, "ruby") {
				lockInfo.RubyVersion = strings.TrimSpace(line)
			}
		case "BUNDLED WITH":
			version := strings.TrimSpace(line)
			if version != "" && version != "BUNDLED WITH" {
				lockInfo.BundlerVersion = version
			}
		}
	}

	return lockInfo, nil
}

func (a *RubyPackageAnalyzer) AnalyzeDependencies(projectInfo *ProjectInfo) (*types.DependencyTree, error) {
	packages, err := a.ExtractPackages(projectInfo)
	if err != nil {
		return nil, err
	}

	projectName := "ruby-project"
	projectVersion := "1.0.0"

	// Try to get project name and version from gemspec
	gemspecFiles, err := filepath.Glob(filepath.Join(projectInfo.Path, "*.gemspec"))
	if err == nil && len(gemspecFiles) > 0 {
		if name, version := a.extractProjectInfo(gemspecFiles[0]); name != "" {
			projectName = name
			if version != "" {
				projectVersion = version
			}
		}
	}

	root := &types.DependencyTree{
		Name:         projectName,
		Version:      projectVersion,
		Type:         "root",
		Dependencies: make([]types.DependencyTree, 0),
	}

	for _, pkg := range packages {
		dep := types.DependencyTree{
			Name:         pkg.Name,
			Version:      pkg.Version,
			Type:         pkg.Type,
			Threats:      pkg.Threats,
			Dependencies: make([]types.DependencyTree, 0),
		}
		root.Dependencies = append(root.Dependencies, dep)
	}

	return root, nil
}

func (a *RubyPackageAnalyzer) extractProjectInfo(gemspecPath string) (string, string) {
	data, err := os.ReadFile(gemspecPath)
	if err != nil {
		return "", ""
	}

	content := string(data)

	// Extract name and version from gemspec
	nameRegex := regexp.MustCompile(`s\.name\s*=\s*['"]([^'"]+)['"]`)
	versionRegex := regexp.MustCompile(`s\.version\s*=\s*['"]([^'"]+)['"]`)

	var name, version string

	if matches := nameRegex.FindStringSubmatch(content); len(matches) >= 2 {
		name = matches[1]
	}

	if matches := versionRegex.FindStringSubmatch(content); len(matches) >= 2 {
		version = matches[1]
	}

	return name, version
}