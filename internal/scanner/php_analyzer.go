package scanner

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/Alivanroy/Typosentinel/internal/config"
	"github.com/Alivanroy/Typosentinel/pkg/types"
)

// PHPPackageAnalyzer analyzes PHP projects
type PHPPackageAnalyzer struct {
	config *config.Config
}

// NewPHPPackageAnalyzer creates a new PHP analyzer
func NewPHPPackageAnalyzer(cfg *config.Config) *PHPPackageAnalyzer {
	return &PHPPackageAnalyzer{
		config: cfg,
	}
}

// ComposerJSON represents the structure of composer.json
type ComposerJSON struct {
	Name             string                 `json:"name"`
	Version          string                 `json:"version"`
	Description      string                 `json:"description"`
	Type             string                 `json:"type"`
	Keywords         []string               `json:"keywords"`
	Homepage         string                 `json:"homepage"`
	License          interface{}            `json:"license"`
	Authors          []ComposerAuthor       `json:"authors"`
	Require          map[string]string      `json:"require"`
	RequireDev       map[string]string      `json:"require-dev"`
	Suggest          map[string]string      `json:"suggest"`
	Provide          map[string]string      `json:"provide"`
	Conflict         map[string]string      `json:"conflict"`
	Replace          map[string]string      `json:"replace"`
	Autoload         ComposerAutoload       `json:"autoload"`
	AutoloadDev      ComposerAutoload       `json:"autoload-dev"`
	Repositories     []ComposerRepository   `json:"repositories"`
	Config           map[string]interface{} `json:"config"`
	Scripts          map[string]interface{} `json:"scripts"`
	Extra            map[string]interface{} `json:"extra"`
	MinimumStability string                 `json:"minimum-stability"`
	PreferStable     bool                   `json:"prefer-stable"`
}

type ComposerAuthor struct {
	Name     string `json:"name"`
	Email    string `json:"email"`
	Homepage string `json:"homepage"`
	Role     string `json:"role"`
}

type ComposerAutoload struct {
	Psr4                map[string]interface{} `json:"psr-4"`
	Psr0                map[string]interface{} `json:"psr-0"`
	Classmap            []string               `json:"classmap"`
	Files               []string               `json:"files"`
	ExcludeFromClassmap []string               `json:"exclude-from-classmap"`
}

type ComposerRepository struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}

// ComposerLock represents the structure of composer.lock
type ComposerLock struct {
	Readme           []string               `json:"_readme"`
	ContentHash      string                 `json:"content-hash"`
	Packages         []ComposerLockPackage  `json:"packages"`
	PackagesDev      []ComposerLockPackage  `json:"packages-dev"`
	Aliases          []interface{}          `json:"aliases"`
	MinimumStability string                 `json:"minimum-stability"`
	StabilityFlags   map[string]interface{} `json:"stability-flags"`
	PreferStable     bool                   `json:"prefer-stable"`
	PreferLowest     bool                   `json:"prefer-lowest"`
	Platform         map[string]string      `json:"platform"`
	PlatformDev      map[string]string      `json:"platform-dev"`
	PluginAPIVersion string                 `json:"plugin-api-version"`
}

type ComposerLockPackage struct {
	Name            string            `json:"name"`
	Version         string            `json:"version"`
	Source          ComposerSource    `json:"source"`
	Dist            ComposerDist      `json:"dist"`
	Require         map[string]string `json:"require"`
	RequireDev      map[string]string `json:"require-dev"`
	Conflict        map[string]string `json:"conflict"`
	Replace         map[string]string `json:"replace"`
	Provide         map[string]string `json:"provide"`
	Suggest         map[string]string `json:"suggest"`
	Type            string            `json:"type"`
	Autoload        ComposerAutoload  `json:"autoload"`
	NotificationURL string            `json:"notification-url"`
	License         []string          `json:"license"`
	Authors         []ComposerAuthor  `json:"authors"`
	Description     string            `json:"description"`
	Homepage        string            `json:"homepage"`
	Keywords        []string          `json:"keywords"`
	Support         map[string]string `json:"support"`
	Time            string            `json:"time"`
}

type ComposerSource struct {
	Type      string `json:"type"`
	URL       string `json:"url"`
	Reference string `json:"reference"`
}

type ComposerDist struct {
	Type      string `json:"type"`
	URL       string `json:"url"`
	Reference string `json:"reference"`
	Shasum    string `json:"shasum"`
}

func (a *PHPPackageAnalyzer) ExtractPackages(projectInfo *ProjectInfo) ([]*types.Package, error) {
	var packages []*types.Package

	// Parse composer.json for dependency information
	composerJSONPath := filepath.Join(projectInfo.Path, "composer.json")
	if _, err := os.Stat(composerJSONPath); err == nil {
		jsonPackages, err := a.parseComposerJSON(composerJSONPath)
		if err != nil {
			return nil, fmt.Errorf("failed to parse composer.json: %w", err)
		}
		packages = append(packages, jsonPackages...)
	}

	// Parse composer.lock for exact versions
	composerLockPath := filepath.Join(projectInfo.Path, "composer.lock")
	if _, err := os.Stat(composerLockPath); err == nil {
		lockPackages, err := a.parseComposerLock(composerLockPath)
		if err != nil {
			return nil, fmt.Errorf("failed to parse composer.lock: %w", err)
		}
		// Merge lock file information with composer.json packages
		packages = a.mergeLockInfo(packages, lockPackages)
	}

	return packages, nil
}

func (a *PHPPackageAnalyzer) parseComposerJSON(filePath string) ([]*types.Package, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	var composerData ComposerJSON
	if err := json.Unmarshal(data, &composerData); err != nil {
		return nil, fmt.Errorf("failed to parse composer.json: %w", err)
	}

	var packages []*types.Package

	// Parse production dependencies
	for name, version := range composerData.Require {
		// Skip PHP platform requirements
		if strings.HasPrefix(name, "php") || strings.HasPrefix(name, "ext-") {
			continue
		}

		pkg := &types.Package{
			Name:     name,
			Version:  version,
			Registry: "packagist.org",
			Type:     "production",
			Metadata: &types.PackageMetadata{
				Name:     name,
				Version:  version,
				Registry: "packagist.org",
				Metadata: map[string]interface{}{
					"ecosystem": "php",
					"source":    "composer.json",
				},
			},
		}
		packages = append(packages, pkg)
	}

	// Parse development dependencies
	for name, version := range composerData.RequireDev {
		// Skip PHP platform requirements
		if strings.HasPrefix(name, "php") || strings.HasPrefix(name, "ext-") {
			continue
		}

		pkg := &types.Package{
			Name:     name,
			Version:  version,
			Registry: "packagist.org",
			Type:     "development",
			Metadata: &types.PackageMetadata{
				Name:     name,
				Version:  version,
				Registry: "packagist.org",
				Metadata: map[string]interface{}{
					"ecosystem": "php",
					"source":    "composer.json",
				},
			},
		}
		packages = append(packages, pkg)
	}

	return packages, nil
}

func (a *PHPPackageAnalyzer) parseComposerLock(filePath string) (map[string]*types.Package, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	var lockData ComposerLock
	if err := json.Unmarshal(data, &lockData); err != nil {
		return nil, fmt.Errorf("failed to parse composer.lock: %w", err)
	}

	packages := make(map[string]*types.Package)

	// Parse production packages
	for _, lockPkg := range lockData.Packages {
		pkg := &types.Package{
			Name:     lockPkg.Name,
			Version:  lockPkg.Version,
			Registry: "packagist.org",
			Type:     "production",
			Metadata: &types.PackageMetadata{
				Name:     lockPkg.Name,
				Version:  lockPkg.Version,
				Registry: "packagist.org",
				Metadata: map[string]interface{}{
					"ecosystem":   "php",
					"source":      "composer.lock",
					"description": lockPkg.Description,
					"homepage":    lockPkg.Homepage,
					"license":     lockPkg.License,
					"authors":     lockPkg.Authors,
					"keywords":    lockPkg.Keywords,
					"time":        lockPkg.Time,
					"source_url":  lockPkg.Source.URL,
					"source_ref":  lockPkg.Source.Reference,
					"dist_url":    lockPkg.Dist.URL,
					"dist_shasum": lockPkg.Dist.Shasum,
				},
			},
		}
		packages[lockPkg.Name] = pkg
	}

	// Parse development packages
	for _, lockPkg := range lockData.PackagesDev {
		pkg := &types.Package{
			Name:     lockPkg.Name,
			Version:  lockPkg.Version,
			Registry: "packagist.org",
			Type:     "development",
			Metadata: &types.PackageMetadata{
				Name:     lockPkg.Name,
				Version:  lockPkg.Version,
				Registry: "packagist.org",
				Metadata: map[string]interface{}{
					"ecosystem":   "php",
					"source":      "composer.lock",
					"description": lockPkg.Description,
					"homepage":    lockPkg.Homepage,
					"license":     lockPkg.License,
					"authors":     lockPkg.Authors,
					"keywords":    lockPkg.Keywords,
					"time":        lockPkg.Time,
					"source_url":  lockPkg.Source.URL,
					"source_ref":  lockPkg.Source.Reference,
					"dist_url":    lockPkg.Dist.URL,
					"dist_shasum": lockPkg.Dist.Shasum,
				},
			},
		}
		packages[lockPkg.Name] = pkg
	}

	return packages, nil
}

func (a *PHPPackageAnalyzer) mergeLockInfo(jsonPackages []*types.Package, lockPackages map[string]*types.Package) []*types.Package {
	// Update composer.json packages with exact versions from lock file
	for _, pkg := range jsonPackages {
		if lockPkg, exists := lockPackages[pkg.Name]; exists {
			pkg.Version = lockPkg.Version
			if pkg.Metadata == nil {
				pkg.Metadata = &types.PackageMetadata{
					Name:     pkg.Name,
					Version:  pkg.Version,
					Registry: pkg.Registry,
					Metadata: make(map[string]interface{}),
				}
			}
			// Merge metadata from lock file
			for key, value := range lockPkg.Metadata.Metadata {
				pkg.Metadata.Metadata[key] = value
			}
			pkg.Metadata.Metadata["exact_version"] = lockPkg.Version
		}
	}

	// Add any packages from lock file that weren't in composer.json (transitive dependencies)
	jsonPackageNames := make(map[string]bool)
	for _, pkg := range jsonPackages {
		jsonPackageNames[pkg.Name] = true
	}

	for name, lockPkg := range lockPackages {
		if !jsonPackageNames[name] {
			lockPkg.Type = "transitive"
			jsonPackages = append(jsonPackages, lockPkg)
		}
	}

	return jsonPackages
}

func (a *PHPPackageAnalyzer) AnalyzeDependencies(projectInfo *ProjectInfo) (*types.DependencyTree, error) {
	packages, err := a.ExtractPackages(projectInfo)
	if err != nil {
		return nil, err
	}

	projectName := "php-project"
	projectVersion := "1.0.0"

	// Try to get project name and version from composer.json
	composerJSONPath := filepath.Join(projectInfo.Path, "composer.json")
	if _, err := os.Stat(composerJSONPath); err == nil {
		if name, version := a.extractProjectInfo(composerJSONPath); name != "" {
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

func (a *PHPPackageAnalyzer) extractProjectInfo(composerJSONPath string) (string, string) {
	data, err := os.ReadFile(composerJSONPath)
	if err != nil {
		return "", ""
	}

	var composerData ComposerJSON
	if err := json.Unmarshal(data, &composerData); err != nil {
		return "", ""
	}

	return composerData.Name, composerData.Version
}
