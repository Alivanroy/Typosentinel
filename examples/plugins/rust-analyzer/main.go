package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/Alivanroy/Typosentinel/internal/scanner"
	"github.com/Alivanroy/Typosentinel/pkg/types"
)

// NewAnalyzer is the plugin entry point required by TypoSentinel
func NewAnalyzer() scanner.LanguageAnalyzer {
	return &RustAnalyzer{}
}

// RustAnalyzer implements the LanguageAnalyzer interface for Rust/Cargo projects
type RustAnalyzer struct {
	logger scanner.Logger
}

// CargoToml represents the structure of a Cargo.toml file
type CargoToml struct {
	Package      CargoPackage        `toml:"package"`
	Dependencies map[string]CargoDep `toml:"dependencies"`
	DevDeps      map[string]CargoDep `toml:"dev-dependencies"`
	BuildDeps    map[string]CargoDep `toml:"build-dependencies"`
	Workspace    *CargoWorkspace     `toml:"workspace"`
}

// CargoPackage represents the [package] section
type CargoPackage struct {
	Name        string   `toml:"name"`
	Version     string   `toml:"version"`
	Authors     []string `toml:"authors"`
	Edition     string   `toml:"edition"`
	Description string   `toml:"description"`
	License     string   `toml:"license"`
	Repository  string   `toml:"repository"`
}

// CargoDep represents a dependency entry
type CargoDep struct {
	Version  string   `toml:"version"`
	Path     string   `toml:"path"`
	Git      string   `toml:"git"`
	Branch   string   `toml:"branch"`
	Tag      string   `toml:"tag"`
	Rev      string   `toml:"rev"`
	Registry string   `toml:"registry"`
	Features []string `toml:"features"`
	Optional bool     `toml:"optional"`
	Default  bool     `toml:"default-features"`
}

// CargoWorkspace represents workspace configuration
type CargoWorkspace struct {
	Members []string `toml:"members"`
}

// CargoLock represents Cargo.lock structure
type CargoLock struct {
	Version  int                `json:"version"`
	Packages []CargoLockPackage `json:"package"`
}

// CargoLockPackage represents a package in Cargo.lock
type CargoLockPackage struct {
	Name         string   `json:"name"`
	Version      string   `json:"version"`
	Source       string   `json:"source"`
	Checksum     string   `json:"checksum"`
	Dependencies []string `json:"dependencies"`
}

// GetMetadata returns metadata about the Rust analyzer
func (r *RustAnalyzer) GetMetadata() *scanner.AnalyzerMetadata {
	return &scanner.AnalyzerMetadata{
		Name:                "rust-cargo",
		Version:             "1.0.0",
		Author:              "TypoSentinel Team",
		Description:         "Analyzer for Rust projects using Cargo package manager",
		SupportedExtensions: []string{".rs"},
		ManifestFiles:       []string{"Cargo.toml"},
		LockFiles:           []string{"Cargo.lock"},
		Registries:          []string{"crates.io"},
	}
}

// CanAnalyze determines if this analyzer can handle the given project
func (r *RustAnalyzer) CanAnalyze(projectInfo *scanner.ProjectInfo) bool {
	// Check if it's explicitly marked as a Rust project
	if projectInfo.Type == "rust" || projectInfo.Type == "cargo" {
		return true
	}

	// Check for Cargo.toml file
	cargoTomlPath := filepath.Join(projectInfo.Path, "Cargo.toml")
	if _, err := os.Stat(cargoTomlPath); err == nil {
		return true
	}

	// Check for .rs files in the project
	return r.hasRustFiles(projectInfo.Path)
}

// AnalyzeProject analyzes a Rust project and returns dependency information
func (r *RustAnalyzer) AnalyzeProject(ctx *scanner.AnalyzerContext) (*scanner.AnalysisResult, error) {
	r.logger = ctx.Logger
	r.logger.Info("Starting Rust project analysis", "path", ctx.ProjectInfo.Path)

	// Extract dependencies
	packages, err := r.ExtractDependencies(ctx.ProjectInfo)
	if err != nil {
		return nil, fmt.Errorf("failed to extract dependencies: %w", err)
	}

	// Analyze workspace if present
	workspacePackages, err := r.analyzeWorkspace(ctx.ProjectInfo)
	if err != nil {
		r.logger.Warn("Failed to analyze workspace", "error", err)
	} else {
		packages = append(packages, workspacePackages...)
	}

	// Build metadata
	metadata := map[string]interface{}{
		"analyzer":     "rust-cargo",
		"project_type": "rust",
		"has_lockfile": r.hasLockFile(ctx.ProjectInfo.Path),
	}

	// Add Cargo.toml metadata if available
	if cargoMeta, err := r.extractCargoMetadata(ctx.ProjectInfo.Path); err == nil {
		metadata["cargo_metadata"] = cargoMeta
	}

	r.logger.Info("Rust analysis completed", "packages_found", len(packages))

	return &scanner.AnalysisResult{
		Packages:     packages,
		ProjectType:  "rust",
		AnalyzerName: "rust-cargo",
		Metadata:     metadata,
	}, nil
}

// ExtractDependencies extracts dependencies from Cargo.toml and Cargo.lock
func (r *RustAnalyzer) ExtractDependencies(projectInfo *scanner.ProjectInfo) ([]*types.Package, error) {
	var packages []*types.Package

	// Parse Cargo.toml
	cargoTomlPath := filepath.Join(projectInfo.Path, "Cargo.toml")
	tomlPackages, err := r.parseCargoToml(cargoTomlPath)
	if err != nil {
		return nil, fmt.Errorf("failed to parse Cargo.toml: %w", err)
	}
	packages = append(packages, tomlPackages...)

	// Parse Cargo.lock if available
	cargoLockPath := filepath.Join(projectInfo.Path, "Cargo.lock")
	if _, err := os.Stat(cargoLockPath); err == nil {
		lockPackages, err := r.parseCargoLock(cargoLockPath)
		if err != nil {
			r.logger.Warn("Failed to parse Cargo.lock", "error", err)
		} else {
			// Merge lock file information with TOML packages
			packages = r.mergeLockFileInfo(packages, lockPackages)
		}
	}

	return packages, nil
}

// ValidateProject validates Rust project structure and files
func (r *RustAnalyzer) ValidateProject(projectInfo *scanner.ProjectInfo) error {
	cargoTomlPath := filepath.Join(projectInfo.Path, "Cargo.toml")

	// Check if Cargo.toml exists
	if _, err := os.Stat(cargoTomlPath); os.IsNotExist(err) {
		return fmt.Errorf("Cargo.toml not found in project root")
	}

	// Validate Cargo.toml syntax
	if err := r.validateCargoToml(cargoTomlPath); err != nil {
		return fmt.Errorf("invalid Cargo.toml: %w", err)
	}

	// Check for src directory or main.rs
	srcDir := filepath.Join(projectInfo.Path, "src")
	mainRs := filepath.Join(projectInfo.Path, "src", "main.rs")
	libRs := filepath.Join(projectInfo.Path, "src", "lib.rs")

	if _, err := os.Stat(srcDir); os.IsNotExist(err) {
		return fmt.Errorf("src directory not found")
	}

	if _, err := os.Stat(mainRs); os.IsNotExist(err) {
		if _, err := os.Stat(libRs); os.IsNotExist(err) {
			return fmt.Errorf("neither main.rs nor lib.rs found in src directory")
		}
	}

	return nil
}

// parseCargoToml parses a Cargo.toml file and extracts dependencies
func (r *RustAnalyzer) parseCargoToml(cargoTomlPath string) ([]*types.Package, error) {
	data, err := ioutil.ReadFile(cargoTomlPath)
	if err != nil {
		return nil, err
	}

	// For this example, we'll use a simple parser
	// In a real implementation, you'd use a TOML library like github.com/BurntSushi/toml
	var packages []*types.Package
	lines := strings.Split(string(data), "\n")
	inDependencies := false

	for _, line := range lines {
		line = strings.TrimSpace(line)

		if line == "[dependencies]" {
			inDependencies = true
			continue
		}

		if strings.HasPrefix(line, "[") && line != "[dependencies]" {
			inDependencies = false
			continue
		}

		if inDependencies && strings.Contains(line, "=") {
			parts := strings.SplitN(line, "=", 2)
			if len(parts) == 2 {
				name := strings.TrimSpace(parts[0])
				versionPart := strings.TrimSpace(parts[1])
				version := strings.Trim(versionPart, `"'`)

				pkg := &types.Package{
					Name:     name,
					Version:  version,
					Registry: "crates.io",
					Type:     "rust",
					Metadata: map[string]interface{}{
						"source": "Cargo.toml",
					},
				}
				packages = append(packages, pkg)
			}
		}
	}

	return packages, nil
}

// parseCargoLock parses a Cargo.lock file
func (r *RustAnalyzer) parseCargoLock(cargoLockPath string) ([]*types.Package, error) {
	data, err := ioutil.ReadFile(cargoLockPath)
	if err != nil {
		return nil, err
	}

	// Try to parse as JSON first (newer Cargo.lock format)
	var cargoLock CargoLock
	if err := json.Unmarshal(data, &cargoLock); err == nil {
		return r.convertLockPackages(cargoLock.Packages), nil
	}

	// Fall back to TOML parsing for older format
	return r.parseCargoLockTOML(string(data))
}

// convertLockPackages converts CargoLockPackage to types.Package
func (r *RustAnalyzer) convertLockPackages(lockPackages []CargoLockPackage) []*types.Package {
	var packages []*types.Package

	for _, lockPkg := range lockPackages {
		pkg := &types.Package{
			Name:     lockPkg.Name,
			Version:  lockPkg.Version,
			Registry: "crates.io",
			Type:     "rust",
			Metadata: map[string]interface{}{
				"source":   "Cargo.lock",
				"checksum": lockPkg.Checksum,
			},
		}

		if lockPkg.Source != "" {
			pkg.Metadata["lock_source"] = lockPkg.Source
		}

		packages = append(packages, pkg)
	}

	return packages
}

// parseCargoLockTOML parses TOML format Cargo.lock
func (r *RustAnalyzer) parseCargoLockTOML(content string) ([]*types.Package, error) {
	// Simplified TOML parsing for Cargo.lock
	// In a real implementation, use a proper TOML library
	var packages []*types.Package
	lines := strings.Split(content, "\n")
	inPackage := false
	var currentPkg *types.Package

	for _, line := range lines {
		line = strings.TrimSpace(line)

		if line == "[[package]]" {
			if currentPkg != nil {
				packages = append(packages, currentPkg)
			}
			currentPkg = &types.Package{
				Registry: "crates.io",
				Type:     "rust",
				Metadata: map[string]interface{}{
					"source": "Cargo.lock",
				},
			}
			inPackage = true
			continue
		}

		if inPackage && strings.Contains(line, "=") {
			parts := strings.SplitN(line, "=", 2)
			if len(parts) == 2 {
				key := strings.TrimSpace(parts[0])
				value := strings.Trim(strings.TrimSpace(parts[1]), `"'`)

				switch key {
				case "name":
					currentPkg.Name = value
				case "version":
					currentPkg.Version = value
				case "source":
					currentPkg.Metadata["lock_source"] = value
				case "checksum":
					currentPkg.Metadata["checksum"] = value
				}
			}
		}
	}

	// Add the last package
	if currentPkg != nil {
		packages = append(packages, currentPkg)
	}

	return packages, nil
}

// mergeLockFileInfo merges information from Cargo.lock into Cargo.toml packages
func (r *RustAnalyzer) mergeLockFileInfo(tomlPackages, lockPackages []*types.Package) []*types.Package {
	// Create a map of lock packages for quick lookup
	lockMap := make(map[string]*types.Package)
	for _, lockPkg := range lockPackages {
		lockMap[lockPkg.Name] = lockPkg
	}

	// Update TOML packages with lock file information
	for _, tomlPkg := range tomlPackages {
		if lockPkg, exists := lockMap[tomlPkg.Name]; exists {
			// Use exact version from lock file
			tomlPkg.Version = lockPkg.Version
			// Merge metadata
			for key, value := range lockPkg.Metadata {
				tomlPkg.Metadata[key] = value
			}
			// Remove from lock map to avoid duplicates
			delete(lockMap, tomlPkg.Name)
		}
	}

	// Add remaining lock packages (transitive dependencies)
	for _, lockPkg := range lockMap {
		lockPkg.Metadata["transitive"] = true
		tomlPackages = append(tomlPackages, lockPkg)
	}

	return tomlPackages
}

// analyzeWorkspace analyzes workspace members
func (r *RustAnalyzer) analyzeWorkspace(projectInfo *scanner.ProjectInfo) ([]*types.Package, error) {
	cargoTomlPath := filepath.Join(projectInfo.Path, "Cargo.toml")
	data, err := ioutil.ReadFile(cargoTomlPath)
	if err != nil {
		return nil, err
	}

	// Check if this is a workspace
	if !strings.Contains(string(data), "[workspace]") {
		return nil, nil
	}

	// Parse workspace members (simplified)
	var packages []*types.Package
	lines := strings.Split(string(data), "\n")
	inWorkspace := false

	for _, line := range lines {
		line = strings.TrimSpace(line)

		if line == "[workspace]" {
			inWorkspace = true
			continue
		}

		if strings.HasPrefix(line, "[") && line != "[workspace]" {
			inWorkspace = false
			continue
		}

		if inWorkspace && strings.HasPrefix(line, "members") {
			// Parse workspace members
			// This is a simplified implementation
			break
		}
	}

	return packages, nil
}

// hasRustFiles checks if the project contains Rust source files
func (r *RustAnalyzer) hasRustFiles(projectPath string) bool {
	found := false
	filepath.Walk(projectPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if strings.HasSuffix(info.Name(), ".rs") {
			found = true
			return filepath.SkipDir
		}
		return nil
	})
	return found
}

// hasLockFile checks if Cargo.lock exists
func (r *RustAnalyzer) hasLockFile(projectPath string) bool {
	lockPath := filepath.Join(projectPath, "Cargo.lock")
	_, err := os.Stat(lockPath)
	return err == nil
}

// extractCargoMetadata extracts metadata from Cargo.toml
func (r *RustAnalyzer) extractCargoMetadata(projectPath string) (map[string]interface{}, error) {
	cargoTomlPath := filepath.Join(projectPath, "Cargo.toml")
	data, err := ioutil.ReadFile(cargoTomlPath)
	if err != nil {
		return nil, err
	}

	// Extract basic package information
	metadata := make(map[string]interface{})
	lines := strings.Split(string(data), "\n")
	inPackage := false

	for _, line := range lines {
		line = strings.TrimSpace(line)

		if line == "[package]" {
			inPackage = true
			continue
		}

		if strings.HasPrefix(line, "[") && line != "[package]" {
			inPackage = false
			continue
		}

		if inPackage && strings.Contains(line, "=") {
			parts := strings.SplitN(line, "=", 2)
			if len(parts) == 2 {
				key := strings.TrimSpace(parts[0])
				value := strings.Trim(strings.TrimSpace(parts[1]), `"'`)
				metadata[key] = value
			}
		}
	}

	return metadata, nil
}

// validateCargoToml validates the syntax of Cargo.toml
func (r *RustAnalyzer) validateCargoToml(cargoTomlPath string) error {
	data, err := ioutil.ReadFile(cargoTomlPath)
	if err != nil {
		return err
	}

	// Basic validation - check for required sections
	content := string(data)
	if !strings.Contains(content, "[package]") {
		return fmt.Errorf("missing [package] section")
	}

	// Check for package name
	if !strings.Contains(content, "name") {
		return fmt.Errorf("missing package name")
	}

	// Check for version
	if !strings.Contains(content, "version") {
		return fmt.Errorf("missing package version")
	}

	return nil
}
