package policy

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/Alivanroy/Typosentinel/pkg/types"
)

// DefaultDependencyUpdater implements automated dependency updates
type DefaultDependencyUpdater struct {
	vulnerabilityDB VulnerabilityDatabase
	registryClient  RegistryClient
	config          *DependencyUpdaterConfig
}

// VulnerabilityDatabase interface for checking vulnerabilities
type VulnerabilityDatabase interface {
	CheckVulnerabilities(pkg *types.Package) ([]*types.Vulnerability, error)
	GetSafeVersions(pkg *types.Package) ([]string, error)
}

// RegistryClient interface for interacting with package registries
type RegistryClient interface {
	GetPackageVersions(pkg *types.Package) ([]string, error)
	GetPackageMetadata(pkg *types.Package, version string) (*types.PackageMetadata, error)
	ValidateVersion(pkg *types.Package, version string) (bool, error)
}

// DependencyUpdaterConfig configuration for dependency updates
type DependencyUpdaterConfig struct {
	AllowMajorUpdates    bool          `json:"allow_major_updates"`
	AllowMinorUpdates    bool          `json:"allow_minor_updates"`
	AllowPatchUpdates    bool          `json:"allow_patch_updates"`
	MaxVersionAge        time.Duration `json:"max_version_age"`
	MinConfidenceScore   float64       `json:"min_confidence_score"`
	PreferStableVersions bool          `json:"prefer_stable_versions"`
	ExcludePrerelease    bool          `json:"exclude_prerelease"`
	SupportedRegistries  []string      `json:"supported_registries"`
}

// NewDefaultDependencyUpdater creates a new dependency updater
func NewDefaultDependencyUpdater(
	vulnDB VulnerabilityDatabase,
	registryClient RegistryClient,
	config *DependencyUpdaterConfig,
) *DefaultDependencyUpdater {
	if config == nil {
		config = &DependencyUpdaterConfig{
			AllowMajorUpdates:    false,
			AllowMinorUpdates:    true,
			AllowPatchUpdates:    true,
			MaxVersionAge:        365 * 24 * time.Hour, // 1 year
			MinConfidenceScore:   0.8,
			PreferStableVersions: true,
			ExcludePrerelease:    true,
			SupportedRegistries:  []string{"npm", "pypi", "maven", "nuget", "gem", "cargo", "go"},
		}
	}
	
	return &DefaultDependencyUpdater{
		vulnerabilityDB: vulnDB,
		registryClient:  registryClient,
		config:          config,
	}
}

// UpdateDependency updates a dependency to a target version
func (d *DefaultDependencyUpdater) UpdateDependency(ctx context.Context, pkg *types.Package, targetVersion string) (*UpdateResult, error) {
	// Validate the target version
	validation, err := d.ValidateUpdate(ctx, pkg, targetVersion)
	if err != nil {
		return nil, fmt.Errorf("validation failed: %w", err)
	}
	
	if !validation.Valid {
		return &UpdateResult{
			Package:    pkg,
			OldVersion: pkg.Version,
			NewVersion: targetVersion,
			Success:    false,
			Error:      validation.Reason,
		}, nil
	}

	// Find and update dependency files
	changedFiles, err := d.updateDependencyFiles(pkg, targetVersion)
	if err != nil {
		return nil, fmt.Errorf("failed to update dependency files: %w", err)
	}

	return &UpdateResult{
		Package:      pkg,
		OldVersion:   pkg.Version,
		NewVersion:   targetVersion,
		Success:      true,
		ChangedFiles: changedFiles,
	}, nil
}

// FindSafeVersion finds a safe version for a vulnerable package
func (d *DefaultDependencyUpdater) FindSafeVersion(ctx context.Context, pkg *types.Package) (*SafeVersionResult, error) {
	// Get all available versions
	versions, err := d.registryClient.GetPackageVersions(pkg)
	if err != nil {
		return nil, fmt.Errorf("failed to get package versions: %w", err)
	}

	// Filter versions based on configuration
	filteredVersions := d.filterVersions(pkg, versions)

	// Check each version for vulnerabilities
	for _, version := range filteredVersions {
		testPkg := &types.Package{
			Name:     pkg.Name,
			Version:  version,
			Registry: pkg.Registry,
		}

		vulns, err := d.vulnerabilityDB.CheckVulnerabilities(testPkg)
		if err != nil {
			continue // Skip this version if we can't check it
		}

		// If no vulnerabilities found, this is a safe version
		if len(vulns) == 0 {
			return &SafeVersionResult{
				Package:            pkg,
				RecommendedVersion: version,
				Reason:             "No known vulnerabilities",
				Confidence:         0.95,
				Alternatives:       d.getAlternativeVersions(filteredVersions, version),
			}, nil
		}
	}

	// If no safe version found, recommend the latest version with a warning
	if len(filteredVersions) > 0 {
		return &SafeVersionResult{
			Package:            pkg,
			RecommendedVersion: filteredVersions[0],
			Reason:             "Latest available version (manual review recommended)",
			Confidence:         0.5,
			Alternatives:       filteredVersions[1:],
		}, nil
	}

	return nil, fmt.Errorf("no safe version found for package %s", pkg.Name)
}

// ValidateUpdate validates if an update is safe and allowed
func (d *DefaultDependencyUpdater) ValidateUpdate(ctx context.Context, pkg *types.Package, newVersion string) (*ValidationResult, error) {
	// Check if registry is supported
	if !d.isRegistrySupported(pkg.Registry) {
		return &ValidationResult{
			Valid:  false,
			Reason: fmt.Sprintf("Registry %s is not supported", pkg.Registry),
		}, nil
	}

	// Validate version format
	if !d.isValidVersionFormat(newVersion) {
		return &ValidationResult{
			Valid:  false,
			Reason: "Invalid version format",
		}, nil
	}

	// Check if version exists
	exists, err := d.registryClient.ValidateVersion(pkg, newVersion)
	if err != nil {
		return nil, fmt.Errorf("failed to validate version: %w", err)
	}
	if !exists {
		return &ValidationResult{
			Valid:  false,
			Reason: "Version does not exist in registry",
		}, nil
	}

	// Check version constraints
	constraints := d.checkVersionConstraints(pkg.Version, newVersion)
	if !constraints.allowed {
		return &ValidationResult{
			Valid:  false,
			Reason: constraints.reason,
		}, nil
	}

	// Check for vulnerabilities in new version
	testPkg := &types.Package{
		Name:     pkg.Name,
		Version:  newVersion,
		Registry: pkg.Registry,
	}

	vulns, err := d.vulnerabilityDB.CheckVulnerabilities(testPkg)
	if err != nil {
		return &ValidationResult{
			Valid:    true,
			Reason:   "Update allowed (vulnerability check failed)",
			Warnings: []string{"Could not verify vulnerabilities in target version"},
		}, nil
	}

	warnings := []string{}
	if len(vulns) > 0 {
		warnings = append(warnings, fmt.Sprintf("Target version has %d known vulnerabilities", len(vulns)))
	}

	return &ValidationResult{
		Valid:           true,
		Reason:          "Update validation passed",
		Warnings:        warnings,
		BreakingChanges: constraints.breakingChanges,
	}, nil
}

// Helper methods

func (d *DefaultDependencyUpdater) filterVersions(pkg *types.Package, versions []string) []string {
	var filtered []string
	
	for _, version := range versions {
		// Skip prerelease versions if configured
		if d.config.ExcludePrerelease && d.isPrereleaseVersion(version) {
			continue
		}
		
		// Check version constraints
		constraints := d.checkVersionConstraints(pkg.Version, version)
		if constraints.allowed {
			filtered = append(filtered, version)
		}
	}
	
	return filtered
}

func (d *DefaultDependencyUpdater) getAlternativeVersions(versions []string, recommended string) []string {
	var alternatives []string
	for _, version := range versions {
		if version != recommended && len(alternatives) < 3 {
			alternatives = append(alternatives, version)
		}
	}
	return alternatives
}

func (d *DefaultDependencyUpdater) isRegistrySupported(registry string) bool {
	for _, supported := range d.config.SupportedRegistries {
		if supported == registry {
			return true
		}
	}
	return false
}

func (d *DefaultDependencyUpdater) isValidVersionFormat(version string) bool {
	// Basic semantic version validation
	semverRegex := regexp.MustCompile(`^\d+\.\d+\.\d+(-[a-zA-Z0-9.-]+)?(\+[a-zA-Z0-9.-]+)?$`)
	return semverRegex.MatchString(version)
}

func (d *DefaultDependencyUpdater) isPrereleaseVersion(version string) bool {
	return strings.Contains(version, "-alpha") ||
		strings.Contains(version, "-beta") ||
		strings.Contains(version, "-rc") ||
		strings.Contains(version, "-pre")
}

type versionConstraints struct {
	allowed         bool
	reason          string
	breakingChanges bool
}

func (d *DefaultDependencyUpdater) checkVersionConstraints(currentVersion, newVersion string) versionConstraints {
	// Parse versions (simplified)
	currentParts := strings.Split(currentVersion, ".")
	newParts := strings.Split(newVersion, ".")
	
	if len(currentParts) < 3 || len(newParts) < 3 {
		return versionConstraints{
			allowed: true,
			reason:  "Version format not recognized, allowing update",
		}
	}
	
	// Extract major, minor, patch versions
	currentMajor := currentParts[0]
	currentMinor := currentParts[1]
	newMajor := newParts[0]
	newMinor := newParts[1]
	
	// Check major version changes
	if currentMajor != newMajor {
		if !d.config.AllowMajorUpdates {
			return versionConstraints{
				allowed: false,
				reason:  "Major version updates not allowed",
			}
		}
		return versionConstraints{
			allowed:         true,
			reason:          "Major version update allowed",
			breakingChanges: true,
		}
	}
	
	// Check minor version changes
	if currentMinor != newMinor {
		if !d.config.AllowMinorUpdates {
			return versionConstraints{
				allowed: false,
				reason:  "Minor version updates not allowed",
			}
		}
		return versionConstraints{
			allowed: true,
			reason:  "Minor version update allowed",
		}
	}
	
	// Patch version changes
	if !d.config.AllowPatchUpdates {
		return versionConstraints{
			allowed: false,
			reason:  "Patch version updates not allowed",
		}
	}
	
	return versionConstraints{
		allowed: true,
		reason:  "Patch version update allowed",
	}
}

func (d *DefaultDependencyUpdater) updateDependencyFiles(pkg *types.Package, newVersion string) ([]string, error) {
	var changedFiles []string
	
	// Update based on registry type
	switch pkg.Registry {
	case "npm":
		files, err := d.updateNpmDependencies(pkg, newVersion)
		if err != nil {
			return nil, err
		}
		changedFiles = append(changedFiles, files...)
		
	case "pypi":
		files, err := d.updatePythonDependencies(pkg, newVersion)
		if err != nil {
			return nil, err
		}
		changedFiles = append(changedFiles, files...)
		
	case "maven":
		files, err := d.updateMavenDependencies(pkg, newVersion)
		if err != nil {
			return nil, err
		}
		changedFiles = append(changedFiles, files...)
		
	case "nuget":
		files, err := d.updateNugetDependencies(pkg, newVersion)
		if err != nil {
			return nil, err
		}
		changedFiles = append(changedFiles, files...)
		
	default:
		return nil, fmt.Errorf("unsupported registry: %s", pkg.Registry)
	}
	
	return changedFiles, nil
}

func (d *DefaultDependencyUpdater) updateNpmDependencies(pkg *types.Package, newVersion string) ([]string, error) {
	var changedFiles []string
	
	// Update package.json
	packageJSONPath := "package.json"
	if _, err := os.Stat(packageJSONPath); err == nil {
		err := d.updateNpmPackageJSON(packageJSONPath, pkg.Name, newVersion)
		if err != nil {
			return nil, fmt.Errorf("failed to update package.json: %w", err)
		}
		changedFiles = append(changedFiles, packageJSONPath)
	}
	
	// Update package-lock.json if it exists
	packageLockPath := "package-lock.json"
	if _, err := os.Stat(packageLockPath); err == nil {
		// Note: In a real implementation, you'd need to properly update the lock file
		// This is a simplified version
		changedFiles = append(changedFiles, packageLockPath)
	}
	
	return changedFiles, nil
}

func (d *DefaultDependencyUpdater) updateNpmPackageJSON(filePath, packageName, newVersion string) error {
	data, err := ioutil.ReadFile(filePath)
	if err != nil {
		return err
	}
	
	var packageJSON map[string]interface{}
	err = json.Unmarshal(data, &packageJSON)
	if err != nil {
		return err
	}
	
	// Update dependencies
	if deps, ok := packageJSON["dependencies"].(map[string]interface{}); ok {
		if _, exists := deps[packageName]; exists {
			deps[packageName] = newVersion
		}
	}
	
	// Update devDependencies
	if devDeps, ok := packageJSON["devDependencies"].(map[string]interface{}); ok {
		if _, exists := devDeps[packageName]; exists {
			devDeps[packageName] = newVersion
		}
	}
	
	// Write back to file
	updatedData, err := json.MarshalIndent(packageJSON, "", "  ")
	if err != nil {
		return err
	}
	
	return ioutil.WriteFile(filePath, updatedData, 0644)
}

func (d *DefaultDependencyUpdater) updatePythonDependencies(pkg *types.Package, newVersion string) ([]string, error) {
	var changedFiles []string
	
	// Update requirements.txt
	requirementsPath := "requirements.txt"
	if _, err := os.Stat(requirementsPath); err == nil {
		err := d.updateRequirementsTxt(requirementsPath, pkg.Name, newVersion)
		if err != nil {
			return nil, fmt.Errorf("failed to update requirements.txt: %w", err)
		}
		changedFiles = append(changedFiles, requirementsPath)
	}
	
	// Update setup.py if it exists
	setupPyPath := "setup.py"
	if _, err := os.Stat(setupPyPath); err == nil {
		// Note: Updating setup.py requires more complex parsing
		// This would need a proper Python AST parser in a real implementation
		changedFiles = append(changedFiles, setupPyPath)
	}
	
	return changedFiles, nil
}

func (d *DefaultDependencyUpdater) updateRequirementsTxt(filePath, packageName, newVersion string) error {
	data, err := ioutil.ReadFile(filePath)
	if err != nil {
		return err
	}
	
	lines := strings.Split(string(data), "\n")
	for i, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, packageName) {
			// Update the version
			lines[i] = fmt.Sprintf("%s==%s", packageName, newVersion)
			break
		}
	}
	
	updatedContent := strings.Join(lines, "\n")
	return ioutil.WriteFile(filePath, []byte(updatedContent), 0644)
}

func (d *DefaultDependencyUpdater) updateMavenDependencies(pkg *types.Package, newVersion string) ([]string, error) {
	var changedFiles []string
	
	// Update pom.xml
	pomPath := "pom.xml"
	if _, err := os.Stat(pomPath); err == nil {
		// Note: Updating pom.xml requires XML parsing
		// This is a placeholder for the actual implementation
		changedFiles = append(changedFiles, pomPath)
	}
	
	return changedFiles, nil
}

func (d *DefaultDependencyUpdater) updateNugetDependencies(pkg *types.Package, newVersion string) ([]string, error) {
	var changedFiles []string
	
	// Find .csproj files
	matches, err := filepath.Glob("*.csproj")
	if err != nil {
		return nil, err
	}
	
	for _, csprojPath := range matches {
		// Note: Updating .csproj files requires XML parsing
		// This is a placeholder for the actual implementation
		changedFiles = append(changedFiles, csprojPath)
	}
	
	return changedFiles, nil
}