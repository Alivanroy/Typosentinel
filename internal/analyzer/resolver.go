package analyzer

import (
	"fmt"
	"sort"
	"strings"

	"github.com/sirupsen/logrus"
	"github.com/Alivanroy/Typosentinel/internal/config"
	"github.com/Alivanroy/Typosentinel/pkg/types"
)

// DependencyResolver handles dependency resolution and conflict detection
type DependencyResolver struct {
	config *config.ScannerConfig
}

// ResolutionResult contains the results of dependency resolution
type ResolutionResult struct {
	Resolved  []types.Dependency `json:"resolved"`
	Conflicts []Conflict         `json:"conflicts"`
	Warnings  []Warning          `json:"warnings"`
}

// Conflict represents a dependency version conflict
type Conflict struct {
	PackageName     string   `json:"packageName"`
	ConflictingVersions []VersionInfo `json:"conflictingVersions"`
	Severity        string   `json:"severity"`
	Description     string   `json:"description"`
}

// VersionInfo contains version and source information
type VersionInfo struct {
	Version    string `json:"version"`
	Constraint string `json:"constraint"`
	Source     string `json:"source"`
	Direct     bool   `json:"direct"`
}

// Warning represents a dependency resolution warning
type Warning struct {
	Type        string `json:"type"`
	PackageName string `json:"packageName"`
	Message     string `json:"message"`
	Severity    string `json:"severity"`
}

// NewDependencyResolver creates a new dependency resolver
func NewDependencyResolver(config *config.ScannerConfig) *DependencyResolver {
	return &DependencyResolver{
		config: config,
	}
}

// ResolveDependencies analyzes dependencies and detects conflicts
func (r *DependencyResolver) ResolveDependencies(dependencies []types.Dependency) (*ResolutionResult, error) {
	logrus.Debugf("Resolving %d dependencies", len(dependencies))

	result := &ResolutionResult{
		Resolved:  make([]types.Dependency, 0),
		Conflicts: make([]Conflict, 0),
		Warnings:  make([]Warning, 0),
	}

	// Group dependencies by package name
	packageGroups := r.groupDependenciesByName(dependencies)

	// Analyze each package group for conflicts
	for packageName, deps := range packageGroups {
		conflict, resolved, warnings := r.analyzePackageGroup(packageName, deps)
		
		if conflict != nil {
			result.Conflicts = append(result.Conflicts, *conflict)
		}
		
		if resolved != nil {
			result.Resolved = append(result.Resolved, *resolved)
		}
		
		result.Warnings = append(result.Warnings, warnings...)
	}

	// Sort results for consistent output
	sort.Slice(result.Resolved, func(i, j int) bool {
		return result.Resolved[i].Name < result.Resolved[j].Name
	})
	sort.Slice(result.Conflicts, func(i, j int) bool {
		return result.Conflicts[i].PackageName < result.Conflicts[j].PackageName
	})

	logrus.Debugf("Resolution complete: %d resolved, %d conflicts, %d warnings", 
		len(result.Resolved), len(result.Conflicts), len(result.Warnings))

	return result, nil
}

// groupDependenciesByName groups dependencies by package name
func (r *DependencyResolver) groupDependenciesByName(dependencies []types.Dependency) map[string][]types.Dependency {
	groups := make(map[string][]types.Dependency)
	
	for _, dep := range dependencies {
		if dep.Name == "" {
			continue
		}
		groups[dep.Name] = append(groups[dep.Name], dep)
	}
	
	return groups
}

// analyzePackageGroup analyzes a group of dependencies for the same package
func (r *DependencyResolver) analyzePackageGroup(packageName string, deps []types.Dependency) (*Conflict, *types.Dependency, []Warning) {
	if len(deps) == 0 {
		return nil, nil, nil
	}

	// If only one dependency, no conflict possible
	if len(deps) == 1 {
		return nil, &deps[0], nil
	}

	var warnings []Warning
	var versionInfos []VersionInfo
	var uniqueVersions = make(map[string]bool)
	var resolvedDep *types.Dependency

	// Collect version information
	for _, dep := range deps {
		constraint := ""
		if dep.ExtraData != nil {
			if c, ok := dep.ExtraData["constraint"].(string); ok {
				constraint = c
			}
		}

		versionInfo := VersionInfo{
			Version:    dep.Version,
			Constraint: constraint,
			Source:     dep.Source,
			Direct:     dep.Direct,
		}
		versionInfos = append(versionInfos, versionInfo)
		uniqueVersions[dep.Version] = true
	}

	// Check for version conflicts
	if len(uniqueVersions) > 1 {
		// Multiple versions detected - this is a conflict
		conflict := &Conflict{
			PackageName:         packageName,
			ConflictingVersions: versionInfos,
			Severity:           r.determineConflictSeverity(versionInfos),
			Description:        r.generateConflictDescription(packageName, versionInfos),
		}
		
		// Try to resolve by picking the "best" version
		resolvedDep = r.selectBestVersion(deps)
		
		return conflict, resolvedDep, warnings
	}

	// No version conflict, but check for other issues
	resolvedDep = &deps[0] // All versions are the same, pick the first one

	// Check for duplicate sources
	sources := make(map[string]bool)
	for _, dep := range deps {
		sources[dep.Source] = true
	}

	if len(sources) > 1 {
		warning := Warning{
			Type:        "duplicate_declaration",
			PackageName: packageName,
			Message:     fmt.Sprintf("Package %s is declared in multiple files: %v", packageName, r.getSourceList(deps)),
			Severity:    "low",
		}
		warnings = append(warnings, warning)
	}

	return nil, resolvedDep, warnings
}

// determineConflictSeverity determines the severity of a version conflict
func (r *DependencyResolver) determineConflictSeverity(versions []VersionInfo) string {
	// Check if any are direct dependencies
	hasDirectDep := false
	for _, v := range versions {
		if v.Direct {
			hasDirectDep = true
			break
		}
	}

	// Direct dependency conflicts are more severe
	if hasDirectDep {
		return "high"
	}

	// Check version distance (simplified)
	if r.hasSignificantVersionDifference(versions) {
		return "medium"
	}

	return "low"
}

// hasSignificantVersionDifference checks if versions have significant differences
func (r *DependencyResolver) hasSignificantVersionDifference(versions []VersionInfo) bool {
	// Simplified check - look for major version differences
	majorVersions := make(map[string]bool)
	
	for _, v := range versions {
		major := r.extractMajorVersion(v.Version)
		majorVersions[major] = true
	}
	
	return len(majorVersions) > 1
}

// extractMajorVersion extracts the major version number
func (r *DependencyResolver) extractMajorVersion(version string) string {
	parts := strings.Split(version, ".")
	if len(parts) > 0 {
		return parts[0]
	}
	return version
}

// selectBestVersion selects the best version from conflicting dependencies
func (r *DependencyResolver) selectBestVersion(deps []types.Dependency) *types.Dependency {
	// Prefer direct dependencies
	for _, dep := range deps {
		if dep.Direct {
			return &dep
		}
	}

	// Prefer production dependencies over dev dependencies
	for _, dep := range deps {
		if !dep.Development {
			return &dep
		}
	}

	// Default to first dependency
	return &deps[0]
}

// generateConflictDescription generates a human-readable conflict description
func (r *DependencyResolver) generateConflictDescription(packageName string, versions []VersionInfo) string {
	versionStrs := make([]string, len(versions))
	for i, v := range versions {
		source := r.getShortSource(v.Source)
		if v.Constraint != "" && v.Constraint != v.Version {
			versionStrs[i] = fmt.Sprintf("%s (constraint: %s) from %s", v.Version, v.Constraint, source)
		} else {
			versionStrs[i] = fmt.Sprintf("%s from %s", v.Version, source)
		}
	}
	
	return fmt.Sprintf("Package %s has conflicting versions: %s", packageName, strings.Join(versionStrs, ", "))
}

// getShortSource returns a shortened version of the source path
func (r *DependencyResolver) getShortSource(source string) string {
	parts := strings.Split(source, "/")
	if len(parts) > 0 {
		return parts[len(parts)-1]
	}
	return source
}

// getSourceList returns a list of unique sources
func (r *DependencyResolver) getSourceList(deps []types.Dependency) []string {
	sources := make(map[string]bool)
	for _, dep := range deps {
		sources[r.getShortSource(dep.Source)] = true
	}
	
	var result []string
	for source := range sources {
		result = append(result, source)
	}
	sort.Strings(result)
	return result
}