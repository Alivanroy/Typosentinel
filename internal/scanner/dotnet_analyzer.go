package scanner

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"typosentinel/internal/config"
	"typosentinel/pkg/types"
)

// DotNetPackageAnalyzer analyzes .NET projects
type DotNetPackageAnalyzer struct {
	config *config.Config
}

// NewDotNetPackageAnalyzer creates a new .NET analyzer
func NewDotNetPackageAnalyzer(cfg *config.Config) *DotNetPackageAnalyzer {
	return &DotNetPackageAnalyzer{
		config: cfg,
	}
}

// Project file structures
type CSProj struct {
	XMLName        xml.Name              `xml:"Project"`
	Sdk            string                `xml:"Sdk,attr"`
	PropertyGroups []PropertyGroup       `xml:"PropertyGroup"`
	ItemGroups     []ItemGroup           `xml:"ItemGroup"`
	Targets        []Target              `xml:"Target"`
}

type PropertyGroup struct {
	TargetFramework         string `xml:"TargetFramework"`
	TargetFrameworks        string `xml:"TargetFrameworks"`
	OutputType              string `xml:"OutputType"`
	RootNamespace           string `xml:"RootNamespace"`
	AssemblyName            string `xml:"AssemblyName"`
	Version                 string `xml:"Version"`
	AssemblyVersion         string `xml:"AssemblyVersion"`
	FileVersion             string `xml:"FileVersion"`
	PackageVersion          string `xml:"PackageVersion"`
	Description             string `xml:"Description"`
	Authors                 string `xml:"Authors"`
	Company                 string `xml:"Company"`
	Product                 string `xml:"Product"`
	Copyright               string `xml:"Copyright"`
	PackageLicenseExpression string `xml:"PackageLicenseExpression"`
	RepositoryUrl           string `xml:"RepositoryUrl"`
	PackageProjectUrl       string `xml:"PackageProjectUrl"`
	PackageTags             string `xml:"PackageTags"`
}

type ItemGroup struct {
	PackageReferences []PackageReference `xml:"PackageReference"`
	ProjectReferences []ProjectReference `xml:"ProjectReference"`
	References        []Reference        `xml:"Reference"`
	Compile           []Compile          `xml:"Compile"`
	Content           []Content          `xml:"Content"`
	None              []None             `xml:"None"`
}

type PackageReference struct {
	Include           string `xml:"Include,attr"`
	Version           string `xml:"Version,attr"`
	PrivateAssets     string `xml:"PrivateAssets,attr"`
	IncludeAssets     string `xml:"IncludeAssets,attr"`
	ExcludeAssets     string `xml:"ExcludeAssets,attr"`
	Condition         string `xml:"Condition,attr"`
}

type ProjectReference struct {
	Include string `xml:"Include,attr"`
}

type Reference struct {
	Include   string `xml:"Include,attr"`
	HintPath  string `xml:"HintPath"`
	Private   string `xml:"Private"`
	SpecificVersion string `xml:"SpecificVersion"`
}

type Compile struct {
	Include string `xml:"Include,attr"`
}

type Content struct {
	Include string `xml:"Include,attr"`
}

type None struct {
	Include string `xml:"Include,attr"`
}

type ProjectTarget struct {
	Name string `xml:"Name,attr"`
}

// packages.config structure
type PackagesConfig struct {
	XMLName  xml.Name `xml:"packages"`
	Packages []PackageConfigEntry `xml:"package"`
}

type PackageConfigEntry struct {
	ID              string `xml:"id,attr"`
	Version         string `xml:"version,attr"`
	TargetFramework string `xml:"targetFramework,attr"`
	DevelopmentDependency bool `xml:"developmentDependency,attr"`
}

// project.assets.json structure (NuGet lock file)
type ProjectAssets struct {
	Version   int                           `json:"version"`
	Targets   map[string]map[string]Target  `json:"targets"`
	Libraries map[string]Library           `json:"libraries"`
	Project   ProjectAssetsProject         `json:"project"`
}

type Target struct {
	Type         string                    `json:"type"`
	Framework    string                    `json:"framework"`
	Dependencies map[string]string         `json:"dependencies"`
	Runtime      map[string]RuntimeAsset   `json:"runtime"`
	Compile      map[string]CompileAsset   `json:"compile"`
}

type Library struct {
	Sha512    string            `json:"sha512"`
	Type      string            `json:"type"`
	Path      string            `json:"path"`
	Files     []string          `json:"files"`
	HashPath  string            `json:"hashPath"`
	Serviceable bool            `json:"serviceable"`
}

type RuntimeAsset struct {
	Rid string `json:"rid"`
}

type CompileAsset struct {
	Related []string `json:"related"`
}

type ProjectAssetsProject struct {
	Version      string                    `json:"version"`
	Restore      ProjectRestore            `json:"restore"`
	Frameworks   map[string]Framework      `json:"frameworks"`
}

type ProjectRestore struct {
	ProjectUniqueName string   `json:"projectUniqueName"`
	ProjectName       string   `json:"projectName"`
	ProjectPath       string   `json:"projectPath"`
	PackagesPath      string   `json:"packagesPath"`
	OutputPath        string   `json:"outputPath"`
	ProjectStyle      string   `json:"projectStyle"`
	OriginalTargetFrameworks []string `json:"originalTargetFrameworks"`
	Sources           map[string]Source `json:"sources"`
	FallbackFolders   []string `json:"fallbackFolders"`
	ConfigFilePaths   []string `json:"configFilePaths"`
}

type Source struct {
	ProtocolVersion int `json:"protocolVersion"`
}

type Framework struct {
	TargetAlias   string                    `json:"targetAlias"`
	Imports       []string                  `json:"imports"`
	AssetTargetFallback bool                `json:"assetTargetFallback"`
	Warn          bool                      `json:"warn"`
	FrameworkReferences map[string]FrameworkReference `json:"frameworkReferences"`
	Dependencies  map[string]Dependency     `json:"dependencies"`
}

type FrameworkReference struct {
	PrivateAssets string `json:"privateAssets"`
}

type Dependency struct {
	Target            string `json:"target"`
	Version           string `json:"version"`
	AutoReferenced    bool   `json:"autoReferenced"`
	Include           string `json:"include"`
	Exclude           string `json:"exclude"`
	SuppressParent    string `json:"suppressParent"`
	PrivateAssets     string `json:"privateAssets"`
	IncludeAssets     string `json:"includeAssets"`
	ExcludeAssets     string `json:"excludeAssets"`
}

func (a *DotNetPackageAnalyzer) ExtractPackages(projectInfo *ProjectInfo) ([]*types.Package, error) {
	var packages []*types.Package

	// Find all .csproj, .vbproj, .fsproj files
	projectFiles, err := a.findProjectFiles(projectInfo.Path)
	if err != nil {
		return nil, fmt.Errorf("failed to find project files: %w", err)
	}

	// Parse each project file
	for _, projectFile := range projectFiles {
		projPackages, err := a.parseProjectFile(projectFile)
		if err != nil {
			continue // Skip invalid project files
		}
		packages = append(packages, projPackages...)
	}

	// Parse packages.config files (legacy NuGet format)
	packagesConfigFiles, err := a.findPackagesConfigFiles(projectInfo.Path)
	if err == nil {
		for _, configFile := range packagesConfigFiles {
			configPackages, err := a.parsePackagesConfig(configFile)
			if err != nil {
				continue
			}
			packages = append(packages, configPackages...)
		}
	}

	// Parse project.assets.json (NuGet lock file)
	assetsPath := filepath.Join(projectInfo.Path, "obj", "project.assets.json")
	if _, err := os.Stat(assetsPath); err == nil {
		assetsPackages, err := a.parseProjectAssets(assetsPath)
		if err == nil {
			packages = a.mergeAssetsInfo(packages, assetsPackages)
		}
	}

	return packages, nil
}

func (a *DotNetPackageAnalyzer) findProjectFiles(projectPath string) ([]string, error) {
	var projectFiles []string

	// Look for .csproj, .vbproj, .fsproj files
	patterns := []string{"*.csproj", "*.vbproj", "*.fsproj"}

	for _, pattern := range patterns {
		matches, err := filepath.Glob(filepath.Join(projectPath, pattern))
		if err != nil {
			continue
		}
		projectFiles = append(projectFiles, matches...)
	}

	return projectFiles, nil
}

func (a *DotNetPackageAnalyzer) findPackagesConfigFiles(projectPath string) ([]string, error) {
	var configFiles []string

	// Look for packages.config files
	matches, err := filepath.Glob(filepath.Join(projectPath, "packages.config"))
	if err != nil {
		return nil, err
	}
	configFiles = append(configFiles, matches...)

	// Also check in subdirectories
	err = filepath.Walk(projectPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.Name() == "packages.config" {
			configFiles = append(configFiles, path)
		}
		return nil
	})

	return configFiles, err
}

func (a *DotNetPackageAnalyzer) parseProjectFile(filePath string) ([]*types.Package, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	var project CSProj
	if err := xml.Unmarshal(data, &project); err != nil {
		return nil, fmt.Errorf("failed to parse project file: %w", err)
	}

	var packages []*types.Package

	// Extract PackageReference entries
	for _, itemGroup := range project.ItemGroups {
		for _, pkgRef := range itemGroup.PackageReferences {
			if pkgRef.Include == "" {
				continue
			}

			version := pkgRef.Version
			if version == "" {
				version = "*"
			}

			// Determine if it's a development dependency
			depType := "production"
			if strings.Contains(pkgRef.PrivateAssets, "all") ||
			   strings.Contains(pkgRef.IncludeAssets, "build") ||
			   strings.Contains(pkgRef.Condition, "Debug") {
				depType = "development"
			}

			pkg := &types.Package{
				Name:     pkgRef.Include,
				Version:  version,
				Registry: "nuget.org",
				Type:     depType,
				Metadata: &types.PackageMetadata{
					Name:     pkgRef.Include,
					Version:  version,
					Registry: "nuget.org",
					Metadata: map[string]interface{}{
						"ecosystem":      "dotnet",
						"source":         filepath.Base(filePath),
						"privateAssets":  pkgRef.PrivateAssets,
						"includeAssets":  pkgRef.IncludeAssets,
						"excludeAssets":  pkgRef.ExcludeAssets,
						"condition":      pkgRef.Condition,
					},
				},
			}
			packages = append(packages, pkg)
		}
	}

	return packages, nil
}

func (a *DotNetPackageAnalyzer) parsePackagesConfig(filePath string) ([]*types.Package, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	var config PackagesConfig
	if err := xml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse packages.config: %w", err)
	}

	var packages []*types.Package

	for _, pkg := range config.Packages {
		depType := "production"
		if pkg.DevelopmentDependency {
			depType = "development"
		}

		pkgEntry := &types.Package{
			Name:     pkg.ID,
			Version:  pkg.Version,
			Registry: "nuget.org",
			Type:     depType,
			Metadata: &types.PackageMetadata{
				Name:     pkg.ID,
				Version:  pkg.Version,
				Registry: "nuget.org",
				Metadata: map[string]interface{}{
					"ecosystem":        "dotnet",
					"source":           "packages.config",
					"targetFramework":  pkg.TargetFramework,
					"developmentDependency": pkg.DevelopmentDependency,
				},
			},
		}
		packages = append(packages, pkgEntry)
	}

	return packages, nil
}

func (a *DotNetPackageAnalyzer) parseProjectAssets(filePath string) (map[string]*types.Package, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	var assets ProjectAssets
	if err := json.Unmarshal(data, &assets); err != nil {
		return nil, fmt.Errorf("failed to parse project.assets.json: %w", err)
	}

	packages := make(map[string]*types.Package)

	// Extract packages from libraries
	for libName, lib := range assets.Libraries {
		if lib.Type != "package" {
			continue
		}

		// Parse package name and version from library name (format: "name/version")
		parts := strings.Split(libName, "/")
		if len(parts) != 2 {
			continue
		}

		name := parts[0]
		version := parts[1]

		pkg := &types.Package{
			Name:     name,
			Version:  version,
			Registry: "nuget.org",
			Type:     "production",
			Metadata: &types.PackageMetadata{
				Name:     name,
				Version:  version,
				Registry: "nuget.org",
				Metadata: map[string]interface{}{
					"ecosystem":   "dotnet",
					"source":      "project.assets.json",
					"sha512":      lib.Sha512,
					"path":        lib.Path,
					"hashPath":    lib.HashPath,
					"serviceable": lib.Serviceable,
				},
			},
		}
		packages[name] = pkg
	}

	return packages, nil
}

func (a *DotNetPackageAnalyzer) mergeAssetsInfo(projectPackages []*types.Package, assetsPackages map[string]*types.Package) []*types.Package {
	// Update project packages with exact versions from assets file
	for _, pkg := range projectPackages {
		if assetsPkg, exists := assetsPackages[pkg.Name]; exists {
			pkg.Version = assetsPkg.Version
			if pkg.Metadata == nil {
				pkg.Metadata = &types.PackageMetadata{
					Name:     pkg.Name,
					Version:  pkg.Version,
					Registry: pkg.Registry,
					Metadata: make(map[string]interface{}),
				}
			}
			// Merge metadata from assets file
			for key, value := range assetsPkg.Metadata.Metadata {
				pkg.Metadata.Metadata[key] = value
			}
			pkg.Metadata.Metadata["exact_version"] = assetsPkg.Version
		}
	}

	// Add any packages from assets file that weren't in project files (transitive dependencies)
	projectPackageNames := make(map[string]bool)
	for _, pkg := range projectPackages {
		projectPackageNames[pkg.Name] = true
	}

	for name, assetsPkg := range assetsPackages {
		if !projectPackageNames[name] {
			assetsPkg.Type = "transitive"
			projectPackages = append(projectPackages, assetsPkg)
		}
	}

	return projectPackages
}

func (a *DotNetPackageAnalyzer) AnalyzeDependencies(projectInfo *ProjectInfo) (*types.DependencyTree, error) {
	packages, err := a.ExtractPackages(projectInfo)
	if err != nil {
		return nil, err
	}

	projectName := "dotnet-project"
	projectVersion := "1.0.0"

	// Try to get project name and version from project files
	projectFiles, err := a.findProjectFiles(projectInfo.Path)
	if err == nil && len(projectFiles) > 0 {
		if name, version := a.extractProjectInfo(projectFiles[0]); name != "" {
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

func (a *DotNetPackageAnalyzer) extractProjectInfo(projectPath string) (string, string) {
	data, err := os.ReadFile(projectPath)
	if err != nil {
		return "", ""
	}

	var project CSProj
	if err := xml.Unmarshal(data, &project); err != nil {
		return "", ""
	}

	var name, version string

	// Extract from PropertyGroups
	for _, propGroup := range project.PropertyGroups {
		if propGroup.AssemblyName != "" {
			name = propGroup.AssemblyName
		}
		if propGroup.RootNamespace != "" && name == "" {
			name = propGroup.RootNamespace
		}
		if propGroup.Version != "" {
			version = propGroup.Version
		} else if propGroup.AssemblyVersion != "" {
			version = propGroup.AssemblyVersion
		} else if propGroup.PackageVersion != "" {
			version = propGroup.PackageVersion
		}
	}

	// Fallback to filename if no name found
	if name == "" {
		name = strings.TrimSuffix(filepath.Base(projectPath), filepath.Ext(projectPath))
	}

	return name, version
}