package scanner

import (
	"bufio"
	"encoding/xml"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/Alivanroy/Typosentinel/internal/config"
	"github.com/Alivanroy/Typosentinel/pkg/types"
)

// JavaPackageAnalyzer analyzes Java projects
type JavaPackageAnalyzer struct {
	config *config.Config
}

// NewJavaPackageAnalyzer creates a new Java analyzer
func NewJavaPackageAnalyzer(cfg *config.Config) *JavaPackageAnalyzer {
	return &JavaPackageAnalyzer{
		config: cfg,
	}
}

// Maven POM structures
type MavenPOM struct {
	XMLName      xml.Name           `xml:"project"`
	GroupID      string             `xml:"groupId"`
	ArtifactID   string             `xml:"artifactId"`
	Version      string             `xml:"version"`
	Packaging    string             `xml:"packaging"`
	Name         string             `xml:"name"`
	Description  string             `xml:"description"`
	URL          string             `xml:"url"`
	Parent       *MavenParent       `xml:"parent"`
	Properties   *MavenProperties   `xml:"properties"`
	Dependencies *MavenDependencies `xml:"dependencies"`
	Plugins      *MavenPlugins      `xml:"build>plugins"`
}

type MavenParent struct {
	GroupID    string `xml:"groupId"`
	ArtifactID string `xml:"artifactId"`
	Version    string `xml:"version"`
}

type MavenProperties struct {
	Properties map[string]string `xml:",any"`
}

type MavenDependencies struct {
	Dependency []MavenDependency `xml:"dependency"`
}

type MavenDependency struct {
	GroupID    string `xml:"groupId"`
	ArtifactID string `xml:"artifactId"`
	Version    string `xml:"version"`
	Scope      string `xml:"scope"`
	Type       string `xml:"type"`
	Classifier string `xml:"classifier"`
	Optional   bool   `xml:"optional"`
}

type MavenPlugins struct {
	Plugin []MavenPlugin `xml:"plugin"`
}

type MavenPlugin struct {
	GroupID    string `xml:"groupId"`
	ArtifactID string `xml:"artifactId"`
	Version    string `xml:"version"`
}

// Gradle build structures
type GradleDependency struct {
	Configuration string
	Group         string
	Name          string
	Version       string
}

func (a *JavaPackageAnalyzer) ExtractPackages(projectInfo *ProjectInfo) ([]*types.Package, error) {
	var packages []*types.Package

	// Check for Maven project (pom.xml)
	pomPath := filepath.Join(projectInfo.Path, "pom.xml")
	if _, err := os.Stat(pomPath); err == nil {
		mavenPackages, err := a.parseMavenPOM(pomPath)
		if err != nil {
			return nil, fmt.Errorf("failed to parse pom.xml: %w", err)
		}
		packages = append(packages, mavenPackages...)
	}

	// Check for Gradle project (build.gradle or build.gradle.kts)
	gradlePaths := []string{
		filepath.Join(projectInfo.Path, "build.gradle"),
		filepath.Join(projectInfo.Path, "build.gradle.kts"),
	}

	for _, gradlePath := range gradlePaths {
		if _, err := os.Stat(gradlePath); err == nil {
			gradlePackages, err := a.parseGradleBuild(gradlePath)
			if err != nil {
				return nil, fmt.Errorf("failed to parse %s: %w", gradlePath, err)
			}
			packages = append(packages, gradlePackages...)
			break // Only parse one Gradle file
		}
	}

	// Check for SBT project (build.sbt) - for Scala projects
	sbtPath := filepath.Join(projectInfo.Path, "build.sbt")
	if _, err := os.Stat(sbtPath); err == nil {
		sbtPackages, err := a.parseSBTBuild(sbtPath)
		if err != nil {
			return nil, fmt.Errorf("failed to parse build.sbt: %w", err)
		}
		packages = append(packages, sbtPackages...)
	}

	return packages, nil
}

func (a *JavaPackageAnalyzer) parseMavenPOM(filePath string) ([]*types.Package, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	var pom MavenPOM
	if err := xml.Unmarshal(data, &pom); err != nil {
		return nil, fmt.Errorf("failed to parse POM XML: %w", err)
	}

	var packages []*types.Package

	if pom.Dependencies != nil {
		for _, dep := range pom.Dependencies.Dependency {
			// Skip empty dependencies
			if dep.GroupID == "" || dep.ArtifactID == "" {
				continue
			}

			// Determine dependency type based on scope
			depType := "production"
			switch dep.Scope {
			case "test":
				depType = "development"
			case "provided":
				depType = "provided"
			case "runtime":
				depType = "runtime"
			case "system":
				depType = "system"
			case "import":
				depType = "import"
			}

			version := dep.Version
			if version == "" {
				version = "*"
			}

			pkg := &types.Package{
				Name:     fmt.Sprintf("%s:%s", dep.GroupID, dep.ArtifactID),
				Version:  version,
				Registry: "maven-central",
				Type:     depType,
				Metadata: &types.PackageMetadata{
					Name:     fmt.Sprintf("%s:%s", dep.GroupID, dep.ArtifactID),
					Version:  version,
					Registry: "maven-central",
					Metadata: map[string]interface{}{
						"ecosystem":  "java",
						"source":     "pom.xml",
						"groupId":    dep.GroupID,
						"artifactId": dep.ArtifactID,
						"scope":      dep.Scope,
						"type":       dep.Type,
						"classifier": dep.Classifier,
						"optional":   dep.Optional,
					},
				},
			}
			packages = append(packages, pkg)
		}
	}

	return packages, nil
}

func (a *JavaPackageAnalyzer) parseGradleBuild(filePath string) ([]*types.Package, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var packages []*types.Package
	scanner := bufio.NewScanner(file)

	// Regex patterns for parsing Gradle dependencies
	// Supports both Groovy and Kotlin DSL syntax
	depRegexes := []*regexp.Regexp{
		// implementation 'group:artifact:version'
		regexp.MustCompile(`^\s*(\w+)\s+['"]([^:'"]+):([^:'"]+):([^'"]+)['"]`),
		// implementation group: 'group', name: 'artifact', version: 'version'
		regexp.MustCompile(`^\s*(\w+)\s+group:\s*['"]([^'"]+)['"]\s*,\s*name:\s*['"]([^'"]+)['"]\s*,\s*version:\s*['"]([^'"]+)['"]`),
		// implementation("group:artifact:version")
		regexp.MustCompile(`^\s*(\w+)\(['"]([^:'"]+):([^:'"]+):([^'"]+)['"]\)`),
	}

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip comments and empty lines
		if strings.HasPrefix(line, "//") || strings.HasPrefix(line, "/*") || line == "" {
			continue
		}

		// Try each regex pattern
		for _, regex := range depRegexes {
			matches := regex.FindStringSubmatch(line)
			if len(matches) >= 5 {
				configuration := matches[1]
				groupID := matches[2]
				artifactID := matches[3]
				version := matches[4]

				// Determine dependency type based on configuration
				depType := "production"
				switch configuration {
				case "testImplementation", "testCompile", "testRuntime", "testRuntimeOnly":
					depType = "development"
				case "compileOnly", "providedCompile":
					depType = "provided"
				case "runtimeOnly", "runtime":
					depType = "runtime"
				}

				pkg := &types.Package{
					Name:     fmt.Sprintf("%s:%s", groupID, artifactID),
					Version:  version,
					Registry: "maven-central",
					Type:     depType,
					Metadata: &types.PackageMetadata{
						Name:     fmt.Sprintf("%s:%s", groupID, artifactID),
						Version:  version,
						Registry: "maven-central",
						Metadata: map[string]interface{}{
							"ecosystem":     "java",
							"source":        filepath.Base(filePath),
							"groupId":       groupID,
							"artifactId":    artifactID,
							"configuration": configuration,
						},
					},
				}
				packages = append(packages, pkg)
				break
			}
		}
	}

	return packages, nil
}

func (a *JavaPackageAnalyzer) parseSBTBuild(filePath string) ([]*types.Package, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var packages []*types.Package
	scanner := bufio.NewScanner(file)

	// Regex patterns for parsing SBT dependencies
	depRegexes := []*regexp.Regexp{
		// libraryDependencies += "group" % "artifact" % "version"
		regexp.MustCompile(`libraryDependencies\s*\+=\s*['"]([^'"]+)['"]\s*%\s*['"]([^'"]+)['"]\s*%\s*['"]([^'"]+)['"]`),
		// libraryDependencies += "group" %% "artifact" % "version"
		regexp.MustCompile(`libraryDependencies\s*\+=\s*['"]([^'"]+)['"]\s*%%\s*['"]([^'"]+)['"]\s*%\s*['"]([^'"]+)['"]`),
		// "group" % "artifact" % "version" % "test"
		regexp.MustCompile(`['"]([^'"]+)['"]\s*%\s*['"]([^'"]+)['"]\s*%\s*['"]([^'"]+)['"]\s*%\s*['"]([^'"]+)['"]`),
	}

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip comments and empty lines
		if strings.HasPrefix(line, "//") || strings.HasPrefix(line, "/*") || line == "" {
			continue
		}

		// Try each regex pattern
		for _, regex := range depRegexes {
			matches := regex.FindStringSubmatch(line)
			if len(matches) >= 4 {
				groupID := matches[1]
				artifactID := matches[2]
				version := matches[3]

				depType := "production"
				if len(matches) >= 5 && matches[4] == "test" {
					depType = "development"
				}

				pkg := &types.Package{
					Name:     fmt.Sprintf("%s:%s", groupID, artifactID),
					Version:  version,
					Registry: "maven-central",
					Type:     depType,
					Metadata: &types.PackageMetadata{
						Name:     fmt.Sprintf("%s:%s", groupID, artifactID),
						Version:  version,
						Registry: "maven-central",
						Metadata: map[string]interface{}{
							"ecosystem":  "scala",
							"source":     "build.sbt",
							"groupId":    groupID,
							"artifactId": artifactID,
						},
					},
				}
				packages = append(packages, pkg)
				break
			}
		}
	}

	return packages, nil
}

func (a *JavaPackageAnalyzer) AnalyzeDependencies(projectInfo *ProjectInfo) (*types.DependencyTree, error) {
	packages, err := a.ExtractPackages(projectInfo)
	if err != nil {
		return nil, err
	}

	projectName := "java-project"
	projectVersion := "1.0.0"

	// Try to get project name and version from pom.xml
	pomPath := filepath.Join(projectInfo.Path, "pom.xml")
	if _, err := os.Stat(pomPath); err == nil {
		if name, version := a.extractMavenProjectInfo(pomPath); name != "" {
			projectName = name
			if version != "" {
				projectVersion = version
			}
		}
	}

	// Try Gradle settings if Maven not found
	if projectName == "java-project" {
		gradlePaths := []string{
			filepath.Join(projectInfo.Path, "build.gradle"),
			filepath.Join(projectInfo.Path, "build.gradle.kts"),
		}
		for _, gradlePath := range gradlePaths {
			if _, err := os.Stat(gradlePath); err == nil {
				if name, version := a.extractGradleProjectInfo(gradlePath); name != "" {
					projectName = name
					if version != "" {
						projectVersion = version
					}
				}
				break
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

func (a *JavaPackageAnalyzer) extractMavenProjectInfo(pomPath string) (string, string) {
	data, err := os.ReadFile(pomPath)
	if err != nil {
		return "", ""
	}

	var pom MavenPOM
	if err := xml.Unmarshal(data, &pom); err != nil {
		return "", ""
	}

	name := pom.ArtifactID
	if pom.Name != "" {
		name = pom.Name
	}

	return name, pom.Version
}

func (a *JavaPackageAnalyzer) extractGradleProjectInfo(gradlePath string) (string, string) {
	data, err := os.ReadFile(gradlePath)
	if err != nil {
		return "", ""
	}

	content := string(data)

	// Extract project name and version from Gradle build file
	nameRegex := regexp.MustCompile(`(?:rootProject\.)?name\s*=\s*['"]([^'"]+)['"]`)
	versionRegex := regexp.MustCompile(`version\s*=\s*['"]([^'"]+)['"]`)

	var name, version string

	if matches := nameRegex.FindStringSubmatch(content); len(matches) >= 2 {
		name = matches[1]
	}

	if matches := versionRegex.FindStringSubmatch(content); len(matches) >= 2 {
		version = matches[1]
	}

	return name, version
}
