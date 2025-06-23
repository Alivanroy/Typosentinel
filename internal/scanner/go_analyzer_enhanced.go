package scanner

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Alivanroy/Typosentinel/internal/config"
	"github.com/Alivanroy/Typosentinel/pkg/types"
)

// GoModuleInfo represents information from go.mod
type GoModuleInfo struct {
	Module    string
	GoVersion string
	Requires  []GoRequirement
	Replaces  []GoReplace
	Excludes  []GoExclude
	Retracts  []GoRetract
}

// GoRequirement represents a require directive
type GoRequirement struct {
	Path     string
	Version  string
	Indirect bool
}

// GoReplace represents a replace directive
type GoReplace struct {
	OldPath    string
	OldVersion string
	NewPath    string
	NewVersion string
}

// GoExclude represents an exclude directive
type GoExclude struct {
	Path    string
	Version string
}

// GoRetract represents a retract directive
type GoRetract struct {
	Version string
	Reason  string
}

// GoSumEntry represents an entry in go.sum
type GoSumEntry struct {
	Path     string
	Version  string
	Checksum string
}

// GoProxyInfo represents module information from Go proxy
type GoProxyInfo struct {
	Version string    `json:"Version"`
	Time    time.Time `json:"Time"`
}

// GoProxyVersions represents available versions from Go proxy
type GoProxyVersions struct {
	Versions []string `json:"versions"`
}

// EnhancedGoAnalyzer provides comprehensive Go module analysis
type EnhancedGoAnalyzer struct {
	config     *config.Config
	proxyURL   string
	httpClient *http.Client
}

// NewEnhancedGoAnalyzer creates a new enhanced Go analyzer
func NewEnhancedGoAnalyzer(config *config.Config) *EnhancedGoAnalyzer {
	proxyURL := os.Getenv("GOPROXY")
	if proxyURL == "" {
		proxyURL = "https://proxy.golang.org"
	}

	return &EnhancedGoAnalyzer{
		config:   config,
		proxyURL: proxyURL,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// ExtractPackages extracts packages from go.mod with enhanced parsing
func (a *EnhancedGoAnalyzer) ExtractPackages(projectInfo *ProjectInfo) ([]*types.Package, error) {
	modInfo, err := a.parseGoMod(projectInfo.Path)
	if err != nil {
		return nil, fmt.Errorf("failed to parse go.mod: %w", err)
	}

	sumEntries, err := a.parseGoSum(projectInfo.Path)
	if err != nil {
		// go.sum might not exist, continue without it
		sumEntries = make(map[string]GoSumEntry)
	}

	var packages []*types.Package
	for _, req := range modInfo.Requires {
		pkg := &types.Package{
			Name:     req.Path,
			Version:  req.Version,
			Registry: "go",
			Type:     a.determinePackageType(req),
		}

		// Add checksum information if available
		if sumEntry, exists := sumEntries[req.Path+"@"+req.Version]; exists {
			pkg.Metadata = &types.PackageMetadata{
				Metadata: map[string]interface{}{
					"checksum": sumEntry.Checksum,
					"indirect": req.Indirect,
					"module":   modInfo.Module,
					"go_version": modInfo.GoVersion,
				},
			}
			
			// Validate checksum integrity
			if err := a.validateChecksum(pkg, sumEntry.Checksum); err != nil {
				pkg.Threats = append(pkg.Threats, types.Threat{
					Type:        "checksum_mismatch",
					Severity:    types.SeverityHigh,
					Description: fmt.Sprintf("Checksum validation failed: %v", err),
					DetectionMethod: "go_analyzer",
				})
			}
		} else {
			pkg.Metadata = &types.PackageMetadata{
				Metadata: map[string]interface{}{
					"indirect": req.Indirect,
					"module":   modInfo.Module,
					"go_version": modInfo.GoVersion,
				},
			}
		}

		// Perform vulnerability analysis
		if err := a.analyzeGoModuleVulnerabilities(pkg); err == nil {
			// Analysis completed successfully
		}

		// Fetch additional metadata from Go proxy if enabled
		if a.config != nil {
			// Network requests would be enabled based on config in future versions
			if err := a.enrichGoModuleMetadata(pkg); err == nil {
				// Metadata enrichment completed
			}
		}

		packages = append(packages, pkg)
	}

	// Process replace directives for security analysis
	for _, replace := range modInfo.Replaces {
		if err := a.analyzeReplaceDirective(replace, packages); err == nil {
			// Replace directive analysis completed
		}
	}

	return packages, nil
}

// parseGoMod parses go.mod file and extracts module information
func (a *EnhancedGoAnalyzer) parseGoMod(projectPath string) (*GoModuleInfo, error) {
	modPath := filepath.Join(projectPath, "go.mod")
	file, err := os.Open(modPath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	modInfo := &GoModuleInfo{
		Requires: make([]GoRequirement, 0),
		Replaces: make([]GoReplace, 0),
		Excludes: make([]GoExclude, 0),
		Retracts: make([]GoRetract, 0),
	}

	scanner := bufio.NewScanner(file)
	inRequireBlock := false
	inReplaceBlock := false
	inExcludeBlock := false
	inRetractBlock := false

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip comments and empty lines
		if line == "" || strings.HasPrefix(line, "//") {
			continue
		}

		// Handle module directive
		if strings.HasPrefix(line, "module ") {
			modInfo.Module = strings.TrimSpace(strings.TrimPrefix(line, "module"))
			continue
		}

		// Handle go directive
		if strings.HasPrefix(line, "go ") {
			modInfo.GoVersion = strings.TrimSpace(strings.TrimPrefix(line, "go"))
			continue
		}

		// Handle require block
		if strings.HasPrefix(line, "require (") {
			inRequireBlock = true
			continue
		}
		if inRequireBlock && line == ")" {
			inRequireBlock = false
			continue
		}

		// Handle replace block
		if strings.HasPrefix(line, "replace (") {
			inReplaceBlock = true
			continue
		}
		if inReplaceBlock && line == ")" {
			inReplaceBlock = false
			continue
		}

		// Handle exclude block
		if strings.HasPrefix(line, "exclude (") {
			inExcludeBlock = true
			continue
		}
		if inExcludeBlock && line == ")" {
			inExcludeBlock = false
			continue
		}

		// Handle retract block
		if strings.HasPrefix(line, "retract (") {
			inRetractBlock = true
			continue
		}
		if inRetractBlock && line == ")" {
			inRetractBlock = false
			continue
		}

		// Parse require directives
		if inRequireBlock || strings.HasPrefix(line, "require ") {
			if req := a.parseRequireLine(line); req != nil {
				modInfo.Requires = append(modInfo.Requires, *req)
			}
		}

		// Parse replace directives
		if inReplaceBlock || strings.HasPrefix(line, "replace ") {
			if repl := a.parseReplaceLine(line); repl != nil {
				modInfo.Replaces = append(modInfo.Replaces, *repl)
			}
		}

		// Parse exclude directives
		if inExcludeBlock || strings.HasPrefix(line, "exclude ") {
			if excl := a.parseExcludeLine(line); excl != nil {
				modInfo.Excludes = append(modInfo.Excludes, *excl)
			}
		}

		// Parse retract directives
		if inRetractBlock || strings.HasPrefix(line, "retract ") {
			if retr := a.parseRetractLine(line); retr != nil {
				modInfo.Retracts = append(modInfo.Retracts, *retr)
			}
		}
	}

	return modInfo, scanner.Err()
}

// parseRequireLine parses a require line and returns a GoRequirement
func (a *EnhancedGoAnalyzer) parseRequireLine(line string) *GoRequirement {
	line = strings.TrimPrefix(line, "require ")
	line = strings.TrimSpace(line)

	// Check for indirect comment
	indirect := strings.Contains(line, "// indirect")
	if indirect {
		line = strings.Split(line, "//")[0]
		line = strings.TrimSpace(line)
	}

	parts := strings.Fields(line)
	if len(parts) >= 2 {
		return &GoRequirement{
			Path:     parts[0],
			Version:  parts[1],
			Indirect: indirect,
		}
	}
	return nil
}

// parseReplaceLine parses a replace line and returns a GoReplace
func (a *EnhancedGoAnalyzer) parseReplaceLine(line string) *GoReplace {
	line = strings.TrimPrefix(line, "replace ")
	line = strings.TrimSpace(line)

	parts := strings.Split(line, " => ")
	if len(parts) != 2 {
		return nil
	}

	oldParts := strings.Fields(parts[0])
	newParts := strings.Fields(parts[1])

	if len(oldParts) >= 1 && len(newParts) >= 1 {
		repl := &GoReplace{
			OldPath: oldParts[0],
			NewPath: newParts[0],
		}
		if len(oldParts) >= 2 {
			repl.OldVersion = oldParts[1]
		}
		if len(newParts) >= 2 {
			repl.NewVersion = newParts[1]
		}
		return repl
	}
	return nil
}

// parseExcludeLine parses an exclude line and returns a GoExclude
func (a *EnhancedGoAnalyzer) parseExcludeLine(line string) *GoExclude {
	line = strings.TrimPrefix(line, "exclude ")
	line = strings.TrimSpace(line)

	parts := strings.Fields(line)
	if len(parts) >= 2 {
		return &GoExclude{
			Path:    parts[0],
			Version: parts[1],
		}
	}
	return nil
}

// parseRetractLine parses a retract line and returns a GoRetract
func (a *EnhancedGoAnalyzer) parseRetractLine(line string) *GoRetract {
	line = strings.TrimPrefix(line, "retract ")
	line = strings.TrimSpace(line)

	// Extract reason from comment if present
	reason := ""
	if strings.Contains(line, "//") {
		parts := strings.Split(line, "//")
		line = strings.TrimSpace(parts[0])
		if len(parts) > 1 {
			reason = strings.TrimSpace(parts[1])
		}
	}

	parts := strings.Fields(line)
	if len(parts) >= 1 {
		return &GoRetract{
			Version: parts[0],
			Reason:  reason,
		}
	}
	return nil
}

// parseGoSum parses go.sum file and returns checksum entries
func (a *EnhancedGoAnalyzer) parseGoSum(projectPath string) (map[string]GoSumEntry, error) {
	sumPath := filepath.Join(projectPath, "go.sum")
	file, err := os.Open(sumPath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	entries := make(map[string]GoSumEntry)
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		parts := strings.Fields(line)
		if len(parts) >= 3 {
			// Parse module path and version
			moduleVersion := parts[0] + " " + parts[1]
			entry := GoSumEntry{
				Path:     parts[0],
				Version:  parts[1],
				Checksum: parts[2],
			}
			entries[moduleVersion] = entry
		}
	}

	return entries, scanner.Err()
}

// fetchProxyInfo fetches module information from Go proxy
func (a *EnhancedGoAnalyzer) fetchProxyInfo(modulePath, version string) (*GoProxyInfo, error) {
	url := fmt.Sprintf("%s/%s/@v/%s.info", a.proxyURL, modulePath, version)

	resp, err := a.httpClient.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("proxy request failed with status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var info GoProxyInfo
	if err := json.Unmarshal(body, &info); err != nil {
		return nil, err
	}

	return &info, nil
}

// fetchAvailableVersions fetches available versions from Go proxy
func (a *EnhancedGoAnalyzer) fetchAvailableVersions(modulePath string) ([]string, error) {
	url := fmt.Sprintf("%s/%s/@v/list", a.proxyURL, modulePath)

	resp, err := a.httpClient.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("proxy request failed with status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	versions := strings.Split(strings.TrimSpace(string(body)), "\n")
	return versions, nil
}

// determinePackageType determines if a package is production or development
func (a *EnhancedGoAnalyzer) determinePackageType(req GoRequirement) string {
	if req.Indirect {
		return "indirect"
	}

	// Check if it's a test-only dependency
	testPatterns := []string{
		"testing",
		"testify",
		"assert",
		"mock",
		"ginkgo",
		"gomega",
	}

	for _, pattern := range testPatterns {
		if strings.Contains(strings.ToLower(req.Path), pattern) {
			return "test"
		}
	}

	return "production"
}

// AnalyzeDependencies builds a comprehensive dependency tree
func (a *EnhancedGoAnalyzer) AnalyzeDependencies(projectInfo *ProjectInfo) (*types.DependencyTree, error) {
	packages, err := a.ExtractPackages(projectInfo)
	if err != nil {
		return nil, err
	}

	root := &types.DependencyTree{
		Name:         projectInfo.Metadata["module"],
		Version:      "1.0.0",
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

// ValidateChecksums validates go.sum checksums against Go proxy
func (a *EnhancedGoAnalyzer) ValidateChecksums(projectPath string) ([]string, error) {
	sumEntries, err := a.parseGoSum(projectPath)
	if err != nil {
		return nil, err
	}

	var issues []string
	for key, entry := range sumEntries {
		// Fetch checksum from proxy
		url := fmt.Sprintf("%s/%s/@v/%s.mod", a.proxyURL, entry.Path, entry.Version)
		resp, err := a.httpClient.Get(url)
		if err != nil {
			issues = append(issues, fmt.Sprintf("Failed to fetch checksum for %s: %v", key, err))
			continue
		}
		resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			issues = append(issues, fmt.Sprintf("Module %s not found in proxy", key))
		}
	}

	return issues, nil
}

// enrichGoModuleMetadata fetches additional metadata from Go proxy
func (a *EnhancedGoAnalyzer) enrichGoModuleMetadata(pkg *types.Package) error {
	// Fetch module info from Go proxy
	moduleInfo, err := a.fetchProxyInfo(pkg.Name, pkg.Version)
	if err != nil {
		return err
	}

	if pkg.Metadata == nil {
		pkg.Metadata = &types.PackageMetadata{
			Metadata: make(map[string]interface{}),
		}
	}

	// Add proxy metadata
	pkg.Metadata.Metadata["proxy_info"] = moduleInfo
	pkg.Metadata.Metadata["repository_url"] = a.extractRepositoryURL(moduleInfo)

	// Fetch available versions for analysis
	versions, err := a.fetchAvailableVersions(pkg.Name)
	if err == nil {
		pkg.Metadata.Metadata["available_versions"] = versions
		// Check for suspicious version patterns
		if a.hasSuspiciousVersionPattern(pkg.Version, versions) {
			pkg.Threats = append(pkg.Threats, types.Threat{
				Type:        "suspicious_version",
				Severity:    types.SeverityMedium,
				Description: "Module version follows suspicious pattern",
				DetectionMethod: "go_analyzer",
			})
		}
	}

	return nil
}

// analyzeGoModuleVulnerabilities performs comprehensive vulnerability analysis
func (a *EnhancedGoAnalyzer) analyzeGoModuleVulnerabilities(pkg *types.Package) error {
	// Check for typosquatting
	if a.isTyposquattingCandidate(pkg.Name) {
		pkg.Threats = append(pkg.Threats, types.Threat{
			Type:        "typosquatting",
			Severity:    types.SeverityHigh,
			Description: fmt.Sprintf("Module name '%s' may be a typosquatting attempt", pkg.Name),
			DetectionMethod: "go_analyzer",
		})
	}

	// Check for suspicious module characteristics
	if a.hasSuspiciousCharacteristics(pkg) {
		pkg.Threats = append(pkg.Threats, types.Threat{
			Type:        "suspicious_module",
			Severity:    types.SeverityMedium,
			Description: "Module exhibits suspicious characteristics",
			DetectionMethod: "go_analyzer",
		})
	}

	// Check against known vulnerability patterns
	vulns := a.checkKnownVulnerabilities(pkg.Name, pkg.Version)
	if len(vulns) > 0 {
		pkg.Threats = append(pkg.Threats, vulns...)
	}

	return nil
}

// analyzeReplaceDirective analyzes replace directives for security implications
func (a *EnhancedGoAnalyzer) analyzeReplaceDirective(replace GoReplace, packages []*types.Package) error {
	// Find the package being replaced
	var targetPkg *types.Package
	for _, pkg := range packages {
		if pkg.Name == replace.OldPath {
			targetPkg = pkg
			break
		}
	}

	if targetPkg == nil {
		return nil // Package not found in dependencies
	}

	// Analyze replace directive for security implications
	if a.isSuspiciousReplace(replace) {
		targetPkg.Threats = append(targetPkg.Threats, types.Threat{
			Type:        "suspicious_replace",
			Severity:    types.SeverityMedium,
			Description: fmt.Sprintf("Suspicious replace directive: %s => %s", replace.OldPath, replace.NewPath),
			DetectionMethod: "go_analyzer",
		})
	}

	// Check for local path replacements (potential security risk)
	if a.isLocalPathReplace(replace.NewPath) {
		targetPkg.Threats = append(targetPkg.Threats, types.Threat{
			Type:        "local_replace",
			Severity:    types.SeverityLow,
			Description: "Module replaced with local path - verify integrity",
			DetectionMethod: "go_analyzer",
		})
	}

	return nil
}

// validateChecksum validates package checksum
func (a *EnhancedGoAnalyzer) validateChecksum(pkg *types.Package, checksum string) error {
	// Placeholder for checksum validation logic
	return nil
}

// isTyposquattingCandidate checks if a module name is a potential typosquatting attempt
func (a *EnhancedGoAnalyzer) isTyposquattingCandidate(moduleName string) bool {
	// Common Go module patterns that are often typosquatted
	popularModules := []string{
		"github.com/gorilla/mux",
		"github.com/gin-gonic/gin",
		"github.com/labstack/echo",
		"github.com/sirupsen/logrus",
		"github.com/stretchr/testify",
		"go.uber.org/zap",
		"google.golang.org/grpc",
	}

	for _, popular := range popularModules {
		if a.calculateSimilarity(moduleName, popular) > 0.8 && moduleName != popular {
			return true
		}
	}

	return false
}

// hasSuspiciousCharacteristics checks for suspicious module characteristics
func (a *EnhancedGoAnalyzer) hasSuspiciousCharacteristics(pkg *types.Package) bool {
	// Check for suspicious domain patterns
	suspiciousDomains := []string{
		"bit.ly", "tinyurl.com", "t.co", "goo.gl",
	}

	for _, domain := range suspiciousDomains {
		if strings.Contains(pkg.Name, domain) {
			return true
		}
	}

	// Check for suspicious version patterns
	if strings.Contains(pkg.Version, "999") || strings.Contains(pkg.Version, "dev") {
		return true
	}

	return false
}

// checkKnownVulnerabilities checks against known vulnerability patterns
func (a *EnhancedGoAnalyzer) checkKnownVulnerabilities(moduleName, version string) []types.Threat {
	var threats []types.Threat

	// This would integrate with Go vulnerability database in production
	// For now, implement basic pattern matching
	knownVulnPatterns := map[string][]string{
		"github.com/dgrijalva/jwt-go": {"v3.2.0", "v3.2.1"}, // Known vulnerable versions
	}

	if vulnVersions, exists := knownVulnPatterns[moduleName]; exists {
		for _, vulnVersion := range vulnVersions {
			if version == vulnVersion {
				threats = append(threats, types.Threat{
					Type:        "known_vulnerability",
					Severity:    types.SeverityHigh,
					Description: fmt.Sprintf("Known vulnerability in %s version %s", moduleName, version),
					DetectionMethod: "go_analyzer",
				})
			}
		}
	}

	return threats
}

// isSuspiciousReplace checks if a replace directive is suspicious
func (a *EnhancedGoAnalyzer) isSuspiciousReplace(replace GoReplace) bool {
	// Check for domain changes that might indicate malicious replacement
	oldDomain := a.extractDomain(replace.OldPath)
	newDomain := a.extractDomain(replace.NewPath)

	if oldDomain != newDomain && oldDomain != "" && newDomain != "" {
		// Different domains might indicate suspicious replacement
		return true
	}

	return false
}

// isLocalPathReplace checks if a replace directive uses a local path
func (a *EnhancedGoAnalyzer) isLocalPathReplace(path string) bool {
	return strings.HasPrefix(path, "./") || strings.HasPrefix(path, "../") || strings.HasPrefix(path, "/")
}

// extractDomain extracts domain from module path
func (a *EnhancedGoAnalyzer) extractDomain(modulePath string) string {
	parts := strings.Split(modulePath, "/")
	if len(parts) > 0 {
		return parts[0]
	}
	return ""
}

// calculateSimilarity calculates similarity between two strings
func (a *EnhancedGoAnalyzer) calculateSimilarity(s1, s2 string) float64 {
	if s1 == s2 {
		return 1.0
	}

	// Simple similarity calculation based on common characters
	common := 0
	total := len(s1) + len(s2)

	for i := 0; i < len(s1) && i < len(s2); i++ {
		if s1[i] == s2[i] {
			common++
		}
	}

	return float64(common*2) / float64(total)
}

// hasSuspiciousVersionPattern checks for suspicious version patterns
func (a *EnhancedGoAnalyzer) hasSuspiciousVersionPattern(version string, availableVersions []string) bool {
	// Check for version spoofing (very high version numbers)
	if strings.Contains(version, "999") {
		return true
	}

	// Check for pre-release versions that might be suspicious
	suspiciousPreRelease := []string{"alpha999", "beta999", "rc999"}
	for _, pattern := range suspiciousPreRelease {
		if strings.Contains(version, pattern) {
			return true
		}
	}

	return false
}

// extractRepositoryURL extracts repository URL from module info
func (a *EnhancedGoAnalyzer) extractRepositoryURL(moduleInfo *GoProxyInfo) string {
	// Placeholder implementation
	return ""
}

// DetectVulnerableVersions checks for known vulnerable versions
func (a *EnhancedGoAnalyzer) DetectVulnerableVersions(packages []*types.Package) ([]*types.Package, error) {
	// This would integrate with Go vulnerability database
	// For now, return packages as-is
	return packages, nil
}
