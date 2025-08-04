package config

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// ProjectType represents the detected project type
type ProjectType string

const (
	ProjectTypeNodeJS     ProjectType = "nodejs"
	ProjectTypePython     ProjectType = "python"
	ProjectTypeGo         ProjectType = "go"
	ProjectTypeRust       ProjectType = "rust"
	ProjectTypeJava       ProjectType = "java"
	ProjectTypeRuby       ProjectType = "ruby"
	ProjectTypePHP        ProjectType = "php"
	ProjectTypeMultiLang  ProjectType = "multilang"
	ProjectTypeUnknown    ProjectType = "unknown"
)

// SecurityPreset represents predefined security configurations
type SecurityPreset string

const (
	PresetQuick      SecurityPreset = "quick"
	PresetBalanced   SecurityPreset = "balanced"
	PresetThorough   SecurityPreset = "thorough"
	PresetParanoid   SecurityPreset = "paranoid"
	PresetEnterprise SecurityPreset = "enterprise"
)

// ProjectInfo contains detected project characteristics
type ProjectInfo struct {
	Type         ProjectType
	Languages    []string
	Size         ProjectSize
	Dependencies int
	HasCI        bool
	IsMonorepo   bool
	Framework    string
}

// ProjectSize represents the project size category
type ProjectSize string

const (
	SizeSmall  ProjectSize = "small"   // < 100 files
	SizeMedium ProjectSize = "medium"  // 100-1000 files
	SizeLarge  ProjectSize = "large"   // 1000-10000 files
	SizeHuge   ProjectSize = "huge"    // > 10000 files
)

// SmartDefaultsEngine generates intelligent configuration defaults
type SmartDefaultsEngine struct {
	projectDetector     *ProjectDetector
	environmentDetector *EnvironmentDetector
}

// ProjectDetector detects project characteristics
type ProjectDetector struct{}

// EnvironmentDetector detects runtime environment
type EnvironmentDetector struct{}

// NewSmartDefaultsEngine creates a new smart defaults engine
func NewSmartDefaultsEngine() *SmartDefaultsEngine {
	return &SmartDefaultsEngine{
		projectDetector:     &ProjectDetector{},
		environmentDetector: &EnvironmentDetector{},
	}
}

// DetectProject analyzes the project directory and returns project information
func (e *SmartDefaultsEngine) DetectProject(projectPath string) (*ProjectInfo, error) {
	return e.projectDetector.DetectProject(projectPath)
}

// GenerateConfig generates an optimized configuration based on project analysis
func (s *SmartDefaultsEngine) GenerateConfig(projectPath string, preset SecurityPreset) (*Config, error) {
	// Detect project characteristics
	projectInfo, err := s.projectDetector.DetectProject(projectPath)
	if err != nil {
		return nil, fmt.Errorf("failed to detect project: %w", err)
	}

	// Detect environment
	envInfo := s.environmentDetector.DetectEnvironment()

	// Generate base configuration
	config := s.generateBaseConfig(projectInfo, envInfo, preset)

	// Apply project-specific optimizations
	s.applyProjectOptimizations(config, projectInfo)

	// Apply environment-specific optimizations
	s.applyEnvironmentOptimizations(config, envInfo)

	return config, nil
}

// DetectProject analyzes the project directory and returns project information
func (pd *ProjectDetector) DetectProject(projectPath string) (*ProjectInfo, error) {
	info := &ProjectInfo{
		Type:      ProjectTypeUnknown,
		Languages: []string{},
	}

	// Check for common project files
	files, err := os.ReadDir(projectPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read project directory: %w", err)
	}

	var fileCount int
	var dependencyFiles []string

	for _, file := range files {
		if file.IsDir() {
			continue
		}

		fileName := file.Name()
		fileCount++

		// Detect project type based on key files
		switch fileName {
		case "package.json":
			info.Type = ProjectTypeNodeJS
			info.Languages = append(info.Languages, "javascript")
			dependencyFiles = append(dependencyFiles, fileName)
		case "requirements.txt", "setup.py", "pyproject.toml", "Pipfile":
			info.Type = ProjectTypePython
			info.Languages = append(info.Languages, "python")
			dependencyFiles = append(dependencyFiles, fileName)
		case "go.mod", "go.sum":
			info.Type = ProjectTypeGo
			info.Languages = append(info.Languages, "go")
			dependencyFiles = append(dependencyFiles, fileName)
		case "Cargo.toml":
			info.Type = ProjectTypeRust
			info.Languages = append(info.Languages, "rust")
			dependencyFiles = append(dependencyFiles, fileName)
		case "pom.xml", "build.gradle":
			info.Type = ProjectTypeJava
			info.Languages = append(info.Languages, "java")
			dependencyFiles = append(dependencyFiles, fileName)
		case "Gemfile":
			info.Type = ProjectTypeRuby
			info.Languages = append(info.Languages, "ruby")
			dependencyFiles = append(dependencyFiles, fileName)
		case "composer.json":
			info.Type = ProjectTypePHP
			info.Languages = append(info.Languages, "php")
			dependencyFiles = append(dependencyFiles, fileName)
		}

		// Check for CI/CD files
		if strings.Contains(fileName, ".yml") || strings.Contains(fileName, ".yaml") {
			if strings.Contains(fileName, "ci") || strings.Contains(fileName, "workflow") {
				info.HasCI = true
			}
		}
	}

	// Determine project size
	info.Size = pd.determineProjectSize(fileCount)

	// Check for monorepo indicators
	info.IsMonorepo = pd.detectMonorepo(projectPath)

	// If multiple languages detected, mark as multilang
	if len(info.Languages) > 1 {
		info.Type = ProjectTypeMultiLang
	}

	// Estimate dependency count
	info.Dependencies = pd.estimateDependencyCount(projectPath, dependencyFiles)

	return info, nil
}

// determineProjectSize categorizes project size based on file count
func (pd *ProjectDetector) determineProjectSize(fileCount int) ProjectSize {
	switch {
	case fileCount < 100:
		return SizeSmall
	case fileCount < 1000:
		return SizeMedium
	case fileCount < 10000:
		return SizeLarge
	default:
		return SizeHuge
	}
}

// detectMonorepo checks for monorepo indicators
func (pd *ProjectDetector) detectMonorepo(projectPath string) bool {
	// Check for common monorepo structures
	monorepoIndicators := []string{
		"packages",
		"apps",
		"services",
		"modules",
		"workspaces",
	}

	for _, indicator := range monorepoIndicators {
		if _, err := os.Stat(filepath.Join(projectPath, indicator)); err == nil {
			return true
		}
	}

	return false
}

// estimateDependencyCount estimates the number of dependencies
func (pd *ProjectDetector) estimateDependencyCount(projectPath string, dependencyFiles []string) int {
	// This is a simplified estimation
	// In a real implementation, we would parse the actual dependency files
	baseCount := len(dependencyFiles) * 20 // Rough estimate
	
	// Adjust based on project type and size
	if len(dependencyFiles) > 2 {
		baseCount *= 2 // Likely more complex project
	}

	return baseCount
}

// EnvironmentInfo contains detected environment characteristics
type EnvironmentInfo struct {
	IsCI          bool
	IsContainer   bool
	IsProduction  bool
	CPUCores      int
	MemoryGB      int
	IsCloudEnv    bool
}

// DetectEnvironment detects the current runtime environment
func (ed *EnvironmentDetector) DetectEnvironment() *EnvironmentInfo {
	info := &EnvironmentInfo{
		CPUCores: runtime.NumCPU(),
	}

	// Check for CI environment
	ciEnvVars := []string{"CI", "CONTINUOUS_INTEGRATION", "GITHUB_ACTIONS", "GITLAB_CI", "JENKINS_URL"}
	for _, envVar := range ciEnvVars {
		if os.Getenv(envVar) != "" {
			info.IsCI = true
			break
		}
	}

	// Check for container environment
	if _, err := os.Stat("/.dockerenv"); err == nil {
		info.IsContainer = true
	}

	// Check for production environment
	env := strings.ToLower(os.Getenv("NODE_ENV"))
	if env == "production" || env == "prod" {
		info.IsProduction = true
	}

	// Check for cloud environment
	cloudEnvVars := []string{"AWS_REGION", "GOOGLE_CLOUD_PROJECT", "AZURE_SUBSCRIPTION_ID"}
	for _, envVar := range cloudEnvVars {
		if os.Getenv(envVar) != "" {
			info.IsCloudEnv = true
			break
		}
	}

	return info
}

// generateBaseConfig creates a base configuration based on preset
func (s *SmartDefaultsEngine) generateBaseConfig(projectInfo *ProjectInfo, envInfo *EnvironmentInfo, preset SecurityPreset) *Config {
	config := &Config{
		App: AppConfig{
			Name:        "typosentinel",
			Version:     "1.2.0",
			Environment: EnvDevelopment,
			Debug:       false,
			Verbose:     false,
			LogLevel:    "info",
			DataDir:     "./data",
			TempDir:     "/tmp",
			MaxWorkers:  s.calculateOptimalWorkers(envInfo.CPUCores),
		},
		Server: ServerConfig{
			Host:         "localhost",
			Port:         8080,
			ReadTimeout:  30 * time.Second,
			WriteTimeout: 30 * time.Second,
			IdleTimeout:  60 * time.Second,
		},
		TypoDetection: s.generateTypoDetectionConfig(preset),
		Features:      s.generateFeatureConfig(preset),
		Policies:      s.generatePoliciesConfig(preset),
	}

	// Adjust for environment
	if envInfo.IsProduction {
		config.App.Environment = EnvProduction
		config.App.Debug = false
		config.App.LogLevel = "warn"
	} else if envInfo.IsCI {
		config.App.Environment = EnvTesting
		config.App.Debug = false
		config.App.LogLevel = "info"
	}

	return config
}

// generateTypoDetectionConfig creates typo detection config based on preset
func (s *SmartDefaultsEngine) generateTypoDetectionConfig(preset SecurityPreset) *TypoDetectionConfig {
	switch preset {
	case PresetQuick:
		return &TypoDetectionConfig{
			Enabled:           true,
			Threshold:         0.9,
			MaxDistance:       2,
			CheckSimilarNames: true,
			CheckHomoglyphs:   false,
		}
	case PresetBalanced:
		return &TypoDetectionConfig{
			Enabled:           true,
			Threshold:         0.8,
			MaxDistance:       3,
			CheckSimilarNames: true,
			CheckHomoglyphs:   true,
		}
	case PresetThorough:
		return &TypoDetectionConfig{
			Enabled:           true,
			Threshold:         0.7,
			MaxDistance:       4,
			CheckSimilarNames: true,
			CheckHomoglyphs:   true,
		}
	case PresetParanoid, PresetEnterprise:
		return &TypoDetectionConfig{
			Enabled:           true,
			Threshold:         0.6,
			MaxDistance:       5,
			CheckSimilarNames: true,
			CheckHomoglyphs:   true,
		}
	default:
		return &TypoDetectionConfig{
			Enabled:           true,
			Threshold:         0.8,
			MaxDistance:       3,
			CheckSimilarNames: true,
			CheckHomoglyphs:   true,
		}
	}
}

// generateFeatureConfig creates feature config based on preset
func (s *SmartDefaultsEngine) generateFeatureConfig(preset SecurityPreset) FeatureConfig {
	switch preset {
	case PresetQuick:
		return FeatureConfig{
			MLScoring:       false,
			AdvancedMetrics: false,
			Caching:         true,
			AsyncProcessing: false,
			Webhooks:        false,
			BulkScanning:    false,
		}
	case PresetBalanced:
		return FeatureConfig{
			MLScoring:       true,
			AdvancedMetrics: true,
			Caching:         true,
			AsyncProcessing: true,
			Webhooks:        false,
			BulkScanning:    true,
		}
	case PresetThorough, PresetParanoid, PresetEnterprise:
		return FeatureConfig{
			MLScoring:       true,
			AdvancedMetrics: true,
			Caching:         true,
			AsyncProcessing: true,
			Webhooks:        true,
			BulkScanning:    true,
		}
	default:
		return FeatureConfig{
			MLScoring:       true,
			AdvancedMetrics: true,
			Caching:         true,
			AsyncProcessing: true,
			Webhooks:        false,
			BulkScanning:    true,
		}
	}
}

// generatePoliciesConfig creates policies config based on preset
func (s *SmartDefaultsEngine) generatePoliciesConfig(preset SecurityPreset) PoliciesConfig {
	switch preset {
	case PresetQuick:
		return PoliciesConfig{
			FailOnThreats:  false,
			MinThreatLevel: "high",
		}
	case PresetBalanced:
		return PoliciesConfig{
			FailOnThreats:  true,
			MinThreatLevel: "medium",
		}
	case PresetThorough:
		return PoliciesConfig{
			FailOnThreats:  true,
			MinThreatLevel: "low",
		}
	case PresetParanoid, PresetEnterprise:
		return PoliciesConfig{
			FailOnThreats:  true,
			MinThreatLevel: "low",
		}
	default:
		return PoliciesConfig{
			FailOnThreats:  true,
			MinThreatLevel: "medium",
		}
	}
}

// calculateOptimalWorkers calculates optimal number of workers based on CPU cores
func (s *SmartDefaultsEngine) calculateOptimalWorkers(cpuCores int) int {
	// Use 2x CPU cores for I/O bound operations, but cap at reasonable limits
	workers := cpuCores * 2
	
	if workers < 2 {
		workers = 2
	} else if workers > 20 {
		workers = 20
	}
	
	return workers
}

// applyProjectOptimizations applies project-specific optimizations
func (s *SmartDefaultsEngine) applyProjectOptimizations(config *Config, projectInfo *ProjectInfo) {
	// Adjust timeouts based on project size
	switch projectInfo.Size {
	case SizeSmall:
		config.Server.ReadTimeout = 15 * time.Second
		config.Server.WriteTimeout = 15 * time.Second
	case SizeMedium:
		config.Server.ReadTimeout = 30 * time.Second
		config.Server.WriteTimeout = 30 * time.Second
	case SizeLarge:
		config.Server.ReadTimeout = 60 * time.Second
		config.Server.WriteTimeout = 60 * time.Second
	case SizeHuge:
		config.Server.ReadTimeout = 120 * time.Second
		config.Server.WriteTimeout = 120 * time.Second
	}

	// Adjust worker count based on project complexity
	if projectInfo.Dependencies > 100 {
		config.App.MaxWorkers = min(config.App.MaxWorkers*2, 30)
	}

	// Enable advanced features for complex projects
	if projectInfo.IsMonorepo || projectInfo.Type == ProjectTypeMultiLang {
		config.Features.BulkScanning = true
		config.Features.AsyncProcessing = true
	}
}

// applyEnvironmentOptimizations applies environment-specific optimizations
func (s *SmartDefaultsEngine) applyEnvironmentOptimizations(config *Config, envInfo *EnvironmentInfo) {
	// CI/CD optimizations
	if envInfo.IsCI {
		config.Features.Caching = false // Avoid cache issues in CI
		config.App.Verbose = true       // More verbose output for CI logs
	}

	// Container optimizations
	if envInfo.IsContainer {
		config.Server.Host = "0.0.0.0" // Bind to all interfaces in container
	}

	// Production optimizations
	if envInfo.IsProduction {
		config.Features.AdvancedMetrics = true
		config.Features.Webhooks = true
	}

	// Resource-based optimizations
	if envInfo.CPUCores >= 8 {
		config.Features.AsyncProcessing = true
		config.App.MaxWorkers = min(envInfo.CPUCores*2, 40)
	}
}

// min returns the minimum of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// GetPresetDescription returns a human-readable description of the preset
func GetPresetDescription(preset SecurityPreset) string {
	switch preset {
	case PresetQuick:
		return "Fast scanning with basic security checks. Good for development and quick validation."
	case PresetBalanced:
		return "Balanced security and performance. Recommended for most projects."
	case PresetThorough:
		return "Comprehensive security scanning. Slower but more thorough detection."
	case PresetParanoid:
		return "Maximum security with aggressive detection. May produce more false positives."
	case PresetEnterprise:
		return "Enterprise-grade security with all features enabled. Optimized for production environments."
	default:
		return "Standard security configuration."
	}
}

// GetProjectTypeDescription returns a description of the detected project type
func GetProjectTypeDescription(projectType ProjectType) string {
	switch projectType {
	case ProjectTypeNodeJS:
		return "Node.js/JavaScript project detected"
	case ProjectTypePython:
		return "Python project detected"
	case ProjectTypeGo:
		return "Go project detected"
	case ProjectTypeRust:
		return "Rust project detected"
	case ProjectTypeJava:
		return "Java project detected"
	case ProjectTypeRuby:
		return "Ruby project detected"
	case ProjectTypePHP:
		return "PHP project detected"
	case ProjectTypeMultiLang:
		return "Multi-language project detected"
	default:
		return "Unknown project type"
	}
}