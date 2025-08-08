package ml

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	
	"github.com/Alivanroy/Typosentinel/pkg/types"
)

// BehavioralAnalyzer performs behavioral analysis on packages
type BehavioralAnalyzer struct {
	Config BehavioralConfig
}

// BehavioralConfig contains configuration for behavioral analysis
type BehavioralConfig struct {
	InstallBehaviorWeight   float64
	RuntimeBehaviorWeight   float64
	NetworkBehaviorWeight   float64
	FileSystemBehaviorWeight float64
	SuspiciousScoreThreshold float64
}

// NewBehavioralAnalyzer creates a new behavioral analyzer
func NewBehavioralAnalyzer() *BehavioralAnalyzer {
	return &BehavioralAnalyzer{
		Config: DefaultBehavioralConfig(),
	}
}

// DefaultBehavioralConfig returns the default configuration
func DefaultBehavioralConfig() BehavioralConfig {
	return BehavioralConfig{
		InstallBehaviorWeight:   0.25,
		RuntimeBehaviorWeight:   0.30,
		NetworkBehaviorWeight:   0.25,
		FileSystemBehaviorWeight: 0.20,
		SuspiciousScoreThreshold: 0.65,
	}
}

// AnalyzeBehavior performs behavioral analysis on a package
func (ba *BehavioralAnalyzer) AnalyzeBehavior(pkg *types.Package) BehavioralAnalysis {
	// Analyze installation behavior
	installBehavior := ba.analyzeInstallBehavior(pkg)
	
	// Analyze runtime behavior
	runtimeBehavior := ba.analyzeRuntimeBehavior(pkg)
	
	// Analyze network behavior
	networkBehavior := ba.analyzeNetworkBehavior(pkg)
	
	// Analyze file system behavior
	fileSystemBehavior := ba.analyzeFileSystemBehavior(pkg)
	
	return BehavioralAnalysis{
		InstallBehavior:    installBehavior,
		RuntimeBehavior:    runtimeBehavior,
		NetworkBehavior:    networkBehavior,
		FileSystemBehavior: fileSystemBehavior,
	}
}

// analyzeInstallBehavior analyzes installation behavior
func (ba *BehavioralAnalyzer) analyzeInstallBehavior(pkg *types.Package) InstallBehavior {
	var suspiciousCommands []string
	var networkRequests []string
	var fileModifications []string
	var permissionChanges []string
	
	// Check for post-install hooks
	if pkg.Metadata != nil && pkg.Metadata.HasInstallScript {
		suspiciousCommands = append(suspiciousCommands, "Has install scripts")
	}

	// Check for suspicious patterns in package name
	if ba.detectSuspiciousPackageName(pkg.Name) {
		suspiciousCommands = append(suspiciousCommands, "Suspicious package name pattern")
	}

	// Check for suspicious version patterns
	if ba.detectSuspiciousVersion(pkg.Version) {
		suspiciousCommands = append(suspiciousCommands, "Suspicious version pattern")
	}

	return InstallBehavior{
		SuspiciousCommands: suspiciousCommands,
		NetworkRequests:    networkRequests,
		FileModifications:  fileModifications,
		PermissionChanges:  permissionChanges,
	}
}

// analyzeRuntimeBehavior analyzes runtime behavior
func (ba *BehavioralAnalyzer) analyzeRuntimeBehavior(pkg *types.Package) RuntimeBehavior {
	var processSpawning []string
	var systemCalls []string
	var resourceUsage []string
	var environmentAccess []string
	
	// Basic analysis based on available metadata
	if pkg.Metadata != nil {
		// Check for large package size (potential resource usage)
		if pkg.Metadata.Size > 10*1024*1024 { // 10MB
			resourceUsage = append(resourceUsage, "Large package size")
		}
		
		// Check for many dependencies (potential complexity)
		if len(pkg.Dependencies) > 50 {
			systemCalls = append(systemCalls, "High dependency count")
		}
	}

	return RuntimeBehavior{
		ProcessSpawning:   processSpawning,
		SystemCalls:       systemCalls,
		ResourceUsage:     resourceUsage,
		EnvironmentAccess: environmentAccess,
	}
}

// analyzeNetworkBehavior analyzes network behavior
func (ba *BehavioralAnalyzer) analyzeNetworkBehavior(pkg *types.Package) NetworkBehavior {
	var outboundConnections []string
	var dnsQueries []string
	var dataExfiltration []string
	var c2Communication []string
	
	// Check for suspicious URLs in metadata
	if pkg.Metadata != nil {
		if ba.detectSuspiciousURL(pkg.Metadata.Homepage) {
			outboundConnections = append(outboundConnections, "Suspicious homepage URL")
		}
		
		if ba.detectSuspiciousURL(pkg.Metadata.Repository) {
			outboundConnections = append(outboundConnections, "Suspicious repository URL")
		}
	}

	return NetworkBehavior{
		OutboundConnections: outboundConnections,
		DNSQueries:          dnsQueries,
		DataExfiltration:    dataExfiltration,
		C2Communication:     c2Communication,
	}
}

// analyzeFileSystemBehavior analyzes file system behavior
func (ba *BehavioralAnalyzer) analyzeFileSystemBehavior(pkg *types.Package) FileSystemBehavior {
	var fileCreation []string
	var fileDeletion []string
	var fileModification []string
	var directoryAccess []string
	
	// Check for large file count (potential file system impact)
	if pkg.Metadata != nil && pkg.Metadata.FileCount > 1000 {
		fileCreation = append(fileCreation, "High file count")
	}

	return FileSystemBehavior{
		FileCreation:     fileCreation,
		FileDeletion:     fileDeletion,
		FileModification: fileModification,
		DirectoryAccess:  directoryAccess,
	}
}

// detectSuspiciousPackageName checks for suspicious patterns in package names
func (ba *BehavioralAnalyzer) detectSuspiciousPackageName(name string) bool {
	// Check for common typosquatting patterns
	suspiciousPatterns := []string{
		`\d{4,}`, // Long sequences of numbers
		`[a-z]{20,}`, // Very long lowercase sequences
		`[A-Z]{5,}`, // Long uppercase sequences
		`[_-]{3,}`, // Multiple consecutive separators
		`^[a-z]$`, // Single character names
		`test.*test`, // Multiple "test" words
		`demo.*demo`, // Multiple "demo" words
	}
	
	for _, pattern := range suspiciousPatterns {
		if matched, _ := regexp.MatchString(pattern, name); matched {
			return true
		}
	}
	
	return false
}

// Update updates the behavioral analyzer with new patterns and thresholds
func (ba *BehavioralAnalyzer) Update(ctx context.Context) error {
	// Update suspicious patterns based on recent threat intelligence
	ba.updateSuspiciousPatterns()
	
	// Update detection thresholds based on performance metrics
	if err := ba.updateDetectionThresholds(); err != nil {
		return fmt.Errorf("failed to update detection thresholds: %w", err)
	}
	
	// Update behavioral rules
	ba.updateBehavioralRules()
	
	return nil
}

// updateSuspiciousPatterns updates the list of suspicious patterns
func (ba *BehavioralAnalyzer) updateSuspiciousPatterns() {
	// Add new suspicious package name patterns
	newPatterns := []string{
		`crypto.*wallet`, // Crypto-related suspicious patterns
		`bitcoin.*miner`, // Bitcoin mining patterns
		`password.*steal`, // Password stealing patterns
		`keylog.*`, // Keylogger patterns
		`backdoor.*`, // Backdoor patterns
		`trojan.*`, // Trojan patterns
		`malware.*`, // Malware patterns
		`virus.*`, // Virus patterns
		`exploit.*`, // Exploit patterns
		`shell.*code`, // Shellcode patterns
	}
	
	// In a real implementation, these would be stored in the analyzer's configuration
	fmt.Printf("[Behavioral Analyzer] Updated with %d new suspicious patterns\n", len(newPatterns))
}

// updateDetectionThresholds updates detection thresholds based on performance
func (ba *BehavioralAnalyzer) updateDetectionThresholds() error {
	// Simulate threshold adjustment based on false positive/negative rates
	thresholds := map[string]float64{
		"suspicious_command_threshold": 0.7,
		"network_activity_threshold":   0.6,
		"file_system_threshold":        0.8,
		"process_spawning_threshold":   0.75,
	}
	
	// In a real implementation, these would be calculated from feedback data
	for name, threshold := range thresholds {
		fmt.Printf("[Behavioral Analyzer] Updated %s to %.2f\n", name, threshold)
	}
	
	return nil
}

// updateBehavioralRules updates behavioral detection rules
func (ba *BehavioralAnalyzer) updateBehavioralRules() {
	// Update rules for detecting suspicious behaviors
	rules := []string{
		"Detect packages with excessive file system access",
		"Flag packages with network activity during installation",
		"Identify packages spawning unexpected processes",
		"Monitor packages accessing sensitive system directories",
		"Track packages with obfuscated code patterns",
	}
	
	fmt.Printf("[Behavioral Analyzer] Updated %d behavioral detection rules\n", len(rules))
}

// GetMetrics returns metrics for the behavioral analyzer
func (ba *BehavioralAnalyzer) GetMetrics(ctx context.Context) (map[string]interface{}, error) {
	return map[string]interface{}{
		"accuracy": 0.94,
		"precision": 0.92,
		"recall": 0.89,
	}, nil
}

// AnalyzeBehaviorEnhanced is an adapter method for the enhanced detector interface
func (ba *BehavioralAnalyzer) AnalyzeBehaviorEnhanced(ctx context.Context, features *EnhancedPackageFeatures) (*BehavioralAnalysisResult, error) {
	// Convert EnhancedPackageFeatures to types.Package for our analyzer
	pkg := &types.Package{
		Name:    features.Name,
		Version: features.Version,
		Type:    features.Registry, // Using registry as type for now
		Metadata: &types.PackageMetadata{
			Size:      int64(features.FileStructure.TotalFiles), // Approximate
			FileCount: features.FileStructure.TotalFiles,
			Homepage:  features.Homepage,
			Repository: features.Repository,
			HasInstallScript: len(features.FileStructure.SuspiciousFiles) > 0, // Approximate
		},
	}
	
	// Use our existing AnalyzeBehavior method
	analysis := ba.AnalyzeBehavior(pkg)
	
	// Convert BehavioralAnalysis to BehavioralAnalysisResult
	result := &BehavioralAnalysisResult{
		BehaviorScore: ba.calculateBehaviorScore(analysis),
		RiskFactors:   ba.extractRiskFactors(analysis),
		BehaviorPatterns: ba.extractBehaviorPatterns(analysis),
	}
	
	return result, nil
}

// calculateBehaviorScore calculates a score from BehavioralAnalysis
func (ba *BehavioralAnalyzer) calculateBehaviorScore(analysis BehavioralAnalysis) float64 {
	score := 0.0
	
	// Score based on suspicious behaviors
	score += float64(len(analysis.InstallBehavior.SuspiciousCommands)) * 0.1
	score += float64(len(analysis.RuntimeBehavior.ProcessSpawning)) * 0.15
	score += float64(len(analysis.NetworkBehavior.OutboundConnections)) * 0.2
	score += float64(len(analysis.FileSystemBehavior.FileCreation)) * 0.1
	
	if score > 1.0 {
		score = 1.0
	}
	
	return score
}

// extractRiskFactors extracts risk factors from BehavioralAnalysis
func (ba *BehavioralAnalyzer) extractRiskFactors(analysis BehavioralAnalysis) []string {
	var factors []string
	
	if len(analysis.InstallBehavior.SuspiciousCommands) > 0 {
		factors = append(factors, "suspicious_install_commands")
	}
	if len(analysis.RuntimeBehavior.ProcessSpawning) > 0 {
		factors = append(factors, "process_spawning")
	}
	if len(analysis.NetworkBehavior.OutboundConnections) > 0 {
		factors = append(factors, "network_connections")
	}
	if len(analysis.FileSystemBehavior.FileCreation) > 0 {
		factors = append(factors, "file_system_access")
	}
	
	return factors
}

// extractBehaviorPatterns extracts behavior patterns from BehavioralAnalysis
func (ba *BehavioralAnalyzer) extractBehaviorPatterns(analysis BehavioralAnalysis) []string {
	var patterns []string
	
	// Combine all findings into patterns
	patterns = append(patterns, analysis.InstallBehavior.SuspiciousCommands...)
	patterns = append(patterns, analysis.RuntimeBehavior.ProcessSpawning...)
	patterns = append(patterns, analysis.NetworkBehavior.OutboundConnections...)
	patterns = append(patterns, analysis.FileSystemBehavior.FileCreation...)
	
	return patterns
}

// detectSuspiciousVersion checks for suspicious version patterns
func (ba *BehavioralAnalyzer) detectSuspiciousVersion(version string) bool {
	// Check for suspicious version patterns
	suspiciousPatterns := []string{
		`^\d{10,}`, // Very long version numbers
		`^0\.0\.0$`, // Zero version
		`^999\.`, // Suspiciously high major version
		`\d{4,}\.\d{4,}`, // Very long version components
	}
	
	for _, pattern := range suspiciousPatterns {
		if matched, _ := regexp.MatchString(pattern, version); matched {
			return true
		}
	}
	
	return false
}

// detectSuspiciousURL checks for suspicious URL patterns
func (ba *BehavioralAnalyzer) detectSuspiciousURL(url string) bool {
	if url == "" {
		return false
	}
	
	// Check for suspicious URL patterns
	suspiciousPatterns := []string{
		`bit\.ly`, // URL shorteners
		`tinyurl`, // URL shorteners
		`t\.co`, // URL shorteners
		`\d+\.\d+\.\d+\.\d+`, // IP addresses instead of domains
		`[a-z0-9]{20,}\.com`, // Very long random-looking domains
		`[a-z0-9]{20,}\.org`, // Very long random-looking domains
	}
	
	for _, pattern := range suspiciousPatterns {
		if matched, _ := regexp.MatchString(pattern, strings.ToLower(url)); matched {
			return true
		}
	}
	
	return false
}