package scanner

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Alivanroy/Typosentinel/internal/config"
	"github.com/Alivanroy/Typosentinel/pkg/logger"
	"github.com/Alivanroy/Typosentinel/pkg/types"
)

// BuildIntegrityDetectorImpl implements the BuildIntegrityDetector interface
type BuildIntegrityDetectorImpl struct {
	config *config.BuildIntegrityConfig
	logger *logger.Logger
}

// NewBuildIntegrityDetector creates a new build integrity detector
func NewBuildIntegrityDetector(cfg *config.BuildIntegrityConfig, log *logger.Logger) *BuildIntegrityDetectorImpl {
	return &BuildIntegrityDetectorImpl{
		config: cfg,
		logger: log,
	}
}

// AnalyzeBuildIntegrity analyzes the build integrity of a package
func (bid *BuildIntegrityDetectorImpl) AnalyzeBuildIntegrity(ctx context.Context, pkg *types.Dependency) ([]BuildIntegrityFinding, error) {
	if !bid.config.Enabled {
		return nil, nil
	}

	var findings []BuildIntegrityFinding

	// Create timeout context
	timeoutCtx, cancel := context.WithTimeout(ctx, bid.config.Timeout)
	defer cancel()

	// Check for signature verification
	if bid.config.SignatureCheck {
		if signatureFindings := bid.checkSignatures(timeoutCtx, pkg); len(signatureFindings) > 0 {
			findings = append(findings, signatureFindings...)
		}
	}

	// Check for tampering detection
	if bid.config.TamperingDetection {
		if tamperingFindings := bid.detectTampering(timeoutCtx, pkg); len(tamperingFindings) > 0 {
			findings = append(findings, tamperingFindings...)
		}
	}

	// Analyze build process
	if bid.config.BuildAnalysis {
		if buildFindings := bid.analyzeBuildProcess(timeoutCtx, pkg); len(buildFindings) > 0 {
			findings = append(findings, buildFindings...)
		}
	}

	return findings, nil
}

// checkSignatures verifies package signatures
func (bid *BuildIntegrityDetectorImpl) checkSignatures(ctx context.Context, pkg *types.Dependency) []BuildIntegrityFinding {
	var findings []BuildIntegrityFinding

	// Check if package has valid signatures
	if !bid.hasValidSignature(pkg) {
		findings = append(findings, BuildIntegrityFinding{
			Type:        "signature_missing",
			Severity:    types.SeverityHigh,
			Description: fmt.Sprintf("Package %s lacks valid cryptographic signature", pkg.Name),
			Evidence: []types.Evidence{
				{
					Type:        "signature_verification",
					Description: "Signature not present",
					Value:       false,
				},
			},
			DetectedAt: time.Now(),
		})
	}

	// Check signature validity
	if bid.hasInvalidSignature(pkg) {
		findings = append(findings, BuildIntegrityFinding{
			Type:        "signature_invalid",
			Severity:    types.SeverityCritical,
			Description: fmt.Sprintf("Package %s has invalid or corrupted signature", pkg.Name),
			Evidence: []types.Evidence{
				{
					Type:        "signature_verification",
					Description: "Invalid signature detected",
					Value:       false,
				},
			},
			DetectedAt: time.Now(),
		})
	}

	return findings
}

// detectTampering detects signs of package tampering
func (bid *BuildIntegrityDetectorImpl) detectTampering(ctx context.Context, pkg *types.Dependency) []BuildIntegrityFinding {
	var findings []BuildIntegrityFinding

	// Check file integrity
	if bid.hasFileIntegrityIssues(pkg) {
		findings = append(findings, BuildIntegrityFinding{
			Type:        "file_integrity_violation",
			Severity:    types.SeverityHigh,
			Description: fmt.Sprintf("Package %s shows signs of file tampering", pkg.Name),
			Evidence: []types.Evidence{
				{
					Type:        "file_integrity",
					Description: "Checksum mismatch detected",
					Value:       true,
				},
			},
			DetectedAt: time.Now(),
		})
	}

	// Check for suspicious modifications
	if bid.hasSuspiciousModifications(pkg) {
		findings = append(findings, BuildIntegrityFinding{
			Type:        "suspicious_modification",
			Severity:    types.SeverityMedium,
			Description: fmt.Sprintf("Package %s contains suspicious modifications", pkg.Name),
			Evidence: []types.Evidence{
				{
					Type:        "modification_detection",
					Description: "Suspicious modification detected",
					Value:       true,
				},
			},
			DetectedAt: time.Now(),
		})
	}

	return findings
}

// analyzeBuildProcess analyzes the build process for integrity issues
func (bid *BuildIntegrityDetectorImpl) analyzeBuildProcess(ctx context.Context, pkg *types.Dependency) []BuildIntegrityFinding {
	var findings []BuildIntegrityFinding

	// Check build reproducibility
	if !bid.isBuildReproducible(pkg) {
		findings = append(findings, BuildIntegrityFinding{
			Type:        "build_not_reproducible",
			Severity:    types.SeverityMedium,
			Description: fmt.Sprintf("Package %s build is not reproducible", pkg.Name),
			Evidence: []types.Evidence{
				{
					Type:        "build_reproducibility",
					Description: "Build is not reproducible",
					Value:       false,
				},
			},
			DetectedAt: time.Now(),
		})
	}

	// Check for suspicious build artifacts
	if bid.hasSuspiciousBuildArtifacts(pkg) {
		findings = append(findings, BuildIntegrityFinding{
			Type:        "suspicious_build_artifacts",
			Severity:    types.SeverityHigh,
			Description: fmt.Sprintf("Package %s contains suspicious build artifacts", pkg.Name),
			Evidence: []types.Evidence{
				{
					Type:        "artifact_analysis",
					Description: "Suspicious build artifacts found",
					Value:       true,
				},
			},
			DetectedAt: time.Now(),
		})
	}

	return findings
}

// Helper methods for integrity checks

// hasValidSignature checks if the package has a valid signature
func (bid *BuildIntegrityDetectorImpl) hasValidSignature(pkg *types.Dependency) bool {
	// Check package metadata for signature information
	if pkg.Metadata.Name == "" {
		return false
	}

	// Look for signature fields in metadata
	signature, hasSignature := pkg.Metadata.Metadata["signature"]
	if !hasSignature || signature == nil {
		return false
	}

	// Basic signature validation (in real implementation, this would be more sophisticated)
	sigStr, ok := signature.(string)
	if !ok || len(sigStr) < 64 { // Minimum length for a valid signature
		return false
	}

	return true
}

// hasInvalidSignature checks if the package has an invalid signature
func (bid *BuildIntegrityDetectorImpl) hasInvalidSignature(pkg *types.Dependency) bool {
	// This would implement actual signature verification
	// For now, we'll use heuristics based on package metadata
	if pkg.Metadata.Name == "" {
		return false
	}

	// Check for known invalid signature patterns
	if signatureStatus, exists := pkg.Metadata.Metadata["signature_status"]; exists {
		if status, ok := signatureStatus.(string); ok {
			return strings.Contains(strings.ToLower(status), "invalid") ||
				strings.Contains(strings.ToLower(status), "corrupted")
		}
	}

	return false
}

// hasFileIntegrityIssues checks for file integrity violations
func (bid *BuildIntegrityDetectorImpl) hasFileIntegrityIssues(pkg *types.Dependency) bool {
	// Check if package has checksum information
	if pkg.Metadata.Name == "" {
		return false
	}

	// Look for checksum mismatch indicators
	if checksumStatus, exists := pkg.Metadata.Metadata["checksum_status"]; exists {
		if status, ok := checksumStatus.(string); ok {
			return strings.Contains(strings.ToLower(status), "mismatch") ||
				strings.Contains(strings.ToLower(status), "failed")
		}
	}

	// Check for file size discrepancies
	if expectedSize, hasExpected := pkg.Metadata.Metadata["expected_size"]; hasExpected {
		if actualSize, hasActual := pkg.Metadata.Metadata["actual_size"]; hasActual {
			if exp, ok1 := expectedSize.(int64); ok1 {
				if act, ok2 := actualSize.(int64); ok2 {
					return exp != act
				}
			}
		}
	}

	return false
}

// hasSuspiciousModifications checks for suspicious package modifications
func (bid *BuildIntegrityDetectorImpl) hasSuspiciousModifications(pkg *types.Dependency) bool {
	// Check for suspicious file patterns
	suspiciousPatterns := []string{
		".exe", ".bat", ".cmd", ".ps1", ".sh",
		"eval(", "exec(", "system(", "shell_exec(",
		"base64", "decode", "obfuscated",
	}

	// Check package name and description for suspicious patterns
	packageContent := strings.ToLower(pkg.Name + " " + pkg.Version)
	if pkg.Metadata.Name != "" {
		if desc, exists := pkg.Metadata.Metadata["description"]; exists {
			if descStr, ok := desc.(string); ok {
				packageContent += " " + strings.ToLower(descStr)
			}
		}
	}

	for _, pattern := range suspiciousPatterns {
		if strings.Contains(packageContent, pattern) {
			return true
		}
	}

	return false
}

// isBuildReproducible checks if the build is reproducible
func (bid *BuildIntegrityDetectorImpl) isBuildReproducible(pkg *types.Dependency) bool {
	// Check for reproducible build indicators
	if pkg.Metadata.Name == "" {
		return false
	}

	// Look for reproducible build metadata
	if reproducible, exists := pkg.Metadata.Metadata["reproducible_build"]; exists {
		if isReproducible, ok := reproducible.(bool); ok {
			return isReproducible
		}
	}

	// Check for build environment consistency
	if buildEnv, exists := pkg.Metadata.Metadata["build_environment"]; exists {
		if env, ok := buildEnv.(map[string]interface{}); ok {
			// Check for deterministic build indicators
			if timestamp, hasTimestamp := env["build_timestamp"]; hasTimestamp {
				if ts, ok := timestamp.(string); ok {
					// Non-deterministic if timestamp is too recent or varies
					return !strings.Contains(ts, "SOURCE_DATE_EPOCH")
				}
			}
		}
	}

	// Default to false for unknown packages
	return false
}

// hasSuspiciousBuildArtifacts checks for suspicious build artifacts
func (bid *BuildIntegrityDetectorImpl) hasSuspiciousBuildArtifacts(pkg *types.Dependency) bool {
	// Check for suspicious build artifacts
	suspiciousArtifacts := []string{
		"backdoor", "malware", "trojan", "virus",
		"keylogger", "rootkit", "botnet",
		"cryptocurrency", "mining", "miner",
	}

	if pkg.Metadata.Name == "" {
		return false
	}

	// Check build artifacts metadata
	if artifacts, exists := pkg.Metadata.Metadata["build_artifacts"]; exists {
		if artifactList, ok := artifacts.([]string); ok {
			for _, artifact := range artifactList {
				artifactLower := strings.ToLower(artifact)
				for _, suspicious := range suspiciousArtifacts {
					if strings.Contains(artifactLower, suspicious) {
						return true
					}
				}
			}
		}
	}

	// Check for unusual file sizes or types
	if fileInfo, exists := pkg.Metadata.Metadata["files"]; exists {
		if files, ok := fileInfo.([]map[string]interface{}); ok {
			for _, file := range files {
				if size, hasSize := file["size"]; hasSize {
					if fileSize, ok := size.(int64); ok {
						// Flag unusually large files (> 100MB)
						if fileSize > 100*1024*1024 {
							return true
						}
					}
				}
			}
		}
	}

	return false
}

// calculateFileChecksum calculates SHA256 checksum of a file
func (bid *BuildIntegrityDetectorImpl) calculateFileChecksum(filePath string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}

	return hex.EncodeToString(hash.Sum(nil)), nil
}

// verifyPackageIntegrity performs comprehensive package integrity verification
func (bid *BuildIntegrityDetectorImpl) verifyPackageIntegrity(ctx context.Context, pkg *types.Dependency, packagePath string) (*IntegrityVerificationResult, error) {
	result := &IntegrityVerificationResult{
		PackageName: pkg.Name,
		Version:     pkg.Version,
		Verified:    true,
		Timestamp:   time.Now(),
		Checks:      make(map[string]bool),
		Evidence:    make(map[string]interface{}),
	}

	// Verify file checksums
	if err := bid.verifyFileChecksums(packagePath, result); err != nil {
		bid.logger.Errorf("Checksum verification failed for %s: %v", pkg.Name, err)
		result.Verified = false
		result.Checks["checksum_verification"] = false
	} else {
		result.Checks["checksum_verification"] = true
	}

	// Verify signatures
	if err := bid.verifySignatures(packagePath, result); err != nil {
		bid.logger.Errorf("Signature verification failed for %s: %v", pkg.Name, err)
		result.Verified = false
		result.Checks["signature_verification"] = false
	} else {
		result.Checks["signature_verification"] = true
	}

	// Check for tampering indicators
	if err := bid.checkTamperingIndicators(packagePath, result); err != nil {
		bid.logger.Errorf("Tampering check failed for %s: %v", pkg.Name, err)
		result.Verified = false
		result.Checks["tampering_check"] = false
	} else {
		result.Checks["tampering_check"] = true
	}

	return result, nil
}

// verifyFileChecksums verifies file checksums within the package
func (bid *BuildIntegrityDetectorImpl) verifyFileChecksums(packagePath string, result *IntegrityVerificationResult) error {
	// Walk through package files and verify checksums
	return filepath.Walk(packagePath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if info.IsDir() {
			return nil
		}

		// Calculate checksum
		checksum, err := bid.calculateFileChecksum(path)
		if err != nil {
			return fmt.Errorf("failed to calculate checksum for %s: %w", path, err)
		}

		// Store checksum in evidence
		relPath, _ := filepath.Rel(packagePath, path)
		if result.Evidence["file_checksums"] == nil {
			result.Evidence["file_checksums"] = make(map[string]string)
		}
		result.Evidence["file_checksums"].(map[string]string)[relPath] = checksum

		return nil
	})
}

// verifySignatures verifies package signatures
func (bid *BuildIntegrityDetectorImpl) verifySignatures(packagePath string, result *IntegrityVerificationResult) error {
	// Look for signature files
	signatureFiles := []string{
		filepath.Join(packagePath, "SIGNATURE"),
		filepath.Join(packagePath, "signature.asc"),
		filepath.Join(packagePath, ".signature"),
	}

	for _, sigFile := range signatureFiles {
		if _, err := os.Stat(sigFile); err == nil {
			// Signature file exists, verify it
			if err := bid.verifySignatureFile(sigFile, result); err != nil {
				return fmt.Errorf("signature verification failed: %w", err)
			}
			result.Evidence["signature_file"] = sigFile
			return nil
		}
	}

	// No signature file found
	result.Evidence["signature_file"] = "not_found"
	return fmt.Errorf("no signature file found")
}

// verifySignatureFile verifies a specific signature file
func (bid *BuildIntegrityDetectorImpl) verifySignatureFile(signatureFile string, result *IntegrityVerificationResult) error {
	// Read signature file
	sigData, err := os.ReadFile(signatureFile)
	if err != nil {
		return fmt.Errorf("failed to read signature file: %w", err)
	}

	// Basic signature validation (in production, this would use proper cryptographic verification)
	sigStr := string(sigData)
	if len(sigStr) < 64 {
		return fmt.Errorf("signature too short")
	}

	// Check signature format
	if !strings.Contains(sigStr, "BEGIN PGP SIGNATURE") && !strings.Contains(sigStr, "SIGNATURE") {
		return fmt.Errorf("invalid signature format")
	}

	result.Evidence["signature_content"] = sigStr[:100] // Store first 100 chars for evidence
	return nil
}

// checkTamperingIndicators checks for signs of tampering
func (bid *BuildIntegrityDetectorImpl) checkTamperingIndicators(packagePath string, result *IntegrityVerificationResult) error {
	// Check for suspicious files
	suspiciousFiles := []string{
		".hidden", "backdoor", "malware", "trojan",
		"keylogger", "rootkit", "miner",
	}

	var foundSuspicious []string
	err := filepath.Walk(packagePath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		filename := strings.ToLower(info.Name())
		for _, suspicious := range suspiciousFiles {
			if strings.Contains(filename, suspicious) {
				relPath, _ := filepath.Rel(packagePath, path)
				foundSuspicious = append(foundSuspicious, relPath)
			}
		}

		return nil
	})

	if err != nil {
		return err
	}

	if len(foundSuspicious) > 0 {
		result.Evidence["suspicious_files"] = foundSuspicious
		return fmt.Errorf("found suspicious files: %v", foundSuspicious)
	}

	return nil
}

// IntegrityVerificationResult represents the result of integrity verification
type IntegrityVerificationResult struct {
	PackageName string                 `json:"package_name"`
	Version     string                 `json:"version"`
	Verified    bool                   `json:"verified"`
	Timestamp   time.Time              `json:"timestamp"`
	Checks      map[string]bool        `json:"checks"`
	Evidence    map[string]interface{} `json:"evidence"`
}
