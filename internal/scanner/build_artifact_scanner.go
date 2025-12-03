package scanner

import (
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Alivanroy/Typosentinel/pkg/types"
	"github.com/sirupsen/logrus"
)

// BuildArtifactScanner scans build directories for unexpected binaries
type BuildArtifactScanner struct {
	buildDirs         []string
	binaryExts        []string
	maxFileSize       int64
	signatureVerifier *SignatureVerifier
}

// NewBuildArtifactScanner creates a new build artifact scanner
func NewBuildArtifactScanner() *BuildArtifactScanner {
	return &BuildArtifactScanner{
		buildDirs: []string{
			"node_modules/.bin",
			"node_modules",
			"dist",
			"build",
			"out",
			".next",
			"target",
			"bin",
			"obj",
		},
		binaryExts: []string{
			".exe", ".dll", ".so", ".dylib", ".node",
			".bin", ".o", ".a", ".class", ".jar",
			".dex", ".apk", ".ipa",
		},
		maxFileSize:       100 * 1024 * 1024, // 100MB max
		signatureVerifier: NewSignatureVerifier(),
	}
}

// ScanProject scans project build directories for unexpected binaries
func (bas *BuildArtifactScanner) ScanProject(projectPath string) ([]types.Threat, error) {
	var threats []types.Threat

	for _, dir := range bas.buildDirs {
		dirPath := filepath.Join(projectPath, dir)
		if _, err := os.Stat(dirPath); os.IsNotExist(err) {
			continue
		}

		logrus.Debugf("[BuildArtifactScanner] Scanning %s", dirPath)
		dirThreats, err := bas.scanDirectory(dirPath, projectPath)
		if err != nil {
			logrus.Warnf("[BuildArtifactScanner] Error scanning %s: %v", dirPath, err)
			continue
		}

		threats = append(threats, dirThreats...)
	}

	logrus.Infof("[BuildArtifactScanner] Found %d unexpected binaries", len(threats))
	return threats, nil
}

// scanDirectory scans a specific directory for binaries
func (bas *BuildArtifactScanner) scanDirectory(dirPath, projectPath string) ([]types.Threat, error) {
	var threats []types.Threat

	err := filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}

		if info.IsDir() {
			return nil
		}

		// Check if file is a binary
		if !bas.isBinaryFile(path) {
			return nil
		}

		// Calculate file hash
		hash, err := bas.calculateFileHash(path)
		if err != nil {
			logrus.Debugf("[BuildArtifactScanner] Failed to hash %s: %v", path, err)
			return nil
		}

		// Determine severity based on location
		severity := bas.calculateSeverity(path, info)

		relPath, _ := filepath.Rel(projectPath, path)

		threat := types.Threat{
			Type:            types.ThreatTypeUnexpectedBinary,
			Severity:        severity,
			Confidence:      0.85,
			Description:     fmt.Sprintf("Unexpected binary found in build directory: %s", relPath),
			DetectionMethod: "build_artifact_analysis",
			Recommendation:  "Review the binary to ensure it's legitimate. Binaries in build outputs should match source code and package manifests.",
			Evidence: []types.Evidence{
				{
					Type:        "file",
					Description: "Binary file path",
					Value:       relPath,
				},
				{
					Type:        "hash",
					Description: "SHA-256 checksum",
					Value:       hash,
				},
				{
					Type:        "size",
					Description: "File size in bytes",
					Value:       fmt.Sprintf("%d", info.Size()),
				},
			},
			Metadata: map[string]interface{}{
				"file_path":     path,
				"relative_path": relPath,
				"file_size":     info.Size(),
				"sha256":        hash,
			},
			DetectedAt: time.Now(),
		}

		threats = append(threats, threat)
		return nil
	})

	return threats, err
}

// isBinaryFile checks if a file is a binary based on magic bytes
func (bas *BuildArtifactScanner) isBinaryFile(filePath string) bool {
	// Check extension first
	ext := strings.ToLower(filepath.Ext(filePath))
	for _, binExt := range bas.binaryExts {
		if ext == binExt {
			return true
		}
	}

	// Check magic bytes
	file, err := os.Open(filePath)
	if err != nil {
		return false
	}
	defer file.Close()

	header := make([]byte, 512)
	n, err := file.Read(header)
	if err != nil || n < 4 {
		return false
	}

	// PE (Windows)
	if header[0] == 'M' && header[1] == 'Z' {
		return true
	}

	// ELF (Linux)
	if header[0] == 0x7F && header[1] == 'E' && header[2] == 'L' && header[3] == 'F' {
		return true
	}

	// Mach-O (macOS) - little/big endian
	if (header[0] == 0xCF && header[1] == 0xFA && header[2] == 0xED && header[3] == 0xFE) ||
		(header[0] == 0xFE && header[1] == 0xED && header[2] == 0xFA && header[3] == 0xCF) {
		return true
	}

	// Check for null bytes (common in binary files, unlikely in source)
	nullCount := 0
	for i := 0; i < n && i < 512; i++ {
		if header[i] == 0 {
			nullCount++
		}
	}

	// If >5% of the first 512 bytes are nulls, likely binary
	if float64(nullCount)/float64(n) > 0.05 {
		return true
	}

	return false
}

// calculateFileHash computes SHA-256 hash of a file
func (bas *BuildArtifactScanner) calculateFileHash(filePath string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}

	return fmt.Sprintf("%x", hash.Sum(nil)), nil
}

// calculateSeverity determines threat severity based on binary location
func (bas *BuildArtifactScanner) calculateSeverity(path string, info os.FileInfo) types.Severity {
	normPath := strings.ReplaceAll(path, "\\", "/")

	// Critical: Binaries in unexpected locations
	criticalPaths := []string{
		"/test/", "/tests/", "/__test__/",
		"/example/", "/examples/",
		"/doc/", "/docs/",
	}

	for _, critPath := range criticalPaths {
		if strings.Contains(normPath, critPath) {
			return types.SeverityCritical
		}
	}

	// High: Binaries in node_modules (except .bin)
	if strings.Contains(normPath, "node_modules") && !strings.Contains(normPath, "node_modules/.bin") {
		return types.SeverityHigh
	}

	// High: Large binaries (> 10MB)
	if info.Size() > 10*1024*1024 {
		return types.SeverityHigh
	}

	// Medium: Binaries in build outputs (expected but should be verified)
	return types.SeverityMedium
}
