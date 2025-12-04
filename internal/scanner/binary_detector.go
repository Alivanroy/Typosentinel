package scanner

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Alivanroy/Typosentinel/pkg/types"
)

// BinaryDetector detects executable binaries in packages
type BinaryDetector struct{}

// NewBinaryDetector creates a new binary detector
func NewBinaryDetector() *BinaryDetector {
	return &BinaryDetector{}
}

// ExecutableFormat represents a detected executable format
type ExecutableFormat struct {
	Type        string
	Description string
}

// Magic byte signatures for common executable formats
var executableSignatures = map[string]ExecutableFormat{
	"\x7fELF":          {Type: "ELF", Description: "Linux/Unix executable"},
	"MZ":               {Type: "PE", Description: "Windows executable (PE/COFF)"},
	"\xfe\xed\xfa\xce": {Type: "Mach-O_32", Description: "macOS executable (32-bit)"},
	"\xfe\xed\xfa\xcf": {Type: "Mach-O_64", Description: "macOS executable (64-bit)"},
	"\xcf\xfa\xed\xfe": {Type: "Mach-O_32_Rev", Description: "macOS executable (32-bit, reversed)"},
	"\xce\xfa\xed\xfe": {Type: "Mach-O_64_Rev", Description: "macOS executable (64-bit, reversed)"},
	"#!":               {Type: "Script", Description: "Script with shebang"},
	"\xca\xfe\xba\xbe": {Type: "Java", Description: "Java class file"},
	"\x50\x4b\x03\x04": {Type: "ZIP", Description: "ZIP archive (may contain executables)"},
}

// DetectBinariesInDirectory scans a directory for binary executables
func (bd *BinaryDetector) DetectBinariesInDirectory(path string) ([]types.Threat, error) {
	var threats []types.Threat
	var detectedBinaries []string

	err := filepath.Walk(path, func(filePath string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // Skip files with errors
		}

		// Skip directories
		if info.IsDir() {
			return nil
		}

		// Skip very large files (> 50MB) to avoid performance issues
		if info.Size() > 50*1024*1024 {
			return nil
		}

		// Check if file is executable
		if format, isExec := bd.isExecutableFile(filePath); isExec {
			relPath, _ := filepath.Rel(path, filePath)
			detectedBinaries = append(detectedBinaries, fmt.Sprintf("%s (%s)", relPath, format.Description))
		}

		return nil
	})

	if err != nil {
		return nil, err
	}

	// Create threat if binaries were found
	if len(detectedBinaries) > 0 {
		severity := bd.calculateSeverity(path, detectedBinaries)

		threat := types.Threat{
			Type:            types.ThreatTypeBinaryDetection,
			Severity:        severity,
			Confidence:      0.95,
			Description:     fmt.Sprintf("Package contains %d executable file(s)", len(detectedBinaries)),
			DetectionMethod: "binary_magic_byte_analysis",
			Recommendation:  "Review binary files before installing. Binaries can execute arbitrary code and may contain malware. Legitimate packages typically only include binaries in specific scenarios (native addons, CLI tools).",
			Evidence: []types.Evidence{
				{
					Type:        "binary_files",
					Description: "Detected executable files",
					Value:       strings.Join(detectedBinaries, "; "),
				},
			},
			DetectedAt: time.Now(),
		}

		threats = append(threats, threat)
	}

	return threats, nil
}

// isExecutableFile checks if a file is an executable based on magic bytes
func (bd *BinaryDetector) isExecutableFile(path string) (ExecutableFormat, bool) {
	file, err := os.Open(path)
	if err != nil {
		return ExecutableFormat{}, false
	}
	defer file.Close()

	// Read first 512 bytes for magic byte checking
	header := make([]byte, 512)
	n, err := io.ReadFull(file, header)
	if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
		return ExecutableFormat{}, false
	}
	header = header[:n]

	// Check against known signatures
	for signature, format := range executableSignatures {
		if bytes.HasPrefix(header, []byte(signature)) {
			return format, true
		}
	}

	// Check file extension for common executables (secondary check)
	ext := strings.ToLower(filepath.Ext(path))
	extensionFormats := map[string]ExecutableFormat{
		".exe":   {Type: "PE_Ext", Description: "Windows executable (.exe)"},
		".dll":   {Type: "DLL", Description: "Windows library (.dll)"},
		".so":    {Type: "SO", Description: "Shared library (.so)"},
		".dylib": {Type: "DYLIB", Description: "macOS library (.dylib)"},
		".node":  {Type: "Node_Addon", Description: "Node.js native addon (.node)"},
	}

	if format, ok := extensionFormats[ext]; ok {
		return format, true
	}

	return ExecutableFormat{}, false
}

// calculateSeverity determines threat severity based on context
func (bd *BinaryDetector) calculateSeverity(packagePath string, binaries []string) types.Severity {
	// Check if binaries are in expected locations for legitimate use cases
	legitimatePaths := []string{
		"node_modules",
		"build/Release",
		"build/",
		"bin/",
		"vendor/",
	}

	allInLegitPath := true
	for _, binary := range binaries {
		norm := strings.ReplaceAll(binary, "\\", "/")
		inLegitPath := false
		for _, legitPath := range legitimatePaths {
			if strings.Contains(norm, legitPath) {
				inLegitPath = true
				break
			}
		}
		if !inLegitPath {
			allInLegitPath = false
			break
		}
	}

	// If binaries are in unexpected locations, higher severity
	if !allInLegitPath {
		return types.SeverityHigh
	}

	// Multiple binaries or specific types are more suspicious
	if len(binaries) > 5 {
		return types.SeverityHigh
	}

	return types.SeverityMedium
}
