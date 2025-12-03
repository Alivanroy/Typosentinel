package scanner

import (
	"debug/pe"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/Alivanroy/Typosentinel/pkg/types"
	"github.com/sirupsen/logrus"
)

// SignatureVerifier verifies digital signatures on binaries
type SignatureVerifier struct {
	recentCertThreshold time.Duration // Flag certs issued within this duration
}

// NewSignatureVerifier creates a new signature verifier
func NewSignatureVerifier() *SignatureVerifier {
	return &SignatureVerifier{
		recentCertThreshold: 30 * 24 * time.Hour, // 30 days
	}
}

// VerifyBinary verifies a binary's digital signature
func (sv *SignatureVerifier) VerifyBinary(filePath string) (*types.Threat, error) {
	// Determine file type
	ext := strings.ToLower(filepath.Ext(filePath))

	// Check magic bytes
	header, err := sv.readFileHeader(filePath)
	if err != nil {
		return nil, err
	}

	// Windows PE
	if len(header) >= 2 && header[0] == 'M' && header[1] == 'Z' {
		return sv.verifyPESignature(filePath)
	}

	// macOS Mach-O (check extension as fallback)
	if ext == ".dylib" || ext == ".app" {
		return sv.verifyMacOSSignature(filePath)
	}

	// Unsupported format
	return nil, fmt.Errorf("unsupported binary format")
}

// verifyPESignature verifies Windows PE (Authenticode) signatures
func (sv *SignatureVerifier) verifyPESignature(filePath string) (*types.Threat, error) {
	// On Windows, use sigcheck or certutil
	// On non-Windows, parse PE manually (limited validation)

	// Try to extract certificate info from PE
	certInfo, err := sv.extractPECertInfo(filePath)
	if err != nil {
		logrus.Debugf("[SignatureVerifier] No signature found in %s: %v", filePath, err)
		// No signature is suspicious
		return sv.createUnsignedThreat(filePath), nil
	}

	// Check if certificate is recent
	if certInfo.IsRecent(sv.recentCertThreshold) {
		return sv.createRecentCertThreat(filePath, certInfo), nil
	}

	// Check if self-signed
	if certInfo.IsSelfSigned {
		return sv.createSelfSignedThreat(filePath, certInfo), nil
	}

	return nil, nil // No threat
}

// verifyMacOSSignature verifies macOS code signatures
func (sv *SignatureVerifier) verifyMacOSSignature(filePath string) (*types.Threat, error) {
	// Use codesign command if available
	cmd := exec.Command("codesign", "-dvv", filePath)
	output, err := cmd.CombinedOutput()
	if err != nil {
		// Binary is not signed
		return sv.createUnsignedThreat(filePath), nil
	}

	outputStr := string(output)

	// Parse codesign output for certificate info
	certInfo := sv.parseMacOSCertInfo(outputStr)

	// Check if certificate is recent
	if certInfo.IsRecent(sv.recentCertThreshold) {
		return sv.createRecentCertThreat(filePath, certInfo), nil
	}

	// Check if self-signed (ad-hoc signature)
	if strings.Contains(outputStr, "adhoc") || certInfo.IsSelfSigned {
		return sv.createSelfSignedThreat(filePath, certInfo), nil
	}

	return nil, nil
}

// CertInfo contains certificate information
type CertInfo struct {
	Subject      string
	Issuer       string
	NotBefore    time.Time
	NotAfter     time.Time
	IsSelfSigned bool
}

// IsRecent checks if certificate was issued recently
func (ci *CertInfo) IsRecent(threshold time.Duration) bool {
	if ci.NotBefore.IsZero() {
		return false
	}
	return time.Since(ci.NotBefore) < threshold
}

// extractPECertInfo extracts certificate info from PE file
func (sv *SignatureVerifier) extractPECertInfo(filePath string) (*CertInfo, error) {
	f, err := pe.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	// Read certificate table from PE optional header
	// This is a simplified implementation - full validation requires parsing PKCS#7
	var certDirEntry pe.DataDirectory

	switch oh := f.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		if len(oh.DataDirectory) > 4 {
			certDirEntry = oh.DataDirectory[4] // SECURITY directory
		}
	case *pe.OptionalHeader64:
		if len(oh.DataDirectory) > 4 {
			certDirEntry = oh.DataDirectory[4]
		}
	default:
		return nil, fmt.Errorf("unsupported PE format")
	}

	if certDirEntry.Size == 0 {
		return nil, fmt.Errorf("no certificate found")
	}

	// For now, just flag as needing external validation
	// Full implementation would parse PKCS#7 structure
	return &CertInfo{
		Subject:      "Unknown (requires full PKCS#7 parsing)",
		Issuer:       "Unknown",
		IsSelfSigned: false, // Can't determine without full parsing
	}, nil
}

// parseMacOSCertInfo parses codesign output
func (sv *SignatureVerifier) parseMacOSCertInfo(output string) *CertInfo {
	certInfo := &CertInfo{}

	// Parse Authority line: "Authority=Apple Development: ..."
	authorityRe := regexp.MustCompile(`Authority=(.+)`)
	if matches := authorityRe.FindStringSubmatch(output); len(matches) > 1 {
		certInfo.Issuer = matches[1]
		certInfo.Subject = matches[1] // Simplified
	}

	// Parse TeamIdentifier
	teamIDRe := regexp.MustCompile(`TeamIdentifier=(.+)`)
	if matches := teamIDRe.FindStringSubmatch(output); len(matches) > 1 {
		// If team ID exists, likely not self-signed
		certInfo.IsSelfSigned = false
	} else {
		certInfo.IsSelfSigned = true
	}

	return certInfo
}

// readFileHeader reads first 512 bytes of file
func (sv *SignatureVerifier) readFileHeader(filePath string) ([]byte, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	header := make([]byte, 512)
	n, err := f.Read(header)
	if err != nil {
		return nil, err
	}

	return header[:n], nil
}

// Threat creation helpers

func (sv *SignatureVerifier) createUnsignedThreat(filePath string) *types.Threat {
	relPath := filepath.Base(filePath)
	return &types.Threat{
		Type:            types.ThreatTypeUntrustedSignature,
		Severity:        types.SeverityHigh,
		Confidence:      0.8,
		Description:     fmt.Sprintf("Binary '%s' is not digitally signed", relPath),
		DetectionMethod: "signature_verification",
		Recommendation:  "Unsigned binaries can be tampered with. Verify the source and integrity of this binary.",
		Evidence: []types.Evidence{
			{
				Type:        "signature_status",
				Description: "Digital signature status",
				Value:       "unsigned",
			},
			{
				Type:        "file",
				Description: "Binary file path",
				Value:       relPath,
			},
		},
		Metadata: map[string]interface{}{
			"file_path":     filePath,
			"relative_path": relPath,
		},
		DetectedAt: time.Now(),
	}
}

func (sv *SignatureVerifier) createSelfSignedThreat(filePath string, certInfo *CertInfo) *types.Threat {
	relPath := filepath.Base(filePath)
	return &types.Threat{
		Type:            types.ThreatTypeUntrustedSignature,
		Severity:        types.SeverityHigh,
		Confidence:      0.85,
		Description:     fmt.Sprintf("Binary '%s' is self-signed or ad-hoc signed", relPath),
		DetectionMethod: "signature_verification",
		Recommendation:  "Self-signed binaries may indicate unauthorized modifications. Verify the source.",
		Evidence: []types.Evidence{
			{
				Type:        "signature_status",
				Description: "Digital signature status",
				Value:       "self-signed",
			},
			{
				Type:        "certificate_subject",
				Description: "Certificate subject",
				Value:       certInfo.Subject,
			},
			{
				Type:        "file",
				Description: "Binary file path",
				Value:       relPath,
			},
		},
		Metadata: map[string]interface{}{
			"file_path":     filePath,
			"relative_path": relPath,
		},
		DetectedAt: time.Now(),
	}
}

func (sv *SignatureVerifier) createRecentCertThreat(filePath string, certInfo *CertInfo) *types.Threat {
	relPath := filepath.Base(filePath)
	age := time.Since(certInfo.NotBefore)
	return &types.Threat{
		Type:            types.ThreatTypeUntrustedSignature,
		Severity:        types.SeverityMedium,
		Confidence:      0.7,
		Description:     fmt.Sprintf("Binary '%s' is signed with a recently issued certificate (< 30 days)", relPath),
		DetectionMethod: "signature_verification",
		Recommendation:  "Recently issued certificates may indicate a compromised signing process (like SolarWinds). Verify legitimacy.",
		Evidence: []types.Evidence{
			{
				Type:        "signature_status",
				Description: "Digital signature status",
				Value:       "recent_certificate",
			},
			{
				Type:        "certificate_age",
				Description: "Certificate age (days)",
				Value:       fmt.Sprintf("%.0f", age.Hours()/24),
			},
			{
				Type:        "certificate_subject",
				Description: "Certificate subject",
				Value:       certInfo.Subject,
			},
			{
				Type:        "file",
				Description: "Binary file path",
				Value:       relPath,
			},
		},
		Metadata: map[string]interface{}{
			"file_path":     filePath,
			"relative_path": relPath,
		},
		DetectedAt: time.Now(),
	}
}
