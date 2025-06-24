package provenance

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

// ProvenanceAnalyzer performs software provenance and integrity analysis
type ProvenanceAnalyzer struct {
	config *Config
	client *http.Client
}

// Config contains provenance analyzer configuration
type Config struct {
	Enabled bool `yaml:"enabled"`
	
	// Sigstore configuration
	SigstoreEnabled bool `yaml:"sigstore_enabled"`
	SigstoreRekorURL string `yaml:"sigstore_rekor_url"`
	SigstoreFulcioURL string `yaml:"sigstore_fulcio_url"`
	SigstoreCTLogURL string `yaml:"sigstore_ctlog_url"`
	
	// SLSA configuration
	SLSAEnabled bool `yaml:"slsa_enabled"`
	SLSAMinLevel int `yaml:"slsa_min_level"`
	SLSARequiredBuilders []string `yaml:"slsa_required_builders"`
	
	// Verification settings
	VerifySignatures bool `yaml:"verify_signatures"`
	VerifyProvenance bool `yaml:"verify_provenance"`
	VerifyIntegrity bool `yaml:"verify_integrity"`
	RequireTransparencyLog bool `yaml:"require_transparency_log"`
	
	// Trust settings
	TrustedPublishers []string `yaml:"trusted_publishers"`
	TrustedSigners []string `yaml:"trusted_signers"`
	TrustedBuilders []string `yaml:"trusted_builders"`
	
	// Timeout and retry settings
	Timeout string `yaml:"timeout"`
	RetryAttempts int `yaml:"retry_attempts"`
	Verbose bool `yaml:"verbose"`
}

// AnalysisResult represents provenance analysis results
type AnalysisResult struct {
	PackageName string `json:"package_name"`
	PackageVersion string `json:"package_version"`
	Registry string `json:"registry"`
	AnalysisTimestamp time.Time `json:"analysis_timestamp"`
	
	// Signature verification
	SignatureVerification *SignatureVerification `json:"signature_verification"`
	
	// SLSA provenance
	SLSAProvenance *SLSAProvenance `json:"slsa_provenance"`
	
	// Integrity checks
	IntegrityChecks *IntegrityChecks `json:"integrity_checks"`
	
	// Transparency log verification
	TransparencyLog *TransparencyLogVerification `json:"transparency_log"`
	
	// Trust assessment
	TrustAssessment *TrustAssessment `json:"trust_assessment"`
	
	// Overall assessment
	OverallScore float64 `json:"overall_score"`
	TrustLevel string `json:"trust_level"`
	Findings []Finding `json:"findings"`
	Warnings []string `json:"warnings"`
	Recommendations []string `json:"recommendations"`
	
	// Metadata
	ProcessingTime time.Duration `json:"processing_time"`
	VerificationSources []string `json:"verification_sources"`
}

// SignatureVerification represents signature verification results
type SignatureVerification struct {
	Verified bool `json:"verified"`
	Signatures []Signature `json:"signatures"`
	Certificates []Certificate `json:"certificates"`
	KeylessSignatures []KeylessSignature `json:"keyless_signatures"`
	VerificationErrors []string `json:"verification_errors"`
	TrustScore float64 `json:"trust_score"`
}

// Signature represents a digital signature
type Signature struct {
	Algorithm string `json:"algorithm"`
	Value string `json:"value"`
	KeyID string `json:"key_id,omitempty"`
	Signer string `json:"signer"`
	Timestamp time.Time `json:"timestamp"`
	Verified bool `json:"verified"`
	Trusted bool `json:"trusted"`
	Metadata map[string]interface{} `json:"metadata"`
}

// Certificate represents a signing certificate
type Certificate struct {
	Subject string `json:"subject"`
	Issuer string `json:"issuer"`
	SerialNumber string `json:"serial_number"`
	NotBefore time.Time `json:"not_before"`
	NotAfter time.Time `json:"not_after"`
	Fingerprint string `json:"fingerprint"`
	Valid bool `json:"valid"`
	Trusted bool `json:"trusted"`
	Extensions map[string]string `json:"extensions"`
}

// KeylessSignature represents a keyless signature (e.g., OIDC-based)
type KeylessSignature struct {
	Issuer string `json:"issuer"`
	Subject string `json:"subject"`
	Audience string `json:"audience"`
	Email string `json:"email,omitempty"`
	WorkflowTrigger string `json:"workflow_trigger,omitempty"`
	WorkflowSHA string `json:"workflow_sha,omitempty"`
	WorkflowName string `json:"workflow_name,omitempty"`
	WorkflowRepository string `json:"workflow_repository,omitempty"`
	Verified bool `json:"verified"`
	Trusted bool `json:"trusted"`
}

// SLSAProvenance represents SLSA provenance information
type SLSAProvenance struct {
	Present bool `json:"present"`
	Level int `json:"level"`
	Builder *SLSABuilder `json:"builder"`
	BuildType string `json:"build_type"`
	Invocation *SLSAInvocation `json:"invocation"`
	BuildConfig map[string]interface{} `json:"build_config"`
	Materials []SLSAMaterial `json:"materials"`
	Metadata *SLSAMetadata `json:"metadata"`
	Verified bool `json:"verified"`
	TrustScore float64 `json:"trust_score"`
	Compliance *SLSACompliance `json:"compliance"`
}

// SLSABuilder represents the builder information
type SLSABuilder struct {
	ID string `json:"id"`
	Version string `json:"version"`
	Trusted bool `json:"trusted"`
	Verified bool `json:"verified"`
}

// SLSAInvocation represents build invocation details
type SLSAInvocation struct {
	ConfigSource *SLSAConfigSource `json:"config_source"`
	Parameters map[string]interface{} `json:"parameters"`
	Environment map[string]string `json:"environment"`
}

// SLSAConfigSource represents the configuration source
type SLSAConfigSource struct {
	URI string `json:"uri"`
	Digest map[string]string `json:"digest"`
	EntryPoint string `json:"entry_point"`
}

// SLSAMaterial represents build materials
type SLSAMaterial struct {
	URI string `json:"uri"`
	Digest map[string]string `json:"digest"`
}

// SLSAMetadata represents SLSA metadata
type SLSAMetadata struct {
	BuildInvocationID string `json:"build_invocation_id"`
	BuildStartedOn time.Time `json:"build_started_on"`
	BuildFinishedOn time.Time `json:"build_finished_on"`
	Completeness *SLSACompleteness `json:"completeness"`
	Reproducible bool `json:"reproducible"`
}

// SLSACompleteness represents completeness information
type SLSACompleteness struct {
	Parameters bool `json:"parameters"`
	Environment bool `json:"environment"`
	Materials bool `json:"materials"`
}

// SLSACompliance represents SLSA compliance assessment
type SLSACompliance struct {
	Level int `json:"level"`
	Requirements map[string]bool `json:"requirements"`
	Violations []string `json:"violations"`
	Score float64 `json:"score"`
}

// IntegrityChecks represents integrity verification results
type IntegrityChecks struct {
	HashVerification *HashVerification `json:"hash_verification"`
	SizeVerification *SizeVerification `json:"size_verification"`
	ContentVerification *ContentVerification `json:"content_verification"`
	OverallVerified bool `json:"overall_verified"`
	TrustScore float64 `json:"trust_score"`
}

// HashVerification represents hash verification results
type HashVerification struct {
	Algorithm string `json:"algorithm"`
	ExpectedHash string `json:"expected_hash"`
	ActualHash string `json:"actual_hash"`
	Verified bool `json:"verified"`
	Source string `json:"source"`
}

// SizeVerification represents size verification results
type SizeVerification struct {
	ExpectedSize int64 `json:"expected_size"`
	ActualSize int64 `json:"actual_size"`
	Verified bool `json:"verified"`
	Source string `json:"source"`
}

// ContentVerification represents content verification results
type ContentVerification struct {
	ManifestVerified bool `json:"manifest_verified"`
	FilesVerified bool `json:"files_verified"`
	PermissionsVerified bool `json:"permissions_verified"`
	ModifiedFiles []string `json:"modified_files"`
	MissingFiles []string `json:"missing_files"`
	ExtraFiles []string `json:"extra_files"`
}

// TransparencyLogVerification represents transparency log verification
type TransparencyLogVerification struct {
	Present bool `json:"present"`
	Entries []TransparencyLogEntry `json:"entries"`
	Verified bool `json:"verified"`
	TrustScore float64 `json:"trust_score"`
}

// TransparencyLogEntry represents a transparency log entry
type TransparencyLogEntry struct {
	LogIndex int64 `json:"log_index"`
	LogID string `json:"log_id"`
	KindVersion *KindVersion `json:"kind_version"`
	IntegratedTime int64 `json:"integrated_time"`
	InclusionPromise *InclusionPromise `json:"inclusion_promise"`
	InclusionProof *InclusionProof `json:"inclusion_proof"`
	Verification *LogEntryVerification `json:"verification"`
}

// KindVersion represents the kind and version of log entry
type KindVersion struct {
	Kind string `json:"kind"`
	Version string `json:"version"`
}

// InclusionPromise represents inclusion promise
type InclusionPromise struct {
	SignedEntryTimestamp string `json:"signed_entry_timestamp"`
}

// InclusionProof represents inclusion proof
type InclusionProof struct {
	LogIndex int64 `json:"log_index"`
	RootHash string `json:"root_hash"`
	TreeSize int64 `json:"tree_size"`
	Hashes []string `json:"hashes"`
	Checkpoint *Checkpoint `json:"checkpoint"`
}

// Checkpoint represents a transparency log checkpoint
type Checkpoint struct {
	Envelope string `json:"envelope"`
}

// LogEntryVerification represents log entry verification results
type LogEntryVerification struct {
	InclusionProof *InclusionProofVerification `json:"inclusion_proof"`
	SignedEntryTimestamp *SignedEntryTimestampVerification `json:"signed_entry_timestamp"`
}

// InclusionProofVerification represents inclusion proof verification
type InclusionProofVerification struct {
	Verified bool `json:"verified"`
}

// SignedEntryTimestampVerification represents SET verification
type SignedEntryTimestampVerification struct {
	Verified bool `json:"verified"`
}

// TrustAssessment represents overall trust assessment
type TrustAssessment struct {
	PublisherTrust *PublisherTrust `json:"publisher_trust"`
	SignerTrust *SignerTrust `json:"signer_trust"`
	BuilderTrust *BuilderTrust `json:"builder_trust"`
	OverallTrustScore float64 `json:"overall_trust_score"`
	TrustLevel string `json:"trust_level"`
	RiskFactors []string `json:"risk_factors"`
}

// PublisherTrust represents publisher trust assessment
type PublisherTrust struct {
	Publisher string `json:"publisher"`
	Trusted bool `json:"trusted"`
	Reputation float64 `json:"reputation"`
	VerificationHistory []string `json:"verification_history"`
}

// SignerTrust represents signer trust assessment
type SignerTrust struct {
	Signer string `json:"signer"`
	Trusted bool `json:"trusted"`
	Reputation float64 `json:"reputation"`
	CertificateChain []string `json:"certificate_chain"`
}

// BuilderTrust represents builder trust assessment
type BuilderTrust struct {
	Builder string `json:"builder"`
	Trusted bool `json:"trusted"`
	Reputation float64 `json:"reputation"`
	Compliance float64 `json:"compliance"`
}

// Finding represents a security or trust finding
type Finding struct {
	ID string `json:"id"`
	Type string `json:"type"`
	Severity string `json:"severity"`
	Title string `json:"title"`
	Description string `json:"description"`
	Evidence []string `json:"evidence"`
	Remediation string `json:"remediation"`
	Confidence float64 `json:"confidence"`
	Timestamp time.Time `json:"timestamp"`
	Metadata map[string]interface{} `json:"metadata"`
}

// NewProvenanceAnalyzer creates a new provenance analyzer
func NewProvenanceAnalyzer(config *Config) (*ProvenanceAnalyzer, error) {
	if config == nil {
		config = DefaultConfig()
	}
	
	client := &http.Client{
		Timeout: 30 * time.Second,
	}
	
	analyzer := &ProvenanceAnalyzer{
		config: config,
		client: client,
	}
	
	return analyzer, nil
}

// DefaultConfig returns default provenance analyzer configuration
func DefaultConfig() *Config {
	return &Config{
		Enabled: true,
		SigstoreEnabled: true,
		SigstoreRekorURL: "https://rekor.sigstore.dev",
		SigstoreFulcioURL: "https://fulcio.sigstore.dev",
		SigstoreCTLogURL: "https://ctfe.sigstore.dev",
		SLSAEnabled: true,
		SLSAMinLevel: 2,
		SLSARequiredBuilders: []string{
			"https://github.com/slsa-framework/slsa-github-generator",
		},
		VerifySignatures: true,
		VerifyProvenance: true,
		VerifyIntegrity: true,
		RequireTransparencyLog: false,
		TrustedPublishers: []string{},
		TrustedSigners: []string{},
		TrustedBuilders: []string{
			"https://github.com/slsa-framework/slsa-github-generator",
		},
		Timeout: "30s",
		RetryAttempts: 3,
		Verbose: false,
	}
}

// AnalyzePackage performs provenance analysis on a package
func (pa *ProvenanceAnalyzer) AnalyzePackage(ctx context.Context, packagePath, packageName, version, registry string) (*AnalysisResult, error) {
	startTime := time.Now()
	
	result := &AnalysisResult{
		PackageName: packageName,
		PackageVersion: version,
		Registry: registry,
		AnalysisTimestamp: time.Now(),
		Findings: []Finding{},
		Warnings: []string{},
		Recommendations: []string{},
		VerificationSources: []string{},
	}
	
	// Verify signatures
	if pa.config.VerifySignatures {
		sigVerification, err := pa.verifySignatures(ctx, packagePath, packageName, version, registry)
		if err != nil {
			result.Warnings = append(result.Warnings, fmt.Sprintf("Signature verification failed: %v", err))
		} else {
			result.SignatureVerification = sigVerification
		}
	}
	
	// Verify SLSA provenance
	if pa.config.SLSAEnabled && pa.config.VerifyProvenance {
		slsaProvenance, err := pa.verifySLSAProvenance(ctx, packageName, version, registry)
		if err != nil {
			result.Warnings = append(result.Warnings, fmt.Sprintf("SLSA provenance verification failed: %v", err))
		} else {
			result.SLSAProvenance = slsaProvenance
		}
	}
	
	// Verify integrity
	if pa.config.VerifyIntegrity {
		integrityChecks, err := pa.verifyIntegrity(ctx, packagePath, packageName, version, registry)
		if err != nil {
			result.Warnings = append(result.Warnings, fmt.Sprintf("Integrity verification failed: %v", err))
		} else {
			result.IntegrityChecks = integrityChecks
		}
	}
	
	// Verify transparency log
	if pa.config.SigstoreEnabled {
		transparencyLog, err := pa.verifyTransparencyLog(ctx, packageName, version, registry)
		if err != nil {
			result.Warnings = append(result.Warnings, fmt.Sprintf("Transparency log verification failed: %v", err))
		} else {
			result.TransparencyLog = transparencyLog
		}
	}
	
	// Assess trust
	trustAssessment := pa.assessTrust(result)
	result.TrustAssessment = trustAssessment
	
	// Calculate overall score and trust level
	pa.calculateOverallAssessment(result)
	
	// Generate findings
	pa.generateFindings(result)
	
	// Generate recommendations
	pa.generateRecommendations(result)
	
	result.ProcessingTime = time.Since(startTime)
	
	return result, nil
}

// verifySignatures verifies package signatures
func (pa *ProvenanceAnalyzer) verifySignatures(ctx context.Context, packagePath, packageName, version, registry string) (*SignatureVerification, error) {
	verification := &SignatureVerification{
		Verified: false,
		Signatures: []Signature{},
		Certificates: []Certificate{},
		KeylessSignatures: []KeylessSignature{},
		VerificationErrors: []string{},
		TrustScore: 0.0,
	}
	
	// Look for signature files
	signatureFiles := pa.findSignatureFiles(packagePath)
	
	for _, sigFile := range signatureFiles {
		sig, err := pa.parseSignatureFile(sigFile)
		if err != nil {
			verification.VerificationErrors = append(verification.VerificationErrors, fmt.Sprintf("Failed to parse signature file %s: %v", sigFile, err))
			continue
		}
		
		// Verify signature
		verified, err := pa.verifySignature(ctx, packagePath, sig)
		if err != nil {
			verification.VerificationErrors = append(verification.VerificationErrors, fmt.Sprintf("Failed to verify signature: %v", err))
			continue
		}
		
		sig.Verified = verified
		sig.Trusted = pa.isSignerTrusted(sig.Signer)
		verification.Signatures = append(verification.Signatures, *sig)
		
		if verified {
			verification.Verified = true
		}
	}
	
	// Check for keyless signatures (OIDC-based)
	keylessSignatures := pa.findKeylessSignatures(ctx, packageName, version, registry)
	for _, keylessSig := range keylessSignatures {
		verification.KeylessSignatures = append(verification.KeylessSignatures, keylessSig)
		if keylessSig.Verified {
			verification.Verified = true
		}
	}
	
	// Calculate trust score
	verification.TrustScore = pa.calculateSignatureTrustScore(verification)
	
	return verification, nil
}

// verifySLSAProvenance verifies SLSA provenance
func (pa *ProvenanceAnalyzer) verifySLSAProvenance(ctx context.Context, packageName, version, registry string) (*SLSAProvenance, error) {
	provenance := &SLSAProvenance{
		Present: false,
		Level: 0,
		Verified: false,
		TrustScore: 0.0,
		Materials: []SLSAMaterial{},
	}
	
	// Look for SLSA provenance
	provenanceData, err := pa.fetchSLSAProvenance(ctx, packageName, version, registry)
	if err != nil {
		return provenance, err
	}
	
	if provenanceData == nil {
		return provenance, nil
	}
	
	provenance.Present = true
	
	// Parse provenance data
	if err := pa.parseSLSAProvenance(provenanceData, provenance); err != nil {
		return provenance, err
	}
	
	// Verify provenance
	verified, err := pa.verifySLSAProvenanceData(ctx, provenanceData)
	if err != nil {
		return provenance, err
	}
	
	provenance.Verified = verified
	
	// Assess SLSA compliance
	compliance := pa.assessSLSACompliance(provenance)
	provenance.Compliance = compliance
	provenance.Level = compliance.Level
	
	// Calculate trust score
	provenance.TrustScore = pa.calculateSLSATrustScore(provenance)
	
	return provenance, nil
}

// verifyIntegrity verifies package integrity
func (pa *ProvenanceAnalyzer) verifyIntegrity(ctx context.Context, packagePath, packageName, version, registry string) (*IntegrityChecks, error) {
	checks := &IntegrityChecks{
		OverallVerified: false,
		TrustScore: 0.0,
	}
	
	// Verify hash
	hashVerification, err := pa.verifyHash(packagePath, packageName, version, registry)
	if err != nil {
		return checks, err
	}
	checks.HashVerification = hashVerification
	
	// Verify size
	sizeVerification, err := pa.verifySize(packagePath, packageName, version, registry)
	if err != nil {
		return checks, err
	}
	checks.SizeVerification = sizeVerification
	
	// Verify content
	contentVerification, err := pa.verifyContent(packagePath, packageName, version, registry)
	if err != nil {
		return checks, err
	}
	checks.ContentVerification = contentVerification
	
	// Overall verification
	checks.OverallVerified = hashVerification.Verified && sizeVerification.Verified && contentVerification.ManifestVerified
	
	// Calculate trust score
	checks.TrustScore = pa.calculateIntegrityTrustScore(checks)
	
	return checks, nil
}

// verifyTransparencyLog verifies transparency log entries
func (pa *ProvenanceAnalyzer) verifyTransparencyLog(ctx context.Context, packageName, version, registry string) (*TransparencyLogVerification, error) {
	verification := &TransparencyLogVerification{
		Present: false,
		Entries: []TransparencyLogEntry{},
		Verified: false,
		TrustScore: 0.0,
	}
	
	// Search for transparency log entries
	entries, err := pa.searchTransparencyLogEntries(ctx, packageName, version, registry)
	if err != nil {
		return verification, err
	}
	
	if len(entries) == 0 {
		return verification, nil
	}
	
	verification.Present = true
	verification.Entries = entries
	
	// Verify each entry
	allVerified := true
	for i := range verification.Entries {
		entry := &verification.Entries[i]
		verified, err := pa.verifyTransparencyLogEntry(ctx, entry)
		if err != nil {
			return verification, err
		}
		
		if !verified {
			allVerified = false
		}
	}
	
	verification.Verified = allVerified
	
	// Calculate trust score
	verification.TrustScore = pa.calculateTransparencyLogTrustScore(verification)
	
	return verification, nil
}

// Placeholder implementations for complex verification functions
// In production, these would integrate with actual Sigstore and SLSA systems

func (pa *ProvenanceAnalyzer) findSignatureFiles(packagePath string) []string {
	// Find signature files (.sig, .asc, etc.)
	var signatureFiles []string
	
	err := filepath.Walk(packagePath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		
		ext := filepath.Ext(path)
		if ext == ".sig" || ext == ".asc" || ext == ".signature" {
			signatureFiles = append(signatureFiles, path)
		}
		
		return nil
	})
	
	if err != nil {
		return []string{}
	}
	
	return signatureFiles
}

func (pa *ProvenanceAnalyzer) parseSignatureFile(sigFile string) (*Signature, error) {
	// Parse signature file
	content, err := ioutil.ReadFile(sigFile)
	if err != nil {
		return nil, err
	}
	
	return &Signature{
		Algorithm: "RSA-SHA256",
		Value: string(content),
		Signer: "unknown",
		Timestamp: time.Now(),
		Verified: false,
		Trusted: false,
		Metadata: make(map[string]interface{}),
	}, nil
}

func (pa *ProvenanceAnalyzer) verifySignature(ctx context.Context, packagePath string, sig *Signature) (bool, error) {
	// Verify signature against package
	// This would integrate with actual cryptographic verification
	return false, nil // Placeholder
}

func (pa *ProvenanceAnalyzer) isSignerTrusted(signer string) bool {
	// Check if signer is in trusted list
	for _, trustedSigner := range pa.config.TrustedSigners {
		if signer == trustedSigner {
			return true
		}
	}
	return false
}

func (pa *ProvenanceAnalyzer) findKeylessSignatures(ctx context.Context, packageName, version, registry string) []KeylessSignature {
	// Find keyless signatures from transparency logs
	return []KeylessSignature{} // Placeholder
}

func (pa *ProvenanceAnalyzer) fetchSLSAProvenance(ctx context.Context, packageName, version, registry string) (map[string]interface{}, error) {
	// Fetch SLSA provenance from registry or transparency log
	return nil, nil // Placeholder
}

func (pa *ProvenanceAnalyzer) parseSLSAProvenance(data map[string]interface{}, provenance *SLSAProvenance) error {
	// Parse SLSA provenance data
	if builderData, ok := data["builder"].(map[string]interface{}); ok {
		if builderID, ok := builderData["id"].(string); ok {
			provenance.Builder = &SLSABuilder{
				ID: builderID,
				Trusted: pa.isBuilderTrusted(builderID),
			}
		}
	}
	
	return nil
}

func (pa *ProvenanceAnalyzer) verifySLSAProvenanceData(ctx context.Context, data map[string]interface{}) (bool, error) {
	// Verify SLSA provenance signature and content
	return false, nil // Placeholder
}

func (pa *ProvenanceAnalyzer) isBuilderTrusted(builderID string) bool {
	// Check if builder is trusted
	for _, trustedBuilder := range pa.config.TrustedBuilders {
		if builderID == trustedBuilder {
			return true
		}
	}
	return false
}

func (pa *ProvenanceAnalyzer) assessSLSACompliance(provenance *SLSAProvenance) *SLSACompliance {
	// Handle nil provenance
	if provenance == nil {
		return &SLSACompliance{
			Level: 0,
			Requirements: make(map[string]bool),
			Violations: []string{"No provenance data available"},
			Score: 0.0,
		}
	}

	// Assess SLSA compliance level
	compliance := &SLSACompliance{
		Level: 0,
		Requirements: make(map[string]bool),
		Violations: []string{},
		Score: 0.0,
	}

	// Check SLSA Level 1 requirements
	if provenance.Builder != nil && provenance.Builder.ID != "" {
		compliance.Requirements["build_service"] = true
		compliance.Level = 1
	}
	
	// Check SLSA Level 2 requirements
	if provenance.Invocation != nil && provenance.Invocation.ConfigSource != nil {
		compliance.Requirements["version_controlled"] = true
		if compliance.Level >= 1 {
			compliance.Level = 2
		}
	}
	
	// Check SLSA Level 3 requirements
	if provenance.Builder != nil && provenance.Builder.Trusted {
		compliance.Requirements["isolated_build"] = true
		if compliance.Level >= 2 {
			compliance.Level = 3
		}
	}
	
	// Calculate compliance score
	totalRequirements := len(compliance.Requirements)
	metRequirements := 0
	for _, met := range compliance.Requirements {
		if met {
			metRequirements++
		}
	}
	
	if totalRequirements > 0 {
		compliance.Score = float64(metRequirements) / float64(totalRequirements)
	}
	
	return compliance
}

func (pa *ProvenanceAnalyzer) verifyHash(packagePath, packageName, version, registry string) (*HashVerification, error) {
	// Calculate package hash
	file, err := os.Open(packagePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	
	hash := sha256.New()
	if _, err := file.WriteTo(hash); err != nil {
		return nil, err
	}
	
	actualHash := hex.EncodeToString(hash.Sum(nil))
	
	// Fetch expected hash from registry
	expectedHash, err := pa.fetchExpectedHash(packageName, version, registry)
	if err != nil {
		return &HashVerification{
			Algorithm: "SHA256",
			ActualHash: actualHash,
			Verified: false,
			Source: "calculated",
		}, err
	}
	
	return &HashVerification{
		Algorithm: "SHA256",
		ExpectedHash: expectedHash,
		ActualHash: actualHash,
		Verified: expectedHash == actualHash,
		Source: registry,
	}, nil
}

func (pa *ProvenanceAnalyzer) verifySize(packagePath, packageName, version, registry string) (*SizeVerification, error) {
	// Get actual file size
	info, err := os.Stat(packagePath)
	if err != nil {
		return nil, err
	}
	
	actualSize := info.Size()
	
	// Fetch expected size from registry
	expectedSize, err := pa.fetchExpectedSize(packageName, version, registry)
	if err != nil {
		return &SizeVerification{
			ActualSize: actualSize,
			Verified: false,
			Source: "calculated",
		}, err
	}
	
	return &SizeVerification{
		ExpectedSize: expectedSize,
		ActualSize: actualSize,
		Verified: expectedSize == actualSize,
		Source: registry,
	}, nil
}

func (pa *ProvenanceAnalyzer) verifyContent(packagePath, packageName, version, registry string) (*ContentVerification, error) {
	// Verify package content integrity
	return &ContentVerification{
		ManifestVerified: true,
		FilesVerified: true,
		PermissionsVerified: true,
		ModifiedFiles: []string{},
		MissingFiles: []string{},
		ExtraFiles: []string{},
	}, nil // Placeholder
}

func (pa *ProvenanceAnalyzer) searchTransparencyLogEntries(ctx context.Context, packageName, version, registry string) ([]TransparencyLogEntry, error) {
	// Search transparency log for package entries
	return []TransparencyLogEntry{}, nil // Placeholder
}

func (pa *ProvenanceAnalyzer) verifyTransparencyLogEntry(ctx context.Context, entry *TransparencyLogEntry) (bool, error) {
	// Verify transparency log entry
	return false, nil // Placeholder
}

func (pa *ProvenanceAnalyzer) fetchExpectedHash(packageName, version, registry string) (string, error) {
	// Fetch expected hash from registry metadata
	return "", fmt.Errorf("hash not available")
}

func (pa *ProvenanceAnalyzer) fetchExpectedSize(packageName, version, registry string) (int64, error) {
	// Fetch expected size from registry metadata
	return 0, fmt.Errorf("size not available")
}

// Trust assessment and scoring functions
func (pa *ProvenanceAnalyzer) assessTrust(result *AnalysisResult) *TrustAssessment {
	assessment := &TrustAssessment{
		OverallTrustScore: 0.0,
		TrustLevel: "UNKNOWN",
		RiskFactors: []string{},
	}
	
	// Assess publisher trust
	if result.SignatureVerification != nil {
		assessment.PublisherTrust = &PublisherTrust{
			Publisher: "unknown",
			Trusted: false,
			Reputation: 0.5,
			VerificationHistory: []string{},
		}
	}
	
	// Assess signer trust
	if result.SignatureVerification != nil && len(result.SignatureVerification.Signatures) > 0 {
		assessment.SignerTrust = &SignerTrust{
			Signer: result.SignatureVerification.Signatures[0].Signer,
			Trusted: result.SignatureVerification.Signatures[0].Trusted,
			Reputation: 0.5,
			CertificateChain: []string{},
		}
	}
	
	// Assess builder trust
	if result.SLSAProvenance != nil && result.SLSAProvenance.Builder != nil {
		assessment.BuilderTrust = &BuilderTrust{
			Builder: result.SLSAProvenance.Builder.ID,
			Trusted: result.SLSAProvenance.Builder.Trusted,
			Reputation: 0.7,
			Compliance: result.SLSAProvenance.Compliance.Score,
		}
	}
	
	return assessment
}

func (pa *ProvenanceAnalyzer) calculateOverallAssessment(result *AnalysisResult) {
	score := 0.0
	weightSum := 0.0
	
	// Weight signature verification
	if result.SignatureVerification != nil {
		score += result.SignatureVerification.TrustScore * 0.3
		weightSum += 0.3
	}
	
	// Weight SLSA provenance
	if result.SLSAProvenance != nil {
		score += result.SLSAProvenance.TrustScore * 0.3
		weightSum += 0.3
	}
	
	// Weight integrity checks
	if result.IntegrityChecks != nil {
		score += result.IntegrityChecks.TrustScore * 0.2
		weightSum += 0.2
	}
	
	// Weight transparency log
	if result.TransparencyLog != nil {
		score += result.TransparencyLog.TrustScore * 0.2
		weightSum += 0.2
	}
	
	if weightSum > 0 {
		result.OverallScore = score / weightSum
	}
	
	// Determine trust level
	if result.OverallScore > 0.8 {
		result.TrustLevel = "HIGH"
	} else if result.OverallScore > 0.6 {
		result.TrustLevel = "MEDIUM"
	} else if result.OverallScore > 0.4 {
		result.TrustLevel = "LOW"
	} else {
		result.TrustLevel = "VERY_LOW"
	}
}

// Placeholder trust score calculation functions
func (pa *ProvenanceAnalyzer) calculateSignatureTrustScore(verification *SignatureVerification) float64 {
	if verification == nil || !verification.Verified {
		return 0.0
	}
	
	score := 0.5 // Base score for verified signature
	
	// Bonus for trusted signers
	for _, sig := range verification.Signatures {
		if sig.Trusted {
			score += 0.3
			break
		}
	}
	
	// Bonus for keyless signatures
	for _, keylessSig := range verification.KeylessSignatures {
		if keylessSig.Verified && keylessSig.Trusted {
			score += 0.2
			break
		}
	}
	
	return min(score, 1.0)
}

func (pa *ProvenanceAnalyzer) calculateSLSATrustScore(provenance *SLSAProvenance) float64 {
	if provenance == nil || !provenance.Present {
		return 0.0
	}
	
	score := 0.2 // Base score for having provenance
	
	if provenance.Verified {
		score += 0.3
	}
	
	if provenance.Builder != nil && provenance.Builder.Trusted {
		score += 0.3
	}
	
	if provenance.Compliance != nil {
		score += provenance.Compliance.Score * 0.2
	}
	
	return min(score, 1.0)
}

func (pa *ProvenanceAnalyzer) calculateIntegrityTrustScore(checks *IntegrityChecks) float64 {
	if checks == nil {
		return 0.0
	}
	score := 0.0
	
	if checks.HashVerification != nil && checks.HashVerification.Verified {
		score += 0.4
	}
	
	if checks.SizeVerification != nil && checks.SizeVerification.Verified {
		score += 0.2
	}
	
	if checks.ContentVerification != nil && checks.ContentVerification.ManifestVerified {
		score += 0.4
	}
	
	return score
}

func (pa *ProvenanceAnalyzer) calculateTransparencyLogTrustScore(verification *TransparencyLogVerification) float64 {
	if verification == nil || !verification.Present {
		return 0.0
	}
	
	if verification.Verified {
		return 1.0
	}
	
	return 0.5
}

// Finding and recommendation generation
func (pa *ProvenanceAnalyzer) generateFindings(result *AnalysisResult) {
	// Generate findings based on verification results
	if result.SignatureVerification != nil && !result.SignatureVerification.Verified {
		result.Findings = append(result.Findings, Finding{
			ID: "PROV_001",
			Type: "signature_verification",
			Severity: "HIGH",
			Title: "Package Signature Verification Failed",
			Description: "The package signature could not be verified",
			Evidence: result.SignatureVerification.VerificationErrors,
			Remediation: "Verify the package source and signature",
			Confidence: 0.9,
			Timestamp: time.Now(),
		})
	}
	
	if result.SLSAProvenance != nil && !result.SLSAProvenance.Present {
		result.Findings = append(result.Findings, Finding{
			ID: "PROV_002",
			Type: "slsa_provenance",
			Severity: "MEDIUM",
			Title: "SLSA Provenance Not Available",
			Description: "No SLSA provenance information found for this package",
			Remediation: "Request SLSA provenance from the package maintainer",
			Confidence: 0.8,
			Timestamp: time.Now(),
		})
	}
	
	if result.IntegrityChecks != nil && !result.IntegrityChecks.OverallVerified {
		result.Findings = append(result.Findings, Finding{
			ID: "PROV_003",
			Type: "integrity_check",
			Severity: "HIGH",
			Title: "Package Integrity Check Failed",
			Description: "Package integrity verification failed",
			Remediation: "Re-download the package from a trusted source",
			Confidence: 0.95,
			Timestamp: time.Now(),
		})
	}
}

func (pa *ProvenanceAnalyzer) generateRecommendations(result *AnalysisResult) {
	if result.OverallScore < 0.3 {
		result.Recommendations = append(result.Recommendations, "CRITICAL: Do not use this package - insufficient provenance and integrity verification")
	} else if result.OverallScore < 0.6 {
		result.Recommendations = append(result.Recommendations, "CAUTION: Package has limited provenance information - proceed with caution")
	}
	
	if result.SignatureVerification == nil || !result.SignatureVerification.Verified {
		result.Recommendations = append(result.Recommendations, "Verify package signatures before use")
	}
	
	if result.SLSAProvenance == nil || !result.SLSAProvenance.Present {
		result.Recommendations = append(result.Recommendations, "Request SLSA provenance information from package maintainer")
	}
	
	if result.TransparencyLog == nil || !result.TransparencyLog.Present {
		result.Recommendations = append(result.Recommendations, "Package not found in transparency logs - verify authenticity")
	}
}

// ExportResults exports analysis results to JSON
func (pa *ProvenanceAnalyzer) ExportResults(result *AnalysisResult, outputPath string) error {
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal results: %w", err)
	}
	
	return ioutil.WriteFile(outputPath, data, 0644)
}

func min(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}