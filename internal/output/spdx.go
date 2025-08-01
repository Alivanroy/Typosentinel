package output

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/Alivanroy/Typosentinel/internal/scanner"
	"github.com/google/uuid"
)

// SPDXFormatter implements SPDX (Software Package Data Exchange) format
type SPDXFormatter struct {
	version string
	// Enterprise fields
	EnterpriseInfo *SPDXEnterpriseInfo
}

// SPDXDocument represents an SPDX document
type SPDXDocument struct {
	SPDXVersion       string              `json:"spdxVersion"`
	DataLicense       string              `json:"dataLicense"`
	SPDXID            string              `json:"SPDXID"`
	DocumentName      string              `json:"documentName"`
	DocumentNamespace string              `json:"documentNamespace"`
	CreationInfo      SPDXCreationInfo    `json:"creationInfo"`
	Packages          []SPDXPackage       `json:"packages"`
	Relationships     []SPDXRelationship  `json:"relationships"`
	Annotations       []SPDXAnnotation    `json:"annotations,omitempty"`
	// Enterprise extensions
	EnterpriseInfo    *SPDXEnterpriseInfo `json:"enterpriseInfo,omitempty"`
}

// SPDXEnterpriseInfo contains enterprise-specific metadata
type SPDXEnterpriseInfo struct {
	OrganizationID       string                    `json:"organizationId,omitempty"`
	TenantID             string                    `json:"tenantId,omitempty"`
	ScanPolicy           *SPDXScanPolicy           `json:"scanPolicy,omitempty"`
	ComplianceFrameworks []string                  `json:"complianceFrameworks,omitempty"`
	RiskAssessment       *SPDXRiskAssessment       `json:"riskAssessment,omitempty"`
	AuditInfo            *SPDXAuditInfo            `json:"auditInfo,omitempty"`
	ScanContext          *SPDXScanContext          `json:"scanContext,omitempty"`
}

// SPDXScanPolicy represents the scan policy used
type SPDXScanPolicy struct {
	PolicyID      string `json:"policyId,omitempty"`
	PolicyVersion string `json:"policyVersion,omitempty"`
	PolicyName    string `json:"policyName,omitempty"`
	Enforcement   string `json:"enforcement,omitempty"`
}

// SPDXRiskAssessment represents risk assessment data
type SPDXRiskAssessment struct {
	OverallRiskScore float64            `json:"overallRiskScore,omitempty"`
	RiskFactors      map[string]float64 `json:"riskFactors,omitempty"`
	MitigationStatus string             `json:"mitigationStatus,omitempty"`
	Recommendations  []string           `json:"recommendations,omitempty"`
}

// SPDXAuditInfo represents audit trail information
type SPDXAuditInfo struct {
	ScanID             string `json:"scanId,omitempty"`
	ApprovalRequired   bool   `json:"approvalRequired"`
	ApprovalStatus     string `json:"approvalStatus,omitempty"`
	ApprovedBy         string `json:"approvedBy,omitempty"`
	ApprovalTimestamp  string `json:"approvalTimestamp,omitempty"`
	RetentionPeriod    string `json:"retentionPeriod,omitempty"`
	DataClassification string `json:"dataClassification,omitempty"`
}

// SPDXScanContext represents the context of the scan
type SPDXScanContext struct {
	InitiatedBy   string `json:"initiatedBy,omitempty"`
	ScanReason    string `json:"scanReason,omitempty"`
	Environment   string `json:"environment,omitempty"`
	CICDPipeline  string `json:"cicdPipeline,omitempty"`
	ProjectID     string `json:"projectId,omitempty"`
	RepositoryURL string `json:"repositoryUrl,omitempty"`
	Branch        string `json:"branch,omitempty"`
	CommitSHA     string `json:"commitSha,omitempty"`
}

// SPDXCreationInfo contains document creation information
type SPDXCreationInfo struct {
	Created            string   `json:"created"`
	Creators           []string `json:"creators"`
	LicenseListVersion string   `json:"licenseListVersion,omitempty"`
}

// SPDXPackage represents a software package
type SPDXPackage struct {
	SPDXID               string                    `json:"SPDXID"`
	Name                 string                    `json:"name"`
	DownloadLocation     string                    `json:"downloadLocation"`
	FilesAnalyzed        bool                      `json:"filesAnalyzed"`
	LicenseConcluded     string                    `json:"licenseConcluded"`
	LicenseDeclared      string                    `json:"licenseDeclared"`
	CopyrightText        string                    `json:"copyrightText"`
	VersionInfo          string                    `json:"versionInfo,omitempty"`
	Supplier             string                    `json:"supplier,omitempty"`
	Originator           string                    `json:"originator,omitempty"`
	Homepage             string                    `json:"homepage,omitempty"`
	Description          string                    `json:"description,omitempty"`
	ExternalRefs         []SPDXExternalRef         `json:"externalRefs,omitempty"`
	AttributionTexts     []string                  `json:"attributionTexts,omitempty"`
	Annotations          []SPDXAnnotation          `json:"annotations,omitempty"`
	SecurityVulnerabilities []SPDXVulnerability    `json:"securityVulnerabilities,omitempty"`
}

// SPDXExternalRef represents an external reference
type SPDXExternalRef struct {
	ReferenceCategory string `json:"referenceCategory"`
	ReferenceType     string `json:"referenceType"`
	ReferenceLocator  string `json:"referenceLocator"`
	Comment           string `json:"comment,omitempty"`
}

// SPDXRelationship represents a relationship between SPDX elements
type SPDXRelationship struct {
	SPDXElementID      string `json:"spdxElementId"`
	RelationshipType   string `json:"relationshipType"`
	RelatedSPDXElement string `json:"relatedSpdxElement"`
	Comment            string `json:"comment,omitempty"`
}

// SPDXAnnotation represents an annotation
type SPDXAnnotation struct {
	AnnotationType string `json:"annotationType"`
	Annotator      string `json:"annotator"`
	AnnotationDate string `json:"annotationDate"`
	AnnotationComment string `json:"annotationComment"`
}

// SPDXVulnerability represents a security vulnerability
type SPDXVulnerability struct {
	ID          string   `json:"id"`
	Description string   `json:"description"`
	Severity    string   `json:"severity"`
	CVSSv3      string   `json:"cvssv3,omitempty"`
	References  []string `json:"references,omitempty"`
}

// NewSPDXFormatter creates a new SPDX formatter
func NewSPDXFormatter() *SPDXFormatter {
	return &SPDXFormatter{
		version: "SPDX-2.3",
	}
}

// NewEnterpriseSPDXFormatter creates a new SPDX formatter with enterprise metadata
func NewEnterpriseSPDXFormatter(enterpriseInfo *SPDXEnterpriseInfo) *SPDXFormatter {
	return &SPDXFormatter{
		version:        "SPDX-2.3",
		EnterpriseInfo: enterpriseInfo,
	}
}

// Format formats scan results as SPDX JSON
func (f *SPDXFormatter) Format(results *scanner.ScanResults, options FormatterOptions) ([]byte, error) {
	doc := f.createSPDXDocument(results)

	return json.MarshalIndent(doc, "", "  ")
}

// GetMimeType returns the MIME type for SPDX format
func (f *SPDXFormatter) GetMimeType() string {
	return "application/json"
}

// GetFileExtension returns the file extension for SPDX format
func (f *SPDXFormatter) GetFileExtension() string {
	return ".spdx.json"
}

// createSPDXDocument creates an SPDX document from scan results
func (f *SPDXFormatter) createSPDXDocument(results *scanner.ScanResults) *SPDXDocument {
	now := time.Now().UTC().Format(time.RFC3339)
	documentNamespace := fmt.Sprintf("https://typosentinel.com/spdx/%s", uuid.New().String())

	doc := &SPDXDocument{
		SPDXVersion:       f.version,
		DataLicense:       "CC0-1.0",
		SPDXID:            "SPDXRef-DOCUMENT",
		DocumentName:      "Typosentinel Security Scan",
		DocumentNamespace: documentNamespace,
		CreationInfo: SPDXCreationInfo{
			Created:  now,
			Creators: []string{"Tool: Typosentinel"},
			LicenseListVersion: "3.19",
		},
		Packages:      f.createPackages(results),
		Relationships: f.createRelationships(results),
		EnterpriseInfo: f.EnterpriseInfo,
	}

	// Add annotations for threats
	hasThreats := false
	for _, result := range results.Results {
		if len(result.Threats) > 0 {
			hasThreats = true
			break
		}
	}
	if hasThreats {
		doc.Annotations = f.createAnnotations(results)
	}

	return doc
}

// createPackages creates SPDX packages from scan results
func (f *SPDXFormatter) createPackages(results *scanner.ScanResults) []SPDXPackage {
	var packages []SPDXPackage

	// Add packages from scan results
	for _, result := range results.Results {
		pkg := SPDXPackage{
			SPDXID:           f.sanitizeID(fmt.Sprintf("SPDXRef-Package-%s", result.Package.Name)),
			Name:             result.Package.Name,
			DownloadLocation: "NOASSERTION",
			FilesAnalyzed:    false,
			LicenseConcluded: "NOASSERTION",
			LicenseDeclared:  "NOASSERTION",
			CopyrightText:    "NOASSERTION",
			ExternalRefs:     []SPDXExternalRef{},
		}

		// Add version if available
		if result.Package.Version != "" {
			pkg.VersionInfo = result.Package.Version
		}

		// Add security vulnerabilities from threats
		if len(result.Threats) > 0 {
			pkg.SecurityVulnerabilities = f.createVulnerabilitiesFromThreats(result.Threats)
		}

		// Add registry information
		if result.Package.Registry != "" {
			purl := f.createPackageURLFromResult(result)
			ref := SPDXExternalRef{
				ReferenceCategory: "PACKAGE-MANAGER",
				ReferenceType:     "purl",
				ReferenceLocator:  purl,
			}
			pkg.ExternalRefs = append(pkg.ExternalRefs, ref)
		}

		packages = append(packages, pkg)
	}

	return packages
}

// createRelationships creates SPDX relationships
func (f *SPDXFormatter) createRelationships(results *scanner.ScanResults) []SPDXRelationship {
	var relationships []SPDXRelationship

	// Document describes packages
	for _, result := range results.Results {
		packageID := f.sanitizeID(fmt.Sprintf("SPDXRef-Package-%s", result.Package.Name))
		relationships = append(relationships, SPDXRelationship{
			SPDXElementID:      "SPDXRef-DOCUMENT",
			RelationshipType:   "DESCRIBES",
			RelatedSPDXElement: packageID,
		})
	}

	return relationships
}

// createAnnotations creates SPDX annotations for threats
func (f *SPDXFormatter) createAnnotations(results *scanner.ScanResults) []SPDXAnnotation {
	var annotations []SPDXAnnotation
	now := time.Now().UTC().Format(time.RFC3339)

	for _, result := range results.Results {
		for _, threat := range result.Threats {
			annotation := SPDXAnnotation{
				AnnotationType:    "REVIEW",
				Annotator:         "Tool: Typosentinel",
				AnnotationDate:    now,
				AnnotationComment: fmt.Sprintf("Security threat detected: %s (Severity: %s) - %s", threat.Type, threat.Severity, threat.Description),
			}
			annotations = append(annotations, annotation)
		}
	}

	return annotations
}

// createVulnerabilitiesFromThreats creates SPDX vulnerabilities from threats
func (f *SPDXFormatter) createVulnerabilitiesFromThreats(threats []scanner.Threat) []SPDXVulnerability {
	var vulnerabilities []SPDXVulnerability

	for i, threat := range threats {
		vuln := SPDXVulnerability{
			ID:          fmt.Sprintf("TYPOSENTINEL-%d", i+1),
			Description: threat.Description,
			Severity:    threat.Severity,
		}

		// Add references if available
		if threat.Source != "" {
			vuln.References = []string{threat.Source}
		}

		vulnerabilities = append(vulnerabilities, vuln)
	}

	return vulnerabilities
}

// createPackageURLFromResult creates a Package URL for a scan result
func (f *SPDXFormatter) createPackageURLFromResult(result scanner.ScanResult) string {
	// Basic PURL format: pkg:type/namespace/name@version
	pkgType := "generic"
	switch result.Package.Registry {
		case "npm":
			pkgType = "npm"
		case "pypi":
			pkgType = "pypi"
		case "maven":
			pkgType = "maven"
		case "nuget":
			pkgType = "nuget"
		case "gem":
			pkgType = "gem"
		case "cargo":
			pkgType = "cargo"
		case "go":
			pkgType = "golang"
	}

	purl := fmt.Sprintf("pkg:%s/%s", pkgType, result.Package.Name)
	if result.Package.Version != "" {
		purl += "@" + result.Package.Version
	}

	return purl
}



// sanitizeID sanitizes a string for use as an SPDX ID
func (f *SPDXFormatter) sanitizeID(s string) string {
	// Replace invalid characters with hyphens
	replacer := strings.NewReplacer(
		" ", "-",
		"/", "-",
		"\\", "-",
		":", "-",
		".", "-",
		"@", "-",
	)
	return replacer.Replace(s)
}