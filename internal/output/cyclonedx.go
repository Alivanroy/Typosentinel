package output

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/Alivanroy/Typosentinel/internal/scanner"
	"github.com/google/uuid"
)

// CycloneDXFormatter implements the CycloneDX SBOM format
type CycloneDXFormatter struct{}

// CycloneDXDocument represents a CycloneDX SBOM document
type CycloneDXDocument struct {
	BOMFormat       string                   `json:"bomFormat"`
	SpecVersion     string                   `json:"specVersion"`
	SerialNumber    string                   `json:"serialNumber"`
	Version         int                      `json:"version"`
	Metadata        CycloneDXMetadata        `json:"metadata"`
	Components      []CycloneDXComponent     `json:"components"`
	Services        []CycloneDXService       `json:"services,omitempty"`
	Dependencies    []CycloneDXDependency    `json:"dependencies,omitempty"`
	Vulnerabilities []CycloneDXVulnerability `json:"vulnerabilities,omitempty"`
}

// CycloneDXMetadata contains metadata about the SBOM
type CycloneDXMetadata struct {
	Timestamp string              `json:"timestamp"`
	Tools     []CycloneDXTool     `json:"tools"`
	Authors   []CycloneDXAuthor   `json:"authors,omitempty"`
	Component *CycloneDXComponent `json:"component,omitempty"`
}

// CycloneDXTool represents a tool used to create the SBOM
type CycloneDXTool struct {
	Vendor  string `json:"vendor"`
	Name    string `json:"name"`
	Version string `json:"version"`
}

// CycloneDXAuthor represents an author of the SBOM
type CycloneDXAuthor struct {
	Name  string `json:"name"`
	Email string `json:"email,omitempty"`
}

// CycloneDXComponent represents a software component
type CycloneDXComponent struct {
	Type         string                 `json:"type"`
	BOMRef       string                 `json:"bom-ref"`
	Name         string                 `json:"name"`
	Version      string                 `json:"version,omitempty"`
	Description  string                 `json:"description,omitempty"`
	Scope        string                 `json:"scope,omitempty"`
	Hashes       []CycloneDXHash        `json:"hashes,omitempty"`
	Licenses     []CycloneDXLicense     `json:"licenses,omitempty"`
	Copyright    string                 `json:"copyright,omitempty"`
	CPE          string                 `json:"cpe,omitempty"`
	PURL         string                 `json:"purl,omitempty"`
	ExternalRefs []CycloneDXExternalRef `json:"externalReferences,omitempty"`
	Properties   []CycloneDXProperty    `json:"properties,omitempty"`
}

// CycloneDXService represents a service
type CycloneDXService struct {
	BOMRef         string                 `json:"bom-ref"`
	Name           string                 `json:"name"`
	Version        string                 `json:"version,omitempty"`
	Description    string                 `json:"description,omitempty"`
	Endpoints      []string               `json:"endpoints,omitempty"`
	Authenticated  bool                   `json:"authenticated,omitempty"`
	XTrustBoundary bool                   `json:"x-trust-boundary,omitempty"`
	Data           []CycloneDXDataFlow    `json:"data,omitempty"`
	Licenses       []CycloneDXLicense     `json:"licenses,omitempty"`
	ExternalRefs   []CycloneDXExternalRef `json:"externalReferences,omitempty"`
}

// CycloneDXDependency represents a dependency relationship
type CycloneDXDependency struct {
	Ref       string   `json:"ref"`
	DependsOn []string `json:"dependsOn,omitempty"`
}

// CycloneDXVulnerability represents a security vulnerability
type CycloneDXVulnerability struct {
	BOMRef         string                   `json:"bom-ref"`
	ID             string                   `json:"id"`
	Source         CycloneDXVulnSource      `json:"source"`
	References     []CycloneDXVulnReference `json:"references,omitempty"`
	Ratings        []CycloneDXVulnRating    `json:"ratings,omitempty"`
	CWEs           []int                    `json:"cwes,omitempty"`
	Description    string                   `json:"description,omitempty"`
	Detail         string                   `json:"detail,omitempty"`
	Recommendation string                   `json:"recommendation,omitempty"`
	Affects        []CycloneDXVulnAffects   `json:"affects,omitempty"`
	Published      string                   `json:"published,omitempty"`
	Updated        string                   `json:"updated,omitempty"`
	Credits        CycloneDXVulnCredits     `json:"credits,omitempty"`
	Tools          []CycloneDXTool          `json:"tools,omitempty"`
	Analysis       CycloneDXVulnAnalysis    `json:"analysis,omitempty"`
}

// CycloneDXHash represents a hash value
type CycloneDXHash struct {
	Algorithm string `json:"alg"`
	Content   string `json:"content"`
}

// CycloneDXLicense represents a license
type CycloneDXLicense struct {
	License CycloneDXLicenseChoice `json:"license"`
}

// CycloneDXLicenseChoice represents a license choice
type CycloneDXLicenseChoice struct {
	ID   string `json:"id,omitempty"`
	Name string `json:"name,omitempty"`
	Text string `json:"text,omitempty"`
	URL  string `json:"url,omitempty"`
}

// CycloneDXExternalRef represents an external reference
type CycloneDXExternalRef struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}

// CycloneDXProperty represents a property
type CycloneDXProperty struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// CycloneDXDataFlow represents data flow information
type CycloneDXDataFlow struct {
	Flow           string `json:"flow"`
	Classification string `json:"classification"`
}

// CycloneDXVulnSource represents a vulnerability source
type CycloneDXVulnSource struct {
	Name string `json:"name"`
	URL  string `json:"url,omitempty"`
}

// CycloneDXVulnReference represents a vulnerability reference
type CycloneDXVulnReference struct {
	ID     string              `json:"id"`
	Source CycloneDXVulnSource `json:"source"`
}

// CycloneDXVulnRating represents a vulnerability rating
type CycloneDXVulnRating struct {
	Source   CycloneDXVulnSource `json:"source"`
	Score    float64             `json:"score,omitempty"`
	Severity string              `json:"severity,omitempty"`
	Method   string              `json:"method,omitempty"`
	Vector   string              `json:"vector,omitempty"`
}

// CycloneDXVulnAffects represents what a vulnerability affects
type CycloneDXVulnAffects struct {
	Ref string `json:"ref"`
}

// CycloneDXVulnCredits represents vulnerability credits
type CycloneDXVulnCredits struct {
	Individuals   []CycloneDXVulnIndividual   `json:"individuals,omitempty"`
	Organizations []CycloneDXVulnOrganization `json:"organizations,omitempty"`
}

// CycloneDXVulnIndividual represents an individual credited for vulnerability discovery
type CycloneDXVulnIndividual struct {
	Name  string `json:"name"`
	Email string `json:"email,omitempty"`
}

// CycloneDXVulnOrganization represents an organization credited for vulnerability discovery
type CycloneDXVulnOrganization struct {
	Name string `json:"name"`
	URL  string `json:"url,omitempty"`
}

// CycloneDXVulnAnalysis represents vulnerability analysis information
type CycloneDXVulnAnalysis struct {
	State         string   `json:"state,omitempty"`
	Justification string   `json:"justification,omitempty"`
	Response      []string `json:"response,omitempty"`
	Detail        string   `json:"detail,omitempty"`
	FirstIssued   string   `json:"firstIssued,omitempty"`
	LastUpdated   string   `json:"lastUpdated,omitempty"`
}

// NewCycloneDXFormatter creates a new CycloneDX formatter
func NewCycloneDXFormatter() *CycloneDXFormatter {
	return &CycloneDXFormatter{}
}

// Format formats scan results as CycloneDX SBOM
func (f *CycloneDXFormatter) Format(results *scanner.ScanResults, options *FormatterOptions) ([]byte, error) {
	doc := f.createCycloneDXDocument(results)
	return json.MarshalIndent(doc, "", "  ")
}

// createCycloneDXDocument creates a CycloneDX document from scan results
func (f *CycloneDXFormatter) createCycloneDXDocument(results *scanner.ScanResults) *CycloneDXDocument {
	now := time.Now().UTC().Format(time.RFC3339)
	serialNumber := fmt.Sprintf("urn:uuid:%s", uuid.New().String())

	doc := &CycloneDXDocument{
		BOMFormat:    "CycloneDX",
		SpecVersion:  "1.4",
		SerialNumber: serialNumber,
		Version:      1,
		Metadata: CycloneDXMetadata{
			Timestamp: now,
			Tools: []CycloneDXTool{
				{
					Vendor:  "Typosentinel",
					Name:    "Typosentinel",
					Version: "1.0.0",
				},
			},
		},
		Components:      f.createComponents(results),
		Dependencies:    f.createDependencies(results),
		Vulnerabilities: f.createVulnerabilities(results),
	}

	return doc
}

// createComponents creates CycloneDX components from scan results
func (f *CycloneDXFormatter) createComponents(results *scanner.ScanResults) []CycloneDXComponent {
	var components []CycloneDXComponent

	for _, result := range results.Results {
		// Skip if package or metadata is nil
		if result.Package == nil || result.Package.Metadata == nil {
			continue
		}

		component := CycloneDXComponent{
			Type:    "library",
			BOMRef:  f.createBOMRef(result.Package.Metadata.Name, result.Package.Metadata.Version),
			Name:    result.Package.Metadata.Name,
			Version: result.Package.Metadata.Version,
			Scope:   "required",
		}

		// Add description if available
		if result.Package.Metadata.Description != "" {
			component.Description = result.Package.Metadata.Description
		}

		// Add license if available
		if result.Package.Metadata.License != "" {
			component.Licenses = []CycloneDXLicense{
				{
					License: CycloneDXLicenseChoice{
						ID: result.Package.Metadata.License,
					},
				},
			}
		}

		// Add PURL if registry information is available
		if result.Package.Metadata.Registry != "" {
			component.PURL = f.createPURL(result)
		}

		// Add external references
		if result.Package.Metadata.Homepage != "" {
			component.ExternalRefs = append(component.ExternalRefs, CycloneDXExternalRef{
				Type: "website",
				URL:  result.Package.Metadata.Homepage,
			})
		}

		if result.Package.Metadata.Repository != "" {
			component.ExternalRefs = append(component.ExternalRefs, CycloneDXExternalRef{
				Type: "vcs",
				URL:  result.Package.Metadata.Repository,
			})
		}

		// Add security properties
		if len(result.Threats) > 0 {
			component.Properties = append(component.Properties, CycloneDXProperty{
				Name:  "typosentinel:threats-detected",
				Value: fmt.Sprintf("%d", len(result.Threats)),
			})
		}

		components = append(components, component)
	}

	return components
}

// createDependencies creates CycloneDX dependencies from scan results
func (f *CycloneDXFormatter) createDependencies(results *scanner.ScanResults) []CycloneDXDependency {
	var dependencies []CycloneDXDependency

	// For now, we'll create a simple dependency structure
	// In a more complete implementation, this would analyze the actual dependency tree
	for _, result := range results.Results {
		dep := CycloneDXDependency{
			Ref: f.createBOMRef(result.Package.Metadata.Name, result.Package.Metadata.Version),
			// DependsOn would be populated with actual dependencies if available
		}
		dependencies = append(dependencies, dep)
	}

	return dependencies
}

// createVulnerabilities creates CycloneDX vulnerabilities from scan results
func (f *CycloneDXFormatter) createVulnerabilities(results *scanner.ScanResults) []CycloneDXVulnerability {
	var vulnerabilities []CycloneDXVulnerability

	for _, result := range results.Results {
		for i, threat := range result.Threats {
			vuln := CycloneDXVulnerability{
				BOMRef: fmt.Sprintf("vuln-%s-%d", f.sanitizeID(result.Package.Metadata.Name), i),
				ID:     fmt.Sprintf("TYPOSENTINEL-%s-%d", f.sanitizeID(result.Package.Metadata.Name), i),
				Source: CycloneDXVulnSource{
					Name: "Typosentinel",
					URL:  "https://typosentinel.com",
				},
				Description:    threat.Description,
				Detail:         threat.Evidence,
				Recommendation: threat.Recommendation,
				Ratings: []CycloneDXVulnRating{
					{
						Source: CycloneDXVulnSource{
							Name: "Typosentinel",
						},
						Score:    threat.Score,
						Severity: threat.Severity,
						Method:   "Other",
					},
				},
				Affects: []CycloneDXVulnAffects{
					{
						Ref: f.createBOMRef(result.Package.Metadata.Name, result.Package.Metadata.Version),
					},
				},
				Analysis: CycloneDXVulnAnalysis{
					State:  "exploitable",
					Detail: fmt.Sprintf("Threat type: %s, Confidence: %.2f", threat.Type, threat.Confidence),
				},
			}

			vulnerabilities = append(vulnerabilities, vuln)
		}
	}

	return vulnerabilities
}

// createBOMRef creates a BOM reference for a component
func (f *CycloneDXFormatter) createBOMRef(name, version string) string {
	if version != "" {
		return fmt.Sprintf("%s@%s", f.sanitizeID(name), version)
	}
	return f.sanitizeID(name)
}

// createPURL creates a Package URL for a scan result
func (f *CycloneDXFormatter) createPURL(result scanner.ScanResult) string {
	pkgType := "generic"
	switch result.Package.Metadata.Registry {
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

	purl := fmt.Sprintf("pkg:%s/%s", pkgType, result.Package.Metadata.Name)
	if result.Package.Metadata.Version != "" {
		purl += "@" + result.Package.Metadata.Version
	}

	return purl
}

// sanitizeID sanitizes a string for use as an ID
func (f *CycloneDXFormatter) sanitizeID(s string) string {
	// Replace invalid characters with hyphens
	result := ""
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' || r == '.' {
			result += string(r)
		} else {
			result += "-"
		}
	}
	return result
}
