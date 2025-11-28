package output

import (
    "encoding/json"
    "github.com/Alivanroy/Typosentinel/internal/scanner"
)

type SPDXDocument struct{
    SPDXVersion string `json:"spdxVersion"`
    DataLicense string `json:"dataLicense"`
    SPDXID string `json:"SPDXID"`
    DocumentName string `json:"name"`
    Packages []SPDXPackage `json:"packages"`
}

type SPDXPackage struct{
    SPDXID string `json:"SPDXID"`
    Name string `json:"name"`
    Version string `json:"versionInfo,omitempty"`
    LicenseConcluded string `json:"licenseConcluded,omitempty"`
}

type SPDXFormatter struct{}

func NewSPDXFormatter() *SPDXFormatter{ return &SPDXFormatter{} }

func (f *SPDXFormatter) Format(res *scanner.ScanResults, opts FormatterOptions) ([]byte, error){
    doc := SPDXDocument{ SPDXVersion: "SPDX-2.3", DataLicense: "CC0-1.0", SPDXID: "SPDXRef-DOCUMENT", DocumentName: "typosentinel-sbom" }
    seen := make(map[string]bool)
    for _, r := range res.Results{
        if r.Package == nil { continue }
        key := r.Package.Name + "@" + r.Package.Version
        if seen[key] { continue }
        seen[key] = true
        doc.Packages = append(doc.Packages, SPDXPackage{ SPDXID: "SPDXRef-Package-"+r.Package.Name, Name: r.Package.Name, Version: r.Package.Version })
    }
    return json.MarshalIndent(doc, "", opts.Indent)
}

