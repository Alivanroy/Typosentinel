# Recursive Scanning Analysis for TypoSentinel

## Current Status

### Documentation vs Implementation Gap

The TypoSentinel documentation in `README.md` and `docs/README.md` shows examples using a `--recursive` flag:

```bash
# Documented example (NOT WORKING)
typosentinel scan \
  --recursive \
  --package-manager npm \
  --workspace-aware \
  --consolidate-report \
  --output monorepo-scan.json \
  .
```

**However, this flag is NOT implemented in the actual codebase.** The `main.go` file only implements these flags for the `scan` command:

- `--deep`: Enable deep analysis
- `--include-dev`: Include development dependencies
- `--threshold`: Similarity threshold for detection
- `--exclude`: Packages to exclude from scan
- `--file`: Specific dependency file to scan
- `--check-vulnerabilities`: Enable vulnerability checking
- `--vulnerability-db`: Vulnerability databases to use
- `--vuln-config`: Path to vulnerability database configuration
- `--sbom-format`: Generate SBOM in specified format
- `--sbom-output`: Output file path for SBOM

### Missing Flags

These flags are documented but **NOT implemented**:
- `--recursive`
- `--workspace-aware`
- `--consolidate-report`
- `--package-manager` (for scan command)
- `--production-only`
- `--fail-on`
- `--format`
- `--workspace`

## Technical Analysis

### Existing Monorepo Detection

The codebase does have some monorepo detection capabilities in `internal/config/smart_defaults.go`:

```go
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
```

### Project Detection Infrastructure

The scanner has project detection capabilities in `internal/scanner/scanner.go`:

```go
// detectProject detects the project type and returns project information
func (s *Scanner) detectProject(projectPath string) (*ProjectInfo, error) {
    // Try each detector
    for _, detector := range s.detectors {
        projectInfo, err := detector.Detect(absPath)
        if err == nil && projectInfo != nil {
            return projectInfo, nil
        }
    }
    // ...
}
```

## Working Solutions for ACME Enterprise

### 1. Manual Recursive Scanning Script

Create a script that implements the missing recursive functionality:

```bash
#!/bin/bash
# recursive-scan.sh

SCAN_DIR="${1:-.}"
OUTPUT_DIR="scan-results"
CONSOLIDATE_REPORT="consolidated-monorepo-scan.json"

mkdir -p "$OUTPUT_DIR"

# Find all package.json files (Node.js projects)
find "$SCAN_DIR" -name "package.json" -not -path "*/node_modules/*" | while read -r package_file; do
    project_dir=$(dirname "$package_file")
    project_name=$(basename "$project_dir")
    
    echo "Scanning Node.js project: $project_name"
    ./typosentinel scan \
        --deep \
        --include-dev \
        --check-vulnerabilities \
        --sbom-format cyclonedx \
        --sbom-output "$OUTPUT_DIR/sbom-$project_name.json" \
        "$project_dir" > "$OUTPUT_DIR/scan-$project_name.json"
done

# Find all requirements.txt files (Python projects)
find "$SCAN_DIR" -name "requirements.txt" -not -path "*/venv/*" -not -path "*/.venv/*" | while read -r req_file; do
    project_dir=$(dirname "$req_file")
    project_name=$(basename "$project_dir")
    
    echo "Scanning Python project: $project_name"
    ./typosentinel scan \
        --deep \
        --check-vulnerabilities \
        --file "$req_file" \
        "$project_dir" > "$OUTPUT_DIR/scan-python-$project_name.json"
done

# Find all go.mod files (Go projects)
find "$SCAN_DIR" -name "go.mod" -not -path "*/vendor/*" | while read -r go_file; do
    project_dir=$(dirname "$go_file")
    project_name=$(basename "$project_dir")
    
    echo "Scanning Go project: $project_name"
    ./typosentinel scan \
        --deep \
        --check-vulnerabilities \
        --file "$go_file" \
        "$project_dir" > "$OUTPUT_DIR/scan-go-$project_name.json"
done

# Find all pom.xml files (Java Maven projects)
find "$SCAN_DIR" -name "pom.xml" -not -path "*/target/*" | while read -r pom_file; do
    project_dir=$(dirname "$pom_file")
    project_name=$(basename "$project_dir")
    
    echo "Scanning Java Maven project: $project_name"
    ./typosentinel scan \
        --deep \
        --check-vulnerabilities \
        --file "$pom_file" \
        "$project_dir" > "$OUTPUT_DIR/scan-java-$project_name.json"
done

echo "Recursive scan completed. Results in $OUTPUT_DIR/"
```

### 2. Using Existing CI/CD Templates

The codebase includes CI/CD templates that implement recursive scanning:

- `.github/workflows/` - GitHub Actions templates
- `.gitlab-ci.yml` - GitLab CI template
- `Jenkinsfile` - Jenkins pipeline

These templates automatically detect and scan multiple project types.

### 3. API-Based Batch Scanning

Use the REST API server for batch scanning:

```bash
# Start the server
./typosentinel server --config config/config.yaml --port 8080

# Use API endpoints for batch scanning
curl -X POST http://localhost:8080/api/v1/enterprise/scan/batch \
  -H "Content-Type: application/json" \
  -d '{
    "projects": [
      {"path": "./frontend-webapp", "type": "nodejs"},
      {"path": "./backend-api", "type": "nodejs"},
      {"path": "./python-microservice", "type": "python"},
      {"path": "./go-microservice", "type": "go"}
    ],
    "options": {
      "deep_scan": true,
      "include_dev": true,
      "check_vulnerabilities": true
    }
  }'
```

## Recommendations

### For Immediate Use

1. **Use the manual script approach** for comprehensive recursive scanning
2. **Leverage existing CI/CD templates** for automated pipeline integration
3. **Use the API server** for programmatic batch scanning

### For TypoSentinel Development

1. **Implement missing flags** in `main.go`:
   - `--recursive`
   - `--workspace-aware`
   - `--consolidate-report`
   - `--package-manager`

2. **Add recursive scanning logic** to the scan command

3. **Update documentation** to match actual implementation

4. **Enhance monorepo detection** to automatically discover all project types

## Conclusion

While TypoSentinel has the underlying infrastructure for project detection and monorepo scanning, the `--recursive` flag documented in the README is not implemented in the CLI. The ACME Enterprise scanning can be achieved through:

1. Custom scripting (most flexible)
2. CI/CD integration (most automated)
3. API-based scanning (most programmatic)

The existing comprehensive scan results show that TypoSentinel's core scanning functionality works well - it's just the recursive discovery that needs to be implemented manually or through the suggested workarounds.