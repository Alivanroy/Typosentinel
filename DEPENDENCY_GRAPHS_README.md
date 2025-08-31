# TypoSentinel Dependency Graphs

This document describes the dependency graphs generated for the TypoSentinel project using the built-in graph generation capabilities.

## Generated Files

### 1. dependency_graph.svg (13.5 KB)
**Visual SVG Graph**
- Interactive scalable vector graphics format
- Color-coded threat levels:
  - Blue: Root package
  - Red: High/Critical threats
  - Yellow: Medium/Low threats
- Shows dependency relationships with connecting lines
- Includes legend for threat interpretation

### 2. dependency_graph.dot (11.6 KB)
**DOT Format Graph**
- Graphviz DOT language format
- Can be rendered with tools like Graphviz, Gephi, or online DOT viewers
- Structure:
  ```dot
  digraph DependencyGraph {
    rankdir=TB;
    node [shape=box, style=filled];
    "." [fillcolor=lightblue, label=".\nPackages: 77"];
    "threat_0" [fillcolor=lightcoral, label="github.com/chromedp/cdproto\nsuspicious"];
  }
  ```

### 3. dependency_graph.json (11.6 KB)
**Structured JSON Data**
- Machine-readable format for programmatic analysis
- Contains:
  - Scan metadata and timestamps
  - Threat summary (77 total packages, 5 low threats, 72 clean)
  - Supply chain analysis results
  - Zero-day and honeypot detection results

### 4. comprehensive_dependency_graph.svg (2.6 KB)
**Comprehensive Export**
- Generated using the export command
- Includes both Go and npm dependencies
- Detected threats in typescript-eslint package (high confidence: 0.92)
- Shows multi-ecosystem dependency analysis

## Analysis Results

### Threat Summary
- **Total Packages Analyzed**: 77 (Go) + additional npm packages
- **Threat Distribution**:
  - Critical: 0
  - High: 0 (Go), 1 (npm - typescript-eslint)
  - Medium: 0
  - Low: 5
  - Clean: 72

### Identified Suspicious Packages
1. `github.com/chromedp/cdproto` - suspicious
2. `github.com/Azure/go-ntlmssp` - suspicious
3. `github.com/dgryski/go-rendezvous` - suspicious
4. `github.com/go-asn1-ber/asn1-ber` - suspicious
5. `github.com/modern-go/concurrent` - suspicious

### Supply Chain Security
- **Supply Chain Risk Level**: 0
- **Supply Chain Risk Score**: 0
- **Build Integrity Findings**: 0
- **Honeypot Detections**: 0
- **Zero-day Findings**: 0

## Usage Examples

### Viewing SVG Graphs
```bash
# Open in browser
start dependency_graph.svg

# Or use any SVG viewer
```

### Processing DOT Files
```bash
# Convert to PNG using Graphviz
dot -Tpng dependency_graph.dot -o dependency_graph.png

# Convert to PDF
dot -Tpdf dependency_graph.dot -o dependency_graph.pdf
```

### Analyzing JSON Data
```bash
# Pretty print JSON
jq '.' dependency_graph.json

# Extract threat summary
jq '.summary' dependency_graph.json

# Count packages by threat level
jq '.summary | to_entries[] | select(.key | contains("threats"))' dependency_graph.json
```

## Command Reference

The graphs were generated using these TypoSentinel commands:

```bash
# Generate basic dependency graph
./typosentinel.exe graph generate . --format svg --include-dev

# Generate DOT format
./typosentinel.exe graph generate . --format dot --include-dev --max-depth 5

# Generate JSON with analysis
./typosentinel.exe graph generate . --format json --include-dev --max-depth 5

# Export comprehensive graph
./typosentinel.exe graph export . --format svg --output comprehensive_dependency_graph.svg --include-dev

# Analyze dependency graph for supply chain risks
./typosentinel.exe graph graph-analyze . --output json
```

## Integration with CI/CD

These dependency graphs can be integrated into CI/CD pipelines for:

1. **Security Monitoring**: Track new threats in dependencies
2. **Compliance Reporting**: Generate visual reports for security audits
3. **Risk Assessment**: Analyze supply chain risks before deployment
4. **Dependency Management**: Identify outdated or suspicious packages

## Next Steps

1. **Regular Scanning**: Set up automated dependency graph generation
2. **Threat Monitoring**: Monitor the identified suspicious packages
3. **Supply Chain Hardening**: Implement additional security measures for high-risk dependencies
4. **Documentation**: Keep dependency graphs updated with each release

For more information, see the TypoSentinel documentation and the `graph` command help.