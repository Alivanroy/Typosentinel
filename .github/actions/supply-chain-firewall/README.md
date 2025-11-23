# Supply Chain Firewall GitHub Actions Integration

This document provides examples of how to integrate the Typosentinel Supply Chain Firewall into your CI/CD pipelines using GitHub Actions.

## Quick Start

Add the supply chain firewall check to your existing workflow:

```yaml
name: CI with Supply Chain Firewall

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main ]

jobs:
  security-check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Supply Chain Firewall Check
        uses: typosentinel/typosentinel/.github/actions/supply-chain-firewall@main
        with:
          asset-criticality: 'INTERNAL'
          policy-threshold: 'block'
          fail-on-violation: true
```

## Configuration Options

### Asset Criticality Levels

- **PUBLIC** (0.5x multiplier): Public-facing applications with low business impact
- **INTERNAL** (1.0x multiplier): Internal tools and applications  
- **CRITICAL** (2.0x multiplier): Critical business applications and infrastructure

### Policy Thresholds

- **block**: Fail builds with risk score ≥ 0.9
- **alert**: Warn on risk score ≥ 0.7, fail on ≥ 0.9
- **review**: Require manual review on risk score ≥ 0.5, fail on ≥ 0.9

### Package File Detection

The action automatically detects package files in this order:
1. `package.json` (Node.js)
2. `requirements.txt` (Python)
3. `go.mod` (Go)
4. `pom.xml` (Java/Maven)
5. `Cargo.toml` (Rust)
6. `composer.json` (PHP)
7. `Gemfile` (Ruby)

You can also specify a specific file:

```yaml
- name: Supply Chain Firewall Check
  uses: typosentinel/typosentinel/.github/actions/supply-chain-firewall@main
  with:
    package-file: 'package.json'
    asset-criticality: 'CRITICAL'
```

## Advanced Usage

### Using Outputs

```yaml
jobs:
  security-check:
    runs-on: ubuntu-latest
    outputs:
      risk-score: ${{ steps.firewall.outputs.risk-score }}
      policy-action: ${{ steps.firewall.outputs.policy-action }}
    steps:
      - uses: actions/checkout@v4
      
      - name: Supply Chain Firewall Check
        id: firewall
        uses: typosentinel/typosentinel/.github/actions/supply-chain-firewall@main
        with:
          asset-criticality: 'CRITICAL'
          
      - name: Risk Assessment Summary
        run: |
          echo "Risk Score: ${{ steps.firewall.outputs.risk-score }}"
          echo "Policy Action: ${{ steps.firewall.outputs.policy-action }}"
```

### Conditional Steps Based on Risk

```yaml
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Supply Chain Firewall Check
        id: firewall
        uses: typosentinel/typosentinel/.github/actions/supply-chain-firewall@main
        with:
          fail-on-violation: false  # Don't fail immediately
          
      - name: Enhanced Security Scan
        if: steps.firewall.outputs.policy-action != 'ALLOWED'
        run: |
          echo "Performing enhanced security scan due to risk level"
          # Run additional security checks
          
      - name: Manual Approval Required
        if: steps.firewall.outputs.policy-action == 'REVIEW'
        run: |
          echo "⚠️ Manual approval required due to supply chain risk"
          echo "Risk Score: ${{ steps.firewall.outputs.risk-score }}"
```

### Multi-Environment Deployment

```yaml
jobs:
  deploy-staging:
    runs-on: ubuntu-latest
    environment: staging
    steps:
      - uses: actions/checkout@v4
      
      - name: Supply Chain Firewall Check (Staging)
        uses: typosentinel/typosentinel/.github/actions/supply-chain-firewall@main
        with:
          asset-criticality: 'INTERNAL'
          policy-threshold: 'alert'
          
  deploy-production:
    runs-on: ubuntu-latest
    environment: production
    needs: deploy-staging
    steps:
      - uses: actions/checkout@v4
      
      - name: Supply Chain Firewall Check (Production)
        uses: typosentinel/typosentinel/.github/actions/supply-chain-firewall@main
        with:
          asset-criticality: 'CRITICAL'
          policy-threshold: 'block'
          fail-on-violation: true
```

## Reusable Workflow

For organizations with many repositories, use the reusable workflow:

```yaml
name: CI

on:
  push:
    branches: [ main ]
  pull_request:
    branches: [ main ]

jobs:
  supply-chain-security:
    uses: typosentinel/typosentinel/.github/workflows/supply-chain-firewall.yml@main
    with:
      asset-criticality: 'INTERNAL'
      policy-threshold: 'block'
      fail-on-violation: true
```

## Integration with Existing Security Tools

```yaml
jobs:
  security-suite:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Dependency Vulnerability Scan
        uses: github/super-linter@v4
        
      - name: Supply Chain Firewall Check
        id: firewall
        uses: typosentinel/typosentinel/.github/actions/supply-chain-firewall@main
        with:
          asset-criticality: 'CRITICAL'
          
      - name: Container Security Scan
        if: steps.firewall.outputs.policy-action == 'ALLOWED'
        uses: aquasecurity/trivy-action@master
        
      - name: SAST Analysis
        if: steps.firewall.outputs.policy-action == 'ALLOWED'
        uses: github/codeql-action/analyze@v2
```

## Policy Examples

### Strict Policy (Financial Services)
```yaml
- name: Supply Chain Firewall Check
  uses: typosentinel/typosentinel/.github/actions/supply-chain-firewall@main
  with:
    asset-criticality: 'CRITICAL'
    policy-threshold: 'block'
    fail-on-violation: true
```

### Moderate Policy (SaaS Applications)
```yaml
- name: Supply Chain Firewall Check
  uses: typosentinel/typosentinel/.github/actions/supply-chain-firewall@main
  with:
    asset-criticality: 'INTERNAL'
    policy-threshold: 'alert'
    fail-on-violation: true
```

### Permissive Policy (Development)
```yaml
- name: Supply Chain Firewall Check
  uses: typosentinel/typosentinel/.github/actions/supply-chain-firewall@main
  with:
    asset-criticality: 'PUBLIC'
    policy-threshold: 'review'
    fail-on-violation: false
```

## Troubleshooting

### Build Fails with "No package file detected"
- Ensure your package manager file is committed to the repository
- Use the `package-file` input to specify the exact file
- Check that the file is in the root directory or adjust the path

### High Risk Scores on Safe Packages
- Review the DIRT analysis output in the workflow artifacts
- Check if legitimate packages have suspicious dependency chains
- Consider adjusting the asset criticality level
- Review the policy thresholds for your use case

### Workflow Performance
- The analysis typically takes 30-60 seconds
- For faster builds, consider running in parallel with other checks
- Use caching strategies for the Typosentinel binary

## Security Considerations

- The action requires read access to your code
- Analysis results are uploaded as workflow artifacts
- Risk scores and policy decisions are logged
- Consider using environment-specific policies
- Review the analysis artifacts for sensitive information