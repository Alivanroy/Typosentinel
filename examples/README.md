# TypoSentinel CI/CD Integration Demo

This directory contains example files demonstrating how to integrate TypoSentinel into your CI/CD pipeline using GitHub Actions.

## 📁 Files

- `github-actions-integration.yml` - Complete GitHub Actions workflow example
- `cicd-demo/` - Sample Node.js project for testing
  - `package.json` - Dependencies to be scanned
  - `index.js` - Simple Express application

## 🚀 Quick Start

### 1. Copy the workflow to your repository

```bash
# Copy the workflow file to your repository
mkdir -p .github/workflows
cp examples/github-actions-integration.yml .github/workflows/typosentinel-security.yml
```

### 2. Configure the workflow

Edit the workflow file to match your project needs:

```yaml
env:
  TYPOSENTINEL_VERSION: 'latest'
  SCAN_LEVEL: 'medium'  # low, medium, high, critical
  FAIL_ON_CRITICAL: 'true'
```

### 3. Set up secrets (optional)

For enhanced notifications, add these secrets to your repository:

- `SLACK_WEBHOOK_URL` - For Slack notifications
- `CREATE_SECURITY_ISSUES` - Set to 'true' to auto-create GitHub issues

## 🛡️ Workflow Features

### Core Security Scanning
- **Automated Scanning**: Runs on every push and PR
- **Multiple Output Formats**: Futuristic CLI display + JSON for processing
- **Threat Analysis**: Categorizes threats by severity
- **Build Failure**: Optionally fails builds on critical threats

### Advanced Analysis
- **Package Analysis**: Deep analysis of suspicious packages
- **Multi-Language Support**: NPM, PyPI, Go modules, etc.
- **Scheduled Scans**: Daily security checks

### Integration & Reporting
- **SARIF Output**: Integrates with GitHub Security tab
- **PR Comments**: Automatic security reports on pull requests
- **Artifact Upload**: Preserves scan results for review
- **Notifications**: Slack alerts and GitHub issues

### Security Integration
- **GitHub Security Tab**: SARIF format results
- **Code Scanning Alerts**: Native GitHub security alerts
- **Dependency Insights**: Detailed package analysis

## 📊 Example Outputs

### Futuristic CLI Output
```
╔══════════════════════════════════════════════════════════════════════════════╗
║  ████████╗██╗   ██╗██████╗  ██████╗ ███████╗███████╗███╗   ██║████████╗    ║
║                    ⚡ NEXT-GEN SUPPLY CHAIN SECURITY ⚡                     ║
╚══════════════════════════════════════════════════════════════════════════════╝

🛡 AI-POWERED THREAT DETECTION SYSTEM 🛡
🔍 Scanning the digital frontier for malicious packages...
```

### PR Comment Example
```markdown
## 🛡️ TypoSentinel Security Scan Results

**Scan Status:** ✅ Passed
**Critical Threats:** 0
**High Threats:** 1
**Total Threats:** 3

⚠️ Found potential typosquatting attempt in package 'expres' (should be 'express')
```

## 🔧 Customization

### Scan Sensitivity Levels
- `low`: Basic typosquatting detection
- `medium`: Enhanced analysis with ML models
- `high`: Deep behavioral analysis
- `critical`: Maximum security with strict thresholds

### Failure Conditions
```yaml
# Fail build on any threats
FAIL_ON_CRITICAL: 'false'
FAIL_ON_HIGH: 'true'

# Custom threat thresholds
MAX_CRITICAL_THREATS: 0
MAX_HIGH_THREATS: 2
```

### Notification Channels
```yaml
# Slack integration
SLACK_WEBHOOK_URL: ${{ secrets.SLACK_WEBHOOK_URL }}

# Email notifications
EMAIL_RECIPIENTS: 'security@company.com'

# Microsoft Teams
TEAMS_WEBHOOK_URL: ${{ secrets.TEAMS_WEBHOOK_URL }}
```

## 🧪 Testing the Integration

### Local Testing
```bash
# Test with the demo project
cd examples/cicd-demo
../../Typosentinel scan . --output futuristic

# Analyze specific packages
../../Typosentinel analyze express npm --output futuristic
```

### CI/CD Testing
1. Push the workflow to your repository
2. Create a pull request with dependency changes
3. Watch the automated security scanning in action
4. Review results in the GitHub Security tab

## 📈 Best Practices

### 1. Gradual Rollout
- Start with `FAIL_ON_CRITICAL: 'false'` to monitor results
- Gradually increase sensitivity as team adapts
- Use scheduled scans for continuous monitoring

### 2. Team Integration
- Train developers on interpreting scan results
- Establish security review processes
- Create incident response procedures

### 3. Performance Optimization
- Cache TypoSentinel binary between runs
- Use matrix builds for multiple environments
- Optimize scan scope for large repositories

### 4. Security Hardening
- Use pinned action versions
- Implement secret scanning
- Regular workflow security reviews

## 🔗 Additional Resources

- [TypoSentinel Documentation](../docs/USER_GUIDE.md)
- [GitHub Actions Security](https://docs.github.com/en/actions/security-guides)
- [SARIF Format Specification](https://sarifweb.azurewebsites.net/)

## 🆘 Troubleshooting

### Common Issues

**Binary Download Fails**
```yaml
# Use alternative download method
- name: Download TypoSentinel
  run: |
    wget -O typosentinel https://github.com/Alivanroy/Typosentinel/releases/latest/download/typosentinel-linux-amd64
    chmod +x typosentinel
```

**Scan Timeout**
```yaml
# Increase timeout for large projects
- name: Run TypoSentinel scan
  timeout-minutes: 30
  run: ./typosentinel scan . --timeout 25m
```

**Memory Issues**
```yaml
# Use larger runner for big projects
runs-on: ubuntu-latest-4-cores
```

For more help, check the [troubleshooting guide](../docs/USER_GUIDE.md#troubleshooting) or [open an issue](https://github.com/Alivanroy/Typosentinel/issues).