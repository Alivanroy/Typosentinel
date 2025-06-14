# TypoSentinel VSCode Extension

A powerful VSCode extension that provides real-time protection against typosquatting attacks and malicious packages in your development environment.

## Features

### 🛡️ Real-time Security Scanning
- **Automatic scanning** of package.json, requirements.txt, and other dependency files
- **Live threat detection** as you type and save files
- **Workspace-wide scanning** with comprehensive security analysis

### 🚨 Intelligent Threat Detection
- **Typosquatting detection** - identifies packages that mimic legitimate ones
- **Malicious package identification** - detects known harmful packages
- **Behavioral analysis** - analyzes package behavior patterns
- **Confidence scoring** - provides reliability metrics for each detection

### 📊 Comprehensive Reporting
- **Interactive security dashboard** with detailed threat analysis
- **Severity-based categorization** (Critical, High, Medium, Low)
- **File-by-file breakdown** of security issues
- **Export capabilities** for security reports

### 🔧 Developer-Friendly Integration
- **Inline diagnostics** with squiggly underlines for threats
- **Hover tooltips** with detailed threat information
- **Quick actions** for threat remediation
- **Status bar indicators** showing security status

### ⚡ Real-time Communication
- **WebSocket integration** for live updates
- **Server health monitoring** with connection status
- **Automatic reconnection** handling

## Installation

1. Install the extension from the VSCode Marketplace
2. Configure the TypoSentinel server endpoint in settings
3. Start scanning your projects for security threats

## Configuration

The extension can be configured through VSCode settings:

### Server Settings
- `typosentinel.serverUrl`: TypoSentinel server URL (default: http://localhost:8080)
- `typosentinel.apiKey`: API key for server authentication
- `typosentinel.timeout`: Request timeout in milliseconds (default: 30000)

### Scanning Settings
- `typosentinel.autoScan`: Enable automatic scanning on file changes (default: true)
- `typosentinel.scanOnSave`: Scan files when saved (default: true)
- `typosentinel.scanWorkspaceOnStartup`: Scan entire workspace on startup (default: false)
- `typosentinel.excludePatterns`: File patterns to exclude from scanning

### Display Settings
- `typosentinel.showInlineWarnings`: Show inline diagnostics (default: true)
- `typosentinel.showStatusBar`: Show status bar indicators (default: true)
- `typosentinel.minimumSeverity`: Minimum severity level to display (default: "low")

### Real-time Settings
- `typosentinel.enableWebSocket`: Enable real-time updates (default: true)
- `typosentinel.webSocketUrl`: WebSocket server URL
- `typosentinel.reconnectInterval`: Reconnection interval in milliseconds (default: 5000)

## Usage

### Quick Start
1. Open a project with dependency files (package.json, requirements.txt, etc.)
2. The extension will automatically start scanning
3. View threats in the TypoSentinel sidebar panel
4. Click on threats to navigate to their locations
5. Use the security report for detailed analysis

### Commands
- `TypoSentinel: Scan Workspace` - Scan all files in the workspace
- `TypoSentinel: Scan Current File` - Scan the currently active file
- `TypoSentinel: View Security Report` - Open the detailed security report
- `TypoSentinel: Test Connection` - Test connection to TypoSentinel server
- `TypoSentinel: Open Settings` - Open extension settings
- `TypoSentinel: Export Report` - Export security report to file

### Sidebar Panel
The TypoSentinel sidebar provides:
- **Security Overview** with threat counts by severity
- **Affected Files** list with threat counts
- **Quick Actions** for common tasks
- **Real-time updates** as threats are detected

### Security Report
The interactive security report includes:
- **Threat distribution charts** showing severity breakdown
- **Top risk packages** with detailed analysis
- **File-by-file threat listing** with navigation
- **Recent threats** with timestamps and details
- **Export functionality** for sharing reports

## Threat Types

The extension detects various types of security threats:

### Typosquatting
- **Character substitution** (e.g., `reqeusts` instead of `requests`)
- **Character insertion** (e.g., `requestss` instead of `requests`)
- **Character deletion** (e.g., `request` instead of `requests`)
- **Character transposition** (e.g., `requsests` instead of `requests`)

### Malicious Packages
- **Known malicious packages** from security databases
- **Suspicious behavior patterns** detected through analysis
- **Packages with security vulnerabilities**

### Behavioral Analysis
- **Network activity** monitoring
- **File system access** patterns
- **Process execution** analysis
- **Registry modifications** (Windows)

## Security Features

### False Positive Reporting
- Report false positives directly from the interface
- Provide feedback to improve detection accuracy
- Maintain local whitelist of trusted packages

### Confidence Scoring
- Each threat includes a confidence score (0-100%)
- Higher scores indicate more reliable detections
- Use confidence levels to prioritize threat response

### Severity Levels
- **Critical**: Immediate action required, high confidence malicious
- **High**: Should be addressed soon, likely security risk
- **Medium**: Moderate risk, investigate when possible
- **Low**: Low risk, monitor for changes

## Troubleshooting

### Connection Issues
1. Verify the TypoSentinel server is running
2. Check the server URL in settings
3. Ensure network connectivity
4. Verify API key if authentication is required

### Scanning Issues
1. Check file patterns in exclude settings
2. Verify file types are supported
3. Ensure sufficient permissions for file access
4. Check server logs for error messages

### Performance Issues
1. Adjust scanning frequency in settings
2. Use exclude patterns for large directories
3. Disable auto-scan for very large projects
4. Monitor server resource usage

## Support

For support and bug reports:
- GitHub Issues: [TypoSentinel Repository](https://github.com/your-org/typosentinel)
- Documentation: [TypoSentinel Docs](https://docs.typosentinel.com)
- Email: support@typosentinel.com

## Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

## License

This extension is licensed under the MIT License. See [LICENSE](LICENSE) for details.

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for version history and updates.