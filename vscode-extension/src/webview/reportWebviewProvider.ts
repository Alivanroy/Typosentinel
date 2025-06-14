import * as vscode from 'vscode';
import * as path from 'path';
import { ApiClient, ScanResult, Threat } from '../api/apiClient';
import { DiagnosticsManager } from '../diagnostics/diagnosticsManager';

export class ReportWebviewProvider implements vscode.WebviewViewProvider {
    public static readonly viewType = 'typosentinel.reportView';
    private _view?: vscode.WebviewView;

    constructor(
        private readonly _extensionUri: vscode.Uri,
        private apiClient: ApiClient,
        private diagnosticsManager: DiagnosticsManager
    ) {}

    public resolveWebviewView(
        webviewView: vscode.WebviewView,
        context: vscode.WebviewViewResolveContext,
        _token: vscode.CancellationToken,
    ) {
        this._view = webviewView;

        webviewView.webview.options = {
            enableScripts: true,
            localResourceRoots: [
                this._extensionUri
            ]
        };

        webviewView.webview.html = this._getHtmlForWebview(webviewView.webview);

        // Handle messages from the webview
        webviewView.webview.onDidReceiveMessage(
            message => {
                switch (message.type) {
                    case 'refresh':
                        this.refresh();
                        break;
                    case 'scanWorkspace':
                        vscode.commands.executeCommand('typosentinel.scanWorkspace');
                        break;
                    case 'scanFile':
                        vscode.commands.executeCommand('typosentinel.scanFile');
                        break;
                    case 'openFile':
                        this.openFile(message.filePath, message.line, message.column);
                        break;
                    case 'reportFalsePositive':
                        this.reportFalsePositive(message.threat);
                        break;
                    case 'exportReport':
                        this.exportReport();
                        break;
                    case 'openSettings':
                        vscode.commands.executeCommand('typosentinel.openSettings');
                        break;
                }
            },
            undefined,
            []
        );

        // Initial data load
        this.refresh();
    }

    public refresh(): void {
        if (this._view) {
            this._view.webview.postMessage({
                type: 'updateData',
                data: this.getReportData()
            });
        }
    }

    private getReportData() {
        const scanResults = this.diagnosticsManager.getAllScanResults();
        const threatCount = this.diagnosticsManager.getThreatCount();
        const files: any[] = [];
        const threats: Threat[] = [];

        for (const [uriString, scanResult] of scanResults.entries()) {
            const uri = vscode.Uri.parse(uriString);
            const fileName = path.basename(uri.fsPath);
            const filePath = uri.fsPath;
            const fileThreats = scanResult.threats || [];

            files.push({
                name: fileName,
                path: filePath,
                threatCount: fileThreats.length,
                lastScan: scanResult.scan_timestamp,
                threats: fileThreats
            });

            threats.push(...fileThreats);
        }

        // Sort files by threat count (descending)
        files.sort((a, b) => b.threatCount - a.threatCount);

        // Group threats by type
        const threatsByType = threats.reduce((acc, threat) => {
            if (!acc[threat.threat_type]) {
                acc[threat.threat_type] = [];
            }
            acc[threat.threat_type].push(threat);
            return acc;
        }, {} as Record<string, Threat[]>);

        // Get top risky packages
        const packageRisks = threats.reduce((acc, threat) => {
            if (!acc[threat.package_name]) {
                acc[threat.package_name] = {
                    name: threat.package_name,
                    count: 0,
                    maxSeverity: 'low',
                    types: new Set()
                };
            }
            acc[threat.package_name].count++;
            acc[threat.package_name].types.add(threat.threat_type);
            
            const severityOrder = { critical: 4, high: 3, medium: 2, low: 1 };
            if (severityOrder[threat.severity as keyof typeof severityOrder] > 
                severityOrder[acc[threat.package_name].maxSeverity as keyof typeof severityOrder]) {
                acc[threat.package_name].maxSeverity = threat.severity;
            }
            
            return acc;
        }, {} as Record<string, any>);

        const topPackages = Object.values(packageRisks)
            .map((pkg: any) => ({
                ...pkg,
                types: Array.from(pkg.types)
            }))
            .sort((a: any, b: any) => b.count - a.count)
            .slice(0, 10);

        return {
            summary: {
                totalFiles: files.length,
                totalThreats: threatCount.total,
                bySeverity: threatCount.bySeverity,
                lastScan: files.length > 0 ? Math.max(...files.map(f => new Date(f.lastScan).getTime())) : null
            },
            files,
            threatsByType,
            topPackages,
            recentThreats: threats
                .slice(0, 10)
        };
    }

    private async openFile(filePath: string, line?: number, column?: number): Promise<void> {
        try {
            const uri = vscode.Uri.file(filePath);
            const document = await vscode.workspace.openTextDocument(uri);
            const editor = await vscode.window.showTextDocument(document);
            
            if (line !== undefined) {
                const position = new vscode.Position(
                    Math.max(0, line - 1),
                    Math.max(0, column || 0)
                );
                editor.selection = new vscode.Selection(position, position);
                editor.revealRange(new vscode.Range(position, position));
            }
        } catch (error) {
            vscode.window.showErrorMessage(`Failed to open file: ${error}`);
        }
    }

    private async reportFalsePositive(threat: Threat): Promise<void> {
        try {
            const reason = await vscode.window.showInputBox({
                prompt: 'Please provide a reason for reporting this as a false positive',
                placeHolder: 'e.g., This is a legitimate package used in our project'
            });
            
            if (reason) {
                const activeEditor = vscode.window.activeTextEditor;
                const filePath = activeEditor ? activeEditor.document.uri.fsPath : '';
                await this.apiClient.reportFalsePositive(threat, filePath);
                vscode.window.showInformationMessage('False positive reported successfully');
                this.refresh();
            }
        } catch (error) {
            vscode.window.showErrorMessage(`Failed to report false positive: ${error}`);
        }
    }

    private async exportReport(): Promise<void> {
        try {
            const uri = await vscode.window.showSaveDialog({
                defaultUri: vscode.Uri.file('typosentinel-report.json'),
                filters: {
                    'JSON': ['json'],
                    'All Files': ['*']
                }
            });
            
            if (uri) {
                const reportData = this.getReportData();
                const jsonContent = JSON.stringify(reportData, null, 2);
                await vscode.workspace.fs.writeFile(uri, Buffer.from(jsonContent, 'utf8'));
                vscode.window.showInformationMessage(`Report exported to ${uri.fsPath}`);
            }
        } catch (error) {
            vscode.window.showErrorMessage(`Failed to export report: ${error}`);
        }
    }

    private _getHtmlForWebview(webview: vscode.Webview): string {
        return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>TypoSentinel Security Report</title>
    <style>
        body {
            font-family: var(--vscode-font-family);
            font-size: var(--vscode-font-size);
            color: var(--vscode-foreground);
            background-color: var(--vscode-editor-background);
            margin: 0;
            padding: 16px;
            line-height: 1.5;
        }
        
        .header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 20px;
            padding-bottom: 16px;
            border-bottom: 1px solid var(--vscode-panel-border);
        }
        
        .title {
            font-size: 18px;
            font-weight: 600;
            margin: 0;
        }
        
        .actions {
            display: flex;
            gap: 8px;
        }
        
        .btn {
            background: var(--vscode-button-background);
            color: var(--vscode-button-foreground);
            border: none;
            padding: 6px 12px;
            border-radius: 3px;
            cursor: pointer;
            font-size: 12px;
            transition: background-color 0.2s;
        }
        
        .btn:hover {
            background: var(--vscode-button-hoverBackground);
        }
        
        .btn-secondary {
            background: var(--vscode-button-secondaryBackground);
            color: var(--vscode-button-secondaryForeground);
        }
        
        .btn-secondary:hover {
            background: var(--vscode-button-secondaryHoverBackground);
        }
        
        .summary-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 16px;
            margin-bottom: 24px;
        }
        
        .summary-card {
            background: var(--vscode-editor-inactiveSelectionBackground);
            border: 1px solid var(--vscode-panel-border);
            border-radius: 6px;
            padding: 16px;
        }
        
        .summary-card h3 {
            margin: 0 0 8px 0;
            font-size: 14px;
            color: var(--vscode-descriptionForeground);
        }
        
        .summary-value {
            font-size: 24px;
            font-weight: 600;
            margin-bottom: 4px;
        }
        
        .summary-detail {
            font-size: 12px;
            color: var(--vscode-descriptionForeground);
        }
        
        .severity-critical { color: #f85149; }
        .severity-high { color: #ff8c00; }
        .severity-medium { color: #f0ad4e; }
        .severity-low { color: #5bc0de; }
        .severity-safe { color: #28a745; }
        
        .section {
            margin-bottom: 24px;
        }
        
        .section-title {
            font-size: 16px;
            font-weight: 600;
            margin-bottom: 12px;
            display: flex;
            align-items: center;
            gap: 8px;
        }
        
        .icon {
            width: 16px;
            height: 16px;
        }
        
        .file-list, .threat-list {
            border: 1px solid var(--vscode-panel-border);
            border-radius: 6px;
            overflow: hidden;
        }
        
        .file-item, .threat-item {
            padding: 12px 16px;
            border-bottom: 1px solid var(--vscode-panel-border);
            cursor: pointer;
            transition: background-color 0.2s;
        }
        
        .file-item:hover, .threat-item:hover {
            background: var(--vscode-list-hoverBackground);
        }
        
        .file-item:last-child, .threat-item:last-child {
            border-bottom: none;
        }
        
        .file-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 4px;
        }
        
        .file-name {
            font-weight: 500;
        }
        
        .threat-count {
            background: var(--vscode-badge-background);
            color: var(--vscode-badge-foreground);
            padding: 2px 6px;
            border-radius: 10px;
            font-size: 11px;
        }
        
        .file-path {
            font-size: 12px;
            color: var(--vscode-descriptionForeground);
            font-family: var(--vscode-editor-font-family);
        }
        
        .threat-header {
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            margin-bottom: 8px;
        }
        
        .threat-package {
            font-weight: 500;
            font-family: var(--vscode-editor-font-family);
        }
        
        .threat-type {
            background: var(--vscode-badge-background);
            color: var(--vscode-badge-foreground);
            padding: 2px 6px;
            border-radius: 3px;
            font-size: 11px;
        }
        
        .threat-description {
            font-size: 12px;
            color: var(--vscode-descriptionForeground);
            margin-bottom: 8px;
        }
        
        .threat-meta {
            display: flex;
            gap: 12px;
            font-size: 11px;
            color: var(--vscode-descriptionForeground);
        }
        
        .threat-actions {
            display: flex;
            gap: 8px;
            margin-top: 8px;
        }
        
        .btn-small {
            padding: 4px 8px;
            font-size: 11px;
        }
        
        .empty-state {
            text-align: center;
            padding: 40px 20px;
            color: var(--vscode-descriptionForeground);
        }
        
        .empty-state .icon {
            width: 48px;
            height: 48px;
            margin: 0 auto 16px;
            opacity: 0.5;
        }
        
        .loading {
            text-align: center;
            padding: 20px;
            color: var(--vscode-descriptionForeground);
        }
        
        .chart-container {
            height: 200px;
            margin: 16px 0;
            display: flex;
            align-items: end;
            gap: 8px;
            padding: 16px;
            background: var(--vscode-editor-inactiveSelectionBackground);
            border-radius: 6px;
        }
        
        .chart-bar {
            flex: 1;
            background: var(--vscode-progressBar-background);
            border-radius: 3px 3px 0 0;
            min-height: 4px;
            position: relative;
            transition: all 0.3s ease;
        }
        
        .chart-bar:hover {
            opacity: 0.8;
        }
        
        .chart-label {
            position: absolute;
            bottom: -20px;
            left: 50%;
            transform: translateX(-50%);
            font-size: 10px;
            color: var(--vscode-descriptionForeground);
            white-space: nowrap;
        }
        
        .chart-value {
            position: absolute;
            top: -20px;
            left: 50%;
            transform: translateX(-50%);
            font-size: 10px;
            color: var(--vscode-foreground);
            font-weight: 500;
        }
    </style>
</head>
<body>
    <div class="header">
        <h1 class="title">🛡️ Security Report</h1>
        <div class="actions">
            <button class="btn btn-secondary" onclick="refreshReport()">🔄 Refresh</button>
            <button class="btn btn-secondary" onclick="exportReport()">📄 Export</button>
            <button class="btn" onclick="scanWorkspace()">🔍 Scan Workspace</button>
        </div>
    </div>
    
    <div id="content">
        <div class="loading">Loading security report...</div>
    </div>
    
    <script>
        const vscode = acquireVsCodeApi();
        let reportData = null;
        
        window.addEventListener('message', event => {
            const message = event.data;
            switch (message.type) {
                case 'updateData':
                    reportData = message.data;
                    renderReport();
                    break;
            }
        });
        
        function renderReport() {
            if (!reportData) return;
            
            const content = document.getElementById('content');
            
            if (reportData.summary.totalThreats === 0) {
                content.innerHTML = renderEmptyState();
                return;
            }
            
            content.innerHTML = [
                renderSummary(),
                renderSeverityChart(),
                renderTopPackages(),
                renderFilesList(),
                renderRecentThreats()
            ].join('');
        }
        
        function renderEmptyState() {
            return \`
                <div class="empty-state">
                    <div class="icon">🛡️</div>
                    <h3>No Security Threats Detected</h3>
                    <p>Your workspace appears to be secure. No suspicious packages or typosquatting attempts were found.</p>
                    <button class="btn" onclick="scanWorkspace()">🔍 Scan Workspace</button>
                </div>
            \`;
        }
        
        function renderSummary() {
            const { summary } = reportData;
            const lastScan = summary.lastScan ? new Date(summary.lastScan).toLocaleString() : 'Never';
            
            return \`
                <div class="summary-grid">
                    <div class="summary-card">
                        <h3>Total Threats</h3>
                        <div class="summary-value \${getSeverityClass(summary.totalThreats)}">
                            \${summary.totalThreats}
                        </div>
                        <div class="summary-detail">Across \${summary.totalFiles} files</div>
                    </div>
                    <div class="summary-card">
                        <h3>Critical</h3>
                        <div class="summary-value severity-critical">\${summary.bySeverity.critical}</div>
                        <div class="summary-detail">Immediate attention required</div>
                    </div>
                    <div class="summary-card">
                        <h3>High Risk</h3>
                        <div class="summary-value severity-high">\${summary.bySeverity.high}</div>
                        <div class="summary-detail">Should be addressed soon</div>
                    </div>
                    <div class="summary-card">
                        <h3>Last Scan</h3>
                        <div class="summary-value">\${formatTimeAgo(summary.lastScan)}</div>
                        <div class="summary-detail">\${lastScan}</div>
                    </div>
                </div>
            \`;
        }
        
        function renderSeverityChart() {
            const { bySeverity } = reportData.summary;
            const maxValue = Math.max(bySeverity.critical, bySeverity.high, bySeverity.medium, bySeverity.low) || 1;
            
            return \`
                <div class="section">
                    <h2 class="section-title">📊 Threat Distribution</h2>
                    <div class="chart-container">
                        <div class="chart-bar severity-critical" style="height: \${(bySeverity.critical / maxValue) * 100}%">
                            <div class="chart-value">\${bySeverity.critical}</div>
                            <div class="chart-label">Critical</div>
                        </div>
                        <div class="chart-bar severity-high" style="height: \${(bySeverity.high / maxValue) * 100}%">
                            <div class="chart-value">\${bySeverity.high}</div>
                            <div class="chart-label">High</div>
                        </div>
                        <div class="chart-bar severity-medium" style="height: \${(bySeverity.medium / maxValue) * 100}%">
                            <div class="chart-value">\${bySeverity.medium}</div>
                            <div class="chart-label">Medium</div>
                        </div>
                        <div class="chart-bar severity-low" style="height: \${(bySeverity.low / maxValue) * 100}%">
                            <div class="chart-value">\${bySeverity.low}</div>
                            <div class="chart-label">Low</div>
                        </div>
                    </div>
                </div>
            \`;
        }
        
        function renderTopPackages() {
            if (!reportData.topPackages.length) return '';
            
            return \`
                <div class="section">
                    <h2 class="section-title">⚠️ Top Risk Packages</h2>
                    <div class="threat-list">
                        \${reportData.topPackages.map(pkg => \`
                            <div class="threat-item">
                                <div class="threat-header">
                                    <span class="threat-package">\${pkg.name}</span>
                                    <span class="threat-type \${getSeverityClass(pkg.maxSeverity)}">\${pkg.maxSeverity}</span>
                                </div>
                                <div class="threat-description">
                                    \${pkg.count} threat\${pkg.count === 1 ? '' : 's'} • Types: \${pkg.types.join(', ')}
                                </div>
                            </div>
                        \`).join('')}
                    </div>
                </div>
            \`;
        }
        
        function renderFilesList() {
            if (!reportData.files.length) return '';
            
            return \`
                <div class="section">
                    <h2 class="section-title">📁 Affected Files</h2>
                    <div class="file-list">
                        \${reportData.files.map(file => \`
                            <div class="file-item" onclick="openFile('\${file.path}')">
                                <div class="file-header">
                                    <span class="file-name">\${file.name}</span>
                                    <span class="threat-count \${getThreatCountClass(file.threatCount)}">
                                        \${file.threatCount} threat\${file.threatCount === 1 ? '' : 's'}
                                    </span>
                                </div>
                                <div class="file-path">\${file.path}</div>
                            </div>
                        \`).join('')}
                    </div>
                </div>
            \`;
        }
        
        function renderRecentThreats() {
            if (!reportData.recentThreats.length) return '';
            
            return \`
                <div class="section">
                    <h2 class="section-title">🚨 Recent Threats</h2>
                    <div class="threat-list">
                        \${reportData.recentThreats.map(threat => \`
                            <div class="threat-item">
                                <div class="threat-header">
                                    <span class="threat-package">\${threat.package_name}</span>
                                    <span class="threat-type \${getSeverityClass(threat.severity)}">\${threat.threat_type}</span>
                                </div>
                                <div class="threat-description">\${threat.description}</div>
                                <div class="threat-meta">
                                    <span>Severity: \${threat.severity}</span>
                                    <span>Confidence: \${(threat.confidence * 100).toFixed(1)}%</span>
                                    \${threat.line_number ? \`<span>Line: \${threat.line_number}</span>\` : ''}
                                </div>
                                <div class="threat-actions">
                                    \${threat.line_number ? \`
                                        <button class="btn btn-small" onclick="openFile('\${threat.file_path}', \${threat.line_number}, \${threat.column_number || 0})">
                                            📍 Go to Location
                                        </button>
                                    \` : ''}
                                    <button class="btn btn-small btn-secondary" onclick="reportFalsePositive(\${JSON.stringify(threat).replace(/"/g, '&quot;')})">
                                        🚫 False Positive
                                    </button>
                                </div>
                            </div>
                        \`).join('')}
                    </div>
                </div>
            \`;
        }
        
        function getSeverityClass(severity) {
            if (typeof severity === 'number') {
                if (severity === 0) return 'severity-safe';
                if (severity <= 5) return 'severity-low';
                if (severity <= 15) return 'severity-medium';
                if (severity <= 30) return 'severity-high';
                return 'severity-critical';
            }
            return \`severity-\${severity}\`;
        }
        
        function getThreatCountClass(count) {
            if (count === 0) return 'severity-safe';
            if (count <= 2) return 'severity-low';
            if (count <= 5) return 'severity-medium';
            if (count <= 10) return 'severity-high';
            return 'severity-critical';
        }
        
        function formatTimeAgo(timestamp) {
            if (!timestamp) return 'Never';
            const now = new Date();
            const diff = now.getTime() - timestamp;
            const minutes = Math.floor(diff / 60000);
            const hours = Math.floor(minutes / 60);
            const days = Math.floor(hours / 24);
            
            if (minutes < 1) return 'Just now';
            if (minutes < 60) return \`\${minutes}m ago\`;
            if (hours < 24) return \`\${hours}h ago\`;
            return \`\${days}d ago\`;
        }
        
        function refreshReport() {
            vscode.postMessage({ type: 'refresh' });
        }
        
        function scanWorkspace() {
            vscode.postMessage({ type: 'scanWorkspace' });
        }
        
        function scanFile() {
            vscode.postMessage({ type: 'scanFile' });
        }
        
        function openFile(filePath, line, column) {
            vscode.postMessage({ 
                type: 'openFile', 
                filePath: filePath,
                line: line,
                column: column
            });
        }
        
        function reportFalsePositive(threat) {
            vscode.postMessage({ 
                type: 'reportFalsePositive', 
                threat: threat
            });
        }
        
        function exportReport() {
            vscode.postMessage({ type: 'exportReport' });
        }
        
        function openSettings() {
            vscode.postMessage({ type: 'openSettings' });
        }
        
        // Request initial data
        vscode.postMessage({ type: 'refresh' });
    </script>
</body>
</html>`;
    }
}