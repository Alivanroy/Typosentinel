import * as vscode from 'vscode';
import * as path from 'path';
import { ApiClient, ScanResult, Threat } from '../api/apiClient';
import { DiagnosticsManager } from '../diagnostics/diagnosticsManager';

export class TypoSentinelProvider implements vscode.TreeDataProvider<TreeItem> {
    private _onDidChangeTreeData: vscode.EventEmitter<TreeItem | undefined | null | void> = new vscode.EventEmitter<TreeItem | undefined | null | void>();
    readonly onDidChangeTreeData: vscode.Event<TreeItem | undefined | null | void> = this._onDidChangeTreeData.event;

    constructor(
        private apiClient: ApiClient,
        private diagnosticsManager: DiagnosticsManager
    ) {}

    refresh(): void {
        this._onDidChangeTreeData.fire();
    }

    getTreeItem(element: TreeItem): vscode.TreeItem {
        return element;
    }

    getChildren(element?: TreeItem): Thenable<TreeItem[]> {
        if (!element) {
            return Promise.resolve(this.getRootItems());
        } else {
            return Promise.resolve(this.getChildItems(element));
        }
    }

    private getRootItems(): TreeItem[] {
        const items: TreeItem[] = [];
        const scanResults = this.diagnosticsManager.getAllScanResults();
        const threatCount = this.diagnosticsManager.getThreatCount();

        // Summary item
        const summaryItem = new TreeItem(
            `Security Overview (${threatCount.total} threats)`,
            vscode.TreeItemCollapsibleState.Expanded,
            'summary'
        );
        summaryItem.iconPath = new vscode.ThemeIcon('shield');
        summaryItem.tooltip = this.createSummaryTooltip(threatCount);
        items.push(summaryItem);

        // Files with threats
        if (scanResults.size > 0) {
            const filesItem = new TreeItem(
                `Scanned Files (${scanResults.size})`,
                vscode.TreeItemCollapsibleState.Expanded,
                'files'
            );
            filesItem.iconPath = new vscode.ThemeIcon('files');
            items.push(filesItem);
        }

        // Quick actions
        const actionsItem = new TreeItem(
            'Quick Actions',
            vscode.TreeItemCollapsibleState.Collapsed,
            'actions'
        );
        actionsItem.iconPath = new vscode.ThemeIcon('zap');
        items.push(actionsItem);

        return items;
    }

    private getChildItems(element: TreeItem): TreeItem[] {
        switch (element.contextValue) {
            case 'summary':
                return this.getSummaryChildren();
            case 'files':
                return this.getFileChildren();
            case 'actions':
                return this.getActionChildren();
            case 'file':
                return this.getThreatChildren(element);
            default:
                return [];
        }
    }

    private getSummaryChildren(): TreeItem[] {
        const threatCount = this.diagnosticsManager.getThreatCount();
        const items: TreeItem[] = [];

        // Severity breakdown
        if (threatCount.bySeverity.critical > 0) {
            const item = new TreeItem(
                `Critical: ${threatCount.bySeverity.critical}`,
                vscode.TreeItemCollapsibleState.None,
                'severity'
            );
            item.iconPath = new vscode.ThemeIcon('error', new vscode.ThemeColor('errorForeground'));
            items.push(item);
        }

        if (threatCount.bySeverity.high > 0) {
            const item = new TreeItem(
                `High: ${threatCount.bySeverity.high}`,
                vscode.TreeItemCollapsibleState.None,
                'severity'
            );
            item.iconPath = new vscode.ThemeIcon('warning', new vscode.ThemeColor('errorForeground'));
            items.push(item);
        }

        if (threatCount.bySeverity.medium > 0) {
            const item = new TreeItem(
                `Medium: ${threatCount.bySeverity.medium}`,
                vscode.TreeItemCollapsibleState.None,
                'severity'
            );
            item.iconPath = new vscode.ThemeIcon('warning', new vscode.ThemeColor('warningForeground'));
            items.push(item);
        }

        if (threatCount.bySeverity.low > 0) {
            const item = new TreeItem(
                `Low: ${threatCount.bySeverity.low}`,
                vscode.TreeItemCollapsibleState.None,
                'severity'
            );
            item.iconPath = new vscode.ThemeIcon('info', new vscode.ThemeColor('foreground'));
            items.push(item);
        }

        if (threatCount.total === 0) {
            const item = new TreeItem(
                'No threats detected',
                vscode.TreeItemCollapsibleState.None,
                'no-threats'
            );
            item.iconPath = new vscode.ThemeIcon('check', new vscode.ThemeColor('testing.iconPassed'));
            items.push(item);
        }

        return items;
    }

    private getFileChildren(): TreeItem[] {
        const scanResults = this.diagnosticsManager.getAllScanResults();
        const items: TreeItem[] = [];

        for (const [uriString, scanResult] of scanResults.entries()) {
            const uri = vscode.Uri.parse(uriString);
            const fileName = path.basename(uri.fsPath);
            const threatCount = scanResult.threats?.length || 0;
            
            const item = new TreeItem(
                `${fileName} (${threatCount} threats)`,
                threatCount > 0 ? vscode.TreeItemCollapsibleState.Collapsed : vscode.TreeItemCollapsibleState.None,
                'file'
            );
            
            item.resourceUri = uri;
            item.tooltip = `${uri.fsPath}\nThreats: ${threatCount}\nLast scan: ${scanResult.scan_timestamp}`;
            
            if (threatCount > 0) {
                const maxSeverity = this.getMaxSeverity(scanResult.threats || []);
                item.iconPath = this.getSeverityIcon(maxSeverity);
            } else {
                item.iconPath = new vscode.ThemeIcon('check', new vscode.ThemeColor('testing.iconPassed'));
            }
            
            // Add command to open file
            item.command = {
                command: 'vscode.open',
                title: 'Open File',
                arguments: [uri]
            };
            
            items.push(item);
        }

        return items.sort((a, b) => {
            // Sort by threat count (descending), then by name
            const aThreats = this.getThreatCountFromLabel(a.label as string);
            const bThreats = this.getThreatCountFromLabel(b.label as string);
            
            if (aThreats !== bThreats) {
                return bThreats - aThreats;
            }
            
            return (a.label as string).localeCompare(b.label as string);
        });
    }

    private getActionChildren(): TreeItem[] {
        const items: TreeItem[] = [];

        // Scan workspace
        const scanWorkspaceItem = new TreeItem(
            'Scan Workspace',
            vscode.TreeItemCollapsibleState.None,
            'action'
        );
        scanWorkspaceItem.iconPath = new vscode.ThemeIcon('search');
        scanWorkspaceItem.command = {
            command: 'typosentinel.scanWorkspace',
            title: 'Scan Workspace'
        };
        items.push(scanWorkspaceItem);

        // Scan current file
        const scanFileItem = new TreeItem(
            'Scan Current File',
            vscode.TreeItemCollapsibleState.None,
            'action'
        );
        scanFileItem.iconPath = new vscode.ThemeIcon('file-text');
        scanFileItem.command = {
            command: 'typosentinel.scanFile',
            title: 'Scan Current File'
        };
        items.push(scanFileItem);

        // View report
        const viewReportItem = new TreeItem(
            'View Security Report',
            vscode.TreeItemCollapsibleState.None,
            'action'
        );
        viewReportItem.iconPath = new vscode.ThemeIcon('graph');
        viewReportItem.command = {
            command: 'typosentinel.viewReport',
            title: 'View Security Report'
        };
        items.push(viewReportItem);

        // Settings
        const settingsItem = new TreeItem(
            'Open Settings',
            vscode.TreeItemCollapsibleState.None,
            'action'
        );
        settingsItem.iconPath = new vscode.ThemeIcon('settings-gear');
        settingsItem.command = {
            command: 'typosentinel.openSettings',
            title: 'Open Settings'
        };
        items.push(settingsItem);

        return items;
    }

    private getThreatChildren(fileItem: TreeItem): TreeItem[] {
        if (!fileItem.resourceUri) {
            return [];
        }

        const threats = this.diagnosticsManager.getThreatsForFile(fileItem.resourceUri);
        const items: TreeItem[] = [];

        for (const threat of threats) {
            const item = new TreeItem(
                `${threat.package_name} (${threat.threat_type})`,
                vscode.TreeItemCollapsibleState.None,
                'threat'
            );
            
            item.iconPath = this.getSeverityIcon(threat.severity);
            item.tooltip = this.createThreatTooltip(threat);
            
            // Add command to navigate to threat location
            if (threat.line_number !== undefined) {
                item.command = {
                    command: 'vscode.open',
                    title: 'Go to Threat',
                    arguments: [
                        fileItem.resourceUri,
                        {
                            selection: new vscode.Range(
                                threat.line_number - 1,
                                threat.column_number || 0,
                                threat.line_number - 1,
                                (threat.column_number || 0) + threat.package_name.length
                            )
                        }
                    ]
                };
            }
            
            items.push(item);
        }

        return items.sort((a, b) => {
            // Sort by severity, then by package name
            const aThreat = threats.find(t => (a.label as string).includes(t.package_name));
            const bThreat = threats.find(t => (b.label as string).includes(t.package_name));
            
            if (aThreat && bThreat) {
                const severityOrder = { critical: 0, high: 1, medium: 2, low: 3 };
                const aSeverity = severityOrder[aThreat.severity as keyof typeof severityOrder];
                const bSeverity = severityOrder[bThreat.severity as keyof typeof severityOrder];
                
                if (aSeverity !== bSeverity) {
                    return aSeverity - bSeverity;
                }
            }
            
            return (a.label as string).localeCompare(b.label as string);
        });
    }

    private createSummaryTooltip(threatCount: any): string {
        const lines = [
            `Total threats: ${threatCount.total}`,
            `Critical: ${threatCount.bySeverity.critical}`,
            `High: ${threatCount.bySeverity.high}`,
            `Medium: ${threatCount.bySeverity.medium}`,
            `Low: ${threatCount.bySeverity.low}`
        ];
        return lines.join('\n');
    }

    private createThreatTooltip(threat: Threat): string {
        const lines = [
            `Package: ${threat.package_name}`,
            `Type: ${threat.threat_type}`,
            `Severity: ${threat.severity}`,
            `Confidence: ${(threat.confidence * 100).toFixed(1)}%`,
            `Description: ${threat.description}`
        ];
        
        if (threat.legitimate_package) {
            lines.push(`Suggested: ${threat.legitimate_package}`);
        }
        
        if (threat.risk_factors && threat.risk_factors.length > 0) {
            lines.push(`Risk factors: ${threat.risk_factors.join(', ')}`);
        }
        
        return lines.join('\n');
    }

    private getMaxSeverity(threats: Threat[]): string {
        const severityOrder = { critical: 0, high: 1, medium: 2, low: 3 };
        let maxSeverity = 'low';
        let maxOrder = 3;
        
        for (const threat of threats) {
            const order = severityOrder[threat.severity as keyof typeof severityOrder];
            if (order < maxOrder) {
                maxOrder = order;
                maxSeverity = threat.severity;
            }
        }
        
        return maxSeverity;
    }

    private getSeverityIcon(severity: string): vscode.ThemeIcon {
        switch (severity.toLowerCase()) {
            case 'critical':
                return new vscode.ThemeIcon('error', new vscode.ThemeColor('errorForeground'));
            case 'high':
                return new vscode.ThemeIcon('warning', new vscode.ThemeColor('errorForeground'));
            case 'medium':
                return new vscode.ThemeIcon('warning', new vscode.ThemeColor('warningForeground'));
            case 'low':
                return new vscode.ThemeIcon('info', new vscode.ThemeColor('foreground'));
            default:
                return new vscode.ThemeIcon('circle-outline');
        }
    }

    private getThreatCountFromLabel(label: string): number {
        const match = label.match(/\((\d+) threats?\)/);
        return match ? parseInt(match[1], 10) : 0;
    }
}

class TreeItem extends vscode.TreeItem {
    constructor(
        public readonly label: string,
        public readonly collapsibleState: vscode.TreeItemCollapsibleState,
        public readonly contextValue: string
    ) {
        super(label, collapsibleState);
    }
}