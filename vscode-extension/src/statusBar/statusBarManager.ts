import * as vscode from 'vscode';
import { ApiClient } from '../api/apiClient';
import { DiagnosticsManager } from '../diagnostics/diagnosticsManager';

export class StatusBarManager {
    private statusBarItem: vscode.StatusBarItem;
    private connectionStatusItem: vscode.StatusBarItem;
    private scanProgressItem: vscode.StatusBarItem | undefined;
    private isConnected: boolean = false;
    private lastScanTime: Date | undefined;
    private scanInProgress: boolean = false;

    constructor(
        private apiClient: ApiClient,
        private diagnosticsManager: DiagnosticsManager
    ) {
        // Main status bar item
        this.statusBarItem = vscode.window.createStatusBarItem(
            vscode.StatusBarAlignment.Left,
            100
        );
        this.statusBarItem.command = 'typosentinel.viewReport';
        this.statusBarItem.show();

        // Connection status item
        this.connectionStatusItem = vscode.window.createStatusBarItem(
            vscode.StatusBarAlignment.Left,
            99
        );
        this.connectionStatusItem.command = 'typosentinel.testConnection';
        this.connectionStatusItem.show();

        this.updateStatusBar();
        this.updateConnectionStatus();
        this.startPeriodicUpdates();
    }

    public updateThreatCount(): void {
        this.updateStatusBar();
    }

    public updateConnectionStatus(connected?: boolean): void {
        if (connected !== undefined) {
            this.isConnected = connected;
        }

        if (this.isConnected) {
            this.connectionStatusItem.text = '$(check) TypoSentinel Connected';
            this.connectionStatusItem.backgroundColor = undefined;
            this.connectionStatusItem.tooltip = 'TypoSentinel server is connected and ready';
        } else {
            this.connectionStatusItem.text = '$(x) TypoSentinel Disconnected';
            this.connectionStatusItem.backgroundColor = new vscode.ThemeColor('statusBarItem.errorBackground');
            this.connectionStatusItem.tooltip = 'TypoSentinel server is not connected. Click to test connection.';
        }
    }

    public setScanInProgress(inProgress: boolean, fileName?: string): void {
        this.scanInProgress = inProgress;

        if (inProgress) {
            if (!this.scanProgressItem) {
                this.scanProgressItem = vscode.window.createStatusBarItem(
                    vscode.StatusBarAlignment.Left,
                    98
                );
            }
            
            const fileText = fileName ? ` ${fileName}` : '';
            this.scanProgressItem.text = `$(sync~spin) Scanning${fileText}...`;
            this.scanProgressItem.tooltip = 'TypoSentinel scan in progress';
            this.scanProgressItem.show();
        } else {
            if (this.scanProgressItem) {
                this.scanProgressItem.hide();
                this.scanProgressItem.dispose();
                this.scanProgressItem = undefined;
            }
            this.lastScanTime = new Date();
            this.updateStatusBar();
        }
    }

    public showScanComplete(threatCount: number, fileName?: string): void {
        const fileText = fileName ? ` in ${fileName}` : '';
        const message = threatCount > 0 
            ? `$(warning) Found ${threatCount} threat${threatCount === 1 ? '' : 's'}${fileText}`
            : `$(check) No threats found${fileText}`;
        
        vscode.window.setStatusBarMessage(message, 3000);
    }

    public showError(message: string): void {
        this.connectionStatusItem.text = '$(error) TypoSentinel Error';
        this.connectionStatusItem.backgroundColor = new vscode.ThemeColor('statusBarItem.errorBackground');
        this.connectionStatusItem.tooltip = `Error: ${message}`;
        
        vscode.window.setStatusBarMessage(`$(error) TypoSentinel: ${message}`, 5000);
    }

    public dispose(): void {
        this.statusBarItem.dispose();
        this.connectionStatusItem.dispose();
        if (this.scanProgressItem) {
            this.scanProgressItem.dispose();
        }
    }

    private updateStatusBar(): void {
        const threatCount = this.diagnosticsManager.getThreatCount();
        const totalThreats = threatCount.total;

        if (totalThreats === 0) {
            this.statusBarItem.text = '$(shield) TypoSentinel: Secure';
            this.statusBarItem.backgroundColor = undefined;
            this.statusBarItem.tooltip = this.createTooltip(threatCount, 'No security threats detected');
        } else {
            const criticalCount = threatCount.bySeverity.critical;
            const highCount = threatCount.bySeverity.high;
            
            if (criticalCount > 0) {
                this.statusBarItem.text = `$(error) TypoSentinel: ${totalThreats} threats`;
                this.statusBarItem.backgroundColor = new vscode.ThemeColor('statusBarItem.errorBackground');
            } else if (highCount > 0) {
                this.statusBarItem.text = `$(warning) TypoSentinel: ${totalThreats} threats`;
                this.statusBarItem.backgroundColor = new vscode.ThemeColor('statusBarItem.warningBackground');
            } else {
                this.statusBarItem.text = `$(info) TypoSentinel: ${totalThreats} threats`;
                this.statusBarItem.backgroundColor = undefined;
            }
            
            this.statusBarItem.tooltip = this.createTooltip(threatCount, 'Click to view security report');
        }
    }

    private createTooltip(threatCount: any, baseMessage: string): string {
        const lines = [baseMessage];
        
        if (threatCount.total > 0) {
            lines.push('');
            lines.push('Threat breakdown:');
            if (threatCount.bySeverity.critical > 0) {
                lines.push(`• Critical: ${threatCount.bySeverity.critical}`);
            }
            if (threatCount.bySeverity.high > 0) {
                lines.push(`• High: ${threatCount.bySeverity.high}`);
            }
            if (threatCount.bySeverity.medium > 0) {
                lines.push(`• Medium: ${threatCount.bySeverity.medium}`);
            }
            if (threatCount.bySeverity.low > 0) {
                lines.push(`• Low: ${threatCount.bySeverity.low}`);
            }
        }
        
        if (this.lastScanTime) {
            lines.push('');
            lines.push(`Last scan: ${this.formatTime(this.lastScanTime)}`);
        }
        
        return lines.join('\n');
    }

    private formatTime(date: Date): string {
        const now = new Date();
        const diffMs = now.getTime() - date.getTime();
        const diffMins = Math.floor(diffMs / 60000);
        const diffHours = Math.floor(diffMins / 60);
        const diffDays = Math.floor(diffHours / 24);

        if (diffMins < 1) {
            return 'just now';
        } else if (diffMins < 60) {
            return `${diffMins} minute${diffMins === 1 ? '' : 's'} ago`;
        } else if (diffHours < 24) {
            return `${diffHours} hour${diffHours === 1 ? '' : 's'} ago`;
        } else {
            return `${diffDays} day${diffDays === 1 ? '' : 's'} ago`;
        }
    }

    private startPeriodicUpdates(): void {
        // Update connection status every 30 seconds
        setInterval(async () => {
            try {
                const health = await this.apiClient.checkHealth();
                this.updateConnectionStatus(health.status === 'healthy');
            } catch (error) {
                this.updateConnectionStatus(false);
            }
        }, 30000);

        // Update status bar every 5 seconds
        setInterval(() => {
            if (!this.scanInProgress) {
                this.updateStatusBar();
            }
        }, 5000);
    }

    // Public methods for external updates
    public async testConnection(): Promise<boolean> {
        try {
            const health = await this.apiClient.checkHealth();
            const connected = health.status === 'healthy';
            this.updateConnectionStatus(connected);
            
            if (connected) {
                vscode.window.showInformationMessage('TypoSentinel server connection successful!');
            } else {
                vscode.window.showWarningMessage('TypoSentinel server is not responding properly.');
            }
            
            return connected;
        } catch (error) {
            this.updateConnectionStatus(false);
            const errorMessage = error instanceof Error ? error.message : 'Unknown error';
            vscode.window.showErrorMessage(`Failed to connect to TypoSentinel server: ${errorMessage}`);
            return false;
        }
    }

    public updateScanProgress(current: number, total: number, fileName?: string): void {
        if (this.scanProgressItem) {
            const percentage = Math.round((current / total) * 100);
            const fileText = fileName ? ` ${fileName}` : '';
            this.scanProgressItem.text = `$(sync~spin) Scanning${fileText}... ${percentage}%`;
            this.scanProgressItem.tooltip = `Scanning progress: ${current}/${total} files (${percentage}%)`;
        }
    }

    public showQuickPick(): void {
        const items = [
            {
                label: '$(search) Scan Workspace',
                description: 'Scan all files in the current workspace',
                command: 'typosentinel.scanWorkspace'
            },
            {
                label: '$(file-text) Scan Current File',
                description: 'Scan the currently active file',
                command: 'typosentinel.scanFile'
            },
            {
                label: '$(graph) View Security Report',
                description: 'Open the detailed security report',
                command: 'typosentinel.viewReport'
            },
            {
                label: '$(settings-gear) Open Settings',
                description: 'Configure TypoSentinel settings',
                command: 'typosentinel.openSettings'
            },
            {
                label: '$(plug) Test Connection',
                description: 'Test connection to TypoSentinel server',
                command: 'typosentinel.testConnection'
            }
        ];

        vscode.window.showQuickPick(items, {
            placeHolder: 'Select a TypoSentinel action'
        }).then(selection => {
            if (selection) {
                vscode.commands.executeCommand(selection.command);
            }
        });
    }
}