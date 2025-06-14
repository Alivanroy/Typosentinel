import * as vscode from 'vscode';

export interface ExtensionConfiguration {
    apiKey: string;
    serverUrl: string;
    enableRealTimeScanning: boolean;
    scanOnSave: boolean;
    showInlineWarnings: boolean;
    confidenceThreshold: number;
    autoScanWorkspace: boolean;
    enableNotifications: boolean;
    maxConcurrentScans: number;
    scanTimeout: number;
}

export class ConfigurationManager {
    private static readonly CONFIGURATION_SECTION = 'typosentinel';
    private configuration: vscode.WorkspaceConfiguration;

    constructor() {
        this.configuration = vscode.workspace.getConfiguration(ConfigurationManager.CONFIGURATION_SECTION);
    }

    public refresh(): void {
        this.configuration = vscode.workspace.getConfiguration(ConfigurationManager.CONFIGURATION_SECTION);
    }

    public getConfiguration(): ExtensionConfiguration {
        return {
            apiKey: this.configuration.get<string>('apiKey', ''),
            serverUrl: this.configuration.get<string>('serverUrl', 'http://localhost:8080'),
            enableRealTimeScanning: this.configuration.get<boolean>('enableRealTimeScanning', true),
            scanOnSave: this.configuration.get<boolean>('scanOnSave', true),
            showInlineWarnings: this.configuration.get<boolean>('showInlineWarnings', true),
            confidenceThreshold: this.configuration.get<number>('confidenceThreshold', 0.7),
            autoScanWorkspace: this.configuration.get<boolean>('autoScanWorkspace', false),
            enableNotifications: this.configuration.get<boolean>('enableNotifications', true),
            maxConcurrentScans: this.configuration.get<number>('maxConcurrentScans', 3),
            scanTimeout: this.configuration.get<number>('scanTimeout', 30000)
        };
    }

    public getApiKey(): string {
        return this.configuration.get<string>('apiKey', '');
    }

    public getServerUrl(): string {
        return this.configuration.get<string>('serverUrl', 'http://localhost:8080');
    }

    public getRealTimeScanning(): boolean {
        return this.configuration.get<boolean>('enableRealTimeScanning', true);
    }

    public getScanOnSave(): boolean {
        return this.configuration.get<boolean>('scanOnSave', true);
    }

    public getShowInlineWarnings(): boolean {
        return this.configuration.get<boolean>('showInlineWarnings', true);
    }

    public getConfidenceThreshold(): number {
        return this.configuration.get<number>('confidenceThreshold', 0.7);
    }

    public getAutoScanWorkspace(): boolean {
        return this.configuration.get<boolean>('autoScanWorkspace', false);
    }

    public getEnableNotifications(): boolean {
        return this.configuration.get<boolean>('enableNotifications', true);
    }

    public getMaxConcurrentScans(): number {
        return this.configuration.get<number>('maxConcurrentScans', 3);
    }

    public getScanTimeout(): number {
        return this.configuration.get<number>('scanTimeout', 30000);
    }

    public async updateApiKey(apiKey: string): Promise<void> {
        await this.configuration.update('apiKey', apiKey, vscode.ConfigurationTarget.Global);
        this.refresh();
    }

    public async updateServerUrl(serverUrl: string): Promise<void> {
        await this.configuration.update('serverUrl', serverUrl, vscode.ConfigurationTarget.Workspace);
        this.refresh();
    }

    public async updateRealTimeScanning(enabled: boolean): Promise<void> {
        await this.configuration.update('enableRealTimeScanning', enabled, vscode.ConfigurationTarget.Workspace);
        this.refresh();
    }

    public async updateScanOnSave(enabled: boolean): Promise<void> {
        await this.configuration.update('scanOnSave', enabled, vscode.ConfigurationTarget.Workspace);
        this.refresh();
    }

    public async updateShowInlineWarnings(enabled: boolean): Promise<void> {
        await this.configuration.update('showInlineWarnings', enabled, vscode.ConfigurationTarget.Workspace);
        this.refresh();
    }

    public async updateConfidenceThreshold(threshold: number): Promise<void> {
        if (threshold < 0.1 || threshold > 1.0) {
            throw new Error('Confidence threshold must be between 0.1 and 1.0');
        }
        await this.configuration.update('confidenceThreshold', threshold, vscode.ConfigurationTarget.Workspace);
        this.refresh();
    }

    public async updateAutoScanWorkspace(enabled: boolean): Promise<void> {
        await this.configuration.update('autoScanWorkspace', enabled, vscode.ConfigurationTarget.Workspace);
        this.refresh();
    }

    public async updateEnableNotifications(enabled: boolean): Promise<void> {
        await this.configuration.update('enableNotifications', enabled, vscode.ConfigurationTarget.Workspace);
        this.refresh();
    }

    public async updateMaxConcurrentScans(max: number): Promise<void> {
        if (max < 1 || max > 10) {
            throw new Error('Max concurrent scans must be between 1 and 10');
        }
        await this.configuration.update('maxConcurrentScans', max, vscode.ConfigurationTarget.Workspace);
        this.refresh();
    }

    public async updateScanTimeout(timeout: number): Promise<void> {
        if (timeout < 5000 || timeout > 120000) {
            throw new Error('Scan timeout must be between 5000ms and 120000ms');
        }
        await this.configuration.update('scanTimeout', timeout, vscode.ConfigurationTarget.Workspace);
        this.refresh();
    }

    public isConfigured(): boolean {
        const config = this.getConfiguration();
        return !!(config.apiKey && config.serverUrl);
    }

    public validateConfiguration(): { isValid: boolean; errors: string[] } {
        const config = this.getConfiguration();
        const errors: string[] = [];

        if (!config.apiKey) {
            errors.push('API key is required');
        }

        if (!config.serverUrl) {
            errors.push('Server URL is required');
        } else {
            try {
                new URL(config.serverUrl);
            } catch {
                errors.push('Server URL is not a valid URL');
            }
        }

        if (config.confidenceThreshold < 0.1 || config.confidenceThreshold > 1.0) {
            errors.push('Confidence threshold must be between 0.1 and 1.0');
        }

        if (config.maxConcurrentScans < 1 || config.maxConcurrentScans > 10) {
            errors.push('Max concurrent scans must be between 1 and 10');
        }

        if (config.scanTimeout < 5000 || config.scanTimeout > 120000) {
            errors.push('Scan timeout must be between 5000ms and 120000ms');
        }

        return {
            isValid: errors.length === 0,
            errors
        };
    }

    public exportConfiguration(): string {
        const config = this.getConfiguration();
        // Remove sensitive data for export
        const exportConfig = { ...config };
        delete (exportConfig as any).apiKey;
        return JSON.stringify(exportConfig, null, 2);
    }

    public async importConfiguration(configJson: string): Promise<void> {
        try {
            const config = JSON.parse(configJson);
            
            // Validate imported configuration
            const validKeys = [
                'serverUrl', 'enableRealTimeScanning', 'scanOnSave', 
                'showInlineWarnings', 'confidenceThreshold', 'autoScanWorkspace',
                'enableNotifications', 'maxConcurrentScans', 'scanTimeout'
            ];

            for (const [key, value] of Object.entries(config)) {
                if (validKeys.includes(key)) {
                    await this.configuration.update(key, value, vscode.ConfigurationTarget.Workspace);
                }
            }

            this.refresh();
        } catch (error) {
            throw new Error(`Failed to import configuration: ${error}`);
        }
    }

    public resetToDefaults(): Promise<void[]> {
        const updates = [
            this.configuration.update('serverUrl', undefined, vscode.ConfigurationTarget.Workspace),
            this.configuration.update('enableRealTimeScanning', undefined, vscode.ConfigurationTarget.Workspace),
            this.configuration.update('scanOnSave', undefined, vscode.ConfigurationTarget.Workspace),
            this.configuration.update('showInlineWarnings', undefined, vscode.ConfigurationTarget.Workspace),
            this.configuration.update('confidenceThreshold', undefined, vscode.ConfigurationTarget.Workspace),
            this.configuration.update('autoScanWorkspace', undefined, vscode.ConfigurationTarget.Workspace),
            this.configuration.update('enableNotifications', undefined, vscode.ConfigurationTarget.Workspace),
            this.configuration.update('maxConcurrentScans', undefined, vscode.ConfigurationTarget.Workspace),
            this.configuration.update('scanTimeout', undefined, vscode.ConfigurationTarget.Workspace)
        ];

        return Promise.all(updates).then(() => {
            this.refresh();
            return [];
        });
    }
}