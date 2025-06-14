import * as vscode from 'vscode';
import { ApiClient, IDEScanRequest, IDEScanResponse, Finding } from '../api/apiClient';
import { DependencyParser, Ecosystem } from '../utils/dependencyParser';
import { ConfigurationManager } from '../config/configurationManager';

/**
 * IDE Provider for real-time dependency scanning
 * Phase 1 implementation of the IDE integration plan
 */
export class IDEProvider implements vscode.HoverProvider, vscode.CodeActionProvider {
    private diagnosticCollection: vscode.DiagnosticCollection;
    private apiClient: ApiClient;
    private configManager: ConfigurationManager;
    private scanTimeout: NodeJS.Timeout | undefined;
    private readonly SCAN_DEBOUNCE_MS = 1000; // 1 second debounce

    constructor(apiClient: ApiClient, configManager: ConfigurationManager) {
        this.apiClient = apiClient;
        this.configManager = configManager;
        this.diagnosticCollection = vscode.languages.createDiagnosticCollection('typosentinel-ide');
    }

    /**
     * Initialize the IDE provider
     */
    public initialize(): void {
        // Register providers
        vscode.languages.registerHoverProvider(
            { pattern: '**/{package.json,requirements.txt,go.mod,pom.xml,build.gradle,build.gradle.kts,composer.json,Cargo.toml}' },
            this
        );
        
        vscode.languages.registerCodeActionsProvider(
            { pattern: '**/{package.json,requirements.txt,go.mod,pom.xml,build.gradle,build.gradle.kts,composer.json,Cargo.toml}' },
            this
        );

        // Listen for file changes
        vscode.workspace.onDidSaveTextDocument(this.onDocumentSaved, this);
        vscode.workspace.onDidChangeTextDocument(this.onDocumentChanged, this);
    }

    /**
     * Handle document save events
     */
    private async onDocumentSaved(document: vscode.TextDocument): Promise<void> {
        if (DependencyParser.isSupportedManifestFile(document.fileName)) {
            await this.scanDocument(document);
        }
    }

    /**
     * Handle document change events with debouncing
     */
    private onDocumentChanged(event: vscode.TextDocumentChangeEvent): void {
        if (!DependencyParser.isSupportedManifestFile(event.document.fileName)) {
            return;
        }

        // Clear existing timeout
        if (this.scanTimeout) {
            clearTimeout(this.scanTimeout);
        }

        // Set new timeout for debounced scanning
        this.scanTimeout = setTimeout(() => {
            this.scanDocument(event.document);
        }, this.SCAN_DEBOUNCE_MS);
    }

    /**
     * Scan a document for dependency issues
     */
    private async scanDocument(document: vscode.TextDocument): Promise<void> {
        try {
            // Parse dependencies from the document
            const parseResult = await DependencyParser.parseDependencies(document.fileName);
            if (!parseResult || parseResult.packages.length === 0) {
                this.diagnosticCollection.set(document.uri, []);
                return;
            }

            // Create scan request
            const scanRequest: IDEScanRequest = {
                ecosystem: parseResult.ecosystem,
                packages: parseResult.packages
            };

            // Call API
            const scanResponse = await this.apiClient.scanDependencies(scanRequest);
            if (!scanResponse) {
                return;
            }

            // Convert findings to diagnostics
            const diagnostics = this.createDiagnostics(document, scanResponse);
            this.diagnosticCollection.set(document.uri, diagnostics);

        } catch (error) {
            console.error('Failed to scan document:', error);
        }
    }

    /**
     * Convert API findings to VS Code diagnostics
     */
    private createDiagnostics(document: vscode.TextDocument, response: IDEScanResponse): vscode.Diagnostic[] {
        const diagnostics: vscode.Diagnostic[] = [];
        const text = document.getText();

        for (const finding of response.findings) {
            const range = this.findPackageRange(text, finding.packageName);
            if (!range) {
                continue;
            }

            const diagnostic = new vscode.Diagnostic(
                range,
                this.createDiagnosticMessage(finding),
                this.getSeverity(finding.severity)
            );

            diagnostic.source = 'TypoSentinel';
            diagnostic.code = finding.cve || finding.type;
            
            // Store finding data for hover and code actions
            (diagnostic as any).typoSentinelFinding = finding;

            diagnostics.push(diagnostic);
        }

        return diagnostics;
    }

    /**
     * Find the range of a package name in the document
     */
    private findPackageRange(text: string, packageName: string): vscode.Range | null {
        const lines = text.split('\n');
        
        for (let i = 0; i < lines.length; i++) {
            const line = lines[i];
            const index = line.indexOf(`"${packageName}"`);
            
            if (index !== -1) {
                return new vscode.Range(
                    new vscode.Position(i, index + 1), // Skip opening quote
                    new vscode.Position(i, index + packageName.length + 1)
                );
            }
            
            // Also check for single quotes
            const singleQuoteIndex = line.indexOf(`'${packageName}'`);
            if (singleQuoteIndex !== -1) {
                return new vscode.Range(
                    new vscode.Position(i, singleQuoteIndex + 1),
                    new vscode.Position(i, singleQuoteIndex + packageName.length + 1)
                );
            }
        }
        
        return null;
    }

    /**
     * Create diagnostic message from finding
     */
    private createDiagnosticMessage(finding: Finding): string {
        let message = `${finding.type}: ${finding.packageName}`;
        
        if (finding.cve) {
            message += ` (${finding.cve})`;
        }
        
        return message;
    }

    /**
     * Convert finding severity to VS Code diagnostic severity
     */
    private getSeverity(severity: string): vscode.DiagnosticSeverity {
        switch (severity.toLowerCase()) {
            case 'critical':
            case 'high':
                return vscode.DiagnosticSeverity.Error;
            case 'medium':
                return vscode.DiagnosticSeverity.Warning;
            case 'low':
                return vscode.DiagnosticSeverity.Information;
            default:
                return vscode.DiagnosticSeverity.Warning;
        }
    }

    /**
     * Provide hover information for diagnostics
     * Phase 1: Rich Hover Info implementation
     */
    public provideHover(
        document: vscode.TextDocument,
        position: vscode.Position,
        token: vscode.CancellationToken
    ): vscode.ProviderResult<vscode.Hover> {
        // Get diagnostics for this document
        const diagnostics = this.diagnosticCollection.get(document.uri);
        if (!diagnostics) {
            return null;
        }

        // Find diagnostic at this position
        const diagnostic = diagnostics.find(d => d.range.contains(position));
        if (!diagnostic || !(diagnostic as any).typoSentinelFinding) {
            return null;
        }

        const finding: Finding = (diagnostic as any).typoSentinelFinding;
        
        // Create rich hover content
        const markdown = new vscode.MarkdownString();
        markdown.isTrusted = true;
        
        // Title
        markdown.appendMarkdown(`### 🚨 ${finding.type}\n\n`);
        
        // Package info
        markdown.appendMarkdown(`**Package:** \`${finding.packageName}\`\n\n`);
        
        // Severity
        const severityIcon = this.getSeverityIcon(finding.severity);
        markdown.appendMarkdown(`**Severity:** ${severityIcon} ${finding.severity}\n\n`);
        
        // CVE if available
        if (finding.cve) {
            markdown.appendMarkdown(`**CVE:** [${finding.cve}](https://cve.mitre.org/cgi-bin/cvename.cgi?name=${finding.cve})\n\n`);
        }
        
        // Description
        if (finding.description) {
            markdown.appendMarkdown(`**Description:**\n${finding.description}\n\n`);
        }
        
        // Remediation info
        if (finding.remediation) {
            markdown.appendMarkdown(`**Recommended Action:**\n`);
            switch (finding.remediation.type) {
                case 'UPGRADE':
                    markdown.appendMarkdown(`Upgrade to version \`${finding.remediation.safeVersion}\``);
                    break;
                case 'REMOVE':
                    markdown.appendMarkdown(`Remove this package - it's malicious`);
                    break;
                case 'REPLACE':
                    markdown.appendMarkdown(`Replace with \`${finding.remediation.alternativePackage}\``);
                    break;
                default:
                    markdown.appendMarkdown(`${finding.remediation.instructions || 'No specific instructions available'}`);
            }
        }

        return new vscode.Hover(markdown, diagnostic.range);
    }

    /**
     * Provide code actions (Quick Fixes)
     * Phase 2: Inline Quick Fixes implementation
     */
    public provideCodeActions(
        document: vscode.TextDocument,
        range: vscode.Range | vscode.Selection,
        context: vscode.CodeActionContext,
        token: vscode.CancellationToken
    ): vscode.ProviderResult<vscode.CodeAction[]> {
        const actions: vscode.CodeAction[] = [];

        // Find TypoSentinel diagnostics in the context
        const typoSentinelDiagnostics = context.diagnostics.filter(
            d => d.source === 'TypoSentinel' && (d as any).typoSentinelFinding
        );

        for (const diagnostic of typoSentinelDiagnostics) {
            const finding: Finding = (diagnostic as any).typoSentinelFinding;
            
            if (finding.remediation) {
                const action = this.createCodeAction(document, diagnostic, finding);
                if (action) {
                    actions.push(action);
                }
            }
        }

        return actions;
    }

    /**
     * Create a code action for a finding
     */
    private createCodeAction(
        document: vscode.TextDocument,
        diagnostic: vscode.Diagnostic,
        finding: Finding
    ): vscode.CodeAction | null {
        if (!finding.remediation) {
            return null;
        }

        const action = new vscode.CodeAction(
            this.getActionTitle(finding),
            vscode.CodeActionKind.QuickFix
        );

        action.diagnostics = [diagnostic];
        action.isPreferred = finding.severity === 'Critical' || finding.severity === 'High';

        // Create the edit based on remediation type
        switch (finding.remediation.type) {
            case 'UPGRADE':
                action.edit = this.createUpgradeEdit(document, finding);
                break;
            case 'REMOVE':
                action.edit = this.createRemoveEdit(document, finding);
                break;
            case 'REPLACE':
                action.edit = this.createReplaceEdit(document, finding);
                break;
        }

        return action;
    }

    /**
     * Get action title based on remediation
     */
    private getActionTitle(finding: Finding): string {
        if (!finding.remediation) {
            return 'Fix issue';
        }

        switch (finding.remediation.type) {
            case 'UPGRADE':
                return `Upgrade ${finding.packageName} to ${finding.remediation.safeVersion}`;
            case 'REMOVE':
                return `Remove ${finding.packageName}`;
            case 'REPLACE':
                return `Replace ${finding.packageName} with ${finding.remediation.alternativePackage}`;
            default:
                return `Fix ${finding.packageName}`;
        }
    }

    /**
     * Create edit for upgrading a package
     */
    private createUpgradeEdit(document: vscode.TextDocument, finding: Finding): vscode.WorkspaceEdit {
        const edit = new vscode.WorkspaceEdit();
        const text = document.getText();
        const lines = text.split('\n');

        for (let i = 0; i < lines.length; i++) {
            const line = lines[i];
            if (line.includes(`"${finding.packageName}"`)) {
                // Find version pattern and replace
                const versionMatch = line.match(/"([^"]+)"\s*:\s*"([^"]+)"/);
                if (versionMatch && versionMatch[1] === finding.packageName) {
                    const newLine = line.replace(
                        versionMatch[2],
                        finding.remediation!.safeVersion!
                    );
                    
                    edit.replace(
                        document.uri,
                        new vscode.Range(
                            new vscode.Position(i, 0),
                            new vscode.Position(i, line.length)
                        ),
                        newLine
                    );
                    break;
                }
            }
        }

        return edit;
    }

    /**
     * Create edit for removing a package
     */
    private createRemoveEdit(document: vscode.TextDocument, finding: Finding): vscode.WorkspaceEdit {
        const edit = new vscode.WorkspaceEdit();
        const text = document.getText();
        const lines = text.split('\n');

        for (let i = 0; i < lines.length; i++) {
            const line = lines[i];
            if (line.includes(`"${finding.packageName}"`)) {
                // Remove the entire line (including comma if present)
                let startLine = i;
                let endLine = i + 1;
                
                // Check if we need to remove trailing comma from previous line
                if (i > 0 && lines[i - 1].trim().endsWith(',') && 
                    (i === lines.length - 1 || !lines[i + 1].trim().includes('"'))) {
                    const prevLine = lines[i - 1];
                    edit.replace(
                        document.uri,
                        new vscode.Range(
                            new vscode.Position(i - 1, 0),
                            new vscode.Position(i - 1, prevLine.length)
                        ),
                        prevLine.replace(/,$/, '')
                    );
                }
                
                edit.delete(
                    document.uri,
                    new vscode.Range(
                        new vscode.Position(startLine, 0),
                        new vscode.Position(endLine, 0)
                    )
                );
                break;
            }
        }

        return edit;
    }

    /**
     * Create edit for replacing a package
     */
    private createReplaceEdit(document: vscode.TextDocument, finding: Finding): vscode.WorkspaceEdit {
        const edit = new vscode.WorkspaceEdit();
        const text = document.getText();
        const lines = text.split('\n');

        for (let i = 0; i < lines.length; i++) {
            const line = lines[i];
            if (line.includes(`"${finding.packageName}"`)) {
                const newLine = line.replace(
                    `"${finding.packageName}"`,
                    `"${finding.remediation!.alternativePackage}"`
                );
                
                edit.replace(
                    document.uri,
                    new vscode.Range(
                        new vscode.Position(i, 0),
                        new vscode.Position(i, line.length)
                    ),
                    newLine
                );
                break;
            }
        }

        return edit;
    }

    /**
     * Get severity icon for hover display
     */
    private getSeverityIcon(severity: string): string {
        switch (severity.toLowerCase()) {
            case 'critical':
                return '🔴';
            case 'high':
                return '🟠';
            case 'medium':
                return '🟡';
            case 'low':
                return '🔵';
            default:
                return '⚪';
        }
    }

    /**
     * Dispose of resources
     */
    public dispose(): void {
        this.diagnosticCollection.dispose();
        if (this.scanTimeout) {
            clearTimeout(this.scanTimeout);
        }
    }

    /**
     * Manually trigger scan for all open manifest files
     */
    public async scanAllOpenManifests(): Promise<void> {
        const openDocuments = vscode.workspace.textDocuments;
        
        for (const document of openDocuments) {
            if (DependencyParser.isSupportedManifestFile(document.fileName)) {
                await this.scanDocument(document);
            }
        }
    }

    /**
     * Clear all diagnostics
     */
    public clearDiagnostics(): void {
        this.diagnosticCollection.clear();
    }
}