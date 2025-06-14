import * as vscode from 'vscode';
import { ScanResult, Threat } from '../api/apiClient';

export class DiagnosticsManager {
    private diagnosticCollection: vscode.DiagnosticCollection;
    private scanResults: Map<string, ScanResult> = new Map();

    constructor() {
        this.diagnosticCollection = vscode.languages.createDiagnosticCollection('typosentinel');
    }

    public getDiagnosticCollection(): vscode.DiagnosticCollection {
        return this.diagnosticCollection;
    }

    public updateDiagnostics(uri: vscode.Uri, scanResult: ScanResult): void {
        this.scanResults.set(uri.toString(), scanResult);
        
        const diagnostics: vscode.Diagnostic[] = [];
        
        if (scanResult.threats && scanResult.threats.length > 0) {
            for (const threat of scanResult.threats) {
                const diagnostic = this.createDiagnostic(threat, uri);
                if (diagnostic) {
                    diagnostics.push(diagnostic);
                }
            }
        }
        
        this.diagnosticCollection.set(uri, diagnostics);
    }

    private createDiagnostic(threat: Threat, uri: vscode.Uri): vscode.Diagnostic | null {
        try {
            const range = this.getThreatRange(threat, uri);
            if (!range) {
                return null;
            }

            const diagnostic = new vscode.Diagnostic(
                range,
                this.formatDiagnosticMessage(threat),
                this.getSeverity(threat.severity)
            );

            diagnostic.source = 'TypoSentinel';
            diagnostic.code = {
                value: threat.threat_type,
                target: vscode.Uri.parse('https://typosentinel.com/docs/threats/' + threat.threat_type)
            };

            // Add related information
            if (threat.legitimate_package) {
                diagnostic.relatedInformation = [
                    new vscode.DiagnosticRelatedInformation(
                        new vscode.Location(uri, range),
                        `Did you mean '${threat.legitimate_package}'?`
                    )
                ];
            }

            // Add tags
            diagnostic.tags = this.getDiagnosticTags(threat);

            return diagnostic;
        } catch (error) {
            console.error('Error creating diagnostic:', error);
            return null;
        }
    }

    private getThreatRange(threat: Threat, uri: vscode.Uri): vscode.Range | null {
        try {
            // If line and column numbers are provided, use them
            if (threat.line_number !== undefined) {
                const line = Math.max(0, threat.line_number - 1); // Convert to 0-based
                const column = threat.column_number || 0;
                
                // Try to get the actual document to determine the range
                const document = vscode.workspace.textDocuments.find(doc => doc.uri.toString() === uri.toString());
                if (document && line < document.lineCount) {
                    const lineText = document.lineAt(line).text;
                    const packageNameIndex = lineText.indexOf(threat.package_name);
                    
                    if (packageNameIndex !== -1) {
                        return new vscode.Range(
                            line,
                            packageNameIndex,
                            line,
                            packageNameIndex + threat.package_name.length
                        );
                    } else {
                        // Fallback to column position
                        return new vscode.Range(
                            line,
                            column,
                            line,
                            Math.min(column + threat.package_name.length, lineText.length)
                        );
                    }
                } else {
                    // Fallback range
                    return new vscode.Range(line, column, line, column + threat.package_name.length);
                }
            }

            // If no line number, try to find the package in the document
            const document = vscode.workspace.textDocuments.find(doc => doc.uri.toString() === uri.toString());
            if (document) {
                return this.findPackageInDocument(document, threat.package_name);
            }

            // Default range (first line)
            return new vscode.Range(0, 0, 0, 0);
        } catch (error) {
            console.error('Error getting threat range:', error);
            return new vscode.Range(0, 0, 0, 0);
        }
    }

    private findPackageInDocument(document: vscode.TextDocument, packageName: string): vscode.Range | null {
        const text = document.getText();
        const lines = text.split('\n');
        
        for (let i = 0; i < lines.length; i++) {
            const line = lines[i];
            const index = line.indexOf(`"${packageName}"`);
            
            if (index !== -1) {
                return new vscode.Range(
                    i,
                    index + 1, // Skip the opening quote
                    i,
                    index + 1 + packageName.length
                );
            }
            
            // Also check for single quotes
            const singleQuoteIndex = line.indexOf(`'${packageName}'`);
            if (singleQuoteIndex !== -1) {
                return new vscode.Range(
                    i,
                    singleQuoteIndex + 1,
                    i,
                    singleQuoteIndex + 1 + packageName.length
                );
            }
        }
        
        return null;
    }

    private formatDiagnosticMessage(threat: Threat): string {
        let message = `${threat.description} (Confidence: ${(threat.confidence * 100).toFixed(1)}%)`;
        
        if (threat.legitimate_package) {
            message += ` - Did you mean '${threat.legitimate_package}'?`;
        }
        
        if (threat.risk_factors && threat.risk_factors.length > 0) {
            message += ` Risk factors: ${threat.risk_factors.join(', ')}`;
        }
        
        return message;
    }

    private getSeverity(severity: string): vscode.DiagnosticSeverity {
        switch (severity.toLowerCase()) {
            case 'critical':
                return vscode.DiagnosticSeverity.Error;
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

    private getDiagnosticTags(threat: Threat): vscode.DiagnosticTag[] {
        const tags: vscode.DiagnosticTag[] = [];
        
        // Add deprecated tag for certain threat types
        if (threat.threat_type === 'deprecated_package') {
            tags.push(vscode.DiagnosticTag.Deprecated);
        }
        
        // Add unnecessary tag for low-confidence threats
        if (threat.confidence < 0.5) {
            tags.push(vscode.DiagnosticTag.Unnecessary);
        }
        
        return tags;
    }

    public clearDiagnostics(uri?: vscode.Uri): void {
        if (uri) {
            this.diagnosticCollection.delete(uri);
            this.scanResults.delete(uri.toString());
        } else {
            this.diagnosticCollection.clear();
            this.scanResults.clear();
        }
    }

    public getScanResult(uri: vscode.Uri): ScanResult | undefined {
        return this.scanResults.get(uri.toString());
    }

    public getAllScanResults(): Map<string, ScanResult> {
        return new Map(this.scanResults);
    }

    public getThreatCount(): { total: number; bySeverity: Record<string, number> } {
        let total = 0;
        const bySeverity: Record<string, number> = {
            critical: 0,
            high: 0,
            medium: 0,
            low: 0
        };

        for (const scanResult of this.scanResults.values()) {
            if (scanResult.threats) {
                total += scanResult.threats.length;
                
                for (const threat of scanResult.threats) {
                    bySeverity[threat.severity] = (bySeverity[threat.severity] || 0) + 1;
                }
            }
        }

        return { total, bySeverity };
    }

    public getThreatsForFile(uri: vscode.Uri): Threat[] {
        const scanResult = this.getScanResult(uri);
        return scanResult?.threats || [];
    }

    public hasThreats(uri?: vscode.Uri): boolean {
        if (uri) {
            const threats = this.getThreatsForFile(uri);
            return threats.length > 0;
        } else {
            return this.getThreatCount().total > 0;
        }
    }

    public refreshDiagnostics(): void {
        // Re-apply all diagnostics
        for (const [uriString, scanResult] of this.scanResults.entries()) {
            const uri = vscode.Uri.parse(uriString);
            this.updateDiagnostics(uri, scanResult);
        }
    }

    public exportDiagnostics(): any {
        const diagnostics: any[] = [];
        
        for (const [uriString, scanResult] of this.scanResults.entries()) {
            diagnostics.push({
                file: uriString,
                scan_result: scanResult,
                timestamp: new Date().toISOString()
            });
        }
        
        return {
            export_timestamp: new Date().toISOString(),
            total_files: diagnostics.length,
            total_threats: this.getThreatCount().total,
            diagnostics
        };
    }

    public dispose(): void {
        this.diagnosticCollection.dispose();
        this.scanResults.clear();
    }
}