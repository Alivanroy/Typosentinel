import * as vscode from 'vscode';
import { ApiClient } from '../api/apiClient';

export interface SecurityReport {
    summary: {
        totalPackages: number;
        vulnerablePackages: number;
        criticalVulnerabilities: number;
        highVulnerabilities: number;
        mediumVulnerabilities: number;
        lowVulnerabilities: number;
    };
    vulnerabilities: any[];
    recommendations: string[];
}

export class SecurityReportProvider {
    constructor(private apiClient: ApiClient) {}

    async generateReport(): Promise<SecurityReport> {
        // This is a placeholder implementation
        // In a real implementation, this would fetch data from the API
        return {
            summary: {
                totalPackages: 0,
                vulnerablePackages: 0,
                criticalVulnerabilities: 0,
                highVulnerabilities: 0,
                mediumVulnerabilities: 0,
                lowVulnerabilities: 0
            },
            vulnerabilities: [],
            recommendations: [
                'Keep dependencies up to date',
                'Review security advisories regularly',
                'Use dependency scanning tools'
            ]
        };
    }

    getWebviewContent(reportData: SecurityReport): string {
        return `
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Security Report</title>
            <style>
                body {
                    font-family: var(--vscode-font-family);
                    color: var(--vscode-foreground);
                    background-color: var(--vscode-editor-background);
                    padding: 20px;
                }
                .summary {
                    background-color: var(--vscode-editor-inactiveSelectionBackground);
                    padding: 15px;
                    border-radius: 5px;
                    margin-bottom: 20px;
                }
                .metric {
                    display: inline-block;
                    margin: 10px;
                    padding: 10px;
                    background-color: var(--vscode-button-background);
                    border-radius: 3px;
                }
                .recommendations {
                    margin-top: 20px;
                }
                .recommendations ul {
                    list-style-type: disc;
                    padding-left: 20px;
                }
            </style>
        </head>
        <body>
            <h1>Security Report</h1>
            
            <div class="summary">
                <h2>Summary</h2>
                <div class="metric">
                    <strong>Total Packages:</strong> ${reportData.summary.totalPackages}
                </div>
                <div class="metric">
                    <strong>Vulnerable Packages:</strong> ${reportData.summary.vulnerablePackages}
                </div>
                <div class="metric">
                    <strong>Critical:</strong> ${reportData.summary.criticalVulnerabilities}
                </div>
                <div class="metric">
                    <strong>High:</strong> ${reportData.summary.highVulnerabilities}
                </div>
                <div class="metric">
                    <strong>Medium:</strong> ${reportData.summary.mediumVulnerabilities}
                </div>
                <div class="metric">
                    <strong>Low:</strong> ${reportData.summary.lowVulnerabilities}
                </div>
            </div>

            <div class="recommendations">
                <h2>Recommendations</h2>
                <ul>
                    ${reportData.recommendations.map(rec => `<li>${rec}</li>`).join('')}
                </ul>
            </div>
        </body>
        </html>
        `;
    }
}