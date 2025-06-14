import axios, { AxiosInstance, AxiosResponse } from 'axios';
import * as vscode from 'vscode';
import { ConfigurationManager } from '../config/configurationManager';

export interface ScanResult {
    file_path: string;
    threats: Threat[];
    scan_timestamp: string;
    scan_duration_ms: number;
    metadata: {
        total_packages: number;
        scanned_packages: number;
        confidence_threshold: number;
    };
}

// New interfaces for IDE integration
export interface IDEScanRequest {
    ecosystem: string;
    packages: PackageInfo[];
}

export interface PackageInfo {
    name: string;
    version: string;
}

export interface IDEScanResponse {
    findings: Finding[];
    dependencyTree?: DependencyTree;
    licenseAnalysis?: LicenseAnalysis;
    projectHealth?: ProjectHealth;
}

export interface Finding {
    packageName: string;
    severity: 'Low' | 'Medium' | 'High' | 'Critical';
    type: string;
    description: string;
    cve?: string;
    remediation?: Remediation;
}

export interface Remediation {
    type: 'UPGRADE' | 'REMOVE' | 'REPLACE';
    safeVersion?: string;
    alternativePackage?: string;
    instructions?: string;
}

export interface DependencyTree {
    direct: PackageInfo[];
    transitive: PackageInfo[];
}

export interface LicenseAnalysis {
    violations: LicenseViolation[];
    recommendations: string[];
}

export interface LicenseViolation {
    packageName: string;
    license: string;
    violationType: string;
    description: string;
}

export interface ProjectHealth {
    score: number;
    metrics: {
        vulnerabilityCount: number;
        outdatedPackages: number;
        licenseIssues: number;
        maintenanceScore: number;
    };
}

export interface Threat {
    package_name: string;
    threat_type: string;
    confidence: number;
    description: string;
    severity: 'low' | 'medium' | 'high' | 'critical';
    line_number?: number;
    column_number?: number;
    suggested_fix?: string;
    legitimate_package?: string;
    risk_factors: string[];
}

export interface HealthCheck {
    status: string;
    version: string;
    uptime: number;
    features: {
        behavioral_analysis: boolean;
        ml_detection: boolean;
        real_time_scanning: boolean;
    };
}

export class ApiClient {
    private client: AxiosInstance;
    private configManager: ConfigurationManager;

    constructor(configManager: ConfigurationManager) {
        this.configManager = configManager;
        this.client = this.createClient();
    }

    private createClient(): AxiosInstance {
        const config = this.configManager.getConfiguration();
        
        return axios.create({
            baseURL: config.serverUrl,
            timeout: 30000,
            headers: {
                'Content-Type': 'application/json',
                'User-Agent': 'TypoSentinel-VSCode/1.0.0',
                ...(config.apiKey && { 'Authorization': `Bearer ${config.apiKey}` })
            }
        });
    }

    public updateConfiguration(): void {
        this.client = this.createClient();
    }

    public async scanFile(filePath: string, content: string): Promise<ScanResult | null> {
        try {
            const response: AxiosResponse<ScanResult> = await this.client.post('/api/scan', {
                file_path: filePath,
                content: content,
                scan_type: 'vscode_extension',
                options: {
                    confidence_threshold: this.configManager.getConfidenceThreshold(),
                    enable_behavioral_analysis: true,
                    enable_ml_detection: true
                }
            });

            return response.data;
        } catch (error) {
            this.handleApiError(error, 'Failed to scan file');
            return null;
        }
    }

    public async scanWorkspace(workspacePath: string, files: string[]): Promise<ScanResult[] | null> {
        try {
            const response: AxiosResponse<ScanResult[]> = await this.client.post('/api/scan/workspace', {
                workspace_path: workspacePath,
                files: files,
                scan_type: 'vscode_workspace',
                options: {
                    confidence_threshold: this.configManager.getConfidenceThreshold(),
                    enable_behavioral_analysis: true,
                    enable_ml_detection: true,
                    recursive: true
                }
            });

            return response.data;
        } catch (error) {
            this.handleApiError(error, 'Failed to scan workspace');
            return null;
        }
    }

    public async getHealthCheck(): Promise<HealthCheck | null> {
        try {
            const response: AxiosResponse<HealthCheck> = await this.client.get('/api/health');
            return response.data;
        } catch (error) {
            this.handleApiError(error, 'Failed to check server health');
            return null;
        }
    }

    public async testConnection(): Promise<boolean> {
        try {
            const health = await this.getHealthCheck();
            return health !== null && health.status === 'healthy';
        } catch (error) {
            return false;
        }
    }

    public async getRecentScans(limit: number = 10): Promise<ScanResult[] | null> {
        try {
            const response: AxiosResponse<ScanResult[]> = await this.client.get(`/api/scans/recent?limit=${limit}`);
            return response.data;
        } catch (error) {
            this.handleApiError(error, 'Failed to fetch recent scans');
            return null;
        }
    }

    public async getPackageInfo(packageName: string, registry: string = 'npm'): Promise<any | null> {
        try {
            const response: AxiosResponse<any> = await this.client.get(`/api/package/${registry}/${packageName}`);
            return response.data;
        } catch (error) {
            this.handleApiError(error, `Failed to fetch package info for ${packageName}`);
            return null;
        }
    }

    public async checkHealth(): Promise<{ status: string }> {
        try {
            const response: AxiosResponse<{ status: string }> = await this.client.get('/health');
            return response.data;
        } catch (error) {
            this.handleApiError(error, 'Failed to check server health');
            return { status: 'unhealthy' };
        }
    }

    public async reportFalsePositive(threat: Threat, filePath: string): Promise<boolean> {
        try {
            await this.client.post('/api/feedback/false-positive', {
                threat: threat,
                file_path: filePath,
                timestamp: new Date().toISOString(),
                source: 'vscode_extension'
            });
            return true;
        } catch (error) {
            this.handleApiError(error, 'Failed to report false positive');
            return false;
        }
    }

    public async submitFeedback(feedback: {
        type: 'bug' | 'feature' | 'improvement';
        description: string;
        severity: 'low' | 'medium' | 'high';
        context?: any;
    }): Promise<boolean> {
        try {
            await this.client.post('/api/feedback', {
                ...feedback,
                timestamp: new Date().toISOString(),
                source: 'vscode_extension',
                version: vscode.extensions.getExtension('typosentinel.typosentinel-vscode')?.packageJSON.version
            });
            return true;
        } catch (error) {
            this.handleApiError(error, 'Failed to submit feedback');
            return false;
        }
    }

    /**
     * New IDE-optimized scan endpoint for real-time dependency analysis
     * Phase 1 implementation of the IDE integration plan
     */
    public async scanDependencies(request: IDEScanRequest): Promise<IDEScanResponse | null> {
        try {
            const response: AxiosResponse<IDEScanResponse> = await this.client.post('/api/v1/scan/ide', {
                ecosystem: request.ecosystem,
                packages: request.packages,
                options: {
                    confidence_threshold: this.configManager.getConfidenceThreshold(),
                    include_remediation: true,
                    include_transitive: false, // Phase 1: direct dependencies only
                    include_license_analysis: false // Phase 3 feature
                }
            });

            return response.data;
        } catch (error) {
            this.handleApiError(error, 'Failed to scan dependencies');
            return null;
        }
    }

    /**
     * Enhanced scan with transitive dependencies and license analysis
     * Phase 3 implementation
     */
    public async scanDependenciesEnhanced(request: IDEScanRequest): Promise<IDEScanResponse | null> {
        try {
            const response: AxiosResponse<IDEScanResponse> = await this.client.post('/api/v1/scan/ide', {
                ecosystem: request.ecosystem,
                packages: request.packages,
                options: {
                    confidence_threshold: this.configManager.getConfidenceThreshold(),
                    include_remediation: true,
                    include_transitive: true,
                    include_license_analysis: true,
                    include_project_health: true
                }
            });

            return response.data;
        } catch (error) {
            this.handleApiError(error, 'Failed to scan dependencies (enhanced)');
            return null;
        }
    }

    private handleApiError(error: any, message: string): void {
        console.error(`TypoSentinel API Error: ${message}`, error);
        
        if (axios.isAxiosError(error)) {
            if (error.response) {
                // Server responded with error status
                const status = error.response.status;
                const data = error.response.data;
                
                switch (status) {
                    case 401:
                        vscode.window.showErrorMessage('TypoSentinel: Invalid API key. Please check your settings.');
                        break;
                    case 403:
                        vscode.window.showErrorMessage('TypoSentinel: Access denied. Please check your permissions.');
                        break;
                    case 429:
                        vscode.window.showWarningMessage('TypoSentinel: Rate limit exceeded. Please try again later.');
                        break;
                    case 500:
                        vscode.window.showErrorMessage('TypoSentinel: Server error. Please try again later.');
                        break;
                    default:
                        vscode.window.showErrorMessage(`TypoSentinel: ${message} (${status})`);
                }
            } else if (error.request) {
                // Network error
                vscode.window.showErrorMessage('TypoSentinel: Cannot connect to server. Please check your network connection and server URL.');
            } else {
                // Other error
                vscode.window.showErrorMessage(`TypoSentinel: ${message}`);
            }
        } else {
            vscode.window.showErrorMessage(`TypoSentinel: ${message}`);
        }
    }

    public getServerUrl(): string {
        return this.configManager.getConfiguration().serverUrl;
    }

    public isConfigured(): boolean {
        const config = this.configManager.getConfiguration();
        return !!(config.serverUrl && config.apiKey);
    }
}