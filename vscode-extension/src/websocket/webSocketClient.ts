import * as vscode from 'vscode';
import WebSocket from 'ws';
import { ConfigurationManager } from '../config/configurationManager';
import { DiagnosticsManager } from '../diagnostics/diagnosticsManager';
import { ScanResult } from '../api/apiClient';

export interface WebSocketMessage {
    type: 'scan_result' | 'scan_progress' | 'server_status' | 'error' | 'ping' | 'pong';
    data: any;
    timestamp: string;
    id?: string;
}

export interface ScanProgressData {
    scan_id: string;
    file_path: string;
    progress: number;
    status: 'started' | 'scanning' | 'completed' | 'failed';
    message?: string;
}

export interface ServerStatusData {
    status: 'online' | 'offline' | 'maintenance';
    version: string;
    features: string[];
    load: number;
}

export class WebSocketClient {
    private ws: WebSocket | null = null;
    private configManager: ConfigurationManager;
    private diagnosticsManager: DiagnosticsManager;
    private reconnectAttempts = 0;
    private maxReconnectAttempts = 5;
    private reconnectDelay = 1000;
    private heartbeatInterval: NodeJS.Timeout | null = null;
    private isConnecting = false;
    private statusBarItem: vscode.StatusBarItem;

    constructor(configManager: ConfigurationManager, diagnosticsManager: DiagnosticsManager) {
        this.configManager = configManager;
        this.diagnosticsManager = diagnosticsManager;
        this.statusBarItem = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Right, 100);
        this.statusBarItem.command = 'typosentinel.openSettings';
        this.updateStatusBar('disconnected');
        this.statusBarItem.show();
    }

    public async connect(): Promise<void> {
        if (this.isConnecting || (this.ws && this.ws.readyState === WebSocket.OPEN)) {
            return;
        }

        const config = this.configManager.getConfiguration();
        if (!config.serverUrl || !config.apiKey) {
            console.log('WebSocket connection skipped: missing configuration');
            this.updateStatusBar('not_configured');
            return;
        }

        this.isConnecting = true;
        this.updateStatusBar('connecting');

        try {
            const wsUrl = this.getWebSocketUrl(config.serverUrl);
            console.log(`Connecting to WebSocket: ${wsUrl}`);

            this.ws = new WebSocket(wsUrl, {
                headers: {
                    'Authorization': `Bearer ${config.apiKey}`,
                    'User-Agent': 'TypoSentinel-VSCode/1.0.0'
                },
                handshakeTimeout: 10000
            });

            this.setupEventHandlers();
        } catch (error) {
            console.error('WebSocket connection error:', error);
            this.handleConnectionError();
        }
    }

    private getWebSocketUrl(serverUrl: string): string {
        const url = new URL(serverUrl);
        url.protocol = url.protocol === 'https:' ? 'wss:' : 'ws:';
        url.pathname = '/ws/vscode';
        return url.toString();
    }

    private setupEventHandlers(): void {
        if (!this.ws) return;

        this.ws.on('open', () => {
            console.log('WebSocket connected');
            this.isConnecting = false;
            this.reconnectAttempts = 0;
            this.updateStatusBar('connected');
            this.startHeartbeat();
            
            // Send initial connection message
            this.send({
                type: 'ping',
                data: { client: 'vscode', version: '1.0.0' },
                timestamp: new Date().toISOString()
            });
        });

        this.ws.on('message', (data: WebSocket.Data) => {
            try {
                const message: WebSocketMessage = JSON.parse(data.toString());
                this.handleMessage(message);
            } catch (error) {
                console.error('Error parsing WebSocket message:', error);
            }
        });

        this.ws.on('close', (code: number, reason: string) => {
            console.log(`WebSocket closed: ${code} - ${reason}`);
            this.isConnecting = false;
            this.updateStatusBar('disconnected');
            this.stopHeartbeat();
            this.scheduleReconnect();
        });

        this.ws.on('error', (error: Error) => {
            console.error('WebSocket error:', error);
            this.handleConnectionError();
        });
    }

    private handleMessage(message: WebSocketMessage): void {
        switch (message.type) {
            case 'scan_result':
                this.handleScanResult(message.data as ScanResult);
                break;
            case 'scan_progress':
                this.handleScanProgress(message.data as ScanProgressData);
                break;
            case 'server_status':
                this.handleServerStatus(message.data as ServerStatusData);
                break;
            case 'error':
                this.handleError(message.data);
                break;
            case 'pong':
                // Heartbeat response
                break;
            default:
                console.log('Unknown WebSocket message type:', message.type);
        }
    }

    private handleScanResult(scanResult: ScanResult): void {
        try {
            const uri = vscode.Uri.file(scanResult.file_path);
            this.diagnosticsManager.updateDiagnostics(uri, scanResult);
            
            if (scanResult.threats && scanResult.threats.length > 0) {
                const threatCount = scanResult.threats.length;
                if (this.configManager.getEnableNotifications()) {
                    vscode.window.showWarningMessage(
                        `TypoSentinel found ${threatCount} threat${threatCount > 1 ? 's' : ''} in ${scanResult.file_path}`,
                        'View Details'
                    ).then(selection => {
                        if (selection === 'View Details') {
                            vscode.commands.executeCommand('typosentinel.viewReport');
                        }
                    });
                }
            }
        } catch (error) {
            console.error('Error handling scan result:', error);
        }
    }

    private handleScanProgress(progressData: ScanProgressData): void {
        // Update progress in status bar or progress notification
        const message = progressData.message || `Scanning ${progressData.file_path}`;
        
        if (progressData.status === 'started') {
            this.updateStatusBar('scanning');
        } else if (progressData.status === 'completed') {
            this.updateStatusBar('connected');
        } else if (progressData.status === 'failed') {
            this.updateStatusBar('error');
            if (this.configManager.getEnableNotifications()) {
                vscode.window.showErrorMessage(`Scan failed: ${progressData.message}`);
            }
        }
    }

    private handleServerStatus(statusData: ServerStatusData): void {
        if (statusData.status === 'maintenance') {
            this.updateStatusBar('maintenance');
            if (this.configManager.getEnableNotifications()) {
                vscode.window.showWarningMessage('TypoSentinel server is under maintenance');
            }
        } else if (statusData.status === 'offline') {
            this.updateStatusBar('disconnected');
        }
    }

    private handleError(errorData: any): void {
        console.error('WebSocket error message:', errorData);
        if (this.configManager.getEnableNotifications()) {
            vscode.window.showErrorMessage(`TypoSentinel: ${errorData.message || 'Unknown error'}`);
        }
    }

    private startHeartbeat(): void {
        this.stopHeartbeat();
        this.heartbeatInterval = setInterval(() => {
            if (this.ws && this.ws.readyState === WebSocket.OPEN) {
                this.send({
                    type: 'ping',
                    data: {},
                    timestamp: new Date().toISOString()
                });
            }
        }, 30000); // 30 seconds
    }

    private stopHeartbeat(): void {
        if (this.heartbeatInterval) {
            clearInterval(this.heartbeatInterval);
            this.heartbeatInterval = null;
        }
    }

    private scheduleReconnect(): void {
        if (this.reconnectAttempts >= this.maxReconnectAttempts) {
            console.log('Max reconnection attempts reached');
            this.updateStatusBar('failed');
            return;
        }

        const delay = this.reconnectDelay * Math.pow(2, this.reconnectAttempts);
        this.reconnectAttempts++;
        
        console.log(`Scheduling reconnection attempt ${this.reconnectAttempts} in ${delay}ms`);
        
        setTimeout(() => {
            if (!this.ws || this.ws.readyState !== WebSocket.OPEN) {
                this.connect();
            }
        }, delay);
    }

    private handleConnectionError(): void {
        this.isConnecting = false;
        this.updateStatusBar('error');
        this.scheduleReconnect();
    }

    private updateStatusBar(status: string): void {
        switch (status) {
            case 'connected':
                this.statusBarItem.text = '$(shield) TypoSentinel';
                this.statusBarItem.tooltip = 'TypoSentinel: Connected';
                this.statusBarItem.backgroundColor = undefined;
                break;
            case 'connecting':
                this.statusBarItem.text = '$(sync~spin) TypoSentinel';
                this.statusBarItem.tooltip = 'TypoSentinel: Connecting...';
                this.statusBarItem.backgroundColor = undefined;
                break;
            case 'disconnected':
                this.statusBarItem.text = '$(shield) TypoSentinel';
                this.statusBarItem.tooltip = 'TypoSentinel: Disconnected';
                this.statusBarItem.backgroundColor = new vscode.ThemeColor('statusBarItem.warningBackground');
                break;
            case 'scanning':
                this.statusBarItem.text = '$(search~spin) TypoSentinel';
                this.statusBarItem.tooltip = 'TypoSentinel: Scanning...';
                this.statusBarItem.backgroundColor = undefined;
                break;
            case 'error':
                this.statusBarItem.text = '$(error) TypoSentinel';
                this.statusBarItem.tooltip = 'TypoSentinel: Connection Error';
                this.statusBarItem.backgroundColor = new vscode.ThemeColor('statusBarItem.errorBackground');
                break;
            case 'maintenance':
                this.statusBarItem.text = '$(tools) TypoSentinel';
                this.statusBarItem.tooltip = 'TypoSentinel: Server Maintenance';
                this.statusBarItem.backgroundColor = new vscode.ThemeColor('statusBarItem.warningBackground');
                break;
            case 'not_configured':
                this.statusBarItem.text = '$(gear) TypoSentinel';
                this.statusBarItem.tooltip = 'TypoSentinel: Not Configured - Click to configure';
                this.statusBarItem.backgroundColor = new vscode.ThemeColor('statusBarItem.warningBackground');
                break;
            case 'failed':
                this.statusBarItem.text = '$(x) TypoSentinel';
                this.statusBarItem.tooltip = 'TypoSentinel: Connection Failed';
                this.statusBarItem.backgroundColor = new vscode.ThemeColor('statusBarItem.errorBackground');
                break;
        }
    }

    public send(message: WebSocketMessage): void {
        if (this.ws && this.ws.readyState === WebSocket.OPEN) {
            try {
                this.ws.send(JSON.stringify(message));
            } catch (error) {
                console.error('Error sending WebSocket message:', error);
            }
        }
    }

    public disconnect(): void {
        this.stopHeartbeat();
        if (this.ws) {
            this.ws.close(1000, 'Extension deactivated');
            this.ws = null;
        }
        this.updateStatusBar('disconnected');
    }

    public reconnect(): void {
        this.disconnect();
        this.reconnectAttempts = 0;
        setTimeout(() => this.connect(), 1000);
    }

    public isConnected(): boolean {
        return this.ws !== null && this.ws.readyState === WebSocket.OPEN;
    }

    public getConnectionStatus(): string {
        if (!this.ws) return 'disconnected';
        
        switch (this.ws.readyState) {
            case WebSocket.CONNECTING:
                return 'connecting';
            case WebSocket.OPEN:
                return 'connected';
            case WebSocket.CLOSING:
                return 'disconnecting';
            case WebSocket.CLOSED:
                return 'disconnected';
            default:
                return 'unknown';
        }
    }

    public dispose(): void {
        this.disconnect();
        this.statusBarItem.dispose();
    }
}