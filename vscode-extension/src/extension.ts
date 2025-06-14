import * as vscode from 'vscode';
import { TypoSentinelProvider } from './providers/typoSentinelProvider';
import { DiagnosticsManager } from './diagnostics/diagnosticsManager';
import { ApiClient } from './api/apiClient';
import { ConfigurationManager } from './config/configurationManager';
import { WebSocketClient } from './websocket/webSocketClient';
import { SecurityReportProvider } from './providers/securityReportProvider';
import { IDEProvider } from './providers/ideProvider';
import { GameTheoryProvider } from './providers/gameTheoryProvider';

let diagnosticsManager: DiagnosticsManager;
let apiClient: ApiClient;
let configManager: ConfigurationManager;
let webSocketClient: WebSocketClient;
let typoSentinelProvider: TypoSentinelProvider;
let securityReportProvider: SecurityReportProvider;
let ideProvider: IDEProvider;
let gameTheoryProvider: GameTheoryProvider;

export function activate(context: vscode.ExtensionContext) {
    console.log('TypoSentinel extension is now active!');

    // Initialize managers and providers
    configManager = new ConfigurationManager();
    apiClient = new ApiClient(configManager);
    diagnosticsManager = new DiagnosticsManager();
    webSocketClient = new WebSocketClient(configManager, diagnosticsManager);
    typoSentinelProvider = new TypoSentinelProvider(apiClient, diagnosticsManager);
    securityReportProvider = new SecurityReportProvider(apiClient);
    
    // Initialize IDE Provider for Phase 1 features
    ideProvider = new IDEProvider(apiClient, configManager);
    ideProvider.initialize();
    
    // Initialize Game Theory Provider
    gameTheoryProvider = new GameTheoryProvider(apiClient, configManager);

    // Register commands
    const scanWorkspaceCommand = vscode.commands.registerCommand('typosentinel.scanWorkspace', async () => {
        await scanWorkspace();
    });

    const scanFileCommand = vscode.commands.registerCommand('typosentinel.scanFile', async (uri?: vscode.Uri) => {
        await scanFile(uri);
    });

    const openSettingsCommand = vscode.commands.registerCommand('typosentinel.openSettings', () => {
        vscode.commands.executeCommand('workbench.action.openSettings', 'typosentinel');
    });

    const viewReportCommand = vscode.commands.registerCommand('typosentinel.viewReport', async () => {
        await showSecurityReport();
    });

    // IDE-specific commands for Phase 1 features
    const scanDependenciesCommand = vscode.commands.registerCommand('typosentinel.scanDependencies', async () => {
        await ideProvider.scanAllOpenManifests();
        vscode.window.showInformationMessage('TypoSentinel: Dependency scan completed');
    });

    const clearDiagnosticsCommand = vscode.commands.registerCommand('typosentinel.clearDiagnostics', () => {
        ideProvider.clearDiagnostics();
        vscode.window.showInformationMessage('TypoSentinel: Diagnostics cleared');
    });

    // Game Theory commands
    const calculateEquilibriumCommand = vscode.commands.registerCommand('typosentinel.gametheory.calculateEquilibrium', () => {
        gameTheoryProvider.calculateNashEquilibrium();
    });

    const assessSupplierRiskCommand = vscode.commands.registerCommand('typosentinel.gametheory.assessSupplierRisk', () => {
        gameTheoryProvider.assessSupplierRisk();
    });

    const optimizeROICommand = vscode.commands.registerCommand('typosentinel.gametheory.optimizeROI', () => {
        gameTheoryProvider.optimizeROI();
    });

    const updatePenaltyCommand = vscode.commands.registerCommand('typosentinel.gametheory.updatePenalty', () => {
        gameTheoryProvider.updatePenaltySystem();
    });

    const showDashboardCommand = vscode.commands.registerCommand('typosentinel.gametheory.showDashboard', async () => {
        await gameTheoryProvider.showGameTheoryDashboard();
    });

    const addPlayerCommand = vscode.commands.registerCommand('typosentinel.gametheory.addPlayer', () => {
        gameTheoryProvider.addPlayer();
    });

    // Register providers
    const treeDataProvider = vscode.window.registerTreeDataProvider('typosentinelView', typoSentinelProvider);

    // Register event listeners
    const onDidSaveDocument = vscode.workspace.onDidSaveTextDocument(async (document) => {
        if (configManager.getScanOnSave() && isRelevantFile(document)) {
            await scanDocument(document);
        }
    });

    const onDidChangeTextDocument = vscode.workspace.onDidChangeTextDocument(async (event) => {
        if (configManager.getRealTimeScanning() && isRelevantFile(event.document)) {
            // Debounce real-time scanning
            debounceRealTimeScan(event.document);
        }
    });

    const onDidChangeConfiguration = vscode.workspace.onDidChangeConfiguration((event) => {
        if (event.affectsConfiguration('typosentinel')) {
            configManager.refresh();
            apiClient.updateConfiguration();
            webSocketClient.reconnect();
        }
    });

    // Add to subscriptions
    context.subscriptions.push(
        scanWorkspaceCommand,
        scanFileCommand,
        openSettingsCommand,
        viewReportCommand,
        scanDependenciesCommand,
        clearDiagnosticsCommand,
        calculateEquilibriumCommand,
        assessSupplierRiskCommand,
        optimizeROICommand,
        updatePenaltyCommand,
        showDashboardCommand,
        addPlayerCommand,
        treeDataProvider,
        onDidSaveDocument,
        onDidChangeTextDocument,
        onDidChangeConfiguration,
        diagnosticsManager.getDiagnosticCollection(),
        ideProvider,
        gameTheoryProvider
    );

    // Initialize WebSocket connection
    webSocketClient.connect();

    // Show welcome message on first activation
    if (context.globalState.get('typosentinel.firstActivation', true)) {
        showWelcomeMessage();
        context.globalState.update('typosentinel.firstActivation', false);
    }

    // Auto-scan workspace if enabled
    if (configManager.getAutoScanWorkspace()) {
        setTimeout(() => scanWorkspace(), 2000);
    }
}

export function deactivate() {
    if (webSocketClient) {
        webSocketClient.disconnect();
    }
    if (gameTheoryProvider) {
        gameTheoryProvider.dispose();
    }
    console.log('TypoSentinel extension deactivated');
}

let realTimeScanTimeout: NodeJS.Timeout | undefined;

function debounceRealTimeScan(document: vscode.TextDocument) {
    if (realTimeScanTimeout) {
        clearTimeout(realTimeScanTimeout);
    }
    
    realTimeScanTimeout = setTimeout(async () => {
        await scanDocument(document);
    }, 1000); // 1 second debounce
}

async function scanWorkspace() {
    const workspaceFolders = vscode.workspace.workspaceFolders;
    if (!workspaceFolders) {
        vscode.window.showWarningMessage('No workspace folder found');
        return;
    }

    vscode.window.withProgress({
        location: vscode.ProgressLocation.Notification,
        title: 'TypoSentinel: Scanning workspace...',
        cancellable: true
    }, async (progress, token) => {
        try {
            const packageFiles = await findPackageFiles();
            const total = packageFiles.length;
            
            for (let i = 0; i < packageFiles.length; i++) {
                if (token.isCancellationRequested) {
                    break;
                }
                
                const file = packageFiles[i];
                progress.report({ 
                    increment: (100 / total),
                    message: `Scanning ${file.fsPath}...` 
                });
                
                const document = await vscode.workspace.openTextDocument(file);
                await scanDocument(document, false);
            }
            
            typoSentinelProvider.refresh();
            vscode.window.showInformationMessage(`TypoSentinel: Scanned ${total} files`);
        } catch (error) {
            vscode.window.showErrorMessage(`TypoSentinel scan failed: ${error}`);
        }
    });
}

async function scanFile(uri?: vscode.Uri) {
    let document: vscode.TextDocument;
    
    if (uri) {
        document = await vscode.workspace.openTextDocument(uri);
    } else {
        const activeEditor = vscode.window.activeTextEditor;
        if (!activeEditor) {
            vscode.window.showWarningMessage('No active file to scan');
            return;
        }
        document = activeEditor.document;
    }
    
    if (!isRelevantFile(document)) {
        vscode.window.showWarningMessage('File type not supported for scanning');
        return;
    }
    
    await scanDocument(document);
}

async function scanDocument(document: vscode.TextDocument, showProgress = true) {
    try {
        if (showProgress) {
            vscode.window.withProgress({
                location: vscode.ProgressLocation.Window,
                title: 'TypoSentinel: Scanning...'
            }, async () => {
                await performScan(document);
            });
        } else {
            await performScan(document);
        }
    } catch (error) {
        console.error('Scan error:', error);
        vscode.window.showErrorMessage(`TypoSentinel scan failed: ${error}`);
    }
}

async function performScan(document: vscode.TextDocument) {
    const scanResult = await apiClient.scanFile(document.uri.fsPath, document.getText());
    
    if (scanResult) {
        diagnosticsManager.updateDiagnostics(document.uri, scanResult);
        typoSentinelProvider.refresh();
        
        if (scanResult.threats && scanResult.threats.length > 0) {
            const threatCount = scanResult.threats.length;
            vscode.window.showWarningMessage(
                `TypoSentinel found ${threatCount} potential threat${threatCount > 1 ? 's' : ''} in ${document.fileName}`,
                'View Details'
            ).then(selection => {
                if (selection === 'View Details') {
                    showSecurityReport();
                }
            });
        }
    }
}

function isRelevantFile(document: vscode.TextDocument): boolean {
    const fileName = document.fileName.toLowerCase();
    const relevantFiles = [
        'package.json',
        'requirements.txt',
        'go.mod',
        'composer.json',
        'cargo.toml'
    ];
    
    return relevantFiles.some(file => fileName.endsWith(file)) ||
           document.languageId === 'json' ||
           document.languageId === 'javascript' ||
           document.languageId === 'typescript';
}

async function findPackageFiles(): Promise<vscode.Uri[]> {
    const patterns = [
        '**/package.json',
        '**/requirements.txt',
        '**/go.mod',
        '**/composer.json',
        '**/Cargo.toml'
    ];
    
    const files: vscode.Uri[] = [];
    
    for (const pattern of patterns) {
        const found = await vscode.workspace.findFiles(pattern, '**/node_modules/**');
        files.push(...found);
    }
    
    return files;
}

async function showSecurityReport() {
    const panel = vscode.window.createWebviewPanel(
        'typosentinelReport',
        'TypoSentinel Security Report',
        vscode.ViewColumn.One,
        {
            enableScripts: true,
            retainContextWhenHidden: true
        }
    );
    
    const reportData = await securityReportProvider.generateReport();
    panel.webview.html = securityReportProvider.getWebviewContent(reportData);
}

function showWelcomeMessage() {
    vscode.window.showInformationMessage(
        'Welcome to TypoSentinel! Configure your API settings to get started.',
        'Open Settings',
        'Scan Workspace'
    ).then(selection => {
        switch (selection) {
            case 'Open Settings':
                vscode.commands.executeCommand('typosentinel.openSettings');
                break;
            case 'Scan Workspace':
                vscode.commands.executeCommand('typosentinel.scanWorkspace');
                break;
        }
    });
}