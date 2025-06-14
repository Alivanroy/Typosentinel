import * as vscode from 'vscode';
import axios from 'axios';
import { WebSocket } from 'ws';

/**
 * Game Theory Risk Assessment Provider for VSCode Extension
 * Implements US-013: Game Theory-Based Risk Assessment
 */

export interface GameTheoryConfig {
    enabled: boolean;
    serverUrl: string;
    apiKey: string;
    maxIterations: number;
    convergenceThreshold: number;
    discountFactor: number;
    updateInterval: number;
    penaltyDecayRate: number;
    roiThreshold: number;
    businessMetricsWeight: number;
}

export interface Player {
    id: string;
    type: PlayerType;
    strategies: Strategy[];
    payoffMatrix: number[][];
    currentStrategy: number;
    historicalActions: ActionHistory[];
    riskProfile: RiskProfile;
    businessMetrics: BusinessMetrics;
    penaltyScore: number;
    trustScore: number;
    lastUpdated: Date;
}

export enum PlayerType {
    Defender = 'defender',
    Attacker = 'attacker',
    Supplier = 'supplier',
    Organization = 'organization'
}

export interface Strategy {
    id: string;
    name: string;
    description: string;
    cost: number;
    effectiveness: number;
    riskReduction: number;
}

export interface SecurityGame {
    id: string;
    name: string;
    players: string[];
    payoffMatrices: { [playerId: string]: number[][] };
    gameType: GameType;
    equilibrium?: NashEquilibrium;
    businessContext: BusinessContext;
    createdAt: Date;
    updatedAt: Date;
}

export enum GameType {
    ZeroSum = 'zero_sum',
    NonZeroSum = 'non_zero_sum',
    Cooperative = 'cooperative',
    Evolutionary = 'evolutionary'
}

export interface NashEquilibrium {
    strategies: { [playerId: string]: number[] };
    payoffs: { [playerId: string]: number };
    stability: number;
    converged: boolean;
    iterations: number;
    roi: number;
    riskReduction: number;
    optimalInvestment: number;
    calculatedAt: Date;
}

export interface RiskProfile {
    riskTolerance: number;
    vulnerabilityScore: number;
    threatExposure: number;
    historicalLosses: SecurityIncident[];
    complianceScore: number;
}

export interface BusinessMetrics {
    revenue: number;
    operationalCost: number;
    securityBudget: number;
    downtimeCost: number;
    reputationValue: number;
    customerTrust: number;
    marketShare: number;
}

export interface BusinessContext {
    industry: string;
    marketCondition: string;
    regulatoryEnv: string;
    competitiveness: number;
    growthStage: string;
}

export interface ActionHistory {
    timestamp: Date;
    strategy: number;
    payoff: number;
    outcome: string;
    context: string;
}

export interface SecurityIncident {
    timestamp: Date;
    type: string;
    severity: string;
    impact: number;
    cost: number;
    resolution: string;
}

export interface SupplierRiskAssessment {
    supplierId: string;
    riskScore: number;
    trustLevel: number;
    securityPosture: SecurityPosture;
    complianceStatus: ComplianceStatus;
    historicalRecord: SecurityIncident[];
    gameTheoryScore: number;
    recommendedAction: string;
    lastAssessed: Date;
}

export interface SecurityPosture {
    vulnerabilityManagement: number;
    incidentResponse: number;
    accessControl: number;
    dataProtection: number;
    securityTraining: number;
    thirdPartyRisk: number;
}

export interface ComplianceStatus {
    soc2: boolean;
    iso27001: boolean;
    gdpr: boolean;
    hipaa: boolean;
    pciDss: boolean;
    lastAudit: Date;
    score: number;
}

export interface ROIAnalysis {
    investment: number;
    expectedReturn: number;
    riskReduction: number;
    paybackPeriod: number; // in days
    netPresentValue: number;
    internalRateReturn: number;
    sensitivityAnalysis: { [factor: string]: number };
    recommendation: string;
}

export interface GameTheoryInsight {
    type: 'equilibrium' | 'supplier_risk' | 'roi_optimization' | 'penalty_update';
    title: string;
    description: string;
    severity: 'info' | 'warning' | 'error' | 'critical';
    data: any;
    timestamp: Date;
    actionable: boolean;
    recommendations: string[];
}

export class GameTheoryProvider {
    private config: GameTheoryConfig;
    private apiClient: any;
    private configManager: any;
    private outputChannel: vscode.OutputChannel;
    private statusBarItem: vscode.StatusBarItem;
    private webSocket?: WebSocket;
    private players: Map<string, Player> = new Map();
    private games: Map<string, SecurityGame> = new Map();
    private insights: GameTheoryInsight[] = [];
    private diagnosticCollection: vscode.DiagnosticCollection;

    constructor(apiClient: any, configManager: any) {
        this.apiClient = apiClient;
        this.configManager = configManager;
        this.config = this.loadConfig();
        this.outputChannel = vscode.window.createOutputChannel('TypoSentinel Game Theory');
        this.statusBarItem = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Right, 100);
        this.diagnosticCollection = vscode.languages.createDiagnosticCollection('gametheory');
        
        this.initialize();
    }

    private loadConfig(): GameTheoryConfig {
        const config = this.configManager ? this.configManager.getConfig() : vscode.workspace.getConfiguration('typosentinel');
        return {
            enabled: config.get('gametheory.enabled', true),
            serverUrl: config.get('serverUrl', 'http://localhost:8080'),
            apiKey: config.get('apiKey', ''),
            maxIterations: config.get('gametheory.maxIterations', 1000),
            convergenceThreshold: config.get('gametheory.convergenceThreshold', 0.001),
            discountFactor: config.get('gametheory.discountFactor', 0.95),
            updateInterval: config.get('gametheory.updateInterval', 24 * 60 * 60 * 1000), // 24 hours
            penaltyDecayRate: config.get('gametheory.penaltyDecayRate', 0.1),
            roiThreshold: config.get('gametheory.roiThreshold', 0.15),
            businessMetricsWeight: config.get('gametheory.businessMetricsWeight', 0.3)
        };
    }

    private async initialize(): Promise<void> {
        if (!this.config.enabled) {
            return;
        }

        try {
            // Initialize status bar
            this.statusBarItem.text = '$(shield) Game Theory: Initializing...';
            this.statusBarItem.show();

            // Load initial data
            await this.loadPlayers();
            await this.loadGames();

            // Setup WebSocket connection for real-time updates
            this.setupWebSocket();

            // Register commands
            this.registerCommands();

            // Setup periodic updates
            this.setupPeriodicUpdates();

            this.statusBarItem.text = '$(shield) Game Theory: Active';
            this.outputChannel.appendLine('Game Theory Provider initialized successfully');

        } catch (error) {
            this.statusBarItem.text = '$(shield) Game Theory: Error';
            this.outputChannel.appendLine(`Failed to initialize Game Theory Provider: ${error}`);
        }
    }

    private registerCommands(): void {
        // Calculate Nash Equilibrium
        vscode.commands.registerCommand('typosentinel.gametheory.calculateEquilibrium', async () => {
            await this.calculateNashEquilibrium();
        });

        // Assess Supplier Risk
        vscode.commands.registerCommand('typosentinel.gametheory.assessSupplierRisk', async () => {
            await this.assessSupplierRisk();
        });

        // Optimize ROI
        vscode.commands.registerCommand('typosentinel.gametheory.optimizeROI', async () => {
            await this.optimizeROI();
        });

        // Update Penalty System
        vscode.commands.registerCommand('typosentinel.gametheory.updatePenalty', async () => {
            await this.updatePenaltySystem();
        });

        // Show Game Theory Dashboard
        vscode.commands.registerCommand('typosentinel.gametheory.showDashboard', async () => {
            await this.showGameTheoryDashboard();
        });

        // Add Player
        vscode.commands.registerCommand('typosentinel.gametheory.addPlayer', async () => {
            await this.addPlayer();
        });
    }

    private setupWebSocket(): void {
        if (!this.config.serverUrl) {
            return;
        }

        try {
            const wsUrl = this.config.serverUrl.replace('http', 'ws') + '/ws/gametheory';
            this.webSocket = new WebSocket(wsUrl);

            this.webSocket.on('open', () => {
                this.outputChannel.appendLine('WebSocket connection established');
            });

            this.webSocket.on('message', (data: string) => {
                try {
                    const message = JSON.parse(data);
                    this.handleWebSocketMessage(message);
                } catch (error) {
                    this.outputChannel.appendLine(`Error parsing WebSocket message: ${error}`);
                }
            });

            this.webSocket.on('error', (error) => {
                this.outputChannel.appendLine(`WebSocket error: ${error}`);
            });

            this.webSocket.on('close', () => {
                this.outputChannel.appendLine('WebSocket connection closed');
                // Attempt to reconnect after 5 seconds
                setTimeout(() => this.setupWebSocket(), 5000);
            });

        } catch (error) {
            this.outputChannel.appendLine(`Failed to setup WebSocket: ${error}`);
        }
    }

    private handleWebSocketMessage(message: any): void {
        switch (message.type) {
            case 'equilibrium_update':
                this.handleEquilibriumUpdate(message.data);
                break;
            case 'risk_assessment_update':
                this.handleRiskAssessmentUpdate(message.data);
                break;
            case 'penalty_update':
                this.handlePenaltyUpdate(message.data);
                break;
            case 'insight':
                this.handleInsight(message.data);
                break;
            default:
                this.outputChannel.appendLine(`Unknown message type: ${message.type}`);
        }
    }

    private setupPeriodicUpdates(): void {
        setInterval(async () => {
            if (this.config.enabled) {
                await this.performPeriodicAnalysis();
            }
        }, this.config.updateInterval);
    }

    private async loadPlayers(): Promise<void> {
        try {
            const response = this.apiClient ? 
                await this.apiClient.get('/gametheory/players') :
                await axios.get(`${this.config.serverUrl}/api/gametheory/players`, {
                    headers: { 'Authorization': `Bearer ${this.config.apiKey}` }
                });

            const data = this.apiClient ? response : response.data;
            data.forEach((player: Player) => {
                this.players.set(player.id, player);
            });

            this.outputChannel.appendLine(`Loaded ${this.players.size} players`);
        } catch (error) {
            this.outputChannel.appendLine(`Failed to load players: ${error}`);
        }
    }

    private async loadGames(): Promise<void> {
        try {
            const response = this.apiClient ? 
                await this.apiClient.get('/gametheory/games') :
                await axios.get(`${this.config.serverUrl}/api/gametheory/games`, {
                    headers: { 'Authorization': `Bearer ${this.config.apiKey}` }
                });

            const data = this.apiClient ? response : response.data;
            data.forEach((game: SecurityGame) => {
                this.games.set(game.id, game);
            });

            this.outputChannel.appendLine(`Loaded ${this.games.size} games`);
        } catch (error) {
            this.outputChannel.appendLine(`Failed to load games: ${error}`);
        }
    }

    public async calculateNashEquilibrium(): Promise<void> {
        try {
            const gameId = await this.selectGame();
            if (!gameId) {
                return;
            }

            vscode.window.withProgress({
                location: vscode.ProgressLocation.Notification,
                title: 'Calculating Nash Equilibrium',
                cancellable: false
            }, async (progress) => {
                progress.report({ increment: 0, message: 'Initializing calculation...' });

                const response = await axios.post(
                    `${this.config.serverUrl}/api/gametheory/equilibrium/${gameId}`,
                    {},
                    { headers: { 'Authorization': `Bearer ${this.config.apiKey}` } }
                );

                progress.report({ increment: 100, message: 'Calculation complete' });

                const equilibrium: NashEquilibrium = response.data;
                await this.displayEquilibriumResults(equilibrium);
            });

        } catch (error) {
            vscode.window.showErrorMessage(`Failed to calculate Nash equilibrium: ${error}`);
        }
    }

    public async assessSupplierRisk(): Promise<void> {
        try {
            const supplierId = await this.selectSupplier();
            if (!supplierId) {
                return;
            }

            vscode.window.withProgress({
                location: vscode.ProgressLocation.Notification,
                title: 'Assessing Supplier Risk',
                cancellable: false
            }, async (progress) => {
                progress.report({ increment: 0, message: 'Analyzing supplier data...' });

                const response = await axios.post(
                    `${this.config.serverUrl}/api/gametheory/supplier-risk/${supplierId}`,
                    {},
                    { headers: { 'Authorization': `Bearer ${this.config.apiKey}` } }
                );

                progress.report({ increment: 100, message: 'Assessment complete' });

                const assessment: SupplierRiskAssessment = response.data;
                await this.displaySupplierRiskResults(assessment);
            });

        } catch (error) {
            vscode.window.showErrorMessage(`Failed to assess supplier risk: ${error}`);
        }
    }

    public async optimizeROI(): Promise<void> {
        try {
            const playerId = await this.selectPlayer();
            if (!playerId) {
                return;
            }

            const investmentOptions = await this.getInvestmentOptions();
            if (!investmentOptions || investmentOptions.length === 0) {
                vscode.window.showWarningMessage('No investment options available');
                return;
            }

            vscode.window.withProgress({
                location: vscode.ProgressLocation.Notification,
                title: 'Optimizing ROI',
                cancellable: false
            }, async (progress) => {
                progress.report({ increment: 0, message: 'Analyzing investment options...' });

                const response = await axios.post(
                    `${this.config.serverUrl}/api/gametheory/roi-optimize/${playerId}`,
                    { investmentOptions },
                    { headers: { 'Authorization': `Bearer ${this.config.apiKey}` } }
                );

                progress.report({ increment: 100, message: 'Optimization complete' });

                const analysis: ROIAnalysis = response.data;
                await this.displayROIResults(analysis);
            });

        } catch (error) {
            vscode.window.showErrorMessage(`Failed to optimize ROI: ${error}`);
        }
    }

    public async updatePenaltySystem(): Promise<void> {
        try {
            const playerId = await this.selectPlayer();
            if (!playerId) {
                return;
            }

            const incident = await this.createSecurityIncident();
            if (!incident) {
                return;
            }

            const response = await axios.post(
                `${this.config.serverUrl}/api/gametheory/penalty/${playerId}`,
                { incident },
                { headers: { 'Authorization': `Bearer ${this.config.apiKey}` } }
            );

            const result = response.data;
            vscode.window.showInformationMessage(
                `Penalty system updated. New penalty score: ${result.penaltyScore.toFixed(2)}, Trust score: ${result.trustScore.toFixed(2)}`
            );

        } catch (error) {
            vscode.window.showErrorMessage(`Failed to update penalty system: ${error}`);
        }
    }

    public async addPlayer(): Promise<void> {
        try {
            const playerId = await vscode.window.showInputBox({
                prompt: 'Enter player ID',
                placeHolder: 'e.g., supplier_acme'
            });

            if (!playerId) {
                return;
            }

            const playerType = await vscode.window.showQuickPick([
                { label: 'Organization', value: PlayerType.Organization },
                { label: 'Supplier', value: PlayerType.Supplier },
                { label: 'Defender', value: PlayerType.Defender },
                { label: 'Attacker', value: PlayerType.Attacker }
            ], {
                placeHolder: 'Select player type'
            });

            if (!playerType) {
                return;
            }

            const businessMetrics = await this.collectBusinessMetrics();
            if (!businessMetrics) {
                return;
            }

            const player: Partial<Player> = {
                id: playerId,
                type: playerType.value,
                businessMetrics,
                trustScore: 0.5,
                penaltyScore: 0,
                strategies: [],
                historicalActions: [],
                riskProfile: {
                    riskTolerance: 0.5,
                    vulnerabilityScore: 50,
                    threatExposure: 50,
                    historicalLosses: [],
                    complianceScore: 50
                },
                lastUpdated: new Date()
            };

            const response = await axios.post(
                `${this.config.serverUrl}/api/gametheory/players`,
                player,
                { headers: { 'Authorization': `Bearer ${this.config.apiKey}` } }
            );

            this.players.set(playerId, response.data);
            vscode.window.showInformationMessage(`Player ${playerId} added successfully`);

        } catch (error) {
            vscode.window.showErrorMessage(`Failed to add player: ${error}`);
        }
    }

    public async showGameTheoryDashboard(): Promise<void> {
        const panel = vscode.window.createWebviewPanel(
            'gameTheoryDashboard',
            'Game Theory Dashboard',
            vscode.ViewColumn.One,
            {
                enableScripts: true,
                retainContextWhenHidden: true
            }
        );

        panel.webview.html = this.getGameTheoryDashboardHtml();

        // Handle messages from webview
        panel.webview.onDidReceiveMessage(async (message) => {
            switch (message.command) {
                case 'calculateEquilibrium':
                    await this.calculateNashEquilibrium();
                    break;
                case 'assessSupplierRisk':
                    await this.assessSupplierRisk();
                    break;
                case 'optimizeROI':
                    await this.optimizeROI();
                    break;
                case 'refreshData':
                    await this.refreshDashboardData(panel);
                    break;
            }
        });

        // Send initial data
        await this.refreshDashboardData(panel);
    }

    private async refreshDashboardData(panel: vscode.WebviewPanel): Promise<void> {
        const data = {
            players: Array.from(this.players.values()),
            games: Array.from(this.games.values()),
            insights: this.insights.slice(-10), // Last 10 insights
            config: this.config
        };

        panel.webview.postMessage({
            command: 'updateData',
            data
        });
    }

    private getGameTheoryDashboardHtml(): string {
        return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Game Theory Dashboard</title>
    <style>
        body {
            font-family: var(--vscode-font-family);
            color: var(--vscode-foreground);
            background-color: var(--vscode-editor-background);
            margin: 0;
            padding: 20px;
        }
        .dashboard-container {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 20px;
            max-width: 1200px;
            margin: 0 auto;
        }
        .card {
            background-color: var(--vscode-editor-widget-background);
            border: 1px solid var(--vscode-widget-border);
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 20px;
        }
        .card h3 {
            margin-top: 0;
            color: var(--vscode-textLink-foreground);
        }
        .metric {
            display: flex;
            justify-content: space-between;
            margin: 10px 0;
        }
        .metric-value {
            font-weight: bold;
            color: var(--vscode-textPreformat-foreground);
        }
        .button {
            background-color: var(--vscode-button-background);
            color: var(--vscode-button-foreground);
            border: none;
            padding: 8px 16px;
            border-radius: 4px;
            cursor: pointer;
            margin: 5px;
        }
        .button:hover {
            background-color: var(--vscode-button-hoverBackground);
        }
        .insight {
            border-left: 4px solid var(--vscode-textLink-foreground);
            padding: 10px;
            margin: 10px 0;
            background-color: var(--vscode-editor-background);
        }
        .insight.warning {
            border-left-color: var(--vscode-editorWarning-foreground);
        }
        .insight.error {
            border-left-color: var(--vscode-editorError-foreground);
        }
        .player-list {
            max-height: 300px;
            overflow-y: auto;
        }
        .player-item {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 8px;
            border-bottom: 1px solid var(--vscode-widget-border);
        }
        .trust-score {
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 12px;
        }
        .trust-high { background-color: #28a745; color: white; }
        .trust-medium { background-color: #ffc107; color: black; }
        .trust-low { background-color: #dc3545; color: white; }
    </style>
</head>
<body>
    <h1>Game Theory Risk Assessment Dashboard</h1>
    
    <div class="dashboard-container">
        <div class="card">
            <h3>Quick Actions</h3>
            <button class="button" onclick="calculateEquilibrium()">Calculate Nash Equilibrium</button>
            <button class="button" onclick="assessSupplierRisk()">Assess Supplier Risk</button>
            <button class="button" onclick="optimizeROI()">Optimize ROI</button>
            <button class="button" onclick="refreshData()">Refresh Data</button>
        </div>
        
        <div class="card">
            <h3>System Metrics</h3>
            <div class="metric">
                <span>Total Players:</span>
                <span class="metric-value" id="totalPlayers">-</span>
            </div>
            <div class="metric">
                <span>Active Games:</span>
                <span class="metric-value" id="activeGames">-</span>
            </div>
            <div class="metric">
                <span>Average Trust Score:</span>
                <span class="metric-value" id="avgTrustScore">-</span>
            </div>
            <div class="metric">
                <span>High Risk Suppliers:</span>
                <span class="metric-value" id="highRiskSuppliers">-</span>
            </div>
        </div>
        
        <div class="card">
            <h3>Players</h3>
            <div class="player-list" id="playerList">
                <!-- Players will be populated here -->
            </div>
        </div>
        
        <div class="card">
            <h3>Recent Insights</h3>
            <div id="insightsList">
                <!-- Insights will be populated here -->
            </div>
        </div>
    </div>
    
    <script>
        const vscode = acquireVsCodeApi();
        
        function calculateEquilibrium() {
            vscode.postMessage({ command: 'calculateEquilibrium' });
        }
        
        function assessSupplierRisk() {
            vscode.postMessage({ command: 'assessSupplierRisk' });
        }
        
        function optimizeROI() {
            vscode.postMessage({ command: 'optimizeROI' });
        }
        
        function refreshData() {
            vscode.postMessage({ command: 'refreshData' });
        }
        
        window.addEventListener('message', event => {
            const message = event.data;
            
            if (message.command === 'updateData') {
                updateDashboard(message.data);
            }
        });
        
        function updateDashboard(data) {
            // Update metrics
            document.getElementById('totalPlayers').textContent = data.players.length;
            document.getElementById('activeGames').textContent = data.games.length;
            
            const avgTrust = data.players.reduce((sum, p) => sum + p.trustScore, 0) / data.players.length;
            document.getElementById('avgTrustScore').textContent = avgTrust.toFixed(2);
            
            const highRisk = data.players.filter(p => p.type === 'supplier' && p.trustScore < 0.5).length;
            document.getElementById('highRiskSuppliers').textContent = highRisk;
            
            // Update player list
            const playerList = document.getElementById('playerList');
            playerList.innerHTML = '';
            
            data.players.forEach(player => {
                const playerItem = document.createElement('div');
                playerItem.className = 'player-item';
                
                const trustClass = player.trustScore >= 0.7 ? 'trust-high' : 
                                 player.trustScore >= 0.4 ? 'trust-medium' : 'trust-low';
                
                playerItem.innerHTML = \`<div><strong>\${player.id}</strong><br><small>\${player.type}</small></div><div class="trust-score \${trustClass}">\${(player.trustScore * 100).toFixed(0)}%</div>\`;
                
                playerList.appendChild(playerItem);
            });
            
            // Update insights
            const insightsList = document.getElementById('insightsList');
            insightsList.innerHTML = '';
            
            data.insights.forEach(insight => {
                const insightItem = document.createElement('div');
                insightItem.className = \`insight \${insight.severity}\`;
                insightItem.innerHTML = \`<strong>\${insight.title}</strong><br><small>\${insight.description}</small><br><small>\${new Date(insight.timestamp).toLocaleString()}</small>\`;
                
                insightsList.appendChild(insightItem);
            });
        }
    </script>
</body>
</html>`;
    }

    // Helper methods

    private async selectGame(): Promise<string | undefined> {
        const gameItems = Array.from(this.games.values()).map(game => ({
            label: game.name,
            description: `${game.players.length} players, ${game.gameType}`,
            value: game.id
        }));

        if (gameItems.length === 0) {
            vscode.window.showWarningMessage('No games available');
            return undefined;
        }

        const selected = await vscode.window.showQuickPick(gameItems, {
            placeHolder: 'Select a game for equilibrium calculation'
        });

        return selected?.value;
    }

    private async selectSupplier(): Promise<string | undefined> {
        const suppliers = Array.from(this.players.values())
            .filter(player => player.type === PlayerType.Supplier)
            .map(supplier => ({
                label: supplier.id,
                description: `Trust: ${(supplier.trustScore * 100).toFixed(0)}%, Penalty: ${supplier.penaltyScore.toFixed(1)}`,
                value: supplier.id
            }));

        if (suppliers.length === 0) {
            vscode.window.showWarningMessage('No suppliers available');
            return undefined;
        }

        const selected = await vscode.window.showQuickPick(suppliers, {
            placeHolder: 'Select a supplier for risk assessment'
        });

        return selected?.value;
    }

    private async selectPlayer(): Promise<string | undefined> {
        const playerItems = Array.from(this.players.values()).map(player => ({
            label: player.id,
            description: `${player.type}, Trust: ${(player.trustScore * 100).toFixed(0)}%`,
            value: player.id
        }));

        if (playerItems.length === 0) {
            vscode.window.showWarningMessage('No players available');
            return undefined;
        }

        const selected = await vscode.window.showQuickPick(playerItems, {
            placeHolder: 'Select a player'
        });

        return selected?.value;
    }

    private async getInvestmentOptions(): Promise<Strategy[] | undefined> {
        // For now, return predefined options
        // In production, this could load from configuration or user input
        return [
            {
                id: 'firewall',
                name: 'Next-Gen Firewall',
                description: 'Advanced firewall with threat intelligence',
                cost: 25000,
                effectiveness: 0.7,
                riskReduction: 40
            },
            {
                id: 'siem',
                name: 'SIEM Solution',
                description: 'Security Information and Event Management',
                cost: 50000,
                effectiveness: 0.8,
                riskReduction: 55
            },
            {
                id: 'training',
                name: 'Security Training',
                description: 'Comprehensive security awareness training',
                cost: 10000,
                effectiveness: 0.5,
                riskReduction: 25
            }
        ];
    }

    private async createSecurityIncident(): Promise<SecurityIncident | undefined> {
        const incidentType = await vscode.window.showInputBox({
            prompt: 'Enter incident type',
            placeHolder: 'e.g., data_breach, malware, phishing'
        });

        if (!incidentType) {
            return undefined;
        }

        const severity = await vscode.window.showQuickPick([
            { label: 'Low', value: 'low' },
            { label: 'Medium', value: 'medium' },
            { label: 'High', value: 'high' },
            { label: 'Critical', value: 'critical' }
        ], {
            placeHolder: 'Select incident severity'
        });

        if (!severity) {
            return undefined;
        }

        const impactStr = await vscode.window.showInputBox({
            prompt: 'Enter impact score (0-100)',
            placeHolder: '50'
        });

        const impact = parseFloat(impactStr || '50');

        const costStr = await vscode.window.showInputBox({
            prompt: 'Enter incident cost',
            placeHolder: '10000'
        });

        const cost = parseFloat(costStr || '10000');

        return {
            timestamp: new Date(),
            type: incidentType,
            severity: severity.value,
            impact,
            cost,
            resolution: 'Pending investigation'
        };
    }

    private async collectBusinessMetrics(): Promise<BusinessMetrics | undefined> {
        const revenue = await vscode.window.showInputBox({
            prompt: 'Enter annual revenue',
            placeHolder: '1000000'
        });

        if (!revenue) {
            return undefined;
        }

        const securityBudget = await vscode.window.showInputBox({
            prompt: 'Enter security budget',
            placeHolder: '100000'
        });

        if (!securityBudget) {
            return undefined;
        }

        return {
            revenue: parseFloat(revenue),
            operationalCost: parseFloat(revenue) * 0.5, // Default to 50% of revenue
            securityBudget: parseFloat(securityBudget),
            downtimeCost: parseFloat(revenue) * 0.05, // Default to 5% of revenue
            reputationValue: parseFloat(revenue) * 0.2, // Default to 20% of revenue
            customerTrust: 0.8, // Default trust level
            marketShare: 0.1 // Default market share
        };
    }

    private async displayEquilibriumResults(equilibrium: NashEquilibrium): Promise<void> {
        const message = `Nash Equilibrium Results:
` +
            `Converged: ${equilibrium.converged}
` +
            `Iterations: ${equilibrium.iterations}
` +
            `Stability: ${equilibrium.stability.toFixed(4)}
` +
            `ROI: ${(equilibrium.roi * 100).toFixed(2)}%
` +
            `Risk Reduction: ${equilibrium.riskReduction.toFixed(2)}%
` +
            `Optimal Investment: $${equilibrium.optimalInvestment.toFixed(2)}`;

        vscode.window.showInformationMessage(message, 'View Details').then(selection => {
            if (selection === 'View Details') {
                this.outputChannel.appendLine('=== Nash Equilibrium Results ===');
                this.outputChannel.appendLine(JSON.stringify(equilibrium, null, 2));
                this.outputChannel.show();
            }
        });
    }

    private async displaySupplierRiskResults(assessment: SupplierRiskAssessment): Promise<void> {
        const message = `Supplier Risk Assessment:
` +
            `Risk Score: ${assessment.riskScore.toFixed(2)}/100
` +
            `Game Theory Score: ${assessment.gameTheoryScore.toFixed(2)}/100
` +
            `Trust Level: ${assessment.trustLevel.toFixed(2)}
` +
            `Recommended Action: ${assessment.recommendedAction}`;

        vscode.window.showInformationMessage(message, 'View Details').then(selection => {
            if (selection === 'View Details') {
                this.outputChannel.appendLine('=== Supplier Risk Assessment ===');
                this.outputChannel.appendLine(JSON.stringify(assessment, null, 2));
                this.outputChannel.show();
            }
        });
    }

    private async displayROIResults(analysis: ROIAnalysis): Promise<void> {
        const message = `ROI Analysis Results:
` +
            `Investment: $${analysis.investment.toFixed(2)}
` +
            `Expected Return: $${analysis.expectedReturn.toFixed(2)}
` +
            `IRR: ${(analysis.internalRateReturn * 100).toFixed(2)}%
` +
            `Payback Period: ${(analysis.paybackPeriod / 365).toFixed(1)} years
` +
            `Recommendation: ${analysis.recommendation}`;

        vscode.window.showInformationMessage(message, 'View Details').then(selection => {
            if (selection === 'View Details') {
                this.outputChannel.appendLine('=== ROI Analysis Results ===');
                this.outputChannel.appendLine(JSON.stringify(analysis, null, 2));
                this.outputChannel.show();
            }
        });
    }

    private handleEquilibriumUpdate(data: any): void {
        const insight: GameTheoryInsight = {
            type: 'equilibrium',
            title: 'Nash Equilibrium Updated',
            description: `New equilibrium calculated with ${data.iterations} iterations`,
            severity: data.converged ? 'info' : 'warning',
            data,
            timestamp: new Date(),
            actionable: !data.converged,
            recommendations: data.converged ? [] : ['Consider adjusting strategy parameters']
        };

        this.insights.push(insight);
        this.showInsightNotification(insight);
    }

    private handleRiskAssessmentUpdate(data: any): void {
        const severity = data.riskScore > 80 ? 'critical' : 
                        data.riskScore > 60 ? 'error' : 
                        data.riskScore > 40 ? 'warning' : 'info';

        const insight: GameTheoryInsight = {
            type: 'supplier_risk',
            title: 'Supplier Risk Assessment Updated',
            description: `${data.supplierId} risk score: ${data.riskScore.toFixed(2)}`,
            severity,
            data,
            timestamp: new Date(),
            actionable: data.riskScore > 60,
            recommendations: data.riskScore > 60 ? [data.recommendedAction] : []
        };

        this.insights.push(insight);
        this.showInsightNotification(insight);
    }

    private handlePenaltyUpdate(data: any): void {
        const insight: GameTheoryInsight = {
            type: 'penalty_update',
            title: 'Penalty System Updated',
            description: `${data.playerId} penalty increased to ${data.penaltyScore.toFixed(2)}`,
            severity: data.penaltyScore > 50 ? 'warning' : 'info',
            data,
            timestamp: new Date(),
            actionable: data.penaltyScore > 50,
            recommendations: data.penaltyScore > 50 ? ['Consider enhanced monitoring'] : []
        };

        this.insights.push(insight);
        this.showInsightNotification(insight);
    }

    private handleInsight(data: GameTheoryInsight): void {
        this.insights.push(data);
        this.showInsightNotification(data);
    }

    private showInsightNotification(insight: GameTheoryInsight): void {
        const message = `${insight.title}: ${insight.description}`;

        switch (insight.severity) {
            case 'critical':
            case 'error':
                vscode.window.showErrorMessage(message);
                break;
            case 'warning':
                vscode.window.showWarningMessage(message);
                break;
            default:
                vscode.window.showInformationMessage(message);
        }
    }

    private async performPeriodicAnalysis(): Promise<void> {
        try {
            // Perform periodic risk assessments for all suppliers
            const suppliers = Array.from(this.players.values())
                .filter(player => player.type === PlayerType.Supplier);

            for (const supplier of suppliers) {
                // Check if assessment is due (e.g., every 7 days)
                const daysSinceUpdate = (Date.now() - supplier.lastUpdated.getTime()) / (1000 * 60 * 60 * 24);
                if (daysSinceUpdate >= 7) {
                    try {
                        await axios.post(
                            `${this.config.serverUrl}/api/gametheory/supplier-risk/${supplier.id}`,
                            {},
                            { headers: { 'Authorization': `Bearer ${this.config.apiKey}` } }
                        );
                    } catch (error) {
                        this.outputChannel.appendLine(`Failed to assess ${supplier.id}: ${error}`);
                    }
                }
            }

        } catch (error) {
            this.outputChannel.appendLine(`Error in periodic analysis: ${error}`);
        }
    }

    public dispose(): void {
        this.statusBarItem.dispose();
        this.outputChannel.dispose();
        this.diagnosticCollection.dispose();
        
        if (this.webSocket) {
            this.webSocket.close();
        }
    }
}