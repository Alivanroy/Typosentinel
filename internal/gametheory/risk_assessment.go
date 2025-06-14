package gametheory

import (
	"context"
	"fmt"
	"math"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

// GameTheoryRiskAssessment implements mathematical risk assessment using game theory models
type GameTheoryRiskAssessment struct {
	config     *GameTheoryConfig
	players    map[string]*Player
	games      map[string]*SecurityGame
	equilibria map[string]*NashEquilibrium
	mu         sync.RWMutex
	logger     *logrus.Logger
}

// GameTheoryConfig contains configuration for game theory analysis
type GameTheoryConfig struct {
	Enabled                bool          `yaml:"enabled"`
	MaxIterations         int           `yaml:"max_iterations"`
	ConvergenceThreshold  float64       `yaml:"convergence_threshold"`
	DiscountFactor        float64       `yaml:"discount_factor"`
	UpdateInterval        time.Duration `yaml:"update_interval"`
	PenaltyDecayRate      float64       `yaml:"penalty_decay_rate"`
	ROIThreshold          float64       `yaml:"roi_threshold"`
	BusinessMetricsWeight float64       `yaml:"business_metrics_weight"`
}

// Player represents a participant in the security game
type Player struct {
	ID                string                 `json:"id"`
	Type              PlayerType             `json:"type"`
	Strategies        []Strategy             `json:"strategies"`
	PayoffMatrix      [][]float64            `json:"payoff_matrix"`
	CurrentStrategy   int                    `json:"current_strategy"`
	HistoricalActions []ActionHistory        `json:"historical_actions"`
	RiskProfile       RiskProfile            `json:"risk_profile"`
	BusinessMetrics   BusinessMetrics        `json:"business_metrics"`
	PenaltyScore      float64                `json:"penalty_score"`
	TrustScore        float64                `json:"trust_score"`
	LastUpdated       time.Time              `json:"last_updated"`
}

// PlayerType defines the type of player in the game
type PlayerType string

const (
	PlayerTypeDefender    PlayerType = "defender"
	PlayerTypeAttacker    PlayerType = "attacker"
	PlayerTypeSupplier    PlayerType = "supplier"
	PlayerTypeOrganization PlayerType = "organization"
)

// Strategy represents a possible action in the security game
type Strategy struct {
	ID          string  `json:"id"`
	Name        string  `json:"name"`
	Description string  `json:"description"`
	Cost        float64 `json:"cost"`
	Effectiveness float64 `json:"effectiveness"`
	RiskReduction float64 `json:"risk_reduction"`
}

// SecurityGame represents a security investment game
type SecurityGame struct {
	ID              string                    `json:"id"`
	Name            string                    `json:"name"`
	Players         []string                  `json:"players"`
	PayoffMatrices  map[string][][]float64    `json:"payoff_matrices"`
	GameType        GameType                  `json:"game_type"`
	Equilibrium     *NashEquilibrium          `json:"equilibrium"`
	BusinessContext BusinessContext           `json:"business_context"`
	CreatedAt       time.Time                 `json:"created_at"`
	UpdatedAt       time.Time                 `json:"updated_at"`
}

// GameType defines the type of security game
type GameType string

const (
	GameTypeZeroSum     GameType = "zero_sum"
	GameTypeNonZeroSum  GameType = "non_zero_sum"
	GameTypeCooperative GameType = "cooperative"
	GameTypeEvolutionary GameType = "evolutionary"
)

// NashEquilibrium represents a Nash equilibrium solution
type NashEquilibrium struct {
	Strategies      map[string][]float64 `json:"strategies"`
	Payoffs         map[string]float64   `json:"payoffs"`
	Stability       float64              `json:"stability"`
	Converged       bool                 `json:"converged"`
	Iterations      int                  `json:"iterations"`
	ROI             float64              `json:"roi"`
	RiskReduction   float64              `json:"risk_reduction"`
	OptimalInvestment float64            `json:"optimal_investment"`
	CalculatedAt    time.Time            `json:"calculated_at"`
}

// RiskProfile contains risk assessment data for a player
type RiskProfile struct {
	RiskTolerance     float64            `json:"risk_tolerance"`
	VulnerabilityScore float64           `json:"vulnerability_score"`
	ThreatExposure    float64            `json:"threat_exposure"`
	HistoricalLosses  []SecurityIncident `json:"historical_losses"`
	ComplianceScore   float64            `json:"compliance_score"`
}

// BusinessMetrics contains business-related metrics
type BusinessMetrics struct {
	Revenue           float64 `json:"revenue"`
	OperationalCost   float64 `json:"operational_cost"`
	SecurityBudget    float64 `json:"security_budget"`
	DowntimeCost      float64 `json:"downtime_cost"`
	ReputationValue   float64 `json:"reputation_value"`
	CustomerTrust     float64 `json:"customer_trust"`
	MarketShare       float64 `json:"market_share"`
}

// BusinessContext provides context for business decisions
type BusinessContext struct {
	Industry        string  `json:"industry"`
	MarketCondition string  `json:"market_condition"`
	RegulatoryEnv   string  `json:"regulatory_env"`
	Competitiveness float64 `json:"competitiveness"`
	GrowthStage     string  `json:"growth_stage"`
}

// ActionHistory tracks historical actions of players
type ActionHistory struct {
	Timestamp   time.Time `json:"timestamp"`
	Strategy    int       `json:"strategy"`
	Payoff      float64   `json:"payoff"`
	Outcome     string    `json:"outcome"`
	Context     string    `json:"context"`
}

// SecurityIncident represents a security incident
type SecurityIncident struct {
	Timestamp   time.Time `json:"timestamp"`
	Type        string    `json:"type"`
	Severity    string    `json:"severity"`
	Impact      float64   `json:"impact"`
	Cost        float64   `json:"cost"`
	Resolution  string    `json:"resolution"`
}

// SupplierRiskAssessment contains supplier-specific risk data
type SupplierRiskAssessment struct {
	SupplierID        string             `json:"supplier_id"`
	RiskScore         float64            `json:"risk_score"`
	TrustLevel        float64            `json:"trust_level"`
	SecurityPosture   SecurityPosture    `json:"security_posture"`
	ComplianceStatus  ComplianceStatus   `json:"compliance_status"`
	HistoricalRecord  []SecurityIncident `json:"historical_record"`
	GameTheoryScore   float64            `json:"game_theory_score"`
	RecommendedAction string             `json:"recommended_action"`
	LastAssessed      time.Time          `json:"last_assessed"`
}

// SecurityPosture represents security posture metrics
type SecurityPosture struct {
	VulnerabilityManagement float64 `json:"vulnerability_management"`
	IncidentResponse        float64 `json:"incident_response"`
	AccessControl           float64 `json:"access_control"`
	DataProtection          float64 `json:"data_protection"`
	SecurityTraining        float64 `json:"security_training"`
	ThirdPartyRisk          float64 `json:"third_party_risk"`
}

// ComplianceStatus represents compliance status
type ComplianceStatus struct {
	SOC2        bool      `json:"soc2"`
	ISO27001    bool      `json:"iso27001"`
	GDPR        bool      `json:"gdpr"`
	HIPAA       bool      `json:"hipaa"`
	PCIDSS      bool      `json:"pci_dss"`
	LastAudit   time.Time `json:"last_audit"`
	Score       float64   `json:"score"`
}

// ROIAnalysis contains return on investment analysis
type ROIAnalysis struct {
	Investment        float64           `json:"investment"`
	ExpectedReturn    float64           `json:"expected_return"`
	RiskReduction     float64           `json:"risk_reduction"`
	PaybackPeriod     time.Duration     `json:"payback_period"`
	NetPresentValue   float64           `json:"net_present_value"`
	InternalRateReturn float64          `json:"internal_rate_return"`
	SensitivityAnalysis map[string]float64 `json:"sensitivity_analysis"`
	Recommendation    string            `json:"recommendation"`
}

// NewGameTheoryRiskAssessment creates a new game theory risk assessment instance
func NewGameTheoryRiskAssessment(config *GameTheoryConfig, logger *logrus.Logger) *GameTheoryRiskAssessment {
	return &GameTheoryRiskAssessment{
		config:     config,
		players:    make(map[string]*Player),
		games:      make(map[string]*SecurityGame),
		equilibria: make(map[string]*NashEquilibrium),
		logger:     logger,
	}
}

// CalculateNashEquilibrium calculates Nash equilibrium for security investments
func (gtra *GameTheoryRiskAssessment) CalculateNashEquilibrium(ctx context.Context, gameID string) (*NashEquilibrium, error) {
	gtra.mu.RLock()
	game, exists := gtra.games[gameID]
	gtra.mu.RUnlock()
	
	if !exists {
		return nil, fmt.Errorf("game %s not found", gameID)
	}

	// Initialize mixed strategies for all players
	strategies := make(map[string][]float64)
	for _, playerID := range game.Players {
		player := gtra.players[playerID]
		numStrategies := len(player.Strategies)
		// Start with uniform distribution
		strategy := make([]float64, numStrategies)
		for i := range strategy {
			strategy[i] = 1.0 / float64(numStrategies)
		}
		strategies[playerID] = strategy
	}

	// Iterative best response algorithm
	var equilibrium *NashEquilibrium
	for iteration := 0; iteration < gtra.config.MaxIterations; iteration++ {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		converged := true
		newStrategies := make(map[string][]float64)

		for _, playerID := range game.Players {
			bestResponse := gtra.calculateBestResponse(playerID, strategies, game)
			newStrategies[playerID] = bestResponse

			// Check convergence
			if !gtra.hasConverged(strategies[playerID], bestResponse) {
				converged = false
			}
		}

		strategies = newStrategies

		if converged {
			equilibrium = &NashEquilibrium{
				Strategies:    strategies,
				Payoffs:       gtra.calculatePayoffs(strategies, game),
				Stability:     gtra.calculateStability(strategies, game),
				Converged:     true,
				Iterations:    iteration + 1,
				CalculatedAt:  time.Now(),
			}
			break
		}
	}

	if equilibrium == nil {
		// Return best approximation if not converged
		equilibrium = &NashEquilibrium{
			Strategies:   strategies,
			Payoffs:      gtra.calculatePayoffs(strategies, game),
			Stability:    gtra.calculateStability(strategies, game),
			Converged:    false,
			Iterations:   gtra.config.MaxIterations,
			CalculatedAt: time.Now(),
		}
	}

	// Calculate ROI and risk reduction
	equilibrium.ROI = gtra.calculateROI(equilibrium, game)
	equilibrium.RiskReduction = gtra.calculateRiskReduction(equilibrium, game)
	equilibrium.OptimalInvestment = gtra.calculateOptimalInvestment(equilibrium, game)

	// Store equilibrium
	gtra.mu.Lock()
	gtra.equilibria[gameID] = equilibrium
	game.Equilibrium = equilibrium
	game.UpdatedAt = time.Now()
	gtra.mu.Unlock()

	return equilibrium, nil
}

// AssessSupplierRisk performs game theory-based supplier risk assessment
func (gtra *GameTheoryRiskAssessment) AssessSupplierRisk(ctx context.Context, supplierID string) (*SupplierRiskAssessment, error) {
	gtra.mu.RLock()
	supplier, exists := gtra.players[supplierID]
	gtra.mu.RUnlock()

	if !exists {
		return nil, fmt.Errorf("supplier %s not found", supplierID)
	}

	// Create supplier-specific game
	gameID := fmt.Sprintf("supplier_risk_%s", supplierID)
	game := &SecurityGame{
		ID:       gameID,
		Name:     fmt.Sprintf("Supplier Risk Game - %s", supplierID),
		Players:  []string{"organization", supplierID},
		GameType: GameTypeNonZeroSum,
		CreatedAt: time.Now(),
	}

	// Build payoff matrices based on supplier's security posture
	game.PayoffMatrices = gtra.buildSupplierPayoffMatrices(supplier)

	// Store game
	gtra.mu.Lock()
	gtra.games[gameID] = game
	gtra.mu.Unlock()

	// Calculate equilibrium
	equilibrium, err := gtra.CalculateNashEquilibrium(ctx, gameID)
	if err != nil {
		return nil, fmt.Errorf("failed to calculate equilibrium: %w", err)
	}

	// Calculate game theory score
	gameTheoryScore := gtra.calculateGameTheoryScore(supplier, equilibrium)

	// Determine recommended action
	recommendedAction := gtra.determineRecommendedAction(gameTheoryScore, supplier)

	assessment := &SupplierRiskAssessment{
		SupplierID:        supplierID,
		RiskScore:         gtra.calculateSupplierRiskScore(supplier),
		TrustLevel:        supplier.TrustScore,
		GameTheoryScore:   gameTheoryScore,
		RecommendedAction: recommendedAction,
		LastAssessed:      time.Now(),
	}

	return assessment, nil
}

// CalculateROIOptimization performs ROI optimization for security controls
func (gtra *GameTheoryRiskAssessment) CalculateROIOptimization(ctx context.Context, playerID string, investmentOptions []Strategy) (*ROIAnalysis, error) {
	gtra.mu.RLock()
	player, exists := gtra.players[playerID]
	gtra.mu.RUnlock()

	if !exists {
		return nil, fmt.Errorf("player %s not found", playerID)
	}

	bestROI := -math.Inf(1)
	var bestStrategy Strategy
	var bestAnalysis *ROIAnalysis

	for _, strategy := range investmentOptions {
		analysis := gtra.analyzeStrategyROI(player, strategy)
		
		if analysis.InternalRateReturn > bestROI {
			bestROI = analysis.InternalRateReturn
			bestStrategy = strategy
			bestAnalysis = analysis
		}
	}

	// Add sensitivity analysis
	bestAnalysis.SensitivityAnalysis = gtra.performSensitivityAnalysis(player, bestStrategy)

	// Generate recommendation
	if bestAnalysis.InternalRateReturn > gtra.config.ROIThreshold {
		bestAnalysis.Recommendation = fmt.Sprintf("Recommended: Invest in %s (IRR: %.2f%%)", bestStrategy.Name, bestAnalysis.InternalRateReturn*100)
	} else {
		bestAnalysis.Recommendation = "Not recommended: ROI below threshold"
	}

	return bestAnalysis, nil
}

// UpdatePenaltySystem updates progressive penalty systems for malicious actors
func (gtra *GameTheoryRiskAssessment) UpdatePenaltySystem(playerID string, incident SecurityIncident) error {
	gtra.mu.Lock()
	defer gtra.mu.Unlock()

	player, exists := gtra.players[playerID]
	if !exists {
		return fmt.Errorf("player %s not found", playerID)
	}

	// Calculate penalty based on incident severity and history
	penalty := gtra.calculateProgressivePenalty(player, incident)
	
	// Update player's penalty score
	player.PenaltyScore += penalty
	
	// Apply decay to previous penalties
	player.PenaltyScore *= (1.0 - gtra.config.PenaltyDecayRate)
	
	// Update trust score inversely to penalty
	player.TrustScore = math.Max(0, 1.0 - (player.PenaltyScore / 100.0))
	
	// Add to historical record
	player.RiskProfile.HistoricalLosses = append(player.RiskProfile.HistoricalLosses, incident)
	player.LastUpdated = time.Now()

	gtra.logger.WithFields(logrus.Fields{
		"player_id": playerID,
		"penalty": penalty,
		"total_penalty": player.PenaltyScore,
		"trust_score": player.TrustScore,
	}).Info("Updated penalty system")

	return nil
}

// Helper methods

func (gtra *GameTheoryRiskAssessment) calculateBestResponse(playerID string, strategies map[string][]float64, game *SecurityGame) []float64 {
	player := gtra.players[playerID]
	numStrategies := len(player.Strategies)
	bestResponse := make([]float64, numStrategies)
	
	// Find best pure strategy
	bestPayoff := -math.Inf(1)
	bestStrategy := 0
	
	for i := 0; i < numStrategies; i++ {
		payoff := gtra.calculateExpectedPayoff(playerID, i, strategies, game)
		if payoff > bestPayoff {
			bestPayoff = payoff
			bestStrategy = i
		}
	}
	
	// Use epsilon-greedy for exploration
	epsilon := 0.1
	for i := range bestResponse {
		if i == bestStrategy {
			bestResponse[i] = 1.0 - epsilon + (epsilon / float64(numStrategies))
		} else {
			bestResponse[i] = epsilon / float64(numStrategies)
		}
	}
	
	return bestResponse
}

func (gtra *GameTheoryRiskAssessment) calculateExpectedPayoff(playerID string, strategy int, strategies map[string][]float64, game *SecurityGame) float64 {
	payoffMatrix := game.PayoffMatrices[playerID]
	if payoffMatrix == nil {
		return 0
	}
	
	expectedPayoff := 0.0
	
	// Calculate expected payoff against other players' mixed strategies
	for otherPlayerID, otherStrategy := range strategies {
		if otherPlayerID == playerID {
			continue
		}
		
		for j, prob := range otherStrategy {
			if strategy < len(payoffMatrix) && j < len(payoffMatrix[strategy]) {
				expectedPayoff += prob * payoffMatrix[strategy][j]
			}
		}
	}
	
	return expectedPayoff
}

func (gtra *GameTheoryRiskAssessment) hasConverged(oldStrategy, newStrategy []float64) bool {
	for i := range oldStrategy {
		if math.Abs(oldStrategy[i] - newStrategy[i]) > gtra.config.ConvergenceThreshold {
			return false
		}
	}
	return true
}

func (gtra *GameTheoryRiskAssessment) calculatePayoffs(strategies map[string][]float64, game *SecurityGame) map[string]float64 {
	payoffs := make(map[string]float64)
	
	for playerID := range strategies {
		payoff := 0.0
		for i, prob := range strategies[playerID] {
			payoff += prob * gtra.calculateExpectedPayoff(playerID, i, strategies, game)
		}
		payoffs[playerID] = payoff
	}
	
	return payoffs
}

func (gtra *GameTheoryRiskAssessment) calculateStability(strategies map[string][]float64, game *SecurityGame) float64 {
	// Calculate stability as inverse of strategy variance
	totalVariance := 0.0
	numPlayers := 0
	
	for _, strategy := range strategies {
		mean := 1.0 / float64(len(strategy))
		variance := 0.0
		
		for _, prob := range strategy {
			variance += math.Pow(prob - mean, 2)
		}
		
		totalVariance += variance
		numPlayers++
	}
	
	avgVariance := totalVariance / float64(numPlayers)
	return 1.0 / (1.0 + avgVariance)
}

func (gtra *GameTheoryRiskAssessment) calculateROI(equilibrium *NashEquilibrium, game *SecurityGame) float64 {
	// Simplified ROI calculation based on payoffs and business metrics
	totalPayoff := 0.0
	totalCost := 0.0
	
	for playerID, payoff := range equilibrium.Payoffs {
		player := gtra.players[playerID]
		if player.Type == PlayerTypeOrganization {
			totalPayoff += payoff
			// Calculate investment cost based on strategy mix
			for i, prob := range equilibrium.Strategies[playerID] {
				if i < len(player.Strategies) {
					totalCost += prob * player.Strategies[i].Cost
				}
			}
		}
	}
	
	if totalCost == 0 {
		return 0
	}
	
	return (totalPayoff - totalCost) / totalCost
}

func (gtra *GameTheoryRiskAssessment) calculateRiskReduction(equilibrium *NashEquilibrium, game *SecurityGame) float64 {
	// Calculate risk reduction based on strategy effectiveness
	totalRiskReduction := 0.0
	numPlayers := 0
	
	for playerID, strategyMix := range equilibrium.Strategies {
		player := gtra.players[playerID]
		if player.Type == PlayerTypeOrganization {
			for i, prob := range strategyMix {
				if i < len(player.Strategies) {
					totalRiskReduction += prob * player.Strategies[i].RiskReduction
				}
			}
			numPlayers++
		}
	}
	
	if numPlayers == 0 {
		return 0
	}
	
	return totalRiskReduction / float64(numPlayers)
}

func (gtra *GameTheoryRiskAssessment) calculateOptimalInvestment(equilibrium *NashEquilibrium, game *SecurityGame) float64 {
	// Calculate optimal investment based on Nash equilibrium
	optimalInvestment := 0.0
	
	for playerID, strategyMix := range equilibrium.Strategies {
		player := gtra.players[playerID]
		if player.Type == PlayerTypeOrganization {
			for i, prob := range strategyMix {
				if i < len(player.Strategies) {
					optimalInvestment += prob * player.Strategies[i].Cost
				}
			}
		}
	}
	
	return optimalInvestment
}

func (gtra *GameTheoryRiskAssessment) buildSupplierPayoffMatrices(supplier *Player) map[string][][]float64 {
	// Build payoff matrices for supplier risk game
	matrices := make(map[string][][]float64)
	
	// Organization strategies: [Trust, Verify, Terminate]
	// Supplier strategies: [Secure, Negligent, Malicious]
	
	// Organization payoff matrix
	orgMatrix := [][]float64{
		{10, -5, -20},  // Trust strategy
		{8, 5, -10},   // Verify strategy
		{0, 0, 0},     // Terminate strategy
	}
	
	// Supplier payoff matrix
	supplierMatrix := [][]float64{
		{10, 5, 0},    // Secure strategy
		{15, 8, 2},   // Negligent strategy
		{20, 10, 5},  // Malicious strategy
	}
	
	// Adjust based on supplier's trust score and penalty
	trustMultiplier := supplier.TrustScore
	penaltyMultiplier := 1.0 + supplier.PenaltyScore/100.0
	
	for i := range orgMatrix {
		for j := range orgMatrix[i] {
			orgMatrix[i][j] *= trustMultiplier
			supplierMatrix[j][i] /= penaltyMultiplier
		}
	}
	
	matrices["organization"] = orgMatrix
	matrices[supplier.ID] = supplierMatrix
	
	return matrices
}

func (gtra *GameTheoryRiskAssessment) calculateGameTheoryScore(supplier *Player, equilibrium *NashEquilibrium) float64 {
	// Calculate game theory score based on equilibrium and supplier characteristics
	baseScore := equilibrium.Payoffs[supplier.ID]
	stabilityBonus := equilibrium.Stability * 10
	trustBonus := supplier.TrustScore * 20
	penaltyPenalty := supplier.PenaltyScore
	
	score := baseScore + stabilityBonus + trustBonus - penaltyPenalty
	
	// Normalize to 0-100 scale
	return math.Max(0, math.Min(100, score))
}

func (gtra *GameTheoryRiskAssessment) calculateSupplierRiskScore(supplier *Player) float64 {
	// Calculate overall supplier risk score
	vulnerabilityWeight := 0.3
	threatWeight := 0.2
	penaltyWeight := 0.3
	trustWeight := 0.2
	
	riskScore := vulnerabilityWeight * supplier.RiskProfile.VulnerabilityScore +
		threatWeight * supplier.RiskProfile.ThreatExposure +
		penaltyWeight * supplier.PenaltyScore +
		trustWeight * (100 - supplier.TrustScore*100)
	
	return math.Max(0, math.Min(100, riskScore))
}

func (gtra *GameTheoryRiskAssessment) determineRecommendedAction(gameTheoryScore float64, supplier *Player) string {
	if gameTheoryScore >= 80 {
		return "Continue partnership with standard monitoring"
	} else if gameTheoryScore >= 60 {
		return "Continue with enhanced monitoring and verification"
	} else if gameTheoryScore >= 40 {
		return "Require security improvements before continuing"
	} else if gameTheoryScore >= 20 {
		return "Consider alternative suppliers"
	} else {
		return "Terminate partnership immediately"
	}
}

func (gtra *GameTheoryRiskAssessment) analyzeStrategyROI(player *Player, strategy Strategy) *ROIAnalysis {
	// Calculate ROI for a specific strategy
	investment := strategy.Cost
	
	// Calculate expected return based on risk reduction and business metrics
	riskReductionValue := strategy.RiskReduction * player.BusinessMetrics.Revenue * 0.01 // 1% of revenue per risk reduction point
	operationalSavings := strategy.Effectiveness * player.BusinessMetrics.OperationalCost * 0.05 // 5% operational savings
	reputationValue := strategy.RiskReduction * player.BusinessMetrics.ReputationValue * 0.02
	
	expectedReturn := riskReductionValue + operationalSavings + reputationValue
	
	// Calculate payback period
	annualReturn := expectedReturn
	paybackPeriod := time.Duration(float64(time.Hour*24*365) * (investment / annualReturn))
	
	// Calculate NPV with discount rate
	discountRate := 0.1 // 10% discount rate
	npv := -investment
	for year := 1; year <= 5; year++ {
		npv += annualReturn / math.Pow(1+discountRate, float64(year))
	}
	
	// Calculate IRR (simplified)
	irr := (expectedReturn / investment) - 1
	
	return &ROIAnalysis{
		Investment:         investment,
		ExpectedReturn:     expectedReturn,
		RiskReduction:      strategy.RiskReduction,
		PaybackPeriod:      paybackPeriod,
		NetPresentValue:    npv,
		InternalRateReturn: irr,
	}
}

func (gtra *GameTheoryRiskAssessment) performSensitivityAnalysis(player *Player, strategy Strategy) map[string]float64 {
	// Perform sensitivity analysis on key variables
	sensitivity := make(map[string]float64)
	
	baseROI := gtra.analyzeStrategyROI(player, strategy).InternalRateReturn
	
	// Test 10% increase in cost
	testStrategy := strategy
	testStrategy.Cost *= 1.1
	newROI := gtra.analyzeStrategyROI(player, testStrategy).InternalRateReturn
	sensitivity["cost_sensitivity"] = (newROI - baseROI) / baseROI
	
	// Test 10% increase in effectiveness
	testStrategy = strategy
	testStrategy.Effectiveness *= 1.1
	newROI = gtra.analyzeStrategyROI(player, testStrategy).InternalRateReturn
	sensitivity["effectiveness_sensitivity"] = (newROI - baseROI) / baseROI
	
	// Test 10% increase in risk reduction
	testStrategy = strategy
	testStrategy.RiskReduction *= 1.1
	newROI = gtra.analyzeStrategyROI(player, testStrategy).InternalRateReturn
	sensitivity["risk_reduction_sensitivity"] = (newROI - baseROI) / baseROI
	
	return sensitivity
}

func (gtra *GameTheoryRiskAssessment) calculateProgressivePenalty(player *Player, incident SecurityIncident) float64 {
	// Calculate progressive penalty based on incident and history
	basePenalty := incident.Impact * 10 // Base penalty proportional to impact
	
	// Progressive multiplier based on historical incidents
	historyMultiplier := 1.0
	recentIncidents := 0
	cutoffTime := time.Now().AddDate(0, -6, 0) // Last 6 months
	
	for _, historicalIncident := range player.RiskProfile.HistoricalLosses {
		if historicalIncident.Timestamp.After(cutoffTime) {
			recentIncidents++
		}
	}
	
	// Exponential increase for repeat offenders
	historyMultiplier = math.Pow(1.5, float64(recentIncidents))
	
	// Severity multiplier
	severityMultiplier := 1.0
	switch incident.Severity {
	case "low":
		severityMultiplier = 1.0
	case "medium":
		severityMultiplier = 2.0
	case "high":
		severityMultiplier = 4.0
	case "critical":
		severityMultiplier = 8.0
	}
	
	return basePenalty * historyMultiplier * severityMultiplier
}

// AddPlayer adds a new player to the game theory system
func (gtra *GameTheoryRiskAssessment) AddPlayer(player *Player) error {
	gtra.mu.Lock()
	defer gtra.mu.Unlock()
	
	gtra.players[player.ID] = player
	gtra.logger.WithField("player_id", player.ID).Info("Added player to game theory system")
	
	return nil
}

// GetPlayer retrieves a player by ID
func (gtra *GameTheoryRiskAssessment) GetPlayer(playerID string) (*Player, error) {
	gtra.mu.RLock()
	defer gtra.mu.RUnlock()
	
	player, exists := gtra.players[playerID]
	if !exists {
		return nil, fmt.Errorf("player %s not found", playerID)
	}
	
	return player, nil
}

// ListPlayers returns all players
func (gtra *GameTheoryRiskAssessment) ListPlayers() []*Player {
	gtra.mu.RLock()
	defer gtra.mu.RUnlock()
	
	players := make([]*Player, 0, len(gtra.players))
	for _, player := range gtra.players {
		players = append(players, player)
	}
	
	return players
}

// GetEquilibrium retrieves equilibrium for a game
func (gtra *GameTheoryRiskAssessment) GetEquilibrium(gameID string) (*NashEquilibrium, error) {
	gtra.mu.RLock()
	defer gtra.mu.RUnlock()
	
	equilibrium, exists := gtra.equilibria[gameID]
	if !exists {
		return nil, fmt.Errorf("equilibrium for game %s not found", gameID)
	}
	
	return equilibrium, nil
}