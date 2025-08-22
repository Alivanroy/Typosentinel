package security

import (
	"context"
	"fmt"
	"math"
	"sync"
	"time"

	"github.com/Alivanroy/Typosentinel/pkg/logger"
	"github.com/Alivanroy/Typosentinel/pkg/types"
)

// QuantumThresholdSystem implements quantum-sensitive threshold detection with predictive capabilities
type QuantumThresholdSystem struct {
	mu                    sync.RWMutex
	logger               *logger.Logger
	quantumStates        map[string]*QuantumState
	predictiveModels     map[string]*PredictiveModel
	coherenceThreshold   float64
	entanglementMatrix   [][]float64
	superpositionStates  map[string]*SuperpositionState
	quantumHistory       []*QuantumSnapshot
	maxHistorySize       int
	updateInterval       time.Duration
	lastUpdate           time.Time
	predictionHorizon    time.Duration
	quantumSensitivity   float64
	phaseCorrelations    map[string]float64
	uncertaintyPrinciple *UncertaintyPrinciple
}

// QuantumState represents the quantum state of a security metric
type QuantumState struct {
	MetricName       string                 `json:"metric_name"`
	Amplitude        complex128             `json:"amplitude"`
	Phase            float64                `json:"phase"`
	Coherence        float64                `json:"coherence"`
	Entanglement     map[string]float64     `json:"entanglement"`
	Superposition    []float64              `json:"superposition"`
	ObservationCount int                    `json:"observation_count"`
	LastObserved     time.Time              `json:"last_observed"`
	Uncertainty      float64                `json:"uncertainty"`
	QuantumEnergy    float64                `json:"quantum_energy"`
	WaveFunction     []complex128           `json:"wave_function"`
	Eigenvalues      []float64              `json:"eigenvalues"`
	Metadata         map[string]interface{} `json:"metadata"`
}

// PredictiveModel represents a quantum-enhanced predictive model
type PredictiveModel struct {
	ModelID           string                 `json:"model_id"`
	ModelType         string                 `json:"model_type"`
	QuantumFeatures   []string               `json:"quantum_features"`
	PredictionWeights []float64              `json:"prediction_weights"`
	Accuracy          float64                `json:"accuracy"`
	Confidence        float64                `json:"confidence"`
	TrainingData      []*QuantumSnapshot     `json:"training_data"`
	LastTrained       time.Time              `json:"last_trained"`
	PredictionHistory []*QuantumPrediction   `json:"prediction_history"`
	QuantumParameters map[string]float64     `json:"quantum_parameters"`
	Metadata          map[string]interface{} `json:"metadata"`
}

// SuperpositionState represents multiple possible states simultaneously
type SuperpositionState struct {
	StateID       string                 `json:"state_id"`
	PossibleStates []PossibleState       `json:"possible_states"`
	Coherence     float64                `json:"coherence"`
	Collapsed     bool                   `json:"collapsed"`
	CollapseTime  time.Time              `json:"collapse_time"`
	Observer      string                 `json:"observer"`
	Metadata      map[string]interface{} `json:"metadata"`
}

// PossibleState represents a single possible state in superposition
type PossibleState struct {
	StateName   string     `json:"state_name"`
	Probability float64    `json:"probability"`
	Amplitude   complex128 `json:"amplitude"`
	Phase       float64    `json:"phase"`
	Energy      float64    `json:"energy"`
}

// QuantumSnapshot captures the quantum state at a specific time
type QuantumSnapshot struct {
	SnapshotID       string                    `json:"snapshot_id"`
	Timestamp        time.Time                 `json:"timestamp"`
	QuantumStates    map[string]*QuantumState  `json:"quantum_states"`
	Entanglements    map[string]map[string]float64 `json:"entanglements"`
	CoherenceLevel   float64                   `json:"coherence_level"`
	SystemEntropy    float64                   `json:"system_entropy"`
	QuantumEnergy    float64                   `json:"quantum_energy"`
	PhaseCorrelations map[string]float64       `json:"phase_correlations"`
	UncertaintyLevel float64                   `json:"uncertainty_level"`
	Metadata         map[string]interface{}    `json:"metadata"`
}

// QuantumPrediction represents a quantum-enhanced prediction
type QuantumPrediction struct {
	PredictionID     string                 `json:"prediction_id"`
	Timestamp        time.Time              `json:"timestamp"`
	PredictionTime   time.Time              `json:"prediction_time"`
	MetricName       string                 `json:"metric_name"`
	PredictedValue   float64                `json:"predicted_value"`
	Confidence       float64                `json:"confidence"`
	Uncertainty      float64                `json:"uncertainty"`
	QuantumFeatures  map[string]float64     `json:"quantum_features"`
	ProbabilityDist  []float64              `json:"probability_distribution"`
	ActualValue      *float64               `json:"actual_value,omitempty"`
	Accuracy         *float64               `json:"accuracy,omitempty"`
	Metadata         map[string]interface{} `json:"metadata"`
}

// UncertaintyPrinciple implements quantum uncertainty calculations
type UncertaintyPrinciple struct {
	PlanckConstant   float64                `json:"planck_constant"`
	UncertaintyPairs map[string][]string    `json:"uncertainty_pairs"`
	MinUncertainty   float64                `json:"min_uncertainty"`
	Metadata         map[string]interface{} `json:"metadata"`
}

// QuantumThresholdResult represents the result of quantum threshold analysis
type QuantumThresholdResult struct {
	AnalysisID        string                 `json:"analysis_id"`
	Timestamp         time.Time              `json:"timestamp"`
	QuantumViolations []*QuantumViolation    `json:"quantum_violations"`
	Predictions       []*QuantumPrediction   `json:"predictions"`
	CoherenceLevel    float64                `json:"coherence_level"`
	EntanglementScore float64                `json:"entanglement_score"`
	UncertaintyLevel  float64                `json:"uncertainty_level"`
	QuantumRisk       float64                `json:"quantum_risk"`
	Recommendations   []string               `json:"recommendations"`
	Metadata          map[string]interface{} `json:"metadata"`
}

// QuantumViolation represents a quantum threshold violation
type QuantumViolation struct {
	ViolationID      string                 `json:"violation_id"`
	MetricName       string                 `json:"metric_name"`
	QuantumThreshold float64                `json:"quantum_threshold"`
	ObservedValue    float64                `json:"observed_value"`
	QuantumDeviation float64                `json:"quantum_deviation"`
	Coherence        float64                `json:"coherence"`
	Phase            float64                `json:"phase"`
	Uncertainty      float64                `json:"uncertainty"`
	Severity         types.Severity         `json:"severity"`
	DetectedAt       time.Time              `json:"detected_at"`
	QuantumSignature map[string]float64     `json:"quantum_signature"`
	Metadata         map[string]interface{} `json:"metadata"`
}

// NewQuantumThresholdSystem creates a new quantum threshold system
func NewQuantumThresholdSystem(logger *logger.Logger) *QuantumThresholdSystem {
	return &QuantumThresholdSystem{
		logger:               logger,
		quantumStates:        make(map[string]*QuantumState),
		predictiveModels:     make(map[string]*PredictiveModel),
		coherenceThreshold:   0.85,
		entanglementMatrix:   make([][]float64, 0),
		superpositionStates:  make(map[string]*SuperpositionState),
		quantumHistory:       make([]*QuantumSnapshot, 0),
		maxHistorySize:       1000,
		updateInterval:       time.Minute * 5,
		predictionHorizon:    time.Hour * 24,
		quantumSensitivity:   0.0001,
		phaseCorrelations:    make(map[string]float64),
		uncertaintyPrinciple: &UncertaintyPrinciple{
			PlanckConstant:   6.62607015e-34,
			UncertaintyPairs: make(map[string][]string),
			MinUncertainty:   1e-10,
			Metadata:         make(map[string]interface{}),
		},
	}
}

// AnalyzeQuantumThresholds performs quantum-sensitive threshold analysis
func (qts *QuantumThresholdSystem) AnalyzeQuantumThresholds(ctx context.Context, metrics *ResourceUsageMetrics) (*QuantumThresholdResult, error) {
	qts.mu.Lock()
	defer qts.mu.Unlock()

	// Update quantum states
	if err := qts.updateQuantumStates(metrics); err != nil {
		return nil, fmt.Errorf("failed to update quantum states: %w", err)
	}

	// Perform quantum measurements
	quantumViolations := qts.detectQuantumViolations(metrics)

	// Generate predictions
	predictions := qts.generateQuantumPredictions(ctx, metrics)

	// Calculate quantum metrics
	coherenceLevel := qts.calculateSystemCoherence()
	entanglementScore := qts.calculateEntanglementScore()
	uncertaintyLevel := qts.calculateUncertaintyLevel()
	quantumRisk := qts.calculateQuantumRisk(quantumViolations, predictions)

	// Generate recommendations
	recommendations := qts.generateRecommendations(quantumViolations, predictions)

	// Create snapshot
	snapshot := qts.createQuantumSnapshot()
	qts.addToHistory(snapshot)

	result := &QuantumThresholdResult{
		AnalysisID:        qts.generateAnalysisID(),
		Timestamp:         time.Now(),
		QuantumViolations: quantumViolations,
		Predictions:       predictions,
		CoherenceLevel:    coherenceLevel,
		EntanglementScore: entanglementScore,
		UncertaintyLevel:  uncertaintyLevel,
		QuantumRisk:       quantumRisk,
		Recommendations:   recommendations,
		Metadata: map[string]interface{}{
			"quantum_sensitivity": qts.quantumSensitivity,
			"coherence_threshold": qts.coherenceThreshold,
			"prediction_horizon":  qts.predictionHorizon.String(),
			"snapshot_id":         snapshot.SnapshotID,
		},
	}

	return result, nil
}

// updateQuantumStates updates the quantum states based on current metrics
func (qts *QuantumThresholdSystem) updateQuantumStates(metrics *ResourceUsageMetrics) error {
	metricMap := map[string]float64{
		"cpu_usage":           metrics.CPUUsage,
		"memory_usage":        float64(metrics.MemoryUsage),
		"goroutine_count":     float64(metrics.GoroutineCount),
		"quantum_fluctuation": metrics.QuantumFluctuation,
		"entropy_deviation":   metrics.EntropyDeviation,
		"phase_correlation":   metrics.PhaseCorrelation,
	}

	for metricName, value := range metricMap {
		state, exists := qts.quantumStates[metricName]
		if !exists {
			state = qts.initializeQuantumState(metricName)
			qts.quantumStates[metricName] = state
		}

		// Update quantum state
		state.Amplitude = complex(value, qts.calculateQuantumPhase(value))
		state.Phase = qts.calculateQuantumPhase(value)
		state.Coherence = qts.calculateCoherence(state)
		state.Uncertainty = qts.calculateUncertainty(state)
		state.QuantumEnergy = qts.calculateQuantumEnergy(state)
		state.ObservationCount++
		state.LastObserved = time.Now()

		// Update wave function
		qts.updateWaveFunction(state, value)

		// Update entanglements
		qts.updateEntanglements(state, metricName)
	}

	return nil
}

// detectQuantumViolations detects quantum threshold violations
func (qts *QuantumThresholdSystem) detectQuantumViolations(metrics *ResourceUsageMetrics) []*QuantumViolation {
	var violations []*QuantumViolation

	// Define quantum thresholds
	quantumThresholds := map[string]float64{
		"quantum_fluctuation": 0.1,
		"entropy_deviation":   0.05,
		"phase_correlation":   0.3,
		"coherence_loss":      0.15,
		"entanglement_break":  0.2,
	}

	metricMap := map[string]float64{
		"quantum_fluctuation": metrics.QuantumFluctuation,
		"entropy_deviation":   metrics.EntropyDeviation,
		"phase_correlation":   metrics.PhaseCorrelation,
		"coherence_loss":      qts.calculateCoherenceLoss(),
		"entanglement_break":  qts.calculateEntanglementBreak(),
	}

	for metricName, value := range metricMap {
		threshold, exists := quantumThresholds[metricName]
		if !exists {
			continue
		}

		if value > threshold {
			violation := &QuantumViolation{
				ViolationID:      qts.generateViolationID(),
				MetricName:       metricName,
				QuantumThreshold: threshold,
				ObservedValue:    value,
				QuantumDeviation: value - threshold,
				Coherence:        qts.getMetricCoherence(metricName),
				Phase:            qts.getMetricPhase(metricName),
				Uncertainty:      qts.getMetricUncertainty(metricName),
				Severity:         qts.calculateViolationSeverity(value, threshold),
				DetectedAt:       time.Now(),
				QuantumSignature: qts.generateQuantumSignature(metricName),
				Metadata: map[string]interface{}{
					"detection_method": "quantum_threshold",
					"sensitivity":      qts.quantumSensitivity,
					"quantum_state":    qts.quantumStates[metricName],
				},
			}
			violations = append(violations, violation)
		}
	}

	return violations
}

// generateQuantumPredictions generates quantum-enhanced predictions
func (qts *QuantumThresholdSystem) generateQuantumPredictions(ctx context.Context, metrics *ResourceUsageMetrics) []*QuantumPrediction {
	var predictions []*QuantumPrediction

	// Generate predictions for each metric
	for metricName, state := range qts.quantumStates {
		model, exists := qts.predictiveModels[metricName]
		if !exists {
			model = qts.initializePredictiveModel(metricName)
			qts.predictiveModels[metricName] = model
		}

		// Generate prediction using quantum features
		prediction := qts.generateSinglePrediction(state, model)
		predictions = append(predictions, prediction)
	}

	return predictions
}

// Helper functions for quantum calculations
func (qts *QuantumThresholdSystem) initializeQuantumState(metricName string) *QuantumState {
	return &QuantumState{
		MetricName:       metricName,
		Amplitude:        complex(0, 0),
		Phase:            0,
		Coherence:        1.0,
		Entanglement:     make(map[string]float64),
		Superposition:    make([]float64, 0),
		ObservationCount: 0,
		LastObserved:     time.Now(),
		Uncertainty:      0,
		QuantumEnergy:    0,
		WaveFunction:     make([]complex128, 0),
		Eigenvalues:      make([]float64, 0),
		Metadata:         make(map[string]interface{}),
	}
}

func (qts *QuantumThresholdSystem) calculateQuantumPhase(value float64) float64 {
	return math.Mod(value*2*math.Pi, 2*math.Pi)
}

func (qts *QuantumThresholdSystem) calculateCoherence(state *QuantumState) float64 {
	// Simplified coherence calculation
	if state.ObservationCount == 0 {
		return 1.0
	}
	return math.Exp(-float64(state.ObservationCount) * 0.01)
}

func (qts *QuantumThresholdSystem) calculateUncertainty(state *QuantumState) float64 {
	// Heisenberg uncertainty principle
	return qts.uncertaintyPrinciple.MinUncertainty * math.Sqrt(float64(state.ObservationCount))
}

func (qts *QuantumThresholdSystem) calculateQuantumEnergy(state *QuantumState) float64 {
	// E = hf (simplified)
	return qts.uncertaintyPrinciple.PlanckConstant * real(state.Amplitude)
}

func (qts *QuantumThresholdSystem) updateWaveFunction(state *QuantumState, value float64) {
	// Add new amplitude to wave function
	newAmplitude := complex(value, qts.calculateQuantumPhase(value))
	state.WaveFunction = append(state.WaveFunction, newAmplitude)

	// Keep only recent values
	if len(state.WaveFunction) > 100 {
		state.WaveFunction = state.WaveFunction[1:]
	}
}

func (qts *QuantumThresholdSystem) updateEntanglements(state *QuantumState, metricName string) {
	// Calculate entanglement with other metrics
	for otherMetric, otherState := range qts.quantumStates {
		if otherMetric != metricName {
			entanglement := qts.calculateEntanglement(state, otherState)
			state.Entanglement[otherMetric] = entanglement
		}
	}
}

func (qts *QuantumThresholdSystem) calculateEntanglement(state1, state2 *QuantumState) float64 {
	// Simplified entanglement calculation based on phase correlation
	phaseDiff := math.Abs(state1.Phase - state2.Phase)
	return math.Cos(phaseDiff)
}

func (qts *QuantumThresholdSystem) calculateSystemCoherence() float64 {
	if len(qts.quantumStates) == 0 {
		return 1.0
	}

	var totalCoherence float64
	for _, state := range qts.quantumStates {
		totalCoherence += state.Coherence
	}
	return totalCoherence / float64(len(qts.quantumStates))
}

func (qts *QuantumThresholdSystem) calculateEntanglementScore() float64 {
	var totalEntanglement float64
	var count int

	for _, state := range qts.quantumStates {
		for _, entanglement := range state.Entanglement {
			totalEntanglement += entanglement
			count++
		}
	}

	if count == 0 {
		return 0
	}
	return totalEntanglement / float64(count)
}

func (qts *QuantumThresholdSystem) calculateUncertaintyLevel() float64 {
	if len(qts.quantumStates) == 0 {
		return 0
	}

	var totalUncertainty float64
	for _, state := range qts.quantumStates {
		totalUncertainty += state.Uncertainty
	}
	return totalUncertainty / float64(len(qts.quantumStates))
}

func (qts *QuantumThresholdSystem) calculateQuantumRisk(violations []*QuantumViolation, predictions []*QuantumPrediction) float64 {
	violationRisk := float64(len(violations)) * 0.3

	var predictionRisk float64
	for _, prediction := range predictions {
		predictionRisk += (1.0 - prediction.Confidence) * prediction.Uncertainty
	}

	return math.Min(violationRisk+predictionRisk, 1.0)
}

func (qts *QuantumThresholdSystem) generateRecommendations(violations []*QuantumViolation, predictions []*QuantumPrediction) []string {
	var recommendations []string

	if len(violations) > 0 {
		recommendations = append(recommendations, "Quantum threshold violations detected - increase monitoring sensitivity")
	}

	if qts.calculateSystemCoherence() < qts.coherenceThreshold {
		recommendations = append(recommendations, "System coherence below threshold - consider quantum state reset")
	}

	for _, prediction := range predictions {
		if prediction.Confidence < 0.7 {
			recommendations = append(recommendations, fmt.Sprintf("Low prediction confidence for %s - retrain model", prediction.MetricName))
		}
	}

	return recommendations
}

// Additional helper functions
func (qts *QuantumThresholdSystem) generateAnalysisID() string {
	return fmt.Sprintf("quantum-analysis-%d", time.Now().UnixNano())
}

func (qts *QuantumThresholdSystem) generateViolationID() string {
	return fmt.Sprintf("quantum-violation-%d", time.Now().UnixNano())
}

func (qts *QuantumThresholdSystem) calculateCoherenceLoss() float64 {
	baselineCoherence := 1.0
	currentCoherence := qts.calculateSystemCoherence()
	return baselineCoherence - currentCoherence
}

func (qts *QuantumThresholdSystem) calculateEntanglementBreak() float64 {
	baselineEntanglement := 1.0
	currentEntanglement := qts.calculateEntanglementScore()
	return baselineEntanglement - currentEntanglement
}

func (qts *QuantumThresholdSystem) getMetricCoherence(metricName string) float64 {
	if state, exists := qts.quantumStates[metricName]; exists {
		return state.Coherence
	}
	return 0
}

func (qts *QuantumThresholdSystem) getMetricPhase(metricName string) float64 {
	if state, exists := qts.quantumStates[metricName]; exists {
		return state.Phase
	}
	return 0
}

func (qts *QuantumThresholdSystem) getMetricUncertainty(metricName string) float64 {
	if state, exists := qts.quantumStates[metricName]; exists {
		return state.Uncertainty
	}
	return 0
}

func (qts *QuantumThresholdSystem) calculateViolationSeverity(value, threshold float64) types.Severity {
	deviation := (value - threshold) / threshold
	if deviation > 0.5 {
		return types.SeverityCritical
	} else if deviation > 0.3 {
		return types.SeverityHigh
	} else if deviation > 0.1 {
		return types.SeverityMedium
	}
	return types.SeverityLow
}

func (qts *QuantumThresholdSystem) generateQuantumSignature(metricName string) map[string]float64 {
	signature := make(map[string]float64)
	if state, exists := qts.quantumStates[metricName]; exists {
		signature["amplitude"] = real(state.Amplitude)
		signature["phase"] = state.Phase
		signature["coherence"] = state.Coherence
		signature["uncertainty"] = state.Uncertainty
		signature["quantum_energy"] = state.QuantumEnergy
	}
	return signature
}

func (qts *QuantumThresholdSystem) initializePredictiveModel(metricName string) *PredictiveModel {
	return &PredictiveModel{
		ModelID:           fmt.Sprintf("quantum-model-%s-%d", metricName, time.Now().UnixNano()),
		ModelType:         "quantum_enhanced",
		QuantumFeatures:   []string{"amplitude", "phase", "coherence", "entanglement"},
		PredictionWeights: []float64{0.3, 0.25, 0.25, 0.2},
		Accuracy:          0.85,
		Confidence:        0.8,
		TrainingData:      make([]*QuantumSnapshot, 0),
		LastTrained:       time.Now(),
		PredictionHistory: make([]*QuantumPrediction, 0),
		QuantumParameters: make(map[string]float64),
		Metadata:          make(map[string]interface{}),
	}
}

func (qts *QuantumThresholdSystem) generateSinglePrediction(state *QuantumState, model *PredictiveModel) *QuantumPrediction {
	// Simplified quantum prediction
	predictedValue := real(state.Amplitude) * model.PredictionWeights[0] +
		state.Phase*model.PredictionWeights[1] +
		state.Coherence*model.PredictionWeights[2]

	confidence := model.Confidence * state.Coherence
	uncertainty := state.Uncertainty

	return &QuantumPrediction{
		PredictionID:   fmt.Sprintf("quantum-pred-%d", time.Now().UnixNano()),
		Timestamp:      time.Now(),
		PredictionTime: time.Now().Add(qts.predictionHorizon),
		MetricName:     state.MetricName,
		PredictedValue: predictedValue,
		Confidence:     confidence,
		Uncertainty:    uncertainty,
		QuantumFeatures: map[string]float64{
			"amplitude": real(state.Amplitude),
			"phase":     state.Phase,
			"coherence": state.Coherence,
		},
		ProbabilityDist: qts.calculateProbabilityDistribution(state),
		Metadata: map[string]interface{}{
			"model_id":     model.ModelID,
			"quantum_state": state,
		},
	}
}

func (qts *QuantumThresholdSystem) calculateProbabilityDistribution(state *QuantumState) []float64 {
	// Simplified probability distribution based on wave function
	dist := make([]float64, 10)
	for i := range dist {
		// Gaussian-like distribution around the amplitude
		x := float64(i) / 10.0
		amplitude := real(state.Amplitude)
		dist[i] = math.Exp(-math.Pow(x-amplitude, 2) / (2 * state.Uncertainty))
	}
	return dist
}

func (qts *QuantumThresholdSystem) createQuantumSnapshot() *QuantumSnapshot {
	// Create deep copy of current quantum states
	statesCopy := make(map[string]*QuantumState)
	for name, state := range qts.quantumStates {
		statesCopy[name] = &QuantumState{
			MetricName:       state.MetricName,
			Amplitude:        state.Amplitude,
			Phase:            state.Phase,
			Coherence:        state.Coherence,
			Entanglement:     make(map[string]float64),
			Superposition:    append([]float64{}, state.Superposition...),
			ObservationCount: state.ObservationCount,
			LastObserved:     state.LastObserved,
			Uncertainty:      state.Uncertainty,
			QuantumEnergy:    state.QuantumEnergy,
			WaveFunction:     append([]complex128{}, state.WaveFunction...),
			Eigenvalues:      append([]float64{}, state.Eigenvalues...),
			Metadata:         make(map[string]interface{}),
		}
		// Copy entanglement map
		for k, v := range state.Entanglement {
			statesCopy[name].Entanglement[k] = v
		}
	}

	return &QuantumSnapshot{
		SnapshotID:        fmt.Sprintf("quantum-snapshot-%d", time.Now().UnixNano()),
		Timestamp:         time.Now(),
		QuantumStates:     statesCopy,
		Entanglements:     qts.copyEntanglements(),
		CoherenceLevel:    qts.calculateSystemCoherence(),
		SystemEntropy:     qts.calculateSystemEntropy(),
		QuantumEnergy:     qts.calculateSystemQuantumEnergy(),
		PhaseCorrelations: qts.copyPhaseCorrelations(),
		UncertaintyLevel:  qts.calculateUncertaintyLevel(),
		Metadata:          make(map[string]interface{}),
	}
}

func (qts *QuantumThresholdSystem) addToHistory(snapshot *QuantumSnapshot) {
	qts.quantumHistory = append(qts.quantumHistory, snapshot)

	// Keep only recent history
	if len(qts.quantumHistory) > qts.maxHistorySize {
		qts.quantumHistory = qts.quantumHistory[1:]
	}
}

func (qts *QuantumThresholdSystem) copyEntanglements() map[string]map[string]float64 {
	entanglements := make(map[string]map[string]float64)
	for name, state := range qts.quantumStates {
		entanglements[name] = make(map[string]float64)
		for k, v := range state.Entanglement {
			entanglements[name][k] = v
		}
	}
	return entanglements
}

func (qts *QuantumThresholdSystem) calculateSystemEntropy() float64 {
	var entropy float64
	for _, state := range qts.quantumStates {
		// Shannon entropy calculation
		if state.Coherence > 0 {
			entropy += -state.Coherence * math.Log2(state.Coherence)
		}
	}
	return entropy
}

func (qts *QuantumThresholdSystem) calculateSystemQuantumEnergy() float64 {
	var totalEnergy float64
	for _, state := range qts.quantumStates {
		totalEnergy += state.QuantumEnergy
	}
	return totalEnergy
}

func (qts *QuantumThresholdSystem) copyPhaseCorrelations() map[string]float64 {
	correlations := make(map[string]float64)
	for k, v := range qts.phaseCorrelations {
		correlations[k] = v
	}
	return correlations
}