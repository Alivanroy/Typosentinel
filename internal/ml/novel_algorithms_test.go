package ml

import (
	"context"
	"testing"
	"time"

	"github.com/Alivanroy/Typosentinel/pkg/logger"
	"github.com/Alivanroy/Typosentinel/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Test data and helpers
func createTestPackage(name, description string, depCount int) *types.Package {
	deps := make([]string, depCount)
	for i := 0; i < depCount; i++ {
		deps[i] = fmt.Sprintf("dep-%d", i)
	}

	return &types.Package{
		Name:         name,
		Description:  description,
		Version:      "1.0.0",
		Dependencies: deps,
		Registry:     "npm",
		Author:       "test-author",
		License:      "MIT",
	}
}

func createTestConfig() *NovelAlgorithmConfig {
	return &NovelAlgorithmConfig{
		QuantumInspiredEnabled:    true,
		GraphAttentionEnabled:     true,
		AdversarialDetectionEnabled: true,
		TransformerEnabled:        true,
		FederatedLearningEnabled:  true,
		CausalInferenceEnabled:    true,
		MetaLearningEnabled:       true,
		SwarmOptimizationEnabled:  true,
		NeuroEvolutionEnabled:     true,
		QuantumMLEnabled:          true,
		LearningRate:              0.001,
		BatchSize:                 32,
		Epochs:                    100,
		Regularization:            0.01,
		DropoutRate:               0.2,
	}
}

func createTestLogger() logger.Logger {
	// Return a test logger implementation
	return &testLogger{}
}

type testLogger struct{}

func (tl *testLogger) Debug(msg string, keysAndValues ...interface{}) {}
func (tl *testLogger) Info(msg string, keysAndValues ...interface{})  {}
func (tl *testLogger) Warn(msg string, keysAndValues ...interface{})  {}
func (tl *testLogger) Error(msg string, keysAndValues ...interface{}) {}
func (tl *testLogger) With(keysAndValues ...interface{}) logger.Logger { return tl }

// Test Novel Algorithm Suite
func TestNewNovelAlgorithmSuite(t *testing.T) {
	config := createTestConfig()
	logger := createTestLogger()

	suite := NewNovelAlgorithmSuite(config, logger)

	assert.NotNil(t, suite)
	assert.Equal(t, config, suite.config)
	assert.NotNil(t, suite.quantumInspiredNet)
	assert.NotNil(t, suite.graphAttentionNet)
	assert.NotNil(t, suite.adversarialDetector)
	assert.NotNil(t, suite.transformerModel)
	assert.NotNil(t, suite.federatedLearner)
	assert.NotNil(t, suite.causalInference)
	assert.NotNil(t, suite.metaLearner)
	assert.NotNil(t, suite.swarmIntelligence)
	assert.NotNil(t, suite.neuroEvolution)
	assert.NotNil(t, suite.quantumML)
}

func TestNovelAlgorithmSuite_AnalyzePackageWithNovelAlgorithms(t *testing.T) {
	config := createTestConfig()
	logger := createTestLogger()
	suite := NewNovelAlgorithmSuite(config, logger)

	testCases := []struct {
		name        string
		pkg         *types.Package
		expectError bool
	}{
		{
			name: "normal package",
			pkg:  createTestPackage("test-package", "A test package", 5),
			expectError: false,
		},
		{
			name: "suspicious package",
			pkg:  createTestPackage("malware-test", "Suspicious package with malware", 50),
			expectError: false,
		},
		{
			name: "complex package",
			pkg:  createTestPackage("complex-pkg", "Complex package with many dependencies", 100),
			expectError: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			result, err := suite.AnalyzePackageWithNovelAlgorithms(ctx, tc.pkg)

			if tc.expectError {
				assert.Error(t, err)
				assert.Nil(t, result)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, result)
				assert.Equal(t, tc.pkg.Name, result.PackageID)
				assert.NotEmpty(t, result.Algorithms)
				assert.GreaterOrEqual(t, result.EnsembleScore, 0.0)
				assert.LessOrEqual(t, result.EnsembleScore, 1.0)
				assert.GreaterOrEqual(t, result.Confidence, 0.0)
				assert.LessOrEqual(t, result.Confidence, 1.0)
				assert.NotEmpty(t, result.ThreatLevel)
				assert.NotEmpty(t, result.Recommendations)
			}
		})
	}
}

func TestQuantumInspiredNeuralNetwork(t *testing.T) {
	config := createTestConfig()
	logger := createTestLogger()
	suite := NewNovelAlgorithmSuite(config, logger)

	// Test quantum-inspired network initialization
	assert.NotNil(t, suite.quantumInspiredNet)
	assert.Equal(t, 3, len(suite.quantumInspiredNet.layers))
	assert.Equal(t, 3, len(suite.quantumInspiredNet.quantumGates))
	assert.GreaterOrEqual(t, suite.quantumInspiredNet.coherence, 0.8)

	// Test quantum features
	pkg := createTestPackage("quantum-test", "Test package", 10)
	features := suite.extractQuantumFeatures(pkg)
	assert.Contains(t, features, "quantum_coherence")
	assert.Contains(t, features, "superposition_states")
	assert.Contains(t, features, "entanglement_pairs")
	assert.Contains(t, features, "quantum_gates")
}

func TestGraphAttentionNetwork(t *testing.T) {
	config := createTestConfig()
	logger := createTestLogger()
	suite := NewNovelAlgorithmSuite(config, logger)

	// Test graph attention network initialization
	assert.NotNil(t, suite.graphAttentionNet)
	assert.Equal(t, 8, suite.graphAttentionNet.attentionHeads)
	assert.Equal(t, 256, suite.graphAttentionNet.hiddenDim)
	assert.Equal(t, 64, suite.graphAttentionNet.outputDim)
	assert.Equal(t, 3, len(suite.graphAttentionNet.linearLayers))

	// Test graph features
	pkg := createTestPackage("graph-test", "Test package", 20)
	features := suite.extractGraphFeatures(pkg)
	assert.Contains(t, features, "attention_heads")
	assert.Contains(t, features, "hidden_dimension")
	assert.Contains(t, features, "dependency_count")
	assert.Equal(t, float64(20), features["dependency_count"])
}

func TestAdversarialMLDetector(t *testing.T) {
	config := createTestConfig()
	logger := createTestLogger()
	suite := NewNovelAlgorithmSuite(config, logger)

	// Test adversarial detector initialization
	assert.NotNil(t, suite.adversarialDetector)
	assert.Equal(t, 3, len(suite.adversarialDetector.defenseStrategies))
	assert.Equal(t, 3, len(suite.adversarialDetector.attackDetectors))
	assert.True(t, suite.adversarialDetector.gradientMasking)

	// Test defense strategies
	for _, strategy := range suite.adversarialDetector.defenseStrategies {
		assert.NotEmpty(t, strategy.Name)
		assert.NotEmpty(t, strategy.Type)
		assert.GreaterOrEqual(t, strategy.Effectiveness, 0.0)
		assert.LessOrEqual(t, strategy.Effectiveness, 1.0)
	}

	// Test attack detectors
	for _, detector := range suite.adversarialDetector.attackDetectors {
		assert.NotEmpty(t, detector.AttackType)
		assert.GreaterOrEqual(t, detector.DetectionRate, 0.0)
		assert.LessOrEqual(t, detector.DetectionRate, 1.0)
		assert.GreaterOrEqual(t, detector.FalsePositiveRate, 0.0)
		assert.LessOrEqual(t, detector.FalsePositiveRate, 1.0)
	}
}

func TestPackageTransformer(t *testing.T) {
	config := createTestConfig()
	logger := createTestLogger()
	suite := NewNovelAlgorithmSuite(config, logger)

	// Test transformer initialization
	assert.NotNil(t, suite.transformerModel)
	assert.Equal(t, 6, len(suite.transformerModel.encoderLayers))
	assert.Equal(t, 6, len(suite.transformerModel.decoderLayers))
	assert.Equal(t, 8, suite.transformerModel.attentionHeads)
	assert.Equal(t, 512, suite.transformerModel.modelDimension)
	assert.Equal(t, 2048, suite.transformerModel.feedForwardDim)
}

func TestFederatedLearningEngine(t *testing.T) {
	config := createTestConfig()
	logger := createTestLogger()
	suite := NewNovelAlgorithmSuite(config, logger)

	// Test federated learning initialization
	assert.NotNil(t, suite.federatedLearner)
	assert.Equal(t, "federated_averaging", suite.federatedLearner.aggregationStrategy)
	assert.NotNil(t, suite.federatedLearner.privacyMechanism)
	assert.Equal(t, 1.0, suite.federatedLearner.privacyMechanism.epsilon)
	assert.Equal(t, 1e-5, suite.federatedLearner.privacyMechanism.delta)
	assert.Equal(t, "gaussian", suite.federatedLearner.privacyMechanism.noiseType)
}

func TestCausalInferenceEngine(t *testing.T) {
	config := createTestConfig()
	logger := createTestLogger()
	suite := NewNovelAlgorithmSuite(config, logger)

	// Test causal inference initialization
	assert.NotNil(t, suite.causalInference)
	assert.NotNil(t, suite.causalInference.causalGraph)
	assert.Equal(t, 4, len(suite.causalInference.confounders))
	assert.Equal(t, 2, len(suite.causalInference.mediators))
	assert.Equal(t, 2, len(suite.causalInference.colliders))

	// Test confounders
	expectedConfounders := []string{"package_age", "author_reputation", "download_count", "maintenance_activity"}
	for _, confounder := range expectedConfounders {
		assert.Contains(t, suite.causalInference.confounders, confounder)
	}
}

func TestMetaLearningSystem(t *testing.T) {
	config := createTestConfig()
	logger := createTestLogger()
	suite := NewNovelAlgorithmSuite(config, logger)

	// Test meta-learning initialization
	assert.NotNil(t, suite.metaLearner)
	assert.NotNil(t, suite.metaLearner.metaModel)
	assert.Equal(t, 5, suite.metaLearner.adaptationSteps)
	assert.Equal(t, 0.001, suite.metaLearner.learningRate)
	assert.Equal(t, 0.01, suite.metaLearner.metaLearningRate)

	// Test base model
	assert.NotNil(t, suite.metaLearner.metaModel.baseModel)
	assert.Equal(t, 3, len(suite.metaLearner.metaModel.baseModel.layers))
	assert.Equal(t, "adam", suite.metaLearner.metaModel.baseModel.optimizer)
	assert.Equal(t, "binary_crossentropy", suite.metaLearner.metaModel.baseModel.lossFunction)
}

func TestSwarmIntelligenceOptimizer(t *testing.T) {
	config := createTestConfig()
	logger := createTestLogger()
	suite := NewNovelAlgorithmSuite(config, logger)

	// Test swarm optimizer initialization
	assert.NotNil(t, suite.swarmIntelligence)
	assert.Equal(t, 50, len(suite.swarmIntelligence.particles))
	assert.Equal(t, 0.9, suite.swarmIntelligence.inertiaWeight)
	assert.Equal(t, 2.0, suite.swarmIntelligence.cognitiveFactor)
	assert.Equal(t, 2.0, suite.swarmIntelligence.socialFactor)
	assert.Equal(t, 1000, suite.swarmIntelligence.maxIterations)
	assert.Equal(t, 1e-6, suite.swarmIntelligence.convergence)
}

func TestNeuroEvolutionEngine(t *testing.T) {
	config := createTestConfig()
	logger := createTestLogger()
	suite := NewNovelAlgorithmSuite(config, logger)

	// Test neuroevolution initialization
	assert.NotNil(t, suite.neuroEvolution)
	assert.Equal(t, 100, len(suite.neuroEvolution.population))
	assert.Equal(t, 100, suite.neuroEvolution.populationSize)
	assert.Equal(t, 50, suite.neuroEvolution.generations)
	assert.Equal(t, 0.1, suite.neuroEvolution.mutationRate)
	assert.Equal(t, 0.7, suite.neuroEvolution.crossoverRate)
	assert.Equal(t, "tournament", suite.neuroEvolution.selectionMethod)
	assert.Equal(t, 10, suite.neuroEvolution.eliteSize)
}

func TestQuantumMLProcessor(t *testing.T) {
	config := createTestConfig()
	logger := createTestLogger()
	suite := NewNovelAlgorithmSuite(config, logger)

	// Test quantum ML initialization
	assert.NotNil(t, suite.quantumML)
	assert.NotNil(t, suite.quantumML.quantumCircuit)
	assert.Equal(t, 4, suite.quantumML.quantumCircuit.qubits)
	assert.Equal(t, 10, suite.quantumML.quantumCircuit.depth)

	// Test quantum kernel
	assert.NotNil(t, suite.quantumML.quantumKernel)
	assert.Equal(t, "qasm_simulator", suite.quantumML.quantumKernel.quantumDevice)
	assert.Equal(t, 1024, suite.quantumML.quantumKernel.shots)

	// Test feature map
	assert.NotNil(t, suite.quantumML.quantumKernel.featureMap)
	assert.Equal(t, "angle", suite.quantumML.quantumKernel.featureMap.encoding)
	assert.Equal(t, 2, suite.quantumML.quantumKernel.featureMap.repetitions)
	assert.Equal(t, "linear", suite.quantumML.quantumKernel.featureMap.entanglement)
}

func TestEnsembleScoring(t *testing.T) {
	config := createTestConfig()
	logger := createTestLogger()
	suite := NewNovelAlgorithmSuite(config, logger)

	// Test ensemble scoring with different algorithm results
	algorithms := map[string]*AlgorithmResult{
		"quantum_inspired": {
			Score:      0.8,
			Confidence: 0.9,
		},
		"graph_attention": {
			Score:      0.6,
			Confidence: 0.85,
		},
		"transformer": {
			Score:      0.7,
			Confidence: 0.88,
		},
	}

	ensembleScore := suite.computeEnsembleScore(algorithms)
	assert.GreaterOrEqual(t, ensembleScore, 0.0)
	assert.LessOrEqual(t, ensembleScore, 1.0)

	// Test threat level determination
	threatLevel := suite.determineThreatLevel(ensembleScore)
	assert.NotEmpty(t, threatLevel)
	assert.Contains(t, []string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "MINIMAL"}, threatLevel)

	// Test confidence computation
	confidence := suite.computeConfidence(algorithms)
	assert.GreaterOrEqual(t, confidence, 0.0)
	assert.LessOrEqual(t, confidence, 1.0)
}

func TestThreatLevelDetermination(t *testing.T) {
	config := createTestConfig()
	logger := createTestLogger()
	suite := NewNovelAlgorithmSuite(config, logger)

	testCases := []struct {
		score    float64
		expected string
	}{
		{0.9, "CRITICAL"},
		{0.8, "CRITICAL"},
		{0.7, "HIGH"},
		{0.6, "HIGH"},
		{0.5, "MEDIUM"},
		{0.4, "MEDIUM"},
		{0.3, "LOW"},
		{0.2, "LOW"},
		{0.1, "MINIMAL"},
		{0.0, "MINIMAL"},
	}

	for _, tc := range testCases {
		t.Run(fmt.Sprintf("score_%.1f", tc.score), func(t *testing.T) {
			threatLevel := suite.determineThreatLevel(tc.score)
			assert.Equal(t, tc.expected, threatLevel)
		})
	}
}

func TestRecommendationGeneration(t *testing.T) {
	config := createTestConfig()
	logger := createTestLogger()
	suite := NewNovelAlgorithmSuite(config, logger)

	testCases := []struct {
		name          string
		ensembleScore float64
		expectedCount int
	}{
		{"critical_threat", 0.9, 3},
		{"high_threat", 0.7, 3},
		{"medium_threat", 0.5, 2},
		{"low_threat", 0.3, 1},
		{"minimal_threat", 0.1, 1},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := &NovelAnalysisResult{
				EnsembleScore: tc.ensembleScore,
				Algorithms:    make(map[string]*AlgorithmResult),
			}

			recommendations := suite.generateRecommendations(result)
			assert.GreaterOrEqual(t, len(recommendations), tc.expectedCount)
			assert.NotEmpty(t, recommendations[0])
		})
	}
}

func TestConfigurationUpdate(t *testing.T) {
	config := createTestConfig()
	logger := createTestLogger()
	suite := NewNovelAlgorithmSuite(config, logger)

	// Test configuration update
	newConfig := createTestConfig()
	newConfig.LearningRate = 0.01
	newConfig.BatchSize = 64

	err := suite.UpdateConfiguration(newConfig)
	assert.NoError(t, err)
	assert.Equal(t, newConfig, suite.config)
	assert.Equal(t, 0.01, suite.config.LearningRate)
	assert.Equal(t, 64, suite.config.BatchSize)
}

func TestGetMetrics(t *testing.T) {
	config := createTestConfig()
	logger := createTestLogger()
	suite := NewNovelAlgorithmSuite(config, logger)

	metrics := suite.GetMetrics()
	assert.NotNil(t, metrics)

	// Check that metrics contain expected algorithm data
	if config.QuantumInspiredEnabled {
		assert.Contains(t, metrics, "quantum_inspired")
		quantumMetrics := metrics["quantum_inspired"].(map[string]interface{})
		assert.Contains(t, quantumMetrics, "coherence")
		assert.Contains(t, quantumMetrics, "layers")
		assert.Contains(t, quantumMetrics, "quantum_gates")
	}

	if config.GraphAttentionEnabled {
		assert.Contains(t, metrics, "graph_attention")
		graphMetrics := metrics["graph_attention"].(map[string]interface{})
		assert.Contains(t, graphMetrics, "attention_heads")
		assert.Contains(t, graphMetrics, "hidden_dim")
	}

	if config.AdversarialDetectionEnabled {
		assert.Contains(t, metrics, "adversarial_detection")
		adversarialMetrics := metrics["adversarial_detection"].(map[string]interface{})
		assert.Contains(t, adversarialMetrics, "defense_strategies")
		assert.Contains(t, adversarialMetrics, "attack_detectors")
	}
}

func TestShutdown(t *testing.T) {
	config := createTestConfig()
	logger := createTestLogger()
	suite := NewNovelAlgorithmSuite(config, logger)

	ctx := context.Background()
	err := suite.Shutdown(ctx)
	assert.NoError(t, err)
}

// Benchmark tests
func BenchmarkNovelAlgorithmSuite_AnalyzePackage(b *testing.B) {
	config := createTestConfig()
	logger := createTestLogger()
	suite := NewNovelAlgorithmSuite(config, logger)
	pkg := createTestPackage("benchmark-test", "Benchmark test package", 25)
	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := suite.AnalyzePackageWithNovelAlgorithms(ctx, pkg)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkQuantumInspiredAnalysis(b *testing.B) {
	config := createTestConfig()
	logger := createTestLogger()
	suite := NewNovelAlgorithmSuite(config, logger)
	pkg := createTestPackage("quantum-benchmark", "Quantum benchmark test", 10)
	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := suite.performQuantumInspiredAnalysis(ctx, pkg)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkGraphAttentionAnalysis(b *testing.B) {
	config := createTestConfig()
	logger := createTestLogger()
	suite := NewNovelAlgorithmSuite(config, logger)
	pkg := createTestPackage("graph-benchmark", "Graph benchmark test", 30)
	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := suite.performGraphAttentionAnalysis(ctx, pkg)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkEnsembleScoring(b *testing.B) {
	config := createTestConfig()
	logger := createTestLogger()
	suite := NewNovelAlgorithmSuite(config, logger)

	algorithms := map[string]*AlgorithmResult{
		"quantum_inspired": {Score: 0.8, Confidence: 0.9},
		"graph_attention": {Score: 0.6, Confidence: 0.85},
		"transformer": {Score: 0.7, Confidence: 0.88},
		"adversarial_detection": {Score: 0.5, Confidence: 0.82},
		"federated_learning": {Score: 0.65, Confidence: 0.8},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = suite.computeEnsembleScore(algorithms)
	}
}

// Integration tests with different configurations
func TestNovelAlgorithmSuite_PartialConfiguration(t *testing.T) {
	// Test with only some algorithms enabled
	config := &NovelAlgorithmConfig{
		QuantumInspiredEnabled:    true,
		GraphAttentionEnabled:     false,
		AdversarialDetectionEnabled: true,
		TransformerEnabled:        false,
		FederatedLearningEnabled:  false,
		CausalInferenceEnabled:    false,
		MetaLearningEnabled:       false,
		SwarmOptimizationEnabled:  false,
		NeuroEvolutionEnabled:     false,
		QuantumMLEnabled:          false,
		LearningRate:              0.001,
		BatchSize:                 32,
		Epochs:                    100,
		Regularization:            0.01,
		DropoutRate:               0.2,
	}

	logger := createTestLogger()
	suite := NewNovelAlgorithmSuite(config, logger)

	assert.NotNil(t, suite.quantumInspiredNet)
	assert.Nil(t, suite.graphAttentionNet)
	assert.NotNil(t, suite.adversarialDetector)
	assert.Nil(t, suite.transformerModel)

	// Test analysis with partial configuration
	pkg := createTestPackage("partial-test", "Partial configuration test", 15)
	ctx := context.Background()
	result, err := suite.AnalyzePackageWithNovelAlgorithms(ctx, pkg)

	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Contains(t, result.Algorithms, "quantum_inspired")
	assert.Contains(t, result.Algorithms, "adversarial_detection")
	assert.NotContains(t, result.Algorithms, "graph_attention")
	assert.NotContains(t, result.Algorithms, "transformer")
}

func TestNovelAlgorithmSuite_ErrorHandling(t *testing.T) {
	config := createTestConfig()
	logger := createTestLogger()
	suite := NewNovelAlgorithmSuite(config, logger)

	// Test with nil package
	ctx := context.Background()
	result, err := suite.AnalyzePackageWithNovelAlgorithms(ctx, nil)
	assert.Error(t, err)
	assert.Nil(t, result)

	// Test with context cancellation
	cancelCtx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	pkg := createTestPackage("cancel-test", "Context cancellation test", 5)
	result, err = suite.AnalyzePackageWithNovelAlgorithms(cancelCtx, pkg)
	// Should handle cancellation gracefully
	if err != nil {
		assert.Contains(t, err.Error(), "context")
	}
}

func TestNovelAlgorithmSuite_ConcurrentAccess(t *testing.T) {
	config := createTestConfig()
	logger := createTestLogger()
	suite := NewNovelAlgorithmSuite(config, logger)

	// Test concurrent access to the suite
	const numGoroutines = 10
	const numAnalyses = 5

	var wg sync.WaitGroup
	errorChan := make(chan error, numGoroutines*numAnalyses)

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < numAnalyses; j++ {
				pkg := createTestPackage(fmt.Sprintf("concurrent-test-%d-%d", id, j), "Concurrent test", 10)
				ctx := context.Background()
				_, err := suite.AnalyzePackageWithNovelAlgorithms(ctx, pkg)
				if err != nil {
					errorChan <- err
				}
			}
		}(i)
	}

	wg.Wait()
	close(errorChan)

	// Check for errors
	for err := range errorChan {
		t.Errorf("Concurrent access error: %v", err)
	}
}

func TestNovelAlgorithmSuite_MemoryUsage(t *testing.T) {
	config := createTestConfig()
	logger := createTestLogger()
	suite := NewNovelAlgorithmSuite(config, logger)

	// Test memory usage with large packages
	largePackage := createTestPackage("large-test", "Large package test with many dependencies", 1000)
	ctx := context.Background()

	// Measure memory before
	var m1, m2 runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&m1)

	// Perform analysis
	result, err := suite.AnalyzePackageWithNovelAlgorithms(ctx, largePackage)
	assert.NoError(t, err)
	assert.NotNil(t, result)

	// Measure memory after
	runtime.GC()
	runtime.ReadMemStats(&m2)

	// Check memory usage is reasonable (less than 100MB increase)
	memoryIncrease := m2.Alloc - m1.Alloc
	assert.Less(t, memoryIncrease, uint64(100*1024*1024), "Memory usage should be reasonable")
}

func TestNovelAlgorithmSuite_Performance(t *testing.T) {
	config := createTestConfig()
	logger := createTestLogger()
	suite := NewNovelAlgorithmSuite(config, logger)

	pkg := createTestPackage("performance-test", "Performance test package", 50)
	ctx := context.Background()

	// Measure execution time
	start := time.Now()
	result, err := suite.AnalyzePackageWithNovelAlgorithms(ctx, pkg)
	duration := time.Since(start)

	assert.NoError(t, err)
	assert.NotNil(t, result)

	// Analysis should complete within reasonable time (10 seconds)
	assert.Less(t, duration, 10*time.Second, "Analysis should complete within 10 seconds")

	// Check that all enabled algorithms were executed
	expectedAlgorithms := []string{
		"quantum_inspired", "graph_attention", "adversarial_detection",
		"transformer", "federated_learning", "causal_inference",
		"meta_learning", "swarm_optimization", "neuroevolution", "quantum_ml",
	}

	for _, alg := range expectedAlgorithms {
		assert.Contains(t, result.Algorithms, alg, "Algorithm %s should be present in results", alg)
	}
}