package ml

import (
	"context"
	"testing"
	"time"

	"github.com/Alivanroy/Typosentinel/internal/config"
	mocks "github.com/Alivanroy/Typosentinel/internal/testing"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTrainingPipeline_StartTraining(t *testing.T) {
	tests := []struct {
		name          string
		modelType     string
		setupData     bool
		expectedError bool
	}{
		{
			name:          "successful_typosquatting_training",
			modelType:     "typosquatting",
			setupData:     true,
			expectedError: false,
		},
		{
			name:          "successful_reputation_training",
			modelType:     "reputation",
			setupData:     true,
			expectedError: false,
		},
		{
			name:          "insufficient_data",
			modelType:     "typosquatting",
			setupData:     false,
			expectedError: true,
		},
		{
			name:          "unsupported_model_type",
			modelType:     "unknown",
			setupData:     true,
			expectedError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup
			cfg := &config.Config{
				MLService: &config.MLServiceConfig{
					Enabled: true,
				},
			}
			
			metricsCollector := mocks.NewMockMetrics()
			pipeline := NewTrainingPipeline(cfg, metricsCollector)

			// Setup training data if needed
			if tt.setupData {
				data, err := pipeline.dataManager.GenerateTrainingData(tt.modelType, 1200)
				require.NoError(t, err)
				
				err = pipeline.dataManager.AddTrainingData(tt.modelType, data)
				require.NoError(t, err)
			}

			// Create training config
			trainingConfig := &TrainingConfig{
				ModelType:       tt.modelType,
				BatchSize:       32,
				Epochs:          5,
				LearningRate:    0.001,
				ValidationSplit: 0.2,
				EarlyStopping:   true,
				Patience:        3,
				MinDelta:        0.001,
				Hyperparameters: make(map[string]interface{}),
			}

			// Test
			ctx := context.Background()
			session, err := pipeline.StartTraining(ctx, tt.modelType, trainingConfig)

			// Assertions
			if tt.expectedError {
				assert.Error(t, err)
				assert.Nil(t, session)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, session)
				assert.Equal(t, tt.modelType, session.ModelType)
				assert.Equal(t, TrainingStatusRunning, session.Status)
				assert.NotEmpty(t, session.ID)

				// Wait for training to complete
				timeout := time.After(30 * time.Second)
				ticker := time.NewTicker(100 * time.Millisecond)
				defer ticker.Stop()

				for {
					select {
					case <-timeout:
						t.Fatal("Training timeout")
					case <-ticker.C:
						if !pipeline.IsTraining() {
							goto trainingComplete
						}
					}
				}

			trainingComplete:
				// Check final status
				history := pipeline.GetTrainingHistory()
				require.Len(t, history, 1)
				
				finalSession := history[0]
				assert.Equal(t, TrainingStatusCompleted, finalSession.Status)
				assert.NotNil(t, finalSession.TrainingMetrics)
				assert.True(t, finalSession.Duration > 0)
			}
		})
	}
}

func TestTrainingDataManager_AddTrainingData(t *testing.T) {
	cfg := &config.Config{}
	manager := NewTrainingDataManager(cfg)

	// Generate test data
	data, err := manager.GenerateTrainingData("typosquatting", 100)
	require.NoError(t, err)
	assert.Len(t, data, 100)

	// Add training data
	err = manager.AddTrainingData("typosquatting", data)
	assert.NoError(t, err)

	// Verify data was added
	assert.True(t, manager.HasSufficientData("typosquatting"))

	// Load and verify data
	loadedData, err := manager.LoadTrainingData("typosquatting")
	assert.NoError(t, err)
	assert.Len(t, loadedData, 100)
}

func TestTrainingDataManager_DataValidation(t *testing.T) {
	cfg := &config.Config{}
	manager := NewTrainingDataManager(cfg)

	// Test with valid data
	validData := []TrainingData{
		{Features: []float64{0.1, 0.2, 0.3}, Label: 0.0},
		{Features: []float64{0.4, 0.5, 0.6}, Label: 1.0},
	}

	err := manager.AddTrainingData("typosquatting", validData)
	assert.NoError(t, err)

	// Test with invalid data (inconsistent feature dimensions)
	invalidData := []TrainingData{
		{Features: []float64{0.1, 0.2}, Label: 0.0},      // 2 features
		{Features: []float64{0.4, 0.5, 0.6}, Label: 1.0}, // 3 features
	}

	err = manager.AddTrainingData("reputation", invalidData)
	assert.Error(t, err)
}

func TestModelEvaluator_EvaluateModel(t *testing.T) {
	evaluator := NewModelEvaluator()

	// Create a mock model
	model := &MockMLModel{
		predictions: []float64{0.1, 0.9, 0.2, 0.8, 0.3},
	}

	// Create test data
	testData := []TrainingData{
		{Features: []float64{0.1}, Label: 0.0},
		{Features: []float64{0.9}, Label: 1.0},
		{Features: []float64{0.2}, Label: 0.0},
		{Features: []float64{0.8}, Label: 1.0},
		{Features: []float64{0.3}, Label: 0.0},
	}

	// Evaluate model
	metrics := evaluator.EvaluateModel(model, testData)

	// Assertions
	assert.NotNil(t, metrics)
	assert.True(t, metrics.Accuracy >= 0.0 && metrics.Accuracy <= 1.0)
	assert.True(t, metrics.Precision >= 0.0 && metrics.Precision <= 1.0)
	assert.True(t, metrics.Recall >= 0.0 && metrics.Recall <= 1.0)
	assert.True(t, metrics.F1Score >= 0.0 && metrics.F1Score <= 1.0)
}

func TestCrossValidator_ValidateModel(t *testing.T) {
	validator := NewCrossValidator(3) // 3-fold validation

	// Create a mock model
	model := &MockMLModel{
		predictions: []float64{0.1, 0.9, 0.2, 0.8, 0.3, 0.7, 0.4, 0.6, 0.5},
	}

	// Create test data (enough for 3-fold validation)
	testData := make([]TrainingData, 9)
	for i := 0; i < 9; i++ {
		testData[i] = TrainingData{
			Features: []float64{float64(i) * 0.1},
			Label:    float64(i % 2),
		}
	}

	// Create training config
	config := &TrainingConfig{
		ModelType:    "typosquatting",
		BatchSize:    2,
		Epochs:       1,
		LearningRate: 0.001,
	}

	// Perform cross-validation
	result, err := validator.ValidateModel(model, testData, config)

	// Assertions
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Len(t, result.FoldResults, 3)
	assert.True(t, result.MeanAccuracy >= 0.0 && result.MeanAccuracy <= 1.0)
	assert.True(t, result.OverallScore >= 0.0 && result.OverallScore <= 1.0)
}

func TestTrainingPipeline_GetTrainingStatus(t *testing.T) {
	cfg := &config.Config{
		MLService: &config.MLServiceConfig{
			Enabled: true,
		},
	}
	
	metricsCollector := mocks.NewMockMetrics()
	pipeline := NewTrainingPipeline(cfg, metricsCollector)

	// Get initial status
	status := pipeline.GetTrainingStatus()
	assert.NotNil(t, status)
	assert.False(t, status["is_training"].(bool))
	assert.Equal(t, 0, status["total_sessions"].(int))
	assert.NotNil(t, status["available_models"])
	assert.NotNil(t, status["data_status"])
}

func TestTrainingDataManager_GenerateTrainingData(t *testing.T) {
	cfg := &config.Config{}
	manager := NewTrainingDataManager(cfg)

	tests := []struct {
		name      string
		modelType string
		count     int
		expectErr bool
	}{
		{
			name:      "generate_typosquatting_data",
			modelType: "typosquatting",
			count:     100,
			expectErr: false,
		},
		{
			name:      "generate_reputation_data",
			modelType: "reputation",
			count:     50,
			expectErr: false,
		},
		{
			name:      "generate_anomaly_data",
			modelType: "anomaly",
			count:     75,
			expectErr: false,
		},
		{
			name:      "unsupported_model_type",
			modelType: "unknown",
			count:     10,
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := manager.GenerateTrainingData(tt.modelType, tt.count)

			if tt.expectErr {
				assert.Error(t, err)
				assert.Nil(t, data)
			} else {
				assert.NoError(t, err)
				assert.Len(t, data, tt.count)

				// Verify data structure
				for _, sample := range data {
					assert.NotEmpty(t, sample.Features)
					assert.True(t, sample.Label >= 0.0 && sample.Label <= 1.0)
					assert.NotNil(t, sample.Metadata)
				}
			}
		})
	}
}

// MockMLModel for testing
type MockMLModel struct {
	predictions []float64
	index       int
	trained     bool
}

func (m *MockMLModel) Predict(features []float64) (*Prediction, error) {
	if m.index >= len(m.predictions) {
		m.index = 0
	}
	
	prediction := &Prediction{
		Model:       "mock",
		Probability: m.predictions[m.index],
		Label:       "test",
		Confidence:  0.8,
	}
	
	m.index++
	return prediction, nil
}

func (m *MockMLModel) Train(data []TrainingData) error {
	m.trained = true
	return nil
}

func (m *MockMLModel) GetModelInfo() *ModelInfo {
	return &ModelInfo{
		Name:    "MockModel",
		Version: "1.0",
		Type:    "test",
	}
}

func (m *MockMLModel) IsReady() bool {
	return true
}

func TestBasicDataValidator_ValidateData(t *testing.T) {
	validator := &BasicDataValidator{modelType: "test"}

	tests := []struct {
		name      string
		data      []TrainingData
		expectErr bool
		isValid   bool
	}{
		{
			name: "valid_data",
			data: []TrainingData{
				{Features: []float64{0.1, 0.2}, Label: 0.0},
				{Features: []float64{0.3, 0.4}, Label: 1.0},
			},
			expectErr: false,
			isValid:   true,
		},
		{
			name:      "empty_data",
			data:      []TrainingData{},
			expectErr: false,
			isValid:   false,
		},
		{
			name: "inconsistent_features",
			data: []TrainingData{
				{Features: []float64{0.1, 0.2}, Label: 0.0},
				{Features: []float64{0.3}, Label: 1.0}, // Different feature count
			},
			expectErr: false,
			isValid:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			report, err := validator.ValidateData(tt.data)

			if tt.expectErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, report)
				assert.Equal(t, tt.isValid, report.IsValid)
				
				if !tt.isValid {
					assert.NotEmpty(t, report.Issues)
				}
			}
		})
	}
}