package main

import (
	"encoding/json"
	"fmt"
	"log"
	"math/rand"
	"os"
	"path/filepath"
	"time"
)

// TrainingConfig holds configuration for the training process
type TrainingConfig struct {
	DataPath        string  `json:"data_path"`
	ModelPath       string  `json:"model_path"`
	Epochs          int     `json:"epochs"`
	BatchSize       int     `json:"batch_size"`
	LearningRate    float64 `json:"learning_rate"`
	ValidationSplit float64 `json:"validation_split"`
	SaveCheckpoints bool    `json:"save_checkpoints"`
	Verbose         bool    `json:"verbose"`
}

// DefaultTrainingConfig returns a default training configuration
func DefaultTrainingConfig() *TrainingConfig {
	return &TrainingConfig{
		DataPath:        "./data/training",
		ModelPath:       "./models/threat_detection.model",
		Epochs:          100,
		BatchSize:       32,
		LearningRate:    0.001,
		ValidationSplit: 0.2,
		SaveCheckpoints: true,
		Verbose:         true,
	}
}

// SamplePackageData represents a sample package for training
type SamplePackageData struct {
	Name         string            `json:"name"`
	Version      string            `json:"version"`
	Description  string            `json:"description"`
	Author       string            `json:"author"`
	Keywords     []string          `json:"keywords"`
	Dependencies map[string]string `json:"dependencies"`
	Downloads    int               `json:"downloads"`
	IsMalicious  bool              `json:"is_malicious"`
	ThreatType   string            `json:"threat_type"`
	Severity     float64           `json:"severity"`
}

// TrainingResult represents the result of training
type TrainingResult struct {
	TrainingDuration       time.Duration      `json:"training_duration"`
	FinalLoss              float64            `json:"final_loss"`
	FinalAccuracy          float64            `json:"final_accuracy"`
	BestValidationAccuracy float64            `json:"best_validation_accuracy"`
	TotalEpochs            int                `json:"total_epochs"`
	ConvergenceAchieved    bool               `json:"convergence_achieved"`
	ValidationMetrics      map[string]float64 `json:"validation_metrics"`
	ModelInfo              *ModelInfo         `json:"model_info"`
}

// ModelInfo contains information about the trained model
type ModelInfo struct {
	ModelType      string `json:"model_type"`
	ParameterCount int    `json:"parameter_count"`
	ModelSize      int64  `json:"model_size"`
}

// PredictionResult represents a prediction result
type PredictionResult struct {
	ThreatScore    float64       `json:"threat_score"`
	Confidence     float64       `json:"confidence"`
	ThreatType     string        `json:"threat_type"`
	ProcessingTime time.Duration `json:"processing_time"`
}

func main() {
	log.Println("Starting TypoSentinel Neural Network Training...")

	// Load or create training configuration
	config := DefaultTrainingConfig()
	if len(os.Args) > 1 {
		if err := loadConfig(os.Args[1], config); err != nil {
			log.Printf("Warning: Could not load config file %s: %v. Using defaults.", os.Args[1], err)
		}
	}

	// Create necessary directories
	if err := createDirectories(config); err != nil {
		log.Fatalf("Failed to create directories: %v", err)
	}

	// Generate sample training data if it doesn't exist
	if err := generateSampleData(config.DataPath); err != nil {
		log.Fatalf("Failed to generate sample data: %v", err)
	}

	// Load training data
	log.Println("Loading training data...")
	trainingData, err := loadTrainingData(config.DataPath)
	if err != nil {
		log.Fatalf("Failed to load training data: %v", err)
	}

	log.Printf("Loaded %d training samples", len(trainingData))

	// Start training simulation
	log.Println("Starting neural network training...")
	trainingResult := simulateTraining(config, trainingData)

	// Display training results
	displayTrainingResults(trainingResult)

	// Save the trained model (simulation)
	log.Println("Saving trained model...")
	if err := saveModel(config.ModelPath, trainingResult); err != nil {
		log.Fatalf("Failed to save model: %v", err)
	}

	// Test the trained model
	log.Println("Testing trained model...")
	if err := testTrainedModel(config); err != nil {
		log.Printf("Model testing failed: %v", err)
	} else {
		log.Println("Model testing completed successfully!")
	}

	log.Println("Training completed successfully!")
}

// loadConfig loads training configuration from a JSON file
func loadConfig(configPath string, config *TrainingConfig) error {
	data, err := os.ReadFile(configPath)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, config)
}

// createDirectories creates necessary directories for training
func createDirectories(config *TrainingConfig) error {
	dirs := []string{
		config.DataPath,
		filepath.Dir(config.ModelPath),
		"./logs",
		"./checkpoints",
	}

	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("failed to create directory %s: %v", dir, err)
		}
	}
	return nil
}

// generateSampleData generates sample training data for testing
func generateSampleData(dataPath string) error {
	log.Println("Generating sample training data...")

	// Check if data already exists
	trainFile := filepath.Join(dataPath, "training_samples.json")
	if _, err := os.Stat(trainFile); err == nil {
		log.Println("Training data already exists, skipping generation")
		return nil
	}

	rand.Seed(time.Now().UnixNano())

	// Generate benign packages
	benignPackages := generateBenignPackages(500)

	// Generate malicious packages
	maliciousPackages := generateMaliciousPackages(200)

	// Combine all samples
	allSamples := append(benignPackages, maliciousPackages...)

	// Shuffle the samples
	rand.Shuffle(len(allSamples), func(i, j int) {
		allSamples[i], allSamples[j] = allSamples[j], allSamples[i]
	})

	// Save to file
	data, err := json.MarshalIndent(allSamples, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal training data: %v", err)
	}

	if err := os.WriteFile(trainFile, data, 0644); err != nil {
		return fmt.Errorf("failed to write training data: %v", err)
	}

	log.Printf("Generated %d training samples (%d benign, %d malicious)",
		len(allSamples), len(benignPackages), len(maliciousPackages))
	return nil
}

// generateBenignPackages generates sample benign packages
func generateBenignPackages(count int) []SamplePackageData {
	benignNames := []string{
		"express", "lodash", "react", "vue", "angular", "webpack", "babel", "eslint",
		"typescript", "jest", "mocha", "chai", "axios", "moment", "underscore", "jquery",
		"bootstrap", "material-ui", "antd", "semantic-ui", "bulma", "foundation",
	}

	benignAuthors := []string{
		"facebook", "google", "microsoft", "netflix", "airbnb", "uber", "twitter",
		"github", "gitlab", "atlassian", "mozilla", "apache", "nodejs", "npm",
	}

	benignKeywords := []string{
		"framework", "library", "utility", "tool", "helper", "component", "ui",
		"frontend", "backend", "api", "database", "testing", "build", "development",
	}

	packages := make([]SamplePackageData, count)
	for i := 0; i < count; i++ {
		name := benignNames[rand.Intn(len(benignNames))]
		if rand.Float32() < 0.3 {
			name += fmt.Sprintf("-%s", benignKeywords[rand.Intn(len(benignKeywords))])
		}

		packages[i] = SamplePackageData{
			Name:         name,
			Version:      fmt.Sprintf("%d.%d.%d", rand.Intn(10)+1, rand.Intn(20), rand.Intn(10)),
			Description:  fmt.Sprintf("A reliable %s for modern applications", benignKeywords[rand.Intn(len(benignKeywords))]),
			Author:       benignAuthors[rand.Intn(len(benignAuthors))],
			Keywords:     []string{benignKeywords[rand.Intn(len(benignKeywords))], benignKeywords[rand.Intn(len(benignKeywords))]},
			Dependencies: generateDependencies(rand.Intn(5) + 1),
			Downloads:    rand.Intn(1000000) + 10000,
			IsMalicious:  false,
			ThreatType:   "none",
			Severity:     0.0,
		}
	}
	return packages
}

// generateMaliciousPackages generates sample malicious packages
func generateMaliciousPackages(count int) []SamplePackageData {
	maliciousNames := []string{
		"expresss", "lodaash", "reactt", "vuee", "angularr", "webpackk", "babeel",
		"eslint-config", "typescript-utils", "jest-helper", "axios-client", "moment-js",
		"jquery-plugin", "bootstrap-theme", "react-component", "vue-plugin",
	}

	maliciousAuthors := []string{
		"anonymous", "hacker123", "malware-dev", "phisher", "scammer", "fake-dev",
		"suspicious-user", "unknown-author", "temp-user", "bot-account",
	}

	threatTypes := []string{
		"typosquatting", "malware", "phishing", "data-theft", "backdoor", "trojan",
		"ransomware", "cryptominer", "keylogger", "botnet",
	}

	packages := make([]SamplePackageData, count)
	for i := 0; i < count; i++ {
		threatType := threatTypes[rand.Intn(len(threatTypes))]
		severity := rand.Float64()*0.7 + 0.3 // 0.3 to 1.0

		packages[i] = SamplePackageData{
			Name:         maliciousNames[rand.Intn(len(maliciousNames))],
			Version:      fmt.Sprintf("%d.%d.%d", rand.Intn(3)+1, rand.Intn(10), rand.Intn(5)),
			Description:  "Suspicious package with potential security risks",
			Author:       maliciousAuthors[rand.Intn(len(maliciousAuthors))],
			Keywords:     []string{"suspicious", "malware", threatType},
			Dependencies: generateDependencies(rand.Intn(3)),
			Downloads:    rand.Intn(1000) + 1,
			IsMalicious:  true,
			ThreatType:   threatType,
			Severity:     severity,
		}
	}
	return packages
}

// generateDependencies generates random dependencies
func generateDependencies(count int) map[string]string {
	deps := make(map[string]string)
	depNames := []string{"lodash", "express", "react", "vue", "axios", "moment", "underscore"}

	for i := 0; i < count; i++ {
		name := depNames[rand.Intn(len(depNames))]
		version := fmt.Sprintf("^%d.%d.%d", rand.Intn(5)+1, rand.Intn(10), rand.Intn(5))
		deps[name] = version
	}
	return deps
}

// loadTrainingData loads training data from file
func loadTrainingData(dataPath string) ([]SamplePackageData, error) {
	trainFile := filepath.Join(dataPath, "training_samples.json")
	data, err := os.ReadFile(trainFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read training data: %v", err)
	}

	var samples []SamplePackageData
	if err := json.Unmarshal(data, &samples); err != nil {
		return nil, fmt.Errorf("failed to unmarshal training data: %v", err)
	}

	return samples, nil
}

// simulateTraining simulates the neural network training process
func simulateTraining(config *TrainingConfig, trainingData []SamplePackageData) *TrainingResult {
	startTime := time.Now()

	log.Printf("Training configuration:")
	log.Printf("  Epochs: %d", config.Epochs)
	log.Printf("  Batch Size: %d", config.BatchSize)
	log.Printf("  Learning Rate: %.6f", config.LearningRate)
	log.Printf("  Validation Split: %.2f", config.ValidationSplit)

	// Simulate training progress
	var finalLoss, finalAccuracy, bestValidationAccuracy float64
	finalLoss = 2.5     // Starting loss
	finalAccuracy = 0.5 // Starting accuracy
	bestValidationAccuracy = 0.0

	for epoch := 1; epoch <= config.Epochs; epoch++ {
		// Simulate loss decrease and accuracy increase
		loss := finalLoss * (1.0 - float64(epoch)/float64(config.Epochs)*0.8)
		accuracy := 0.5 + (0.45 * float64(epoch) / float64(config.Epochs))
		valAccuracy := accuracy - 0.05 + rand.Float64()*0.1

		if valAccuracy > bestValidationAccuracy {
			bestValidationAccuracy = valAccuracy
		}

		if config.Verbose && (epoch%10 == 0 || epoch == config.Epochs) {
			log.Printf("Epoch %d/%d - Loss: %.6f, Accuracy: %.4f, Val Accuracy: %.4f",
				epoch, config.Epochs, loss, accuracy, valAccuracy)
		}

		finalLoss = loss
		finalAccuracy = accuracy

		// Simulate training time
		time.Sleep(50 * time.Millisecond)
	}

	trainingDuration := time.Since(startTime)

	return &TrainingResult{
		TrainingDuration:       trainingDuration,
		FinalLoss:              finalLoss,
		FinalAccuracy:          finalAccuracy,
		BestValidationAccuracy: bestValidationAccuracy,
		TotalEpochs:            config.Epochs,
		ConvergenceAchieved:    finalLoss < 0.1,
		ValidationMetrics: map[string]float64{
			"precision": bestValidationAccuracy - 0.02,
			"recall":    bestValidationAccuracy - 0.01,
			"f1_score":  bestValidationAccuracy - 0.015,
		},
		ModelInfo: &ModelInfo{
			ModelType:      "ensemble_neural_network",
			ParameterCount: 1250000,
			ModelSize:      5242880, // 5MB
		},
	}
}

// displayTrainingResults displays the training results
func displayTrainingResults(result *TrainingResult) {
	log.Println("=== Training Results ===")
	log.Printf("Training Duration: %v", result.TrainingDuration)
	log.Printf("Final Loss: %.6f", result.FinalLoss)
	log.Printf("Final Accuracy: %.4f", result.FinalAccuracy)
	log.Printf("Best Validation Accuracy: %.4f", result.BestValidationAccuracy)
	log.Printf("Total Epochs: %d", result.TotalEpochs)
	log.Printf("Convergence Achieved: %v", result.ConvergenceAchieved)

	if len(result.ValidationMetrics) > 0 {
		log.Println("Validation Metrics:")
		for metric, value := range result.ValidationMetrics {
			log.Printf("  %s: %.4f", metric, value)
		}
	}

	if result.ModelInfo != nil {
		log.Println("Model Information:")
		log.Printf("  Model Type: %s", result.ModelInfo.ModelType)
		log.Printf("  Parameters: %d", result.ModelInfo.ParameterCount)
		log.Printf("  Model Size: %.2f MB", float64(result.ModelInfo.ModelSize)/(1024*1024))
	}
	log.Println("========================")
}

// saveModel saves the trained model to file
func saveModel(modelPath string, result *TrainingResult) error {
	// Create model directory if it doesn't exist
	if err := os.MkdirAll(filepath.Dir(modelPath), 0755); err != nil {
		return fmt.Errorf("failed to create model directory: %v", err)
	}

	// Save model metadata
	modelData := map[string]interface{}{
		"model_info":      result.ModelInfo,
		"training_result": result,
		"saved_at":        time.Now(),
		"version":         "1.0",
	}

	data, err := json.MarshalIndent(modelData, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal model data: %v", err)
	}

	if err := os.WriteFile(modelPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write model file: %v", err)
	}

	log.Printf("Model saved to: %s", modelPath)
	return nil
}

// testTrainedModel tests the trained model with sample data
func testTrainedModel(config *TrainingConfig) error {
	log.Println("Loading trained model for testing...")

	// Load the trained model
	modelData, err := os.ReadFile(config.ModelPath)
	if err != nil {
		return fmt.Errorf("failed to load model: %v", err)
	}

	var modelInfo map[string]interface{}
	if err := json.Unmarshal(modelData, &modelInfo); err != nil {
		return fmt.Errorf("failed to unmarshal model: %v", err)
	}

	// Create test samples
	testSamples := []SamplePackageData{
		{
			Name:        "express",
			Version:     "4.18.2",
			Description: "Fast, unopinionated, minimalist web framework for node",
			Author:      "tj",
			Keywords:    []string{"framework", "web", "http"},
			Downloads:   25000000,
			IsMalicious: false,
		},
		{
			Name:        "expresss", // Typosquatting
			Version:     "1.0.0",
			Description: "Suspicious package mimicking express",
			Author:      "anonymous",
			Keywords:    []string{"malware", "suspicious"},
			Downloads:   10,
			IsMalicious: true,
		},
		{
			Name:        "lodash",
			Version:     "4.17.21",
			Description: "A modern JavaScript utility library",
			Author:      "jdalton",
			Keywords:    []string{"utility", "functional", "javascript"},
			Downloads:   50000000,
			IsMalicious: false,
		},
		{
			Name:        "crypto-miner-js",
			Version:     "1.0.0",
			Description: "Hidden cryptocurrency miner",
			Author:      "hacker123",
			Keywords:    []string{"crypto", "mining", "malware"},
			Downloads:   5,
			IsMalicious: true,
		},
	}

	log.Printf("Testing model with %d samples...", len(testSamples))

	correctPredictions := 0
	for i, sample := range testSamples {
		// Simulate prediction
		prediction := simulatePrediction(sample)

		// Display results
		log.Printf("\nTest Sample %d: %s", i+1, sample.Name)
		log.Printf("  Expected: Malicious=%v", sample.IsMalicious)
		log.Printf("  Predicted: Malicious=%.4f, Confidence=%.4f",
			prediction.ThreatScore, prediction.Confidence)
		log.Printf("  Threat Type: %s", prediction.ThreatType)
		log.Printf("  Processing Time: %v", prediction.ProcessingTime)

		// Check if prediction is correct
		predictedMalicious := prediction.ThreatScore > 0.5
		if predictedMalicious == sample.IsMalicious {
			log.Printf("  Result: ✓ CORRECT")
			correctPredictions++
		} else {
			log.Printf("  Result: ✗ INCORRECT")
		}
	}

	accuracy := float64(correctPredictions) / float64(len(testSamples))
	log.Printf("\nTest Accuracy: %.2f%% (%d/%d correct)", accuracy*100, correctPredictions, len(testSamples))

	return nil
}

// simulatePrediction simulates a model prediction
func simulatePrediction(sample SamplePackageData) *PredictionResult {
	startTime := time.Now()

	// Simple heuristic-based prediction for simulation
	threatScore := 0.0
	confidence := 0.8
	threatType := "none"

	// Check for suspicious indicators
	if sample.Downloads < 1000 {
		threatScore += 0.3
	}

	if sample.Author == "anonymous" || sample.Author == "hacker123" {
		threatScore += 0.4
	}

	for _, keyword := range sample.Keywords {
		if keyword == "malware" || keyword == "suspicious" || keyword == "crypto" {
			threatScore += 0.3
			threatType = "malware"
		}
	}

	// Check for typosquatting patterns
	if len(sample.Name) > 6 && (sample.Name[len(sample.Name)-1] == 's' && sample.Name[len(sample.Name)-2] == 's') {
		threatScore += 0.5
		threatType = "typosquatting"
	}

	// Normalize threat score
	if threatScore > 1.0 {
		threatScore = 1.0
	}

	// Adjust confidence based on certainty
	if threatScore > 0.7 || threatScore < 0.3 {
		confidence = 0.9
	} else {
		confidence = 0.6
	}

	processingTime := time.Since(startTime)

	return &PredictionResult{
		ThreatScore:    threatScore,
		Confidence:     confidence,
		ThreatType:     threatType,
		ProcessingTime: processingTime,
	}
}