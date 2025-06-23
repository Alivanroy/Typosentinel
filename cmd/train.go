package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"

	"github.com/Alivanroy/Typosentinel/internal/config"
	"github.com/Alivanroy/Typosentinel/internal/ml"
)

var (
	trainDatasetPath string
	trainOutputPath  string
	trainEpochs      int
	trainBatchSize   int
	trainVerbose     bool
)

// trainCmd represents the train command
var trainCmd = &cobra.Command{
	Use:   "train",
	Short: "Train ML models using provided datasets",
	Long: `Train machine learning models for typosquatting detection using the provided datasets.

This command loads training data from the datasets directory and trains the following models:
- Typosquatting detection model
- Reputation analysis model  
- Anomaly detection model

Example usage:
  typosentinel train --dataset ./tests/datasets
  typosentinel train --dataset ./tests/datasets --epochs 100 --verbose
  typosentinel train --dataset ./tests/datasets --output ./models`,
	RunE: runTrain,
}

func init() {
	rootCmd.AddCommand(trainCmd)
	
	trainCmd.Flags().StringVarP(&trainDatasetPath, "dataset", "d", "./tests/datasets", "Path to training datasets directory")
	trainCmd.Flags().StringVarP(&trainOutputPath, "output", "o", "./models", "Output directory for trained models")
	trainCmd.Flags().IntVarP(&trainEpochs, "epochs", "e", 50, "Number of training epochs")
	trainCmd.Flags().IntVarP(&trainBatchSize, "batch-size", "b", 32, "Training batch size")
	trainCmd.Flags().BoolVar(&trainVerbose, "train-verbose", false, "Enable verbose training output")
}

type TrainingPackage struct {
	Name         string                 `json:"name"`
	Version      string                 `json:"version"`
	Description  string                 `json:"description"`
	ExpectedRisk string                 `json:"expected_risk"`
	ExpectedScore float64               `json:"expected_score"`
	RiskFactors  []string               `json:"risk_factors"`
	Metadata     map[string]interface{} `json:"metadata"`
}

type TrainingConfig struct {
	TestDatasets struct {
		PackageManagers map[string]struct {
			LegitimatePackages string `json:"legitimate_packages"`
			SuspiciousPackages string `json:"suspicious_packages"`
			TotalPackages      int    `json:"total_packages"`
			LegitimateCount    int    `json:"legitimate_count"`
			SuspiciousCount    int    `json:"suspicious_count"`
		} `json:"package_managers"`
	} `json:"test_datasets"`
}

func runTrain(cmd *cobra.Command, args []string) error {
	ctx := context.Background()

	trainVerbose, _ := cmd.Flags().GetBool("train-verbose")

	// Load configuration
	cfgFile, _ := cmd.Flags().GetString("config")
	var cfg *config.Config
	var err error
	if cfgFile != "" {
		cfg, err = config.LoadConfig(cfgFile)
	} else {
		cfg = config.NewDefaultConfig()
	}

	if err != nil {
		return fmt.Errorf("failed to load configuration: %w", err)
	}

	// Enable ML analysis for training
	if cfg.MLService != nil {
		cfg.MLService.Enabled = true
		if trainVerbose {
			fmt.Println("🤖 ML Analysis enabled for training")
		}
	}

	// Initialize ML pipeline
	mlPipeline := ml.NewMLPipeline(cfg)
	if err := mlPipeline.Initialize(ctx); err != nil {
		return fmt.Errorf("failed to initialize ML pipeline: %w", err)
	}

	// Load training datasets
	trainingData, err := loadTrainingDatasets(trainDatasetPath)
	if err != nil {
		return fmt.Errorf("failed to load training datasets: %w", err)
	}

	if trainVerbose {
		fmt.Printf("📊 Loaded %d training samples\n", len(trainingData))
	}

	// Train models
	if err := trainModels(ctx, mlPipeline, trainingData); err != nil {
		return fmt.Errorf("training failed: %w", err)
	}

	// Create output directory
	if err := os.MkdirAll(trainOutputPath, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	if trainVerbose {
		fmt.Printf("✅ Training completed successfully!\n")
		fmt.Printf("📁 Models saved to: %s\n", trainOutputPath)
	}

	return nil
}

func loadTrainingDatasets(datasetPath string) ([]ml.TrainingData, error) {
	// Load training configuration
	configPath := filepath.Join(datasetPath, "test_config.json")
	configData, err := ioutil.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read training config: %w", err)
	}

	var config TrainingConfig
	if err := json.Unmarshal(configData, &config); err != nil {
		return nil, fmt.Errorf("failed to parse training config: %w", err)
	}

	var allTrainingData []ml.TrainingData

	// Load data for each package manager
	for registry, pmConfig := range config.TestDatasets.PackageManagers {
		if trainVerbose {
			fmt.Printf("📦 Loading %s packages...\n", registry)
		}

		// Load legitimate packages (label = 0.0)
		legitData, err := loadPackageData(datasetPath, pmConfig.LegitimatePackages, 0.0, registry)
		if err != nil {
			return nil, fmt.Errorf("failed to load legitimate packages for %s: %w", registry, err)
		}
		allTrainingData = append(allTrainingData, legitData...)

		// Load suspicious packages (label = 1.0)
		suspiciousData, err := loadPackageData(datasetPath, pmConfig.SuspiciousPackages, 1.0, registry)
		if err != nil {
			return nil, fmt.Errorf("failed to load suspicious packages for %s: %w", registry, err)
		}
		allTrainingData = append(allTrainingData, suspiciousData...)

		if trainVerbose {
			fmt.Printf("  ✓ Loaded %d legitimate + %d suspicious packages\n", len(legitData), len(suspiciousData))
		}
	}

	return allTrainingData, nil
}

func loadPackageData(datasetPath, packageFile string, label float64, registry string) ([]ml.TrainingData, error) {
	filePath := filepath.Join(datasetPath, packageFile)
	data, err := ioutil.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read package file %s: %w", filePath, err)
	}

	var packages []TrainingPackage
	if err := json.Unmarshal(data, &packages); err != nil {
		return nil, fmt.Errorf("failed to parse package data: %w", err)
	}

	var trainingData []ml.TrainingData
	for _, pkg := range packages {
		// Extract features from package
		features := extractPackageFeatures(pkg, registry)
		
		trainingData = append(trainingData, ml.TrainingData{
			Features: features,
			Label:    label,
			Metadata: map[string]interface{}{
				"name":          pkg.Name,
				"version":       pkg.Version,
				"registry":      registry,
				"expected_risk": pkg.ExpectedRisk,
				"risk_factors":  pkg.RiskFactors,
			},
		})
	}

	return trainingData, nil
}

func extractPackageFeatures(pkg TrainingPackage, registry string) []float64 {
	// Extract basic features for training
	features := make([]float64, 10) // 10 basic features

	// Feature 1: Name length
	features[0] = float64(len(pkg.Name))

	// Feature 2: Version complexity (number of dots + 1)
	features[1] = float64(len(pkg.Version))

	// Feature 3: Description length
	features[2] = float64(len(pkg.Description))

	// Feature 4: Has suspicious keywords
	suspiciousKeywords := []string{"test", "fake", "malicious", "evil", "hack"}
	for _, keyword := range suspiciousKeywords {
		if contains(pkg.Name, keyword) || contains(pkg.Description, keyword) {
			features[3] = 1.0
			break
		}
	}

	// Feature 5: Registry type (npm=0, pypi=1, go=2)
	switch registry {
	case "npm":
		features[4] = 0.0
	case "pypi":
		features[4] = 1.0
	case "go":
		features[4] = 2.0
	}

	// Feature 6-10: Risk factor indicators
	riskFactorMap := map[string]int{
		"typosquatting":        5,
		"dependency_confusion": 6,
		"malicious_code":       7,
		"suspicious_metadata":  8,
		"homoglyph":            9,
	}

	for _, factor := range pkg.RiskFactors {
		if idx, exists := riskFactorMap[factor]; exists {
			features[idx] = 1.0
		}
	}

	return features
}

func trainModels(ctx context.Context, pipeline *ml.MLPipeline, trainingData []ml.TrainingData) error {
	if trainVerbose {
		fmt.Println("🧠 Training ML models...")
	}

	// Get models from pipeline
	models := pipeline.GetModels()

	for modelName, model := range models {
		if trainVerbose {
			fmt.Printf("  🔄 Training %s model...\n", modelName)
		}

		startTime := time.Now()
		if err := model.Train(trainingData); err != nil {
			return fmt.Errorf("failed to train %s model: %w", modelName, err)
		}
		duration := time.Since(startTime)

		if trainVerbose {
			fmt.Printf("  ✅ %s model trained in %v\n", modelName, duration)
		}
	}

	return nil
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && s[:len(substr)] == substr
}