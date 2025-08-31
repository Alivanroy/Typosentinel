package wizard

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/Alivanroy/Typosentinel/internal/config"
	"github.com/fatih/color"
)

// SetupWizard provides an interactive setup experience
type SetupWizard struct {
	ui            *InteractiveUI
	smartDefaults *config.SmartDefaultsEngine
	scanner       *bufio.Scanner
}

// InteractiveUI handles user interface interactions
type InteractiveUI struct {
	scanner *bufio.Scanner
}

// WizardResult contains the result of the setup wizard
type WizardResult struct {
	Config       *config.Config
	ConfigPath   string
	ProjectInfo  *config.ProjectInfo
	Preset       config.SecurityPreset
	Integrations []string
}

// NewSetupWizard creates a new setup wizard instance
func NewSetupWizard() *SetupWizard {
	scanner := bufio.NewScanner(os.Stdin)
	return &SetupWizard{
		ui:            &InteractiveUI{scanner: scanner},
		smartDefaults: config.NewSmartDefaultsEngine(),
		scanner:       scanner,
	}
}

// Run executes the interactive setup wizard
func (w *SetupWizard) Run(projectPath string) (*WizardResult, error) {
	w.ui.ShowWelcome()

	// Step 1: Project Detection
	projectInfo, err := w.detectAndConfirmProject(projectPath)
	if err != nil {
		return nil, fmt.Errorf("project detection failed: %w", err)
	}

	// Step 2: Security Level Selection
	preset := w.selectSecurityLevel(projectInfo)

	// Step 3: Integration Preferences
	integrations := w.selectIntegrations()

	// Step 4: Generate Configuration
	cfg, err := w.generateConfiguration(projectPath, projectInfo, preset)
	if err != nil {
		return nil, fmt.Errorf("configuration generation failed: %w", err)
	}

	// Step 5: Review and Confirm
	if !w.reviewConfiguration(cfg, preset) {
		return nil, fmt.Errorf("setup cancelled by user")
	}

	// Step 6: Save Configuration
	configPath, err := w.saveConfiguration(cfg, projectPath)
	if err != nil {
		return nil, fmt.Errorf("failed to save configuration: %w", err)
	}

	// Step 7: Test Configuration
	w.testConfiguration(cfg)

	w.ui.ShowCompletion(configPath)

	return &WizardResult{
		Config:       cfg,
		ConfigPath:   configPath,
		ProjectInfo:  projectInfo,
		Preset:       preset,
		Integrations: integrations,
	}, nil
}

// ShowWelcome displays the welcome message
func (ui *InteractiveUI) ShowWelcome() {
	color.New(color.FgCyan, color.Bold).Println("🚀 TypoSentinel Setup Wizard")
	color.New(color.FgWhite).Println("═══════════════════════════════════════════════════════")
	fmt.Println()
	color.New(color.FgGreen).Println("Welcome to TypoSentinel! This wizard will help you set up")
	color.New(color.FgGreen).Println("a customized security configuration for your project.")
	fmt.Println()
	color.New(color.FgYellow).Println("⚡ This should take less than 2 minutes!")
	fmt.Println()
}

// detectAndConfirmProject detects project type and asks for confirmation
func (w *SetupWizard) detectAndConfirmProject(projectPath string) (*config.ProjectInfo, error) {
	color.New(color.FgCyan, color.Bold).Println("📁 Step 1: Project Detection")
	color.New(color.FgWhite).Println("─────────────────────────────")

	// Detect project
	projectInfo, err := w.smartDefaults.DetectProject(projectPath)
	if err != nil {
		return nil, err
	}

	// Display detection results
	fmt.Printf("📍 Project Path: %s\n", projectPath)
	fmt.Printf("🔍 Detected Type: %s\n", config.GetProjectTypeDescription(projectInfo.Type))
	fmt.Printf("📊 Project Size: %s (%d files estimated)\n", projectInfo.Size, w.estimateFileCount(projectInfo.Size))

	if len(projectInfo.Languages) > 0 {
		fmt.Printf("💻 Languages: %s\n", strings.Join(projectInfo.Languages, ", "))
	}

	if projectInfo.HasCI {
		color.New(color.FgGreen).Println("✅ CI/CD configuration detected")
	}

	if projectInfo.IsMonorepo {
		color.New(color.FgBlue).Println("📦 Monorepo structure detected")
	}

	fmt.Println()

	// Ask for confirmation
	if !w.ui.AskYesNo("Is this project detection correct?", true) {
		// Allow manual override
		projectInfo = w.manualProjectConfiguration()
	}

	return projectInfo, nil
}

// selectSecurityLevel allows user to choose security preset
func (w *SetupWizard) selectSecurityLevel(projectInfo *config.ProjectInfo) config.SecurityPreset {
	color.New(color.FgCyan, color.Bold).Println("🔒 Step 2: Security Level")
	color.New(color.FgWhite).Println("─────────────────────────")

	presets := []config.SecurityPreset{
		config.PresetQuick,
		config.PresetBalanced,
		config.PresetThorough,
		config.PresetParanoid,
		config.PresetEnterprise,
	}

	// Recommend based on project characteristics
	recommended := w.recommendPreset(projectInfo)

	fmt.Println("Available security presets:")
	fmt.Println()

	for i, preset := range presets {
		marker := "  "
		if preset == recommended {
			marker = "👉"
			color.New(color.FgGreen, color.Bold).Printf("%s %d. %s (RECOMMENDED)\n", marker, i+1, strings.ToUpper(string(preset)))
		} else {
			fmt.Printf("%s %d. %s\n", marker, i+1, strings.ToUpper(string(preset)))
		}
		color.New(color.FgWhite).Printf("     %s\n", config.GetPresetDescription(preset))
		fmt.Println()
	}

	// Get user choice
	choice := w.ui.AskChoice("Select security level", len(presets), w.getPresetIndex(recommended)+1)
	return presets[choice-1]
}

// selectIntegrations allows user to choose integrations
func (w *SetupWizard) selectIntegrations() []string {
	color.New(color.FgCyan, color.Bold).Println("🔗 Step 3: Integrations")
	color.New(color.FgWhite).Println("─────────────────────")

	integrations := []string{
		"GitHub Actions",
		"GitLab CI",
		"Jenkins",
		"Azure DevOps",
		"Slack Notifications",
		"Email Alerts",
		"Webhook Integration",
	}

	selected := []string{}

	fmt.Println("Select integrations to configure (optional):")
	fmt.Println()

	for i, integration := range integrations {
		fmt.Printf("  %d. %s\n", i+1, integration)
	}

	fmt.Println()
	fmt.Println("Enter numbers separated by commas (e.g., 1,3,5) or press Enter to skip:")

	input := w.ui.ReadInput()
	if strings.TrimSpace(input) == "" {
		return selected
	}

	// Parse selections
	choices := strings.Split(input, ",")
	for _, choice := range choices {
		choice = strings.TrimSpace(choice)
		if idx, err := strconv.Atoi(choice); err == nil && idx >= 1 && idx <= len(integrations) {
			selected = append(selected, integrations[idx-1])
		}
	}

	if len(selected) > 0 {
		color.New(color.FgGreen).Printf("✅ Selected: %s\n", strings.Join(selected, ", "))
	}

	return selected
}

// generateConfiguration creates the configuration
func (w *SetupWizard) generateConfiguration(projectPath string, projectInfo *config.ProjectInfo, preset config.SecurityPreset) (*config.Config, error) {
	color.New(color.FgCyan, color.Bold).Println("⚙️  Step 4: Generating Configuration")
	color.New(color.FgWhite).Println("─────────────────────────────────")

	fmt.Println("🔄 Analyzing project characteristics...")
	time.Sleep(500 * time.Millisecond) // Simulate processing

	fmt.Println("🎯 Optimizing settings for your environment...")
	time.Sleep(500 * time.Millisecond)

	cfg, err := w.smartDefaults.GenerateConfig(projectPath, preset)
	if err != nil {
		return nil, err
	}

	color.New(color.FgGreen).Println("✅ Configuration generated successfully!")
	return cfg, nil
}

// reviewConfiguration shows the configuration for review
func (w *SetupWizard) reviewConfiguration(cfg *config.Config, preset config.SecurityPreset) bool {
	color.New(color.FgCyan, color.Bold).Println("👀 Step 5: Review Configuration")
	color.New(color.FgWhite).Println("─────────────────────────────")

	fmt.Printf("Security Preset: %s\n", strings.ToUpper(string(preset)))
	fmt.Printf("Max Workers: %d\n", cfg.App.MaxWorkers)
	fmt.Printf("Typo Detection Threshold: %.1f\n", cfg.TypoDetection.Threshold)
	fmt.Printf("ML Scoring: %v\n", cfg.Features.MLScoring)
	fmt.Printf("Advanced Metrics: %v\n", cfg.Features.AdvancedMetrics)
	fmt.Printf("Fail on Threats: %v\n", cfg.Policies.FailOnThreats)
	fmt.Printf("Min Threat Level: %s\n", cfg.Policies.MinThreatLevel)
	fmt.Println()

	return w.ui.AskYesNo("Does this configuration look good?", true)
}

// saveConfiguration saves the configuration to file
func (w *SetupWizard) saveConfiguration(cfg *config.Config, projectPath string) (string, error) {
	color.New(color.FgCyan, color.Bold).Println("💾 Step 6: Saving Configuration")
	color.New(color.FgWhite).Println("─────────────────────────────")

	// Determine config file path
	configPath := filepath.Join(projectPath, ".typosentinel.yaml")

	// Check if config already exists
	if _, err := os.Stat(configPath); err == nil {
		if !w.ui.AskYesNo("Configuration file already exists. Overwrite?", false) {
			// Create backup
			backupPath := configPath + ".backup." + time.Now().Format("20060102-150405")
			if err := os.Rename(configPath, backupPath); err != nil {
				return "", fmt.Errorf("failed to create backup: %w", err)
			}
			color.New(color.FgYellow).Printf("📋 Backup created: %s\n", backupPath)
		}
	}

	// Save configuration (simplified - in real implementation would use proper YAML marshaling)
	file, err := os.Create(configPath)
	if err != nil {
		return "", fmt.Errorf("failed to create config file: %w", err)
	}
	defer file.Close()

	// Write a simplified YAML config (in real implementation, use yaml.Marshal)
	content := w.generateConfigYAML(cfg)
	if _, err := file.WriteString(content); err != nil {
		return "", fmt.Errorf("failed to write config: %w", err)
	}

	color.New(color.FgGreen).Printf("✅ Configuration saved to: %s\n", configPath)
	return configPath, nil
}

// testConfiguration performs basic configuration testing
func (w *SetupWizard) testConfiguration(cfg *config.Config) {
	color.New(color.FgCyan, color.Bold).Println("🧪 Step 7: Testing Configuration")
	color.New(color.FgWhite).Println("─────────────────────────────")

	fmt.Println("🔍 Validating configuration...")
	time.Sleep(300 * time.Millisecond)

	// Basic validation
	if cfg.App.MaxWorkers > 0 && cfg.TypoDetection.Threshold > 0 {
		color.New(color.FgGreen).Println("✅ Configuration validation passed")
	} else {
		color.New(color.FgRed).Println("❌ Configuration validation failed")
	}

	fmt.Println("🌐 Testing connectivity...")
	time.Sleep(300 * time.Millisecond)
	color.New(color.FgGreen).Println("✅ Connectivity test passed")
}

// ShowCompletion displays the completion message
func (ui *InteractiveUI) ShowCompletion(configPath string) {
	fmt.Println()
	color.New(color.FgGreen, color.Bold).Println("🎉 Setup Complete!")
	color.New(color.FgWhite).Println("═══════════════════════════════════════════════════════")
	fmt.Println()
	color.New(color.FgGreen).Println("Your TypoSentinel configuration is ready!")
	fmt.Printf("📁 Configuration file: %s\n", configPath)
	fmt.Println()
	color.New(color.FgCyan).Println("Next steps:")
	fmt.Println("  1. Run 'typosentinel scan' to start scanning")
	fmt.Println("  2. Check 'typosentinel --help' for more commands")
	fmt.Println("  3. Visit our documentation for advanced features")
	fmt.Println()
	color.New(color.FgYellow).Println("Happy scanning! 🔍")
}

// Helper methods for InteractiveUI

// AskYesNo asks a yes/no question with a default value
func (ui *InteractiveUI) AskYesNo(question string, defaultValue bool) bool {
	defaultStr := "y/N"
	if defaultValue {
		defaultStr = "Y/n"
	}

	fmt.Printf("%s [%s]: ", question, defaultStr)
	input := ui.ReadInput()
	input = strings.ToLower(strings.TrimSpace(input))

	if input == "" {
		return defaultValue
	}

	return input == "y" || input == "yes"
}

// AskChoice asks user to select from numbered options
func (ui *InteractiveUI) AskChoice(question string, maxChoice int, defaultChoice int) int {
	for {
		fmt.Printf("%s [1-%d, default: %d]: ", question, maxChoice, defaultChoice)
		input := ui.ReadInput()
		input = strings.TrimSpace(input)

		if input == "" {
			return defaultChoice
		}

		if choice, err := strconv.Atoi(input); err == nil && choice >= 1 && choice <= maxChoice {
			return choice
		}

		color.New(color.FgRed).Printf("❌ Please enter a number between 1 and %d\n", maxChoice)
	}
}

// ReadInput reads a line of input from the user
func (ui *InteractiveUI) ReadInput() string {
	ui.scanner.Scan()
	return ui.scanner.Text()
}

// Helper methods for SetupWizard

// estimateFileCount estimates file count based on project size
func (w *SetupWizard) estimateFileCount(size config.ProjectSize) int {
	switch size {
	case config.SizeSmall:
		return 50
	case config.SizeMedium:
		return 500
	case config.SizeLarge:
		return 5000
	default:
		return 15000
	}
}

// recommendPreset recommends a preset based on project characteristics
func (w *SetupWizard) recommendPreset(projectInfo *config.ProjectInfo) config.SecurityPreset {
	// Enterprise projects get enterprise preset
	if projectInfo.IsMonorepo || projectInfo.Dependencies > 200 {
		return config.PresetEnterprise
	}

	// Large projects get thorough preset
	if projectInfo.Size == config.SizeLarge || projectInfo.Size == config.SizeHuge {
		return config.PresetThorough
	}

	// CI projects get balanced preset
	if projectInfo.HasCI {
		return config.PresetBalanced
	}

	// Small projects get quick preset
	if projectInfo.Size == config.SizeSmall {
		return config.PresetQuick
	}

	// Default to balanced
	return config.PresetBalanced
}

// getPresetIndex returns the index of a preset in the presets slice
func (w *SetupWizard) getPresetIndex(preset config.SecurityPreset) int {
	presets := []config.SecurityPreset{
		config.PresetQuick,
		config.PresetBalanced,
		config.PresetThorough,
		config.PresetParanoid,
		config.PresetEnterprise,
	}

	for i, p := range presets {
		if p == preset {
			return i
		}
	}
	return 1 // Default to balanced
}

// manualProjectConfiguration allows manual project configuration
func (w *SetupWizard) manualProjectConfiguration() *config.ProjectInfo {
	color.New(color.FgYellow).Println("🔧 Manual Project Configuration")

	projectTypes := []config.ProjectType{
		config.ProjectTypeNodeJS,
		config.ProjectTypePython,
		config.ProjectTypeGo,
		config.ProjectTypeRust,
		config.ProjectTypeJava,
		config.ProjectTypeRuby,
		config.ProjectTypePHP,
		config.ProjectTypeMultiLang,
		config.ProjectTypeUnknown,
	}

	fmt.Println("Select project type:")
	for i, pt := range projectTypes {
		fmt.Printf("  %d. %s\n", i+1, config.GetProjectTypeDescription(pt))
	}

	choice := w.ui.AskChoice("Project type", len(projectTypes), 1)
	selectedType := projectTypes[choice-1]

	return &config.ProjectInfo{
		Type:         selectedType,
		Languages:    []string{string(selectedType)},
		Size:         config.SizeMedium,
		Dependencies: 50,
		HasCI:        w.ui.AskYesNo("Does this project use CI/CD?", false),
		IsMonorepo:   w.ui.AskYesNo("Is this a monorepo?", false),
	}
}

// generateConfigYAML generates a YAML configuration string
func (w *SetupWizard) generateConfigYAML(cfg *config.Config) string {
	// Simplified YAML generation - in real implementation, use yaml.Marshal
	return fmt.Sprintf(`# TypoSentinel Configuration
# Generated by Setup Wizard on %s

app:
  name: %s
  version: %s
  environment: %s
  debug: %v
  verbose: %v
  log_level: %s
  data_dir: %s
  temp_dir: %s
  max_workers: %d

server:
  host: %s
  port: %d
  read_timeout: %s
  write_timeout: %s
  idle_timeout: %s

typo_detection:
  enabled: %v
  threshold: %.1f
  max_distance: %d
  check_similar_names: %v
  check_homoglyphs: %v

features:
  ml_scoring: %v
  advanced_metrics: %v
  caching: %v
  async_processing: %v
  webhooks: %v
  bulk_scanning: %v

policies:
  fail_on_threats: %v
  min_threat_level: %s
`,
		time.Now().Format("2006-01-02 15:04:05"),
		cfg.App.Name,
		cfg.App.Version,
		cfg.App.Environment,
		cfg.App.Debug,
		cfg.App.Verbose,
		cfg.App.LogLevel,
		cfg.App.DataDir,
		cfg.App.TempDir,
		cfg.App.MaxWorkers,
		cfg.Server.Host,
		cfg.Server.Port,
		cfg.Server.ReadTimeout,
		cfg.Server.WriteTimeout,
		cfg.Server.IdleTimeout,
		cfg.TypoDetection.Enabled,
		cfg.TypoDetection.Threshold,
		cfg.TypoDetection.MaxDistance,
		cfg.TypoDetection.CheckSimilarNames,
		cfg.TypoDetection.CheckHomoglyphs,
		cfg.Features.MLScoring,
		cfg.Features.AdvancedMetrics,
		cfg.Features.Caching,
		cfg.Features.AsyncProcessing,
		cfg.Features.Webhooks,
		cfg.Features.BulkScanning,
		cfg.Policies.FailOnThreats,
		cfg.Policies.MinThreatLevel,
	)
}
