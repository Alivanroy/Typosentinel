package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/Alivanroy/Typosentinel/internal/dynamic"
)

func main() {
	fmt.Println("🔬 TypoSentinel Dynamic Analyzer Demo")
	fmt.Println("=====================================")

	// Create a demo configuration
	config := &dynamic.Config{
		Enabled:                true,
		SandboxType:            "docker",
		SandboxImage:           "node:16-alpine",
		SandboxTimeout:         "60s",
		MaxConcurrentSandboxes: 2,
		AnalyzeInstallScripts:  true,
		AnalyzeNetworkActivity: true,
		AnalyzeFileSystem:      true,
		AnalyzeProcesses:       true,
		AnalyzeEnvironment:     true,
		MaxExecutionTime:       "30s",
		MaxMemoryUsage:         256 * 1024 * 1024, // 256MB
		MaxDiskUsage:           1024 * 1024 * 1024, // 1GB
		MaxNetworkConnections:  5,
		MonitoringInterval:     "1s",
		Verbose:                true,
		LogLevel:               "info",
	}

	// Create analyzer
	analyzer, err := dynamic.NewDynamicAnalyzer(config)
	if err != nil {
		log.Fatalf("Failed to create dynamic analyzer: %v", err)
	}

	fmt.Printf("✅ Dynamic analyzer created successfully\n")
	fmt.Printf("   - Sandbox Type: %s\n", config.SandboxType)
	fmt.Printf("   - Sandbox Image: %s\n", config.SandboxImage)
	fmt.Printf("   - Max Memory: %d MB\n", config.MaxMemoryUsage/(1024*1024))
	fmt.Printf("   - Max Execution Time: %s\n", config.MaxExecutionTime)

	// Create a test package directory
	testDir := "dynamic-demo-package"
	err = os.MkdirAll(testDir, 0755)
	if err != nil {
		log.Fatalf("Failed to create test directory: %v", err)
	}
	defer os.RemoveAll(testDir)

	// Create package.json
	packageJSON := `{
  "name": "dynamic-demo-package",
  "version": "1.0.0",
  "description": "Demo package for dynamic analysis testing",
  "main": "index.js",
  "scripts": {
    "install": "node install.js",
    "postinstall": "echo 'Package installed successfully'"
  },
  "dependencies": {
    "lodash": "^4.17.21"
  }
}`

	err = os.WriteFile(filepath.Join(testDir, "package.json"), []byte(packageJSON), 0644)
	if err != nil {
		log.Fatalf("Failed to create package.json: %v", err)
	}

	// Create index.js
	indexJS := `const _ = require('lodash');

console.log('Demo package loaded');
console.log('Lodash version:', _.VERSION);

// Simulate some basic operations
const data = ['hello', 'world', 'dynamic', 'analysis'];
const processed = _.map(data, item => _.capitalize(item));
console.log('Processed data:', processed);

module.exports = {
    greet: function(name) {
        return 'Hello, ' + name + '!';
    },
    processData: function(data) {
        return _.map(data, item => _.capitalize(item));
    }
};`

	err = os.WriteFile(filepath.Join(testDir, "index.js"), []byte(indexJS), 0644)
	if err != nil {
		log.Fatalf("Failed to create index.js: %v", err)
	}

	// Create install.js
	installJS := `console.log('Running install script...');
console.log('Creating configuration files...');

const fs = require('fs');
const path = require('path');

// Create a simple config file
const config = {
    version: '1.0.0',
    timestamp: new Date().toISOString(),
    environment: process.env.NODE_ENV || 'development',
    features: ['dynamic-analysis', 'security-scanning']
};

try {
    fs.writeFileSync(path.join(__dirname, 'config.json'), JSON.stringify(config, null, 2));
    console.log('Configuration created successfully');
} catch (error) {
    console.error('Failed to create configuration:', error.message);
}

console.log('Install script completed');`

	err = os.WriteFile(filepath.Join(testDir, "install.js"), []byte(installJS), 0644)
	if err != nil {
		log.Fatalf("Failed to create install.js: %v", err)
	}

	fmt.Printf("\n📦 Test package created: %s\n", testDir)
	fmt.Printf("   - package.json: ✅\n")
	fmt.Printf("   - index.js: ✅\n")
	fmt.Printf("   - install.js: ✅\n")

	// Perform dynamic analysis
	fmt.Printf("\n🔍 Starting dynamic analysis...\n")
	startTime := time.Now()

	ctx := context.Background()
	result, err := analyzer.AnalyzePackage(ctx, testDir)

	duration := time.Since(startTime)

	if err != nil {
		fmt.Printf("❌ Dynamic analysis failed: %v\n", err)
		
		// Check if it's a Docker-related error
		if err.Error() == "failed to create sandbox: maximum concurrent sandboxes reached: 0" ||
		   err.Error() == "failed to create sandbox: unsupported sandbox type: docker" {
			fmt.Printf("\n💡 Note: Docker is not available or not running\n")
			fmt.Printf("   Dynamic analysis requires Docker for full functionality\n")
			fmt.Printf("   Install Docker and ensure it's running to enable dynamic analysis\n")
		}
		
		// Show what would happen with dynamic analysis
		showMockAnalysisResults()
		return
	}

	fmt.Printf("✅ Dynamic analysis completed in %v\n", duration)

	// Display results
	fmt.Printf("\n📊 Analysis Results\n")
	fmt.Printf("==================\n")
	fmt.Printf("Package Name: %s\n", result.PackageName)
	fmt.Printf("Registry: %s\n", result.Registry)
	fmt.Printf("Analysis Timestamp: %s\n", result.AnalysisTimestamp.Format(time.RFC3339))
	fmt.Printf("Processing Time: %v\n", result.ProcessingTime)
	fmt.Printf("Risk Score: %.2f\n", result.RiskScore)
	fmt.Printf("Threat Level: %s\n", result.ThreatLevel)

	// Sandbox information
	fmt.Printf("\n🏗️  Sandbox Information\n")
	fmt.Printf("Type: %s\n", result.SandboxInfo.Type)
	fmt.Printf("Image: %s\n", result.SandboxInfo.Image)
	fmt.Printf("ID: %s\n", result.SandboxInfo.ID)
	fmt.Printf("Status: %s\n", result.SandboxInfo.Status)

	// Execution results
	if len(result.ExecutionResults) > 0 {
		fmt.Printf("\n⚡ Execution Results\n")
		for i, exec := range result.ExecutionResults {
			fmt.Printf("Execution %d:\n", i+1)
			fmt.Printf("  Command: %s\n", exec.Command)
			fmt.Printf("  Exit Code: %d\n", exec.ExitCode)
			fmt.Printf("  Execution Time: %v\n", exec.ExecutionTime)
			if exec.Stdout != "" {
				fmt.Printf("  Stdout: %s\n", exec.Stdout)
			}
			if exec.Stderr != "" {
				fmt.Printf("  Stderr: %s\n", exec.Stderr)
			}
		}
	}

	// Security findings
	if len(result.SecurityFindings) > 0 {
		fmt.Printf("\n🛡️  Security Findings\n")
		for i, finding := range result.SecurityFindings {
			fmt.Printf("Finding %d:\n", i+1)
			fmt.Printf("  Type: %s\n", finding.Type)
			fmt.Printf("  Severity: %s\n", finding.Severity)
			fmt.Printf("  Title: %s\n", finding.Title)
			fmt.Printf("  Description: %s\n", finding.Description)
			fmt.Printf("  Confidence: %.2f\n", finding.Confidence)
		}
	} else {
		fmt.Printf("\n✅ No security findings detected\n")
	}

	// Behavioral analysis
	fmt.Printf("\n🔍 Behavioral Analysis\n")
	fmt.Printf("Network Activities: %d\n", len(result.NetworkActivity))
	fmt.Printf("File System Changes: %d\n", len(result.FileSystemChanges))
	fmt.Printf("Process Activities: %d\n", len(result.ProcessActivity))
	fmt.Printf("Environment Changes: %d\n", len(result.EnvironmentChanges))

	// Warnings and recommendations
	if len(result.Warnings) > 0 {
		fmt.Printf("\n⚠️  Warnings\n")
		for i, warning := range result.Warnings {
			fmt.Printf("%d. %s\n", i+1, warning)
		}
	}

	if len(result.Recommendations) > 0 {
		fmt.Printf("\n💡 Recommendations\n")
		for i, rec := range result.Recommendations {
			fmt.Printf("%d. %s\n", i+1, rec)
		}
	}

	// Save results to JSON
	jsonData, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		log.Printf("Failed to marshal results to JSON: %v", err)
	} else {
		err = os.WriteFile("dynamic-analysis-results.json", jsonData, 0644)
		if err != nil {
			log.Printf("Failed to save results to file: %v", err)
		} else {
			fmt.Printf("\n💾 Results saved to: dynamic-analysis-results.json\n")
		}
	}

	fmt.Printf("\n✨ Dynamic analysis demo completed!\n")
}

func showMockAnalysisResults() {
	fmt.Printf("\n📊 Mock Analysis Results (Docker not available)\n")
	fmt.Printf("===============================================\n")
	fmt.Printf("This demonstrates what dynamic analysis would detect:\n\n")

	fmt.Printf("🔍 Install Script Analysis:\n")
	fmt.Printf("   ✅ Script execution: node install.js\n")
	fmt.Printf("   ✅ File operations: config.json creation\n")
	fmt.Printf("   ✅ Environment access: NODE_ENV variable\n")
	fmt.Printf("   ✅ Console output monitoring\n\n")

	fmt.Printf("🌐 Network Activity Monitoring:\n")
	fmt.Printf("   ✅ Outbound connections tracking\n")
	fmt.Printf("   ✅ DNS resolution monitoring\n")
	fmt.Printf("   ✅ Data transmission analysis\n\n")

	fmt.Printf("📁 File System Monitoring:\n")
	fmt.Printf("   ✅ File creation/modification tracking\n")
	fmt.Printf("   ✅ Permission changes detection\n")
	fmt.Printf("   ✅ Sensitive location access monitoring\n\n")

	fmt.Printf("⚙️  Process Monitoring:\n")
	fmt.Printf("   ✅ Child process spawning\n")
	fmt.Printf("   ✅ Resource usage tracking\n")
	fmt.Printf("   ✅ Background process detection\n\n")

	fmt.Printf("🛡️  Security Assessment:\n")
	fmt.Printf("   ✅ Risk scoring based on behaviors\n")
	fmt.Printf("   ✅ Threat level classification\n")
	fmt.Printf("   ✅ Security violation detection\n\n")

	fmt.Printf("💡 To enable full dynamic analysis:\n")
	fmt.Printf("   1. Install Docker: https://docs.docker.com/get-docker/\n")
	fmt.Printf("   2. Start Docker daemon\n")
	fmt.Printf("   3. Re-run this demo\n")
}