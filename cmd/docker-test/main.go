package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/Alivanroy/Typosentinel/internal/dynamic"
)

func main() {
	fmt.Println("🔬 TypoSentinel Dynamic Analyzer - Docker Test")
	fmt.Println("==============================================")

	// Create a proper configuration with Docker enabled
	config := &dynamic.Config{
		Enabled:                true,
		SandboxType:           "docker",
		SandboxImage:          "node:16-alpine",
		SandboxTimeout:        "60s",
		MaxConcurrentSandboxes: 2, // Set to 2 instead of 0
		AnalyzeInstallScripts: true,
		AnalyzeNetworkActivity: true,
		AnalyzeFileSystem:     true,
		AnalyzeProcesses:      true,
		AnalyzeEnvironment:    true,
		MaxExecutionTime:      "30s",
		MaxMemoryUsage:        268435456, // 256MB
		MaxDiskUsage:          1073741824, // 1GB
		MaxNetworkConnections: 5,
		MonitoringInterval:    "1s",
		Verbose:               true,
		LogLevel:              "debug",
	}

	// Create dynamic analyzer
	analyzer, err := dynamic.NewDynamicAnalyzer(config)
	if err != nil {
		log.Fatalf("Failed to create dynamic analyzer: %v", err)
	}

	fmt.Printf("✅ Dynamic analyzer created successfully\n")
	fmt.Printf("   - Sandbox Type: %s\n", config.SandboxType)
	fmt.Printf("   - Sandbox Image: %s\n", config.SandboxImage)
	fmt.Printf("   - Max Concurrent Sandboxes: %d\n", config.MaxConcurrentSandboxes)
	fmt.Printf("   - Max Memory: %d MB\n", config.MaxMemoryUsage/1024/1024)
	fmt.Printf("   - Max Execution Time: %s\n", config.MaxExecutionTime)

	// Create a test package directory
	testDir := "docker-test-package"
	if err := os.MkdirAll(testDir, 0755); err != nil {
		log.Fatalf("Failed to create test directory: %v", err)
	}
	defer os.RemoveAll(testDir)

	// Create package.json
	packageJSON := `{
  "name": "docker-test-package",
  "version": "1.0.0",
  "description": "Test package for Docker dynamic analysis",
  "main": "index.js",
  "scripts": {
    "install": "node install.js"
  },
  "dependencies": {
    "lodash": "^4.17.21"
  }
}`

	if err := os.WriteFile(filepath.Join(testDir, "package.json"), []byte(packageJSON), 0644); err != nil {
		log.Fatalf("Failed to create package.json: %v", err)
	}

	// Create index.js
	indexJS := `console.log('Hello from test package!');
const _ = require('lodash');
console.log('Lodash version:', _.VERSION);`

	if err := os.WriteFile(filepath.Join(testDir, "index.js"), []byte(indexJS), 0644); err != nil {
		log.Fatalf("Failed to create index.js: %v", err)
	}

	// Create install.js with some suspicious behaviors
	installJS := `console.log('Running install script...');

// Simulate system information collection
const os = require('os');
const fs = require('fs');
const path = require('path');

console.log('System info:');
console.log('- Platform:', os.platform());
console.log('- Architecture:', os.arch());
console.log('- Hostname:', os.hostname());
console.log('- User info:', os.userInfo());

// Try to write to various locations (simulating data exfiltration)
const sensitiveData = {
    timestamp: new Date().toISOString(),
    platform: os.platform(),
    arch: os.arch(),
    hostname: os.hostname(),
    user: os.userInfo(),
    env: process.env
};

// Try to write to home directory
try {
    const homeDir = os.homedir();
    const suspiciousFile = path.join(homeDir, '.suspicious_data');
    fs.writeFileSync(suspiciousFile, JSON.stringify(sensitiveData, null, 2));
    console.log('✅ Successfully wrote to home directory:', suspiciousFile);
} catch (err) {
    console.log('❌ Failed to write to home directory:', err.message);
}

// Try to write to /tmp
try {
    const tmpFile = '/tmp/suspicious_data';
    fs.writeFileSync(tmpFile, JSON.stringify(sensitiveData, null, 2));
    console.log('✅ Successfully wrote to /tmp:', tmpFile);
} catch (err) {
    console.log('❌ Failed to write to /tmp:', err.message);
}

// Write to local directory
try {
    const localFile = 'collected_data.json';
    fs.writeFileSync(localFile, JSON.stringify(sensitiveData, null, 2));
    console.log('✅ Successfully wrote to local directory:', localFile);
} catch (err) {
    console.log('❌ Failed to write to local directory:', err.message);
}

console.log('Install script completed.');`

	if err := os.WriteFile(filepath.Join(testDir, "install.js"), []byte(installJS), 0644); err != nil {
		log.Fatalf("Failed to create install.js: %v", err)
	}

	fmt.Printf("\n📦 Test package created: %s\n", testDir)
	fmt.Printf("   - package.json: ✅\n")
	fmt.Printf("   - index.js: ✅\n")
	fmt.Printf("   - install.js: ✅ (with suspicious behaviors)\n")

	fmt.Printf("\n🔍 Starting dynamic analysis...\n")

	// Perform dynamic analysis
	ctx := context.Background()
	result, err := analyzer.AnalyzePackage(ctx, testDir)
	if err != nil {
		fmt.Printf("❌ Dynamic analysis failed: %v\n", err)
		fmt.Printf("\n💡 This might be expected if Docker setup needs adjustment\n")
		fmt.Printf("   Check Docker permissions and configuration\n")
		return
	}

	fmt.Printf("✅ Dynamic analysis completed successfully!\n")
	fmt.Printf("\n📊 Analysis Results:\n")
	fmt.Printf("   - Package: %s\n", result.PackageName)
	fmt.Printf("   - Registry: %s\n", result.Registry)
	fmt.Printf("   - Risk Score: %.2f\n", result.RiskScore)
	fmt.Printf("   - Threat Level: %s\n", result.ThreatLevel)
	fmt.Printf("   - Processing Time: %v\n", result.ProcessingTime)

	if len(result.SecurityFindings) > 0 {
		fmt.Printf("\n🚨 Security Findings:\n")
		for i, finding := range result.SecurityFindings {
			fmt.Printf("   %d. %s: %s\n", i+1, finding.Type, finding.Description)
		}
	}

	if len(result.NetworkActivity) > 0 {
		fmt.Printf("\n🌐 Network Activity:\n")
		for i, activity := range result.NetworkActivity {
			fmt.Printf("   %d. %s -> %s:%d\n", i+1, activity.Protocol, activity.DestinationIP, activity.DestinationPort)
		}
	}

	if len(result.FileSystemChanges) > 0 {
		fmt.Printf("\n📁 File System Changes:\n")
		for i, change := range result.FileSystemChanges {
			fmt.Printf("   %d. %s: %s\n", i+1, change.Operation, change.Path)
		}
	}

	if len(result.ProcessActivity) > 0 {
		fmt.Printf("\n⚙️  Process Activity:\n")
		for i, process := range result.ProcessActivity {
			fmt.Printf("   %d. PID %d: %s\n", i+1, process.PID, process.Command)
		}
	}

	fmt.Printf("\n🎉 Docker-based dynamic analysis test completed!\n")
}