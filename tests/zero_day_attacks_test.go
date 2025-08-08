package tests

import (
	"context"
	"testing"
	"time"

	"github.com/Alivanroy/Typosentinel/internal/config"
	"github.com/Alivanroy/Typosentinel/internal/scanner"
	"github.com/Alivanroy/Typosentinel/pkg/logger"
	"github.com/Alivanroy/Typosentinel/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSolarWindsLikeAttack tests detection of SolarWinds-style supply chain attacks
func TestSolarWindsLikeAttack(t *testing.T) {
	ctx := context.Background()
	
	// Initialize logger and detector
	log := logger.New()
	cfg := &config.ZeroDayDetectionConfig{
		Enabled:              true,
		BehavioralAnalysis:   true,
		CodeAnomalyDetection: true,
		RuntimeAnalysis:      true,
		AnomalyThreshold:     0.7,
		Timeout:              30 * time.Second,
	}
	
	detector := scanner.NewZeroDayDetector(cfg, log)
	
	publishedTime := time.Date(2020, 3, 24, 0, 0, 0, 0, time.UTC)
	
	// Create a package that mimics SolarWinds Orion compromise
	solarWindsPackage := &types.Package{
		Name:     "SolarWinds.Orion.Core.BusinessLayer",
		Version:  "2019.4.5220.20574",
		Type:     "nuget",
		Registry: "nuget.org",
		Metadata: &types.PackageMetadata{
			Name:        "SolarWinds.Orion.Core.BusinessLayer",
			Version:     "2019.4.5220.20574",
			Registry:    "nuget.org",
			Description: "SolarWinds Orion Core Business Layer",
			Author:      "SolarWinds",
			Homepage:    "https://www.solarwinds.com",
			License:     "Proprietary",
			Size:        15728640, // ~15MB
			Dependencies: []string{
				"System.Configuration",
				"System.DirectoryServices",
				"System.Management",
				"System.Net.Http",
				"System.Security.Cryptography",
			},
			Checksums: map[string]string{
				"sha256": "32519b85c0b422e4656de6e6c41878e95fd95026267daab4215ee59c107d6c77",
				"md5":    "b91ce2fa41029f6955bff20079468448",
			},
			PublishedAt: &publishedTime,
			LastUpdated: &publishedTime,
			Downloads:   50000,
			Metadata: map[string]interface{}{
				"code_patterns": []string{
					// Suspicious patterns found in SUNBURST
					"OrionImprovementBusinessLayer",
					"GetOrCreateUserID",
					"DelayMin",
					"DelayMax",
					"DnsApi.DnsQuery_W",
					"HttpWebRequest",
					"avsvmcloud.com",
					"freescanonline.com",
					"deftsecurity.com",
					"thedoccloud.com",
					"websitetheme.com",
					"highdatabase.com",
					"incomeupdate.com",
					"databasegalore.com",
					"panhardware.com",
					"zupertech.com",
					"virtualdataserver.com",
					"digitalcollege.org",
					"globalnetworkissues.com",
					"kubecloud.com",
					"lcomputers.com",
					"seobundlekit.com",
					"solartrackingsystem.net",
					"virtualwebdata.com",
				},
				"obfuscation_techniques": []string{
					"string_encryption",
					"control_flow_obfuscation",
					"api_hashing",
					"delayed_execution",
					"environment_checks",
				},
				"persistence_mechanisms": []string{
					"dll_side_loading",
					"legitimate_process_injection",
					"scheduled_tasks",
					"registry_modifications",
				},
				"evasion_techniques": []string{
					"process_hollowing",
					"anti_analysis",
					"sandbox_detection",
					"debugger_detection",
					"vm_detection",
				},
				"c2_communication": []string{
					"dns_tunneling",
					"http_beaconing",
					"domain_generation_algorithm",
					"encrypted_payloads",
				},
				"data_exfiltration": []string{
					"credential_harvesting",
					"file_enumeration",
					"network_reconnaissance",
					"lateral_movement",
				},
			},
		},
	}
	
	// Test zero-day detection
	findings, err := detector.DetectZeroDayThreats(ctx, solarWindsPackage)
	require.NoError(t, err)
	require.NotEmpty(t, findings)
	
	// Verify critical findings
	var criticalFindings []scanner.ZeroDayFinding
	for _, finding := range findings {
		if finding.Severity == types.SeverityCritical {
			criticalFindings = append(criticalFindings, finding)
		}
	}
	
	assert.NotEmpty(t, criticalFindings, "Should detect critical zero-day threats")
	
	// Check for specific SolarWinds attack patterns
	foundSupplyChainAttack := false
	foundC2Communication := false
	foundDataExfiltration := false
	
	for _, finding := range findings {
		switch finding.Type {
		case "supply_chain_compromise":
			foundSupplyChainAttack = true
		case "c2_communication":
			foundC2Communication = true
		case "data_exfiltration":
			foundDataExfiltration = true
		}
	}
	
	assert.True(t, foundSupplyChainAttack, "Should detect supply chain compromise")
	assert.True(t, foundC2Communication, "Should detect C2 communication patterns")
	assert.True(t, foundDataExfiltration, "Should detect data exfiltration patterns")
}

// TestAPTLazarusAttack tests detection of APT Lazarus-style attacks
func TestAPTLazarusAttack(t *testing.T) {
	ctx := context.Background()
	
	log := logger.New()
	cfg := &config.ZeroDayDetectionConfig{
		Enabled:              true,
		BehavioralAnalysis:   true,
		CodeAnomalyDetection: true,
		RuntimeAnalysis:      true,
		AnomalyThreshold:     0.8,
		Timeout:              30 * time.Second,
	}
	
	detector := scanner.NewZeroDayDetector(cfg, log)
	
	publishedTime := time.Date(2023, 8, 15, 0, 0, 0, 0, time.UTC)
	
	// Create a package that mimics APT Lazarus cryptocurrency exchange attack
	lazarusPackage := &types.Package{
		Name:     "crypto-trading-bot",
		Version:  "1.2.3",
		Type:     "npm",
		Registry: "npmjs.org",
		Metadata: &types.PackageMetadata{
			Name:        "crypto-trading-bot",
			Version:     "1.2.3",
			Registry:    "npmjs.org",
			Description: "Advanced cryptocurrency trading bot with AI capabilities",
			Author:      "crypto-dev-team",
			Homepage:    "https://crypto-trading-solutions.com",
			License:     "MIT",
			Size:        2048000, // 2MB
			Dependencies: []string{
				"axios",
				"crypto-js",
				"node-forge",
				"ws",
				"electron",
			},
			Checksums: map[string]string{
				"sha256": "a1b2c3d4e5f6789012345678901234567890123456789012345678901234567890",
			},
			PublishedAt: &publishedTime,
			Downloads:   15000,
			Metadata: map[string]interface{}{
				"code_patterns": []string{
					// APT Lazarus attack patterns
					"wallet.dat",
					"private_keys",
					"mnemonic_phrase",
					"keystore",
					"cryptocurrency",
					"bitcoin",
					"ethereum",
					"exchange_api",
					"trading_credentials",
					"process.env.APPDATA",
					"process.env.USERPROFILE",
					"clipboard",
					"screenshot",
					"keylogger",
					"network_scan",
					"port_scan",
					"lateral_movement",
				},
				"malicious_behaviors": []string{
					"credential_theft",
					"wallet_enumeration",
					"clipboard_monitoring",
					"screenshot_capture",
					"keylogging",
					"network_reconnaissance",
					"data_exfiltration",
					"persistence_installation",
				},
				"evasion_techniques": []string{
					"code_obfuscation",
					"string_encryption",
					"anti_debugging",
					"vm_detection",
					"sandbox_evasion",
					"process_injection",
				},
				"c2_infrastructure": []string{
					"tor_communication",
					"encrypted_channels",
					"domain_fronting",
					"cdn_abuse",
					"legitimate_services_abuse",
				},
				"target_applications": []string{
					"Electrum",
					"Exodus",
					"MetaMask",
					"Coinbase",
					"Binance",
					"Kraken",
					"Bitfinex",
					"KuCoin",
				},
			},
		},
	}
	
	findings, err := detector.DetectZeroDayThreats(ctx, lazarusPackage)
	require.NoError(t, err)
	require.NotEmpty(t, findings)
	
	// Verify APT-specific patterns
	foundCredentialTheft := false
	foundCryptoTargeting := false
	foundAdvancedEvasion := false
	
	for _, finding := range findings {
		if finding.BehaviorType == "credential_theft" {
			foundCredentialTheft = true
		}
		if finding.BehaviorType == "cryptocurrency_targeting" {
			foundCryptoTargeting = true
		}
		if finding.BehaviorType == "advanced_evasion" {
			foundAdvancedEvasion = true
		}
	}
	
	assert.True(t, foundCredentialTheft, "Should detect credential theft patterns")
	assert.True(t, foundCryptoTargeting, "Should detect cryptocurrency targeting")
	assert.True(t, foundAdvancedEvasion, "Should detect advanced evasion techniques")
}

// TestCCCleanerAttack tests detection of CCleaner-style supply chain attacks
func TestCCCleanerAttack(t *testing.T) {
	ctx := context.Background()
	
	log := logger.New()
	cfg := &config.ZeroDayDetectionConfig{
		Enabled:              true,
		BehavioralAnalysis:   true,
		CodeAnomalyDetection: true,
		RuntimeAnalysis:      true,
		AnomalyThreshold:     0.75,
		Timeout:              30 * time.Second,
	}
	
	detector := scanner.NewZeroDayDetector(cfg, log)
	
	publishedTime := time.Date(2017, 8, 2, 0, 0, 0, 0, time.UTC)
	
	// Create a package that mimics CCleaner compromise
	ccleanerPackage := &types.Package{
		Name:     "system-optimizer",
		Version:  "5.33.6162",
		Type:     "exe",
		Registry: "custom",
		Metadata: &types.PackageMetadata{
			Name:        "system-optimizer",
			Version:     "5.33.6162",
			Description: "Advanced system optimization and cleaning utility",
			Author:      "SystemTools Inc",
			License:     "Freeware",
			Size:        25165824, // 24MB
			Checksums: map[string]string{
				"sha256": "6f7958533d28acd14f8c6c8b8f8c6c8b8f8c6c8b8f8c6c8b8f8c6c8b8f8c6c8b",
			},
			PublishedAt: &publishedTime,
			Downloads:   2270000, // High download count like CCleaner
			Metadata: map[string]interface{}{
				"code_patterns": []string{
					// CCleaner attack patterns
					"floxif",
					"StagingArea",
					"DnsQuery",
					"HttpSendRequest",
					"InternetConnect",
					"CreateProcess",
					"WriteProcessMemory",
					"VirtualAllocEx",
					"SetWindowsHookEx",
					"GetAsyncKeyState",
					"FindWindow",
					"EnumWindows",
					"GetWindowText",
				},
				"backdoor_behaviors": []string{
					"remote_code_execution",
					"data_collection",
					"system_reconnaissance",
					"privilege_escalation",
					"persistence_mechanisms",
					"anti_analysis",
				},
				"target_selection": []string{
					"tech_companies",
					"telecommunications",
					"software_vendors",
					"government_agencies",
					"financial_institutions",
				},
				"payload_delivery": []string{
					"staged_deployment",
					"conditional_execution",
					"target_validation",
					"environment_profiling",
				},
				"c2_domains": []string{
					"216.126.225.148",
					"216.126.225.163",
					"get.adobe.com.ssl443.org",
					"speccy.piriform.com.ssl443.org",
				},
			},
		},
	}
	
	findings, err := detector.DetectZeroDayThreats(ctx, ccleanerPackage)
	require.NoError(t, err)
	require.NotEmpty(t, findings)
	
	// Verify CCleaner-specific attack patterns
	foundBackdoor := false
	foundTargetedAttack := false
	foundStagedPayload := false
	
	for _, finding := range findings {
		if finding.Type == "backdoor_installation" {
			foundBackdoor = true
		}
		if finding.BehaviorType == "targeted_attack" {
			foundTargetedAttack = true
		}
		if finding.BehaviorType == "staged_payload" {
			foundStagedPayload = true
		}
	}
	
	assert.True(t, foundBackdoor, "Should detect backdoor installation")
	assert.True(t, foundTargetedAttack, "Should detect targeted attack patterns")
	assert.True(t, foundStagedPayload, "Should detect staged payload delivery")
}

// TestNotPetyaAttack tests detection of NotPetya-style destructive attacks
func TestNotPetyaAttack(t *testing.T) {
	ctx := context.Background()
	
	log := logger.New()
	cfg := &config.ZeroDayDetectionConfig{
		Enabled:              true,
		BehavioralAnalysis:   true,
		CodeAnomalyDetection: true,
		RuntimeAnalysis:      true,
		AnomalyThreshold:     0.9, // Very high threshold for destructive malware
		Timeout:              30 * time.Second,
	}
	
	detector := scanner.NewZeroDayDetector(cfg, log)
	
	publishedTime := time.Date(2017, 6, 27, 0, 0, 0, 0, time.UTC)
	
	// Create a package that mimics NotPetya attack vector
	notpetyaPackage := &types.Package{
		Name:     "accounting-software-update",
		Version:  "1.0.0.338",
		Type:     "msi",
		Registry: "custom",
		Metadata: &types.PackageMetadata{
			Name:        "accounting-software-update",
			Version:     "1.0.0.338",
			Description: "Critical security update for accounting software",
			Author:      "Software Vendor",
			License:     "Commercial",
			Size:        15728640,
			Checksums: map[string]string{
				"sha256": "027cc450ef5f8c5f653329641ec1fed91f694e0d229928963b30f6b0d7d3a745",
			},
			PublishedAt: &publishedTime,
			Downloads:   50000,
			Metadata: map[string]interface{}{
				"code_patterns": []string{
					// NotPetya attack patterns
					"perfc.dat",
					"MBR",
					"VBR",
					"NTFS",
					"EternalBlue",
					"EternalRomance",
					"WMI",
					"PsExec",
					"SMB",
					"ADMIN$",
					"C$",
					"IPC$",
					"lsass.exe",
					"rundll32.exe",
					"schtasks.exe",
					"wevtutil.exe",
					"vssadmin.exe",
					"bcdedit.exe",
				},
				"destructive_behaviors": []string{
					"mbr_overwrite",
					"file_encryption",
					"shadow_copy_deletion",
					"boot_record_modification",
					"system_recovery_disabling",
					"event_log_clearing",
				},
				"propagation_methods": []string{
					"smb_exploitation",
					"wmi_lateral_movement",
					"psexec_deployment",
					"credential_harvesting",
					"network_scanning",
				},
				"evasion_techniques": []string{
					"legitimate_tool_abuse",
					"living_off_the_land",
					"process_injection",
					"reflective_dll_loading",
				},
				"persistence_mechanisms": []string{
					"scheduled_tasks",
					"service_installation",
					"registry_modifications",
					"startup_folder_placement",
				},
			},
		},
	}
	
	findings, err := detector.DetectZeroDayThreats(ctx, notpetyaPackage)
	require.NoError(t, err)
	require.NotEmpty(t, findings)
	
	// Verify NotPetya-specific patterns
	foundDestructiveBehavior := false
	foundLateralMovement := false
	foundSystemDestruction := false
	
	for _, finding := range findings {
		if finding.BehaviorType == "destructive_malware" {
			foundDestructiveBehavior = true
		}
		if finding.BehaviorType == "lateral_movement" {
			foundLateralMovement = true
		}
		if finding.Type == "system_destruction" {
			foundSystemDestruction = true
		}
	}
	
	assert.True(t, foundDestructiveBehavior, "Should detect destructive malware behavior")
	assert.True(t, foundLateralMovement, "Should detect lateral movement capabilities")
	assert.True(t, foundSystemDestruction, "Should detect system destruction patterns")
}

// TestStuxnetLikeAttack tests detection of Stuxnet-style industrial control system attacks
func TestStuxnetLikeAttack(t *testing.T) {
	ctx := context.Background()
	
	log := logger.New()
	cfg := &config.ZeroDayDetectionConfig{
		Enabled:              true,
		BehavioralAnalysis:   true,
		CodeAnomalyDetection: true,
		RuntimeAnalysis:      true,
		AnomalyThreshold:     0.85,
		Timeout:              30 * time.Second,
	}
	
	detector := scanner.NewZeroDayDetector(cfg, log)
	
	publishedTime := time.Date(2010, 6, 15, 0, 0, 0, 0, time.UTC)
	
	// Create a package that mimics Stuxnet attack patterns
	stuxnetPackage := &types.Package{
		Name:     "industrial-control-driver",
		Version:  "2.1.4.0",
		Type:     "sys",
		Registry: "custom",
		Metadata: &types.PackageMetadata{
			Name:        "industrial-control-driver",
			Version:     "2.1.4.0",
			Description: "Industrial control system device driver",
			Author:      "Industrial Solutions Inc",
			License:     "Commercial",
			Size:        1048576, // 1MB
			Checksums: map[string]string{
				"sha256": "b6a9c1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0",
			},
			PublishedAt: &publishedTime,
			Downloads:   5000,
			Metadata: map[string]interface{}{
				"code_patterns": []string{
					// Stuxnet attack patterns
					"s7otbxdx.dll",
					"s7otbxsx.dll",
					"Step7",
					"WinCC",
					"SIMATIC",
					"PLC",
					"SCADA",
					"Profibus",
					"Profinet",
					"OPC",
					"Modbus",
					"DNP3",
					"IEC61850",
					"centrifuge",
					"frequency_converter",
					"motor_control",
					"process_control",
				},
				"ics_behaviors": []string{
					"plc_communication",
					"scada_interaction",
					"process_manipulation",
					"safety_system_bypass",
					"industrial_protocol_abuse",
					"equipment_sabotage",
				},
				"rootkit_capabilities": []string{
					"kernel_level_access",
					"driver_signing_bypass",
					"system_file_replacement",
					"process_hiding",
					"network_traffic_hiding",
				},
				"zero_day_exploits": []string{
					"lnk_vulnerability",
					"print_spooler_exploit",
					"task_scheduler_exploit",
					"win32k_exploit",
				},
				"target_systems": []string{
					"siemens_plc",
					"industrial_networks",
					"critical_infrastructure",
					"nuclear_facilities",
					"power_plants",
					"manufacturing_systems",
				},
			},
		},
	}
	
	findings, err := detector.DetectZeroDayThreats(ctx, stuxnetPackage)
	require.NoError(t, err)
	require.NotEmpty(t, findings)
	
	// Verify Stuxnet-specific patterns
	foundICSTargeting := false
	foundRootkitBehavior := false
	foundZeroDayExploit := false
	foundCriticalInfrastructure := false
	
	for _, finding := range findings {
		if finding.BehaviorType == "ics_targeting" {
			foundICSTargeting = true
		}
		if finding.Type == "rootkit_installation" {
			foundRootkitBehavior = true
		}
		if finding.BehaviorType == "zero_day_exploit" {
			foundZeroDayExploit = true
		}
		if finding.BehaviorType == "critical_infrastructure_targeting" {
			foundCriticalInfrastructure = true
		}
	}
	
	assert.True(t, foundICSTargeting, "Should detect ICS targeting patterns")
	assert.True(t, foundRootkitBehavior, "Should detect rootkit behavior")
	assert.True(t, foundZeroDayExploit, "Should detect zero-day exploit usage")
	assert.True(t, foundCriticalInfrastructure, "Should detect critical infrastructure targeting")
}

// TestBehavioralAnalysisAccuracy tests the accuracy of behavioral analysis
func TestBehavioralAnalysisAccuracy(t *testing.T) {
	ctx := context.Background()
	
	log := logger.New()
	cfg := &config.ZeroDayDetectionConfig{
		Enabled:              true,
		BehavioralAnalysis:   true,
		CodeAnomalyDetection: true,
		RuntimeAnalysis:      true,
		AnomalyThreshold:     0.7,
		Timeout:              30 * time.Second,
	}
	
	detector := scanner.NewZeroDayDetector(cfg, log)
	
	publishedTime := time.Date(2021, 2, 20, 0, 0, 0, 0, time.UTC)
	
	// Test with a legitimate package (should have low risk score)
	legitimatePackage := &types.Package{
		Name:     "lodash",
		Version:  "4.17.21",
		Type:     "npm",
		Registry: "npmjs.org",
		Metadata: &types.PackageMetadata{
			Name:        "lodash",
			Version:     "4.17.21",
			Registry:    "npmjs.org",
			Description: "Lodash modular utilities",
			Author:      "John-David Dalton",
			Homepage:    "https://lodash.com/",
			License:     "MIT",
			Size:        1048576,
			Downloads:   50000000,
			PublishedAt: &publishedTime,
			Metadata: map[string]interface{}{
				"code_patterns": []string{
					"utility_functions",
					"array_manipulation",
					"object_manipulation",
					"functional_programming",
				},
			},
		},
	}
	
	behavioralAnalysis, err := detector.AnalyzeBehavioralPatterns(ctx, legitimatePackage)
	require.NoError(t, err)
	
	// Legitimate packages should have low risk scores
	assert.Less(t, behavioralAnalysis.RiskScore, 0.3, "Legitimate package should have low risk score")
	
	maliciousTime := time.Date(2023, 12, 1, 0, 0, 0, 0, time.UTC)
	
	// Test with a malicious package (should have high risk score)
	maliciousPackage := &types.Package{
		Name:     "malicious-crypto-miner",
		Version:  "1.0.0",
		Type:     "npm",
		Registry: "npmjs.org",
		Metadata: &types.PackageMetadata{
			Name:        "malicious-crypto-miner",
			Version:     "1.0.0",
			Description: "Cryptocurrency mining utility",
			Author:      "anonymous",
			Size:        5242880, // 5MB
			Downloads:   100,
			PublishedAt: &maliciousTime,
			Metadata: map[string]interface{}{
				"code_patterns": []string{
					"crypto_mining",
					"cpu_intensive",
					"network_communication",
					"process_spawning",
					"system_resource_abuse",
					"obfuscated_code",
					"anti_debugging",
					"persistence_mechanisms",
				},
				"suspicious_behaviors": []string{
					"unauthorized_mining",
					"resource_consumption",
					"stealth_operation",
					"c2_communication",
				},
			},
		},
	}
	
	maliciousBehavioralAnalysis, err := detector.AnalyzeBehavioralPatterns(ctx, maliciousPackage)
	require.NoError(t, err)
	
	// Malicious packages should have high risk scores
	assert.Greater(t, maliciousBehavioralAnalysis.RiskScore, 0.8, "Malicious package should have high risk score")
	
	// Verify that the detector can distinguish between legitimate and malicious packages
	assert.Greater(t, maliciousBehavioralAnalysis.RiskScore, behavioralAnalysis.RiskScore+0.5, 
		"Malicious package risk score should be significantly higher than legitimate package")
}

// TestRuntimeAnalysisDetection tests runtime behavior analysis
func TestRuntimeAnalysisDetection(t *testing.T) {
	ctx := context.Background()
	
	log := logger.New()
	cfg := &config.ZeroDayDetectionConfig{
		Enabled:              true,
		BehavioralAnalysis:   true,
		CodeAnomalyDetection: true,
		RuntimeAnalysis:      true,
		AnomalyThreshold:     0.7,
		Timeout:              30 * time.Second,
	}
	
	detector := scanner.NewZeroDayDetector(cfg, log)
	
	publishedTime := time.Date(2023, 11, 15, 0, 0, 0, 0, time.UTC)
	
	// Create a package with suspicious runtime behavior
	suspiciousPackage := &types.Package{
		Name:     "system-monitor",
		Version:  "2.1.0",
		Type:     "npm",
		Registry: "npmjs.org",
		Metadata: &types.PackageMetadata{
			Name:        "system-monitor",
			Version:     "2.1.0",
			Description: "Advanced system monitoring tool",
			Author:      "system-tools",
			Size:        3145728, // 3MB
			Downloads:   5000,
			PublishedAt: &publishedTime,
			Metadata: map[string]interface{}{
				"runtime_behaviors": []string{
					"excessive_cpu_usage",
					"unusual_network_activity",
					"file_system_monitoring",
					"process_injection",
					"memory_manipulation",
					"registry_modifications",
					"service_installation",
					"scheduled_task_creation",
				},
				"network_patterns": []string{
					"c2_beaconing",
					"data_exfiltration",
					"port_scanning",
					"dns_tunneling",
				},
				"evasion_behaviors": []string{
					"anti_vm_checks",
					"debugger_detection",
					"sandbox_evasion",
					"process_hollowing",
				},
			},
		},
	}
	
	runtimeAnalysis, err := detector.AnalyzeRuntimeBehavior(ctx, suspiciousPackage)
	require.NoError(t, err)
	require.NotNil(t, runtimeAnalysis)
	
	// Verify runtime analysis detects suspicious behaviors
	assert.Greater(t, runtimeAnalysis.RiskScore, 0.7, "Should detect high-risk runtime behavior")
	assert.NotEmpty(t, runtimeAnalysis.Behaviors, "Should identify specific runtime behaviors")
	
	// Check for specific runtime behavior detection
	foundSuspiciousNetwork := false
	foundProcessManipulation := false
	foundEvasionTechniques := false
	
	for _, behavior := range runtimeAnalysis.Behaviors {
		switch behavior.Type {
		case "suspicious_network_activity":
			foundSuspiciousNetwork = true
		case "process_manipulation":
			foundProcessManipulation = true
		case "evasion_techniques":
			foundEvasionTechniques = true
		}
	}
	
	assert.True(t, foundSuspiciousNetwork, "Should detect suspicious network activity")
	assert.True(t, foundProcessManipulation, "Should detect process manipulation")
	assert.True(t, foundEvasionTechniques, "Should detect evasion techniques")
}