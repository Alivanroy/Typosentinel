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

// TestAPT29CozyBearAttack tests detection of APT29 (Cozy Bear) sophisticated attacks
// Based on real-world SVR (Russian Foreign Intelligence Service) operations
func TestAPT29CozyBearAttack(t *testing.T) {
	ctx := context.Background()
	
	log := logger.New()
	cfg := &config.ZeroDayDetectionConfig{
		Enabled:              true,
		BehavioralAnalysis:   true,
		CodeAnomalyDetection: true,
		RuntimeAnalysis:      true,
		AnomalyThreshold:     0.9, // Very high threshold for nation-state detection
		Timeout:              45 * time.Second,
	}
	
	detector := scanner.NewZeroDayDetector(cfg, log)
	
	publishedTime := time.Date(2023, 11, 15, 0, 0, 0, 0, time.UTC)
	
	// APT29 typically uses sophisticated supply chain attacks and living-off-the-land techniques
	cozyBearPackage := &types.Package{
		Name:     "microsoft-graph-toolkit",
		Version:  "3.0.2",
		Type:     "npm",
		Registry: "npmjs.org",
		Metadata: &types.PackageMetadata{
			Name:        "microsoft-graph-toolkit",
			Version:     "3.0.2",
			Registry:    "npmjs.org",
			Description: "Microsoft Graph Toolkit - Web Components and MSAL Provider for Microsoft Graph",
			Author:      "microsoft-graph-team",
			Homepage:    "https://github.com/microsoftgraph/microsoft-graph-toolkit",
			License:     "MIT",
			Size:        5242880, // 5MB
			Dependencies: []string{
				"@azure/msal-browser",
				"@microsoft/microsoft-graph-client",
				"lit-element",
				"web-components",
			},
			Checksums: map[string]string{
				"sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
			},
			PublishedAt: &publishedTime,
			Downloads:   250000,
			Metadata: map[string]interface{}{
				"code_patterns": []string{
					// APT29 sophisticated techniques
					"WellKnownSidType",
					"TokenInformationClass",
					"NtQueryInformationToken",
					"LsaEnumerateLogonSessions",
					"WNetEnumResource",
					"NetShareEnum",
					"DsEnumerateDomainTrusts",
					"LdapSearch",
					"WMI_Query",
					"PowerShell_Invoke",
					"CertEnumCertificatesInStore",
					"CryptAcquireContext",
					"BCryptGenRandom",
					"RtlGenRandom",
					"GetTickCount64",
					"QueryPerformanceCounter",
					"IsDebuggerPresent",
					"CheckRemoteDebuggerPresent",
					"NtQueryInformationProcess",
					"ZwQueryInformationProcess",
				},
				"steganography_techniques": []string{
					"image_metadata_hiding",
					"dns_txt_records",
					"http_headers_covert",
					"certificate_abuse",
					"cloud_storage_abuse",
				},
				"living_off_land": []string{
					"powershell_empire",
					"wmi_persistence",
					"scheduled_tasks",
					"registry_run_keys",
					"com_hijacking",
					"dll_search_order",
					"service_dll_hijacking",
				},
				"credential_access": []string{
					"lsass_dumping",
					"sam_database_access",
					"cached_credentials",
					"kerberos_ticket_extraction",
					"ntds_dit_extraction",
					"dcsync_attack",
				},
				"lateral_movement": []string{
					"psexec_variants",
					"wmi_execution",
					"dcom_execution",
					"smb_relay",
					"golden_ticket",
					"silver_ticket",
					"overpass_the_hash",
				},
				"persistence_mechanisms": []string{
					"golden_saml",
					"skeleton_key",
					"directory_service_modifications",
					"trusted_relationship_abuse",
					"application_shimming",
					"accessibility_features",
				},
				"defense_evasion": []string{
					"process_doppelganging",
					"process_hollowing",
					"dll_side_loading",
					"masquerading",
					"timestomp",
					"indicator_removal",
					"log_deletion",
					"event_log_clearing",
				},
				"c2_infrastructure": []string{
					"domain_fronting",
					"cdn_abuse",
					"legitimate_web_services",
					"encrypted_channels",
					"steganographic_c2",
					"dns_over_https",
					"esni_abuse",
				},
				"data_exfiltration": []string{
					"cloud_storage_abuse",
					"legitimate_file_sharing",
					"encrypted_archives",
					"steganographic_exfiltration",
					"dns_exfiltration",
				},
				"target_environments": []string{
					"government_networks",
					"diplomatic_missions",
					"think_tanks",
					"policy_organizations",
					"academic_institutions",
					"technology_companies",
				},
			},
		},
	}
	
	findings, err := detector.DetectZeroDayThreats(ctx, cozyBearPackage)
	require.NoError(t, err)
	require.NotEmpty(t, findings)
	
	// Verify APT29-specific sophisticated techniques
	foundSteganography := false
	foundLivingOffLand := false
	foundAdvancedPersistence := false
	foundCredentialAccess := false
	
	for _, finding := range findings {
		switch finding.BehaviorType {
		case "steganography":
			foundSteganography = true
		case "living_off_land":
			foundLivingOffLand = true
		case "advanced_persistence":
			foundAdvancedPersistence = true
		case "credential_access":
			foundCredentialAccess = true
		}
	}
	
	assert.True(t, foundSteganography, "Should detect steganographic techniques")
	assert.True(t, foundLivingOffLand, "Should detect living-off-the-land techniques")
	assert.True(t, foundAdvancedPersistence, "Should detect advanced persistence mechanisms")
	assert.True(t, foundCredentialAccess, "Should detect credential access techniques")
}

// TestAPT28FancyBearAttack tests detection of APT28 (Fancy Bear) military-grade attacks
// Based on real-world GRU (Russian Military Intelligence) operations
func TestAPT28FancyBearAttack(t *testing.T) {
	ctx := context.Background()
	
	log := logger.New()
	cfg := &config.ZeroDayDetectionConfig{
		Enabled:              true,
		BehavioralAnalysis:   true,
		CodeAnomalyDetection: true,
		RuntimeAnalysis:      true,
		AnomalyThreshold:     0.85,
		Timeout:              45 * time.Second,
	}
	
	detector := scanner.NewZeroDayDetector(cfg, log)
	
	publishedTime := time.Date(2023, 9, 20, 0, 0, 0, 0, time.UTC)
	
	// APT28 known for sophisticated spear-phishing and zero-day exploits
	fancyBearPackage := &types.Package{
		Name:     "outlook-security-addon",
		Version:  "2.1.4",
		Type:     "msi",
		Registry: "custom",
		Metadata: &types.PackageMetadata{
			Name:        "outlook-security-addon",
			Version:     "2.1.4",
			Description: "Enhanced security addon for Microsoft Outlook with advanced threat protection",
			Author:      "SecuritySoft Solutions",
			License:     "Commercial",
			Size:        15728640, // 15MB
			Checksums: map[string]string{
				"sha256": "d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5",
			},
			PublishedAt: &publishedTime,
			Downloads:   75000,
			Metadata: map[string]interface{}{
				"zero_day_exploits": []string{
					// APT28 known zero-day techniques
					"cve_2023_unknown_1", // Simulated unknown CVE
					"cve_2023_unknown_2",
					"windows_kernel_exploit",
					"office_macro_exploit",
					"browser_exploit_kit",
					"pdf_exploit",
					"flash_exploit",
				},
				"spear_phishing": []string{
					"targeted_email_templates",
					"social_engineering_profiles",
					"credential_harvesting_forms",
					"malicious_attachments",
					"weaponized_documents",
				},
				"military_targets": []string{
					"nato_organizations",
					"defense_contractors",
					"military_personnel",
					"government_officials",
					"diplomatic_corps",
					"intelligence_agencies",
				},
				"advanced_malware": []string{
					"x_agent_variants",
					"komplex_backdoor",
					"gamefish_malware",
					"chopstick_implant",
					"coreshell_backdoor",
				},
				"infrastructure_abuse": []string{
					"compromised_websites",
					"typosquatting_domains",
					"bulletproof_hosting",
					"tor_hidden_services",
					"vpn_chaining",
				},
				"operational_security": []string{
					"false_flag_operations",
					"attribution_confusion",
					"infrastructure_compartmentalization",
					"operational_tempo_variation",
				},
				"persistence_techniques": []string{
					"uefi_rootkit",
					"bootkit_installation",
					"hypervisor_rootkit",
					"firmware_modification",
					"bios_implant",
				},
				"anti_forensics": []string{
					"memory_only_execution",
					"fileless_malware",
					"log_tampering",
					"timeline_manipulation",
					"evidence_destruction",
				},
			},
		},
	}
	
	findings, err := detector.DetectZeroDayThreats(ctx, fancyBearPackage)
	require.NoError(t, err)
	require.NotEmpty(t, findings)
	
	// Verify APT28-specific military-grade techniques
	foundZeroDayExploit := false
	foundSpearPhishing := false
	foundAdvancedMalware := false
	foundAntiForesics := false
	
	for _, finding := range findings {
		switch finding.BehaviorType {
		case "zero_day_exploit":
			foundZeroDayExploit = true
		case "spear_phishing":
			foundSpearPhishing = true
		case "advanced_malware":
			foundAdvancedMalware = true
		case "anti_forensics":
			foundAntiForesics = true
		}
	}
	
	assert.True(t, foundZeroDayExploit, "Should detect zero-day exploit techniques")
	assert.True(t, foundSpearPhishing, "Should detect spear-phishing capabilities")
	assert.True(t, foundAdvancedMalware, "Should detect advanced malware signatures")
	assert.True(t, foundAntiForesics, "Should detect anti-forensics techniques")
}

// TestAPT40LeviathianAttack tests detection of APT40 (Leviathan) maritime/naval targeting
// Based on real-world MSS (Chinese Ministry of State Security) operations
func TestAPT40LeviathianAttack(t *testing.T) {
	ctx := context.Background()
	
	log := logger.New()
	cfg := &config.ZeroDayDetectionConfig{
		Enabled:              true,
		BehavioralAnalysis:   true,
		CodeAnomalyDetection: true,
		RuntimeAnalysis:      true,
		AnomalyThreshold:     0.8,
		Timeout:              45 * time.Second,
	}
	
	detector := scanner.NewZeroDayDetector(cfg, log)
	
	publishedTime := time.Date(2023, 10, 5, 0, 0, 0, 0, time.UTC)
	
	// APT40 focuses on maritime industries and naval intelligence
	leviathanPackage := &types.Package{
		Name:     "maritime-navigation-sdk",
		Version:  "4.2.1",
		Type:     "jar",
		Registry: "maven",
		Metadata: &types.PackageMetadata{
			Name:        "maritime-navigation-sdk",
			Version:     "4.2.1",
			Registry:    "maven.org",
			Description: "Advanced maritime navigation and vessel tracking SDK",
			Author:      "NavTech Maritime Solutions",
			License:     "Commercial",
			Size:        8388608, // 8MB
			Checksums: map[string]string{
				"sha256": "a1b2c3d4e5f6789012345678901234567890123456789012345678901234567890",
			},
			PublishedAt: &publishedTime,
			Downloads:   45000,
			Metadata: map[string]interface{}{
				"maritime_targets": []string{
					"shipping_companies",
					"port_authorities",
					"naval_contractors",
					"offshore_drilling",
					"maritime_logistics",
					"vessel_tracking_systems",
					"port_management_systems",
				},
				"intelligence_gathering": []string{
					"vessel_movement_tracking",
					"cargo_manifest_access",
					"port_security_systems",
					"naval_communication_intercept",
					"satellite_imagery_analysis",
					"ais_data_manipulation",
				},
				"supply_chain_targeting": []string{
					"maritime_software_vendors",
					"navigation_equipment_manufacturers",
					"port_technology_providers",
					"shipping_management_systems",
				},
				"custom_malware": []string{
					"china_chopper_variants",
					"poisonivy_maritime",
					"gh0st_rat_naval",
					"plugx_shipping",
					"shadowpad_maritime",
				},
				"data_theft_targets": []string{
					"vessel_blueprints",
					"navigation_charts",
					"port_security_plans",
					"cargo_manifests",
					"crew_information",
					"route_planning_data",
				},
				"operational_techniques": []string{
					"watering_hole_attacks",
					"supply_chain_compromise",
					"strategic_web_compromise",
					"spear_phishing_campaigns",
				},
				"persistence_methods": []string{
					"web_shell_deployment",
					"legitimate_tool_abuse",
					"scheduled_task_persistence",
					"service_installation",
				},
			},
		},
	}
	
	findings, err := detector.DetectZeroDayThreats(ctx, leviathanPackage)
	require.NoError(t, err)
	require.NotEmpty(t, findings)
	
	// Verify APT40-specific maritime targeting
	foundMaritimeTargeting := false
	foundIntelligenceGathering := false
	foundSupplyChainCompromise := false
	foundCustomMalware := false
	
	for _, finding := range findings {
		switch finding.BehaviorType {
		case "maritime_targeting":
			foundMaritimeTargeting = true
		case "intelligence_gathering":
			foundIntelligenceGathering = true
		case "supply_chain_compromise":
			foundSupplyChainCompromise = true
		case "custom_malware":
			foundCustomMalware = true
		}
	}
	
	assert.True(t, foundMaritimeTargeting, "Should detect maritime-specific targeting")
	assert.True(t, foundIntelligenceGathering, "Should detect intelligence gathering capabilities")
	assert.True(t, foundSupplyChainCompromise, "Should detect supply chain compromise techniques")
	assert.True(t, foundCustomMalware, "Should detect custom malware signatures")
}