package behavior

import (
	"fmt"
	"math"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/Alivanroy/Typosentinel/pkg/types"
)

// BehaviorAnalyzer analyzes behavioral patterns and calculates risk scores
type BehaviorAnalyzer struct {
	suspiciousPatterns map[string]*regexp.Regexp
	criticalPaths      []string
	knownBadDomains    map[string]bool
	knownBadIPs        map[string]bool
}

// NewBehaviorAnalyzer creates a new behavior analyzer with predefined patterns
func NewBehaviorAnalyzer() *BehaviorAnalyzer {
	return &BehaviorAnalyzer{
		suspiciousPatterns: compileSuspiciousPatterns(),
		criticalPaths: []string{
			"/etc/passwd", "/etc/shadow", "/root/.ssh", "/home/*/.ssh",
			"/etc/hosts", "/proc", "/sys", "/dev", "/boot",
			"/usr/bin", "/usr/sbin", "/bin", "/sbin",
			"/.dockerenv", "/.kubernetes", "/var/run/docker.sock",
		},
		knownBadDomains: map[string]bool{
			"pastebin.com": true, "ghostbin.com": true, "dpaste.com": true,
			"requestbin.net": true, "webhook.site": true, "ngrok.io": true,
			"localtunnel.me": true, "serveo.net": true, "localhost.run": true,
		},
		knownBadIPs: map[string]bool{
			"1.1.1.1": false, // Cloudflare - legitimate
			"8.8.8.8": false, // Google DNS - legitimate
		},
	}
}

// AnalyzeBehavior analyzes the behavior profile and calculates risk scores
func (ba *BehaviorAnalyzer) AnalyzeBehavior(profile *BehaviorProfile) *BehaviorAnalysis {
	analysis := &BehaviorAnalysis{
		PackageID:       profile.PackageName,
		AnalysisTime:    time.Now(),
		RiskScore:       0.0,
		RiskLevel:       "low",
		ThreatsDetected: []BehaviorThreat{},
		BehaviorSummary: &BehaviorSummary{},
	}

	// Analyze filesystem behavior
	fsScore, fsThreats := ba.analyzeFilesystemBehavior(profile)
	
	// Analyze network behavior  
	netScore, netThreats := ba.analyzeNetworkBehavior(profile)
	
	// Analyze suspicious patterns
	patternScore, patternThreats := ba.analyzeSuspiciousPatterns(profile)
	
	// Analyze process behavior
	procScore, procThreats := ba.analyzeProcessBehavior(profile)

	// Calculate overall risk score
	analysis.RiskScore = ba.calculateOverallRisk(fsScore, netScore, patternScore, procScore)
	analysis.RiskLevel = ba.getRiskLevel(analysis.RiskScore)
	
	// Combine all threats
	analysis.ThreatsDetected = append(analysis.ThreatsDetected, fsThreats...)
	analysis.ThreatsDetected = append(analysis.ThreatsDetected, netThreats...)
	analysis.ThreatsDetected = append(analysis.ThreatsDetected, patternThreats...)
	analysis.ThreatsDetected = append(analysis.ThreatsDetected, procThreats...)

	// Generate behavior summary
	analysis.BehaviorSummary = ba.generateBehaviorSummary(profile, analysis)

	return analysis
}

// analyzeFilesystemBehavior analyzes filesystem access patterns
func (ba *BehaviorAnalyzer) analyzeFilesystemBehavior(profile *BehaviorProfile) (float64, []BehaviorThreat) {
	var threats []BehaviorThreat
	score := 0.0

	// Check for critical path access
	allFiles := append(profile.FilesystemActions.FilesRead, profile.FilesystemActions.FilesWritten...)
	allFiles = append(allFiles, profile.FilesystemActions.FilesCreated...)
	allFiles = append(allFiles, profile.FilesystemActions.FilesDeleted...)
	
	for _, filePath := range allFiles {
		for _, criticalPath := range ba.criticalPaths {
			if strings.Contains(filePath, criticalPath) || 
			   (strings.Contains(criticalPath, "*") && 
			    strings.Contains(filePath, strings.Replace(criticalPath, "*", "", -1))) {
				
				severity := ba.getPathSeverity(filePath)
				threats = append(threats, BehaviorThreat{
					Type:        "filesystem",
					Severity:    fmt.Sprintf("%.1f", severity),
					Description: fmt.Sprintf("Access to critical system path: %s", filePath),
				})
				score += severity * 10.0
			}
		}

		// Check for suspicious file operations
		if strings.Contains(filePath, ".ssh") {
			threats = append(threats, BehaviorThreat{
				Type:        "filesystem",
				Severity:    "8.0",
				Description: "SSH key modification detected",
			})
			score += 8.0 * 10.0
		}

		if strings.HasPrefix(filePath, "/tmp") {
			threats = append(threats, BehaviorThreat{
				Type:        "filesystem",
				Severity:    "6.0",
				Description: "Execution from temporary directory",
			})
			score += 6.0 * 10.0
		}
	}

	// Check for mass file operations
	totalFileOps := len(profile.FilesystemActions.FilesRead) + len(profile.FilesystemActions.FilesWritten) + len(profile.FilesystemActions.FilesCreated) + len(profile.FilesystemActions.FilesDeleted)
	if totalFileOps > 100 {
		threats = append(threats, BehaviorThreat{
			Type:        "filesystem",
			Severity:    "5.0",
			Description: fmt.Sprintf("Unusually high number of filesystem operations: %d", totalFileOps),
		})
		score += 5.0 * 10.0
	}

	return math.Min(score, 100.0), threats
}

// analyzeNetworkBehavior analyzes network activity patterns
func (ba *BehaviorAnalyzer) analyzeNetworkBehavior(profile *BehaviorProfile) (float64, []BehaviorThreat) {
	var threats []BehaviorThreat
	score := 0.0

	// Check DNS queries for suspicious domains
	for _, dnsQuery := range profile.NetworkActivity.DNSQueries {
		if ba.knownBadDomains[dnsQuery.Domain] {
			threats = append(threats, BehaviorThreat{
				Type:        "network",
				Severity:    "7.0",
				Description: fmt.Sprintf("DNS query to known suspicious domain: %s", dnsQuery.Domain),
			})
			score += 7.0 * 10.0
		}
	}

	// Check HTTP requests for suspicious activity
	for _, httpReq := range profile.NetworkActivity.HTTPRequests {
		// Check for suspicious domains in URLs
		for domain := range ba.knownBadDomains {
			if strings.Contains(httpReq.URL, domain) {
				threats = append(threats, BehaviorThreat{
					Type:        "network",
					Severity:    "7.0",
					Description: fmt.Sprintf("HTTP request to suspicious domain: %s", domain),
				})
				score += 7.0 * 10.0
			}
		}

		// Check for large data transmissions
		if httpReq.BodySize > 1024*1024 { // > 1MB sent
			threats = append(threats, BehaviorThreat{
				Type:        "network",
				Severity:    "8.0",
				Description: fmt.Sprintf("Large HTTP request: %d bytes", httpReq.BodySize),
			})
			score += 8.0 * 10.0
		}
	}

	// Check TCP connections for suspicious activity
	for _, conn := range profile.NetworkActivity.TCPConnections {
		// Check for external connections during installation
		if conn.RemotePort != 80 && conn.RemotePort != 443 && conn.RemotePort > 1024 {
			threats = append(threats, BehaviorThreat{
				Type:        "network",
				Severity:    "6.0",
				Description: fmt.Sprintf("Connection to non-standard port: %d", conn.RemotePort),
			})
			score += 6.0 * 10.0
		}

		// Check for large data transmissions
		if conn.BytesSent > 1024*1024 { // > 1MB sent
			threats = append(threats, BehaviorThreat{
				Type:        "network",
				Severity:    "8.0",
				Description: fmt.Sprintf("Large data transmission: %d bytes", conn.BytesSent),
			})
			score += 8.0 * 10.0
		}
	}

	// Check for unusual network activity
	totalNetworkActivity := len(profile.NetworkActivity.DNSQueries) + len(profile.NetworkActivity.HTTPRequests) + len(profile.NetworkActivity.TCPConnections) + len(profile.NetworkActivity.UDPConnections)
	if totalNetworkActivity > 10 {
		threats = append(threats, BehaviorThreat{
			Type:        "network",
			Severity:    "4.0",
			Description: fmt.Sprintf("High network activity: %d connections", totalNetworkActivity),
		})
		score += 4.0 * 10.0
	}

	return math.Min(score, 100.0), threats
}

// analyzeSuspiciousPatterns analyzes code execution patterns
func (ba *BehaviorAnalyzer) analyzeSuspiciousPatterns(profile *BehaviorProfile) (float64, []BehaviorThreat) {
	var threats []BehaviorThreat
	score := 0.0

	// Check for suspicious patterns in raw events
	for _, event := range profile.RawEvents {
		if eventType, ok := event.Data["type"].(string); ok {
			if regex, exists := ba.suspiciousPatterns[eventType]; exists {
				if content, ok := event.Data["content"].(string); ok {
					if regex.MatchString(content) {
						severity := ba.getPatternSeverity(eventType)
						threats = append(threats, BehaviorThreat{
							Type:        "pattern",
							Severity:    fmt.Sprintf("%.1f", severity),
							Description: fmt.Sprintf("Suspicious pattern detected: %s", eventType),
						})
						score += severity * 10.0
					}
				}
			}
		}
	}

	// Check for dynamic code execution
	if profile.SuspiciousPatterns.EvalUsage > 0 {
		threats = append(threats, BehaviorThreat{
			Type:        "pattern",
			Severity:    "9.0",
			Description: fmt.Sprintf("Dynamic code execution detected: %d eval calls", profile.SuspiciousPatterns.EvalUsage),
		})
		score += 9.0 * 10.0
	}

	// Check for obfuscation
	if profile.SuspiciousPatterns.ObfuscatedCode {
		threats = append(threats, BehaviorThreat{
			Type:        "pattern",
			Severity:    "8.0",
			Description: "Code obfuscation detected",
		})
		score += 8.0 * 10.0
	}

	return math.Min(score, 100.0), threats
}

// analyzeProcessBehavior analyzes process execution patterns
func (ba *BehaviorAnalyzer) analyzeProcessBehavior(profile *BehaviorProfile) (float64, []BehaviorThreat) {
	var threats []BehaviorThreat
	score := 0.0

	// Check for privilege escalation
	if profile.SuspiciousPatterns.PrivilegeEscalation > 0 {
		threats = append(threats, BehaviorThreat{
			Type:        "process",
			Severity:    "9.0",
			Description: fmt.Sprintf("Privilege escalation attempt detected: %d attempts", profile.SuspiciousPatterns.PrivilegeEscalation),
		})
		score += 9.0 * 10.0
	}

	// Check for process injection
	if profile.SuspiciousPatterns.ProcessInjection > 0 {
		threats = append(threats, BehaviorThreat{
			Type:        "process",
			Severity:    "9.0",
			Description: fmt.Sprintf("Process injection detected: %d attempts", profile.SuspiciousPatterns.ProcessInjection),
		})
		score += 9.0 * 10.0
	}

	// Check for persistence mechanisms
	if profile.SuspiciousPatterns.DataEncryptionAttempts > 0 {
		threats = append(threats, BehaviorThreat{
			Type:        "process",
			Severity:    "8.0",
			Description: fmt.Sprintf("Persistence mechanism detected: %d encryption attempts", profile.SuspiciousPatterns.DataEncryptionAttempts),
		})
		score += 8.0 * 10.0
	}

	return math.Min(score, 100.0), threats
}

// calculateOverallRisk calculates the overall risk score
func (ba *BehaviorAnalyzer) calculateOverallRisk(fsScore, netScore, patternScore, procScore float64) float64 {
	// Weighted average with emphasis on critical behaviors
	weights := struct {
		filesystem float64
		network    float64
		patterns   float64
		process    float64
	}{
		filesystem: 0.25,
		network:    0.25,
		patterns:   0.25,
		process:    0.25,
	}

	// Apply exponential scaling for high-risk behaviors
	fsScore = ba.exponentialScale(fsScore)
	netScore = ba.exponentialScale(netScore)
	patternScore = ba.exponentialScale(patternScore)
	procScore = ba.exponentialScale(procScore)

	overall := (fsScore*weights.filesystem + 
				netScore*weights.network + 
				patternScore*weights.patterns + 
				procScore*weights.process)

	return math.Min(overall, 100.0)
}

// exponentialScale applies exponential scaling to risk scores
func (ba *BehaviorAnalyzer) exponentialScale(score float64) float64 {
	// Exponential scaling: low scores stay low, high scores become very high
	return math.Pow(score/100.0, 0.5) * 100.0
}

// getRiskLevel determines the risk level based on score
func (ba *BehaviorAnalyzer) getRiskLevel(score float64) string {
	if score >= 80.0 {
		return "critical"
	} else if score >= 60.0 {
		return "high"
	} else if score >= 40.0 {
		return "medium"
	} else if score >= 20.0 {
		return "low"
	}
	return "minimal"
}

// generateBehaviorSummary generates a human-readable behavior summary
func (ba *BehaviorAnalyzer) generateBehaviorSummary(profile *BehaviorProfile, analysis *BehaviorAnalysis) *BehaviorSummary {
	summary := &BehaviorSummary{
		TotalActions:      len(profile.FilesystemActions.FilesRead) + len(profile.NetworkActivity.DNSQueries) + len(profile.RawEvents),
		CriticalActions:   len(analysis.ThreatsDetected),
		RiskFactors:       []string{},
		Recommendations:   []string{},
	}

	// Identify key risk factors
	for _, threat := range analysis.ThreatsDetected {
		severity, _ := strconv.ParseFloat(threat.Severity, 64)
		if severity >= 7.0 {
			summary.RiskFactors = append(summary.RiskFactors, threat.Description)
		}
	}

	// Generate recommendations
	if analysis.RiskScore >= 80.0 {
		summary.Recommendations = append(summary.Recommendations, 
			"IMMEDIATE ACTION: Package exhibits critical malicious behavior - block installation",
			"Investigate package origin and report to security team",
			"Review all projects that may have installed this package")
	} else if analysis.RiskScore >= 60.0 {
		summary.Recommendations = append(summary.Recommendations,
			"HIGH RISK: Package shows suspicious behavior patterns",
			"Consider blocking or sandboxing installation",
			"Monitor network traffic if package is installed")
	} else if analysis.RiskScore >= 40.0 {
		summary.Recommendations = append(summary.Recommendations,
			"MEDIUM RISK: Package exhibits some concerning behaviors",
			"Review package source and maintainer reputation",
			"Consider alternative packages if available")
	} else {
		summary.Recommendations = append(summary.Recommendations,
			"LOW RISK: Package shows minimal suspicious behavior",
			"Standard security monitoring recommended")
	}

	return summary
}

// Helper functions

func (ba *BehaviorAnalyzer) getPathSeverity(path string) float64 {
	if strings.Contains(path, "/etc/passwd") || strings.Contains(path, "/etc/shadow") {
		return 9.0
	}
	if strings.Contains(path, "/root/.ssh") || strings.Contains(path, ".ssh") {
		return 8.0
	}
	if strings.Contains(path, "/proc") || strings.Contains(path, "/sys") {
		return 7.0
	}
	if strings.Contains(path, "/bin") || strings.Contains(path, "/sbin") {
		return 6.0
	}
	return 5.0
}

func (ba *BehaviorAnalyzer) getPatternSeverity(patternType string) float64 {
	severityMap := map[string]float64{
		"eval_execution":        9.0,
		"shell_execution":       9.0,
		"crypto_mining":         8.0,
		"data_exfiltration":     8.0,
		"backdoor":              9.0,
		"obfuscation":           7.0,
		"persistence":           7.0,
		"privilege_escalation":  8.0,
		"network_scanning":      6.0,
		"file_system_scanning":  5.0,
	}
	
	if severity, exists := severityMap[patternType]; exists {
		return severity
	}
	return 5.0
}

func compileSuspiciousPatterns() map[string]*regexp.Regexp {
	patterns := map[string]string{
		"eval_execution":        `(?i)(eval\s*\(|exec\s*\(|system\s*\(|passthru\s*\(|shell_exec\s*\(|proc_open\s*\()`,
		"shell_execution":       `(?i)(/bin/sh|/bin/bash|/usr/bin/sh|cmd\.exe|powershell\.exe)`,
		"crypto_mining":         `(?i)(monero|bitcoin|crypto|mining|xmrig|nicehash|minergate)`,
		"data_exfiltration":       `(?i)(curl.*http|wget.*http|ftp.*get|sftp|scp.*http)`,
		"backdoor":              `(?i)(backdoor|reverse.*shell|bind.*shell|remote.*access)`,
		"obfuscation":           `(?i)(base64_decode|fromCharCode|unescape|atob|btoa|hex2bin)`,
		"persistence":           `(?i)(crontab|systemd|service|registry|startup|autorun)`,
		"privilege_escalation":  `(?i)(sudo|setuid|setgid|chmod.*777|chown.*root)`,
		"network_scanning":      `(?i)(nmap|masscan|zmap|ping.*-c|traceroute|netstat)`,
		"file_system_scanning":  `(?i)(find.*-name|ls.*-la|tree|du.*-sh)`,
	}
	
	compiled := make(map[string]*regexp.Regexp)
	for name, pattern := range patterns {
		if regex, err := regexp.Compile(pattern); err == nil {
			compiled[name] = regex
		}
	}
	
	return compiled
}

// Integration with existing models
func (ba *BehaviorAnalyzer) ConvertToDependencyScanResult(analysis *BehaviorAnalysis) *types.ScanResult {
	// Convert threats to the proper format
	threats := make([]types.Threat, len(analysis.ThreatsDetected))
	for i, threat := range analysis.ThreatsDetected {
		severity := types.SeverityLow
		severityFloat, _ := strconv.ParseFloat(threat.Severity, 64)
		switch {
		case severityFloat >= 8.0:
			severity = types.SeverityCritical
		case severityFloat >= 6.0:
			severity = types.SeverityHigh
		case severityFloat >= 4.0:
			severity = types.SeverityMedium
		}
		
		threats[i] = types.Threat{
			ID:          fmt.Sprintf("behavior_%s_%d", analysis.PackageID, i),
			Package:     analysis.PackageID,
			Type:        types.ThreatTypeMaliciousPackage,
			Severity:    severity,
			Confidence:  0.9, // High confidence for behavior analysis
			Description: threat.Description,
			Evidence: []types.Evidence{
				{
					Type:        "behavioral",
					Description: threat.Type,
					Value:       threat.Evidence,
					Score:       severityFloat,
				},
			},
			DetectedAt:      analysis.AnalysisTime,
			DetectionMethod: "behavioral_analysis",
		}
	}

	return &types.ScanResult{
		ID:        fmt.Sprintf("behavior_%s", analysis.PackageID),
		PackageID: analysis.PackageID,
		Target:    analysis.PackageID,
		Type:      "behavioral_analysis",
		ScanType:  "behavioral",
		Status:    "completed",
		OverallRisk: analysis.RiskLevel,
		RiskScore: analysis.RiskScore,
		Packages: []*types.Package{
			{
				Name:      analysis.PackageID,
				Threats:   threats,
				RiskLevel: types.SeverityHigh, // Will be recalculated based on threats
				RiskScore: analysis.RiskScore,
				AnalyzedAt: analysis.AnalysisTime,
			},
		},
		CreatedAt: analysis.AnalysisTime,
		Metadata: map[string]interface{}{
			"behavior_analysis": analysis,
		},
	}
}

func (ba *BehaviorAnalyzer) convertThreats(threats []BehaviorThreat) []types.Threat {
	var result []types.Threat
	for _, threat := range threats {
		severity := types.SeverityLow
		severityFloat, _ := strconv.ParseFloat(threat.Severity, 64)
		switch {
		case severityFloat >= 8.0:
			severity = types.SeverityCritical
		case severityFloat >= 6.0:
			severity = types.SeverityHigh
		case severityFloat >= 4.0:
			severity = types.SeverityMedium
		}
		
		result = append(result, types.Threat{
			ID:          fmt.Sprintf("behavior_%s", threat.Type),
			Package:     "unknown", // Should be passed as parameter
			Type:        types.ThreatTypeMaliciousPackage,
			Severity:    severity,
			Confidence:  0.9,
			Description: threat.Description,
			Evidence: []types.Evidence{
				{
					Type:        "behavioral",
					Description: threat.Type,
					Value:       threat.Description,
					Score:       severityFloat,
				},
			},
			DetectedAt:      time.Now(),
			DetectionMethod: "behavioral_analysis",
		})
	}
	return result
}