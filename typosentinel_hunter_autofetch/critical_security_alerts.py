#!/usr/bin/env python3
"""
Critical Security Alert Generator
Generates immediate security alerts for critical Python malware findings
"""

import json
import sys
import os
from datetime import datetime
from pathlib import Path

def generate_critical_alerts():
    """Generate critical security alerts based on malware analysis"""
    
    # Load enhanced malware analysis results
    results_file = Path("enhanced_python_malware_results/enhanced_malware_analysis.json")
    if not results_file.exists():
        print("❌ Enhanced malware analysis results not found!")
        return
    
    with open(results_file, 'r') as f:
        results = json.load(f)
    
    # Critical alert criteria
    critical_packages = []
    high_risk_packages = []
    
    for package in results:
        if package['success']:
            critical_count = package.get('critical_findings', 0)
            high_count = package.get('high_findings', 0)
            
            if critical_count > 0:
                critical_packages.append({
                    'name': package['package_name'],
                    'critical_findings': critical_count,
                    'high_findings': high_count,
                    'total_findings': package.get('total_findings', 0),
                    'severity': 'CRITICAL',
                    'threat_level': 'IMMEDIATE_BLOCK'
                })
            elif high_count > 0:
                high_risk_packages.append({
                    'name': package['package_name'],
                    'high_findings': high_count,
                    'total_findings': package.get('total_findings', 0),
                    'severity': 'HIGH',
                    'threat_level': 'REVIEW_REQUIRED'
                })
    
    # Generate alerts
    alerts = []
    
    # Critical alerts
    for pkg in critical_packages:
        alerts.append({
            'alert_id': f"CRIT-{pkg['name'].upper()}-{datetime.now().strftime('%Y%m%d')}",
            'timestamp': datetime.now().isoformat(),
            'severity': 'CRITICAL',
            'package_name': pkg['name'],
            'threat_type': 'MALWARE_DETECTED',
            'action_required': 'IMMEDIATE_BLOCK',
            'description': f"Critical malware detected in {pkg['name']} package",
            'findings_count': pkg['critical_findings'],
            'total_findings': pkg['total_findings'],
            'recommendation': f"BLOCK {pkg['name']} immediately. Scan all environments for this package.",
            'impact': 'HIGH - Potential system compromise, data theft, or credential harvesting'
        })
    
    # High-risk alerts
    for pkg in high_risk_packages:
        alerts.append({
            'alert_id': f"HIGH-{pkg['name'].upper()}-{datetime.now().strftime('%Y%m%d')}",
            'timestamp': datetime.now().isoformat(),
            'severity': 'HIGH',
            'package_name': pkg['name'],
            'threat_type': 'SUSPICIOUS_PATTERNS',
            'action_required': 'REVIEW_AND_ASSESS',
            'description': f"High-risk patterns detected in {pkg['name']} package",
            'findings_count': pkg['high_findings'],
            'total_findings': pkg['total_findings'],
            'recommendation': f"Review {pkg['name']} usage and consider blocking if not essential.",
            'impact': 'MEDIUM - Potential security risks requiring investigation'
        })
    
    # Save alerts
    output_dir = Path("critical_security_alerts")
    output_dir.mkdir(exist_ok=True)
    
    alerts_file = output_dir / "critical_alerts.json"
    with open(alerts_file, 'w') as f:
        json.dump(alerts, f, indent=2)
    
    # Generate alert summary
    generate_alert_summary(alerts, critical_packages, high_risk_packages, output_dir)
    
    print(f"🚨 CRITICAL SECURITY ALERTS GENERATED!")
    print("=" * 60)
    print(f"📁 Alerts saved to: {output_dir}")
    print(f"🔴 Critical alerts: {len(critical_packages)}")
    print(f"🟠 High-risk alerts: {len(high_risk_packages)}")
    print(f"📋 Total alerts: {len(alerts)}")
    
    # Print immediate actions
    if critical_packages:
        print(f"\n🚨 IMMEDIATE ACTION REQUIRED:")
        print("=" * 40)
        for pkg in critical_packages:
            print(f"🔴 BLOCK: {pkg['name']} ({pkg['critical_findings']} critical findings)")
    
    if high_risk_packages:
        print(f"\n⚠️  REVIEW REQUIRED:")
        print("=" * 40)
        for pkg in high_risk_packages:
            print(f"🟠 REVIEW: {pkg['name']} ({pkg['high_findings']} high-risk findings)")

def generate_alert_summary(alerts, critical_packages, high_risk_packages, output_dir):
    """Generate a human-readable alert summary"""
    
    summary_content = f"""# 🚨 CRITICAL SECURITY ALERT SUMMARY

**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  
**Alert Level:** CRITICAL SECURITY INCIDENT

## 🔥 IMMEDIATE THREAT DETECTED

Our Python malware analysis has identified **CRITICAL SECURITY THREATS** requiring immediate action.

### 📊 Alert Statistics
- **Critical Alerts:** {len(critical_packages)}
- **High-Risk Alerts:** {len(high_risk_packages)}
- **Total Security Incidents:** {len(alerts)}

## 🚨 CRITICAL PACKAGES - IMMEDIATE BLOCK REQUIRED

"""
    
    if critical_packages:
        for pkg in critical_packages:
            summary_content += f"""
### 🔴 {pkg['name'].upper()} - CRITICAL MALWARE
- **Threat Level:** CRITICAL
- **Action:** IMMEDIATE BLOCK
- **Critical Findings:** {pkg['critical_findings']}
- **Total Findings:** {pkg['total_findings']}
- **Impact:** System compromise, credential theft, data exfiltration
"""
    else:
        summary_content += "\nNo critical packages detected.\n"
    
    summary_content += f"""
## ⚠️ HIGH-RISK PACKAGES - REVIEW REQUIRED

"""
    
    if high_risk_packages:
        for pkg in high_risk_packages:
            summary_content += f"""
### 🟠 {pkg['name'].upper()} - HIGH RISK
- **Threat Level:** HIGH
- **Action:** REVIEW AND ASSESS
- **High-Risk Findings:** {pkg['high_findings']}
- **Total Findings:** {pkg['total_findings']}
- **Impact:** Potential security risks
"""
    else:
        summary_content += "\nNo high-risk packages detected.\n"
    
    summary_content += f"""
## 🎯 IMMEDIATE ACTIONS REQUIRED

### 1. BLOCK CRITICAL PACKAGES
"""
    
    if critical_packages:
        for pkg in critical_packages:
            summary_content += f"- **BLOCK {pkg['name']} IMMEDIATELY**\n"
    
    summary_content += f"""
### 2. SECURITY SCANNING
- Scan all development and production environments
- Check for presence of blocked packages
- Review dependency manifests (requirements.txt, Pipfile, etc.)

### 3. INCIDENT RESPONSE
- Activate security incident response procedures
- Document all findings and actions taken
- Notify security team and stakeholders

### 4. PREVENTIVE MEASURES
- Implement package verification in CI/CD
- Use dependency pinning with hash verification
- Enable automated security scanning

## 📋 Technical Details

For detailed technical findings and analysis results, refer to:
- `enhanced_malware_analysis.json` - Complete technical analysis
- `python_malware_summary_report.md` - Comprehensive analysis report
- `critical_alerts.json` - Machine-readable alert data

---

**⚠️ This is a CRITICAL SECURITY ALERT requiring immediate attention.**

**Contact Information:**
- Security Team: [security@company.com]
- Incident Response: [incident-response@company.com]
- Emergency Hotline: [+1-XXX-XXX-XXXX]
"""
    
    summary_file = output_dir / "CRITICAL_SECURITY_ALERT.md"
    with open(summary_file, 'w') as f:
        f.write(summary_content)

if __name__ == "__main__":
    generate_critical_alerts()