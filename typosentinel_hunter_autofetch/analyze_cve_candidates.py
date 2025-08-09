#!/usr/bin/env python3
"""
CVE Candidate Malware Analysis Integration
Analyzes high-risk packages identified by the CVE hunter for malware patterns
"""

import json
import os
import sys
from malware_multi_ecosystem import MultiEcosystemMalwareAnalyzer

def load_cve_results(results_file):
    """Load CVE hunt results and extract high-risk packages"""
    try:
        with open(results_file, 'r') as f:
            data = json.load(f)
        
        high_risk_packages = []
        
        # Extract packages flagged for review (data is an array)
        for package_data in data:
            if package_data.get('decision') == 'review':
                ecosystem = package_data.get('ecosystem', 'unknown')
                if ecosystem == 'npm':  # Focus on npm packages for now
                    high_risk_packages.append({
                        'name': package_data.get('name'),
                        'ecosystem': ecosystem,
                        'risk': package_data.get('risk', 0.0),
                        'reasons': package_data.get('reasons', []),
                        'signals': package_data.get('signals', [])
                    })
        
        return high_risk_packages
        
    except Exception as e:
        print(f"❌ Error loading CVE results: {e}")
        return []

def analyze_high_risk_packages(packages, output_dir="malware_analysis_results"):
    """Analyze high-risk packages for malware"""
    
    # Create output directory
    os.makedirs(output_dir, exist_ok=True)
    
    results = {}
    
    print(f"🔍 Starting malware analysis for {len(packages)} high-risk packages")
    print("=" * 80)
    
    for i, package in enumerate(packages, 1):
        package_name = package['name']
        ecosystem = package['ecosystem']
        print(f"\n[{i}/{len(packages)}] Analyzing: {package_name} ({ecosystem})")
        print(f"CVE Risk: {package['risk']}")
        print(f"CVE Reasons: {', '.join(package['reasons'])}")
        print(f"CVE Signals: {', '.join(package['signals'])}")
        
        try:
            # Create a new analyzer instance for each package
            analyzer = MultiEcosystemMalwareAnalyzer()
            
            # Download and analyze package
            success, findings = analyzer.analyze_package(package_name, ecosystem)
            
            results[package_name] = {
                'success': success,
                'cve_risk': package['risk'],
                'cve_reasons': package['reasons'],
                'cve_signals': package['signals'],
                'ecosystem': package['ecosystem'],
                'findings_count': len(findings) if findings else 0,
                'critical_findings': len([f for f in findings if f['severity'] == 'CRITICAL']) if findings else 0,
                'high_findings': len([f for f in findings if f['severity'] == 'HIGH']) if findings else 0
            }
            
        except Exception as e:
            print(f"❌ Error analyzing {package_name}: {e}")
            results[package_name] = {
                'success': False,
                'error': str(e),
                'cve_risk': package['risk'],
                'cve_reasons': package['reasons'],
                'cve_signals': package['signals'],
                'ecosystem': package['ecosystem'],
                'findings_count': 0,
                'critical_findings': 0,
                'high_findings': 0
            }
    
    # Save consolidated results
    results_file = os.path.join(output_dir, "malware_analysis_summary.json")
    with open(results_file, 'w') as f:
        json.dump(results, f, indent=2)
    
    print(f"\n💾 Malware analysis results saved to: {results_file}")
    
    # Generate summary report
    generate_summary_report(results, output_dir)
    
    return results

def generate_summary_report(results, output_dir):
    """Generate a summary report of malware analysis"""
    
    report_file = os.path.join(output_dir, "malware_analysis_report.md")
    
    total_packages = len(results)
    successful_analyses = sum(1 for r in results.values() if r.get('success', False))
    failed_analyses = total_packages - successful_analyses
    
    with open(report_file, 'w') as f:
        f.write("# Malware Analysis Report for CVE Candidates\n\n")
        f.write(f"**Analysis Date:** {os.popen('date').read().strip()}\n\n")
        
        f.write("## Summary\n\n")
        f.write(f"- **Total Packages Analyzed:** {total_packages}\n")
        f.write(f"- **Successful Analyses:** {successful_analyses}\n")
        f.write(f"- **Failed Analyses:** {failed_analyses}\n\n")
        
        f.write("## Package Analysis Results\n\n")
        
        for package_name, result in results.items():
            f.write(f"### {package_name}\n\n")
            f.write(f"- **Ecosystem:** {result.get('ecosystem', 'unknown')}\n")
            f.write(f"- **CVE Risk Score:** {result.get('cve_risk', 0.0)}\n")
            f.write(f"- **CVE Reasons:** {', '.join(result.get('cve_reasons', []))}\n")
            f.write(f"- **Malware Analysis:** {'✅ Completed' if result.get('success') else '❌ Failed'}\n")
            
            if not result.get('success') and 'error' in result:
                f.write(f"- **Error:** {result['error']}\n")
            
            f.write("\n")
        
        f.write("## Recommendations\n\n")
        f.write("1. **Review packages with high CVE risk scores** - These packages showed suspicious patterns in typosquatting analysis\n")
        f.write("2. **Investigate failed analyses** - Packages that couldn't be analyzed may have download or extraction issues\n")
        f.write("3. **Cross-reference findings** - Compare CVE risk factors with malware analysis results\n")
        f.write("4. **Manual review** - Conduct manual code review for packages with multiple risk indicators\n\n")
        
        f.write("## Next Steps\n\n")
        f.write("- Expand analysis to include Go packages\n")
        f.write("- Implement automated threat scoring\n")
        f.write("- Set up continuous monitoring for new package versions\n")
        f.write("- Create whitelist for verified safe packages\n")
    
    print(f"📊 Summary report generated: {report_file}")

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 analyze_cve_candidates.py <cve_results_file>")
        print("Example: python3 analyze_cve_candidates.py out/npm_go_results.json")
        sys.exit(1)
    
    results_file = sys.argv[1]
    
    if not os.path.exists(results_file):
        print(f"❌ Results file not found: {results_file}")
        sys.exit(1)
    
    # Load high-risk packages from CVE results
    high_risk_packages = load_cve_results(results_file)
    
    if not high_risk_packages:
        print("ℹ️  No high-risk packages found in CVE results")
        return
    
    print(f"🎯 Found {len(high_risk_packages)} high-risk packages to analyze:")
    for pkg in high_risk_packages:
        print(f"  • {pkg['name']} (risk: {pkg['risk']}, reasons: {', '.join(pkg['reasons'])})")
    
    # Analyze packages for malware
    results = analyze_high_risk_packages(high_risk_packages)
    
    print(f"\n✅ Malware analysis completed for {len(results)} packages")

if __name__ == "__main__":
    main()