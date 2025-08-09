#!/usr/bin/env python3
"""
Novel CVE Hunter - Targets real existing packages to find undiscovered vulnerabilities
"""

import os, sys, json, argparse, time, random
from pathlib import Path
from typing import List, Dict, Any, Tuple
from datetime import datetime, timedelta

from hunter.fetchers.pypi import fetch_recent_pypi, fetch_pypi_auto
from hunter.fetchers.npm import fetch_npm_meta, fetch_npm_auto
from hunter.scanner import scan
from hunter.rules import is_cve_candidate

# Target categories for novel CVE discovery
NOVEL_CVE_TARGETS = {
    "recent_uploads": {
        "description": "Recently uploaded packages (last 7 days)",
        "risk": "New packages may contain malicious code before detection"
    },
    "low_download_suspicious": {
        "description": "Low download count packages with suspicious names",
        "risk": "Malicious packages often have low adoption initially"
    },
    "version_anomalies": {
        "description": "Packages with unusual version patterns",
        "risk": "Version confusion attacks and dependency confusion"
    },
    "maintainer_changes": {
        "description": "Packages with recent maintainer changes",
        "risk": "Account takeover or social engineering attacks"
    },
    "dependency_confusion": {
        "description": "Packages that might exploit dependency confusion",
        "risk": "Internal package names published publicly"
    }
}

# Suspicious patterns for novel CVE detection
SUSPICIOUS_PATTERNS = {
    "crypto_mining": [
        "miner", "mining", "crypto", "bitcoin", "ethereum", "monero", "hash", "blockchain"
    ],
    "data_exfiltration": [
        "upload", "send", "post", "fetch", "request", "http", "api", "webhook"
    ],
    "system_access": [
        "exec", "shell", "cmd", "process", "system", "admin", "root", "sudo"
    ],
    "obfuscation": [
        "base64", "encode", "decode", "encrypt", "decrypt", "obfuscate", "minify"
    ],
    "typosquatting": [
        "test", "dev", "util", "lib", "tool", "helper", "kit", "pack", "js", "py"
    ]
}

# Common internal package name patterns (for dependency confusion)
INTERNAL_PATTERNS = [
    "company-", "corp-", "internal-", "private-", "org-", "team-",
    "-internal", "-private", "-corp", "-company", "-org",
    "config", "settings", "env", "secrets", "keys", "auth"
]

def generate_dependency_confusion_targets() -> List[str]:
    """Generate potential dependency confusion package names"""
    targets = []
    
    # Common company prefixes
    companies = ["google", "microsoft", "amazon", "apple", "meta", "netflix", "uber", "airbnb"]
    suffixes = ["config", "utils", "tools", "lib", "core", "common", "shared"]
    
    for company in companies:
        for suffix in suffixes:
            targets.extend([
                f"{company}-{suffix}",
                f"{company}_{suffix}",
                f"{suffix}-{company}",
                f"{company}{suffix}",
                f"{company}-internal-{suffix}",
                f"internal-{company}-{suffix}"
            ])
    
    return targets

def generate_version_confusion_targets() -> List[str]:
    """Generate packages that might exploit version confusion"""
    popular_packages = [
        "lodash", "react", "express", "axios", "moment", "chalk", "commander",
        "requests", "numpy", "pandas", "flask", "django", "tensorflow"
    ]
    
    targets = []
    for pkg in popular_packages:
        targets.extend([
            f"{pkg}-v2", f"{pkg}-v3", f"{pkg}-next", f"{pkg}-beta",
            f"{pkg}-alpha", f"{pkg}-rc", f"{pkg}-dev", f"{pkg}-test",
            f"{pkg}2", f"{pkg}3", f"new-{pkg}", f"latest-{pkg}"
        ])
    
    return targets

def analyze_package_metadata(package_data: Dict) -> Dict[str, Any]:
    """Analyze package metadata for suspicious patterns"""
    analysis = {
        "suspicious_score": 0,
        "red_flags": [],
        "metadata_issues": []
    }
    
    name = package_data.get("name", "").lower()
    
    # Check for suspicious name patterns
    for category, patterns in SUSPICIOUS_PATTERNS.items():
        if any(pattern in name for pattern in patterns):
            analysis["red_flags"].append(f"Suspicious {category} pattern in name")
            analysis["suspicious_score"] += 10
    
    # Check for dependency confusion patterns
    for pattern in INTERNAL_PATTERNS:
        if pattern in name:
            analysis["red_flags"].append("Potential dependency confusion target")
            analysis["suspicious_score"] += 15
    
    # Check version patterns
    if any(v in name for v in ["v2", "v3", "next", "beta", "alpha", "rc"]):
        analysis["red_flags"].append("Version confusion potential")
        analysis["suspicious_score"] += 8
    
    # Check for missing or minimal metadata
    description = package_data.get("description", "")
    if not description or len(description) < 10:
        analysis["metadata_issues"].append("Missing or minimal description")
        analysis["suspicious_score"] += 5
    
    return analysis

def enhanced_novel_cve_detection(package: Dict[str, Any], scan_result, metadata_analysis: Dict) -> Tuple[bool, List[str]]:
    """Enhanced detection rules specifically for novel CVEs"""
    reasons = []
    
    # Start with original CVE candidate detection
    is_candidate, original_reasons = is_cve_candidate(package, scan_result)
    reasons.extend(original_reasons)
    
    # Novel CVE specific rules
    
    # High-risk signals that might indicate novel threats
    signals = set(scan_result.signals)
    novel_risk_signals = {
        "code_injection_pattern", "unexpected_network_domain", "download_spike",
        "maintainer_change", "provenance_mismatch", "registry_mismatch"
    }
    
    if signals.intersection(novel_risk_signals):
        reasons.append(f"Novel threat signals: {', '.join(signals.intersection(novel_risk_signals))}")
    
    # Metadata analysis integration
    if metadata_analysis["suspicious_score"] >= 20:
        reasons.append(f"High metadata suspicion score: {metadata_analysis['suspicious_score']}")
    
    if metadata_analysis["red_flags"]:
        reasons.append(f"Metadata red flags: {', '.join(metadata_analysis['red_flags'][:3])}")
    
    # Risk score thresholds for novel CVEs (lower threshold for discovery)
    if scan_result.risk >= 0.5 and scan_result.decision in ["review", "block"]:
        reasons.append(f"Medium-high risk for novel CVE investigation: {scan_result.risk:.3f}")
    
    # Combination patterns that suggest novel threats
    if (scan_result.risk >= 0.3 and 
        len(signals) >= 2 and 
        metadata_analysis["suspicious_score"] >= 10):
        reasons.append("Combined risk factors suggest novel threat")
    
    return (len(reasons) > 0, reasons)

def fetch_novel_targets(ecosystem: str, target_count: int) -> List[Dict[str, Any]]:
    """Fetch packages that are good candidates for novel CVE discovery"""
    targets = []
    
    if ecosystem == "pypi":
        # Get recent packages
        try:
            recent = fetch_recent_pypi(limit=target_count // 2)
            targets.extend(recent)
            print(f"   📅 Fetched {len(recent)} recent PyPI packages")
        except Exception as e:
            print(f"   ❌ Failed to fetch recent PyPI: {e}")
        
        # Add dependency confusion targets
        dep_confusion = generate_dependency_confusion_targets()
        for name in dep_confusion[:target_count // 4]:
            targets.append({"ecosystem": "pypi", "name": name})
        print(f"   🎯 Added {min(len(dep_confusion), target_count // 4)} dependency confusion targets")
        
    elif ecosystem == "npm":
        # Add version confusion targets
        version_confusion = generate_version_confusion_targets()
        for name in version_confusion[:target_count // 2]:
            targets.append({"ecosystem": "npm", "name": name})
        print(f"   🔄 Added {min(len(version_confusion), target_count // 2)} version confusion targets")
        
        # Add dependency confusion targets
        dep_confusion = generate_dependency_confusion_targets()
        for name in dep_confusion[:target_count // 4]:
            targets.append({"ecosystem": "npm", "name": name})
        print(f"   🎯 Added {min(len(dep_confusion), target_count // 4)} dependency confusion targets")
    
    return targets[:target_count]

def main():
    ap = argparse.ArgumentParser(description="Novel CVE Hunter - Discover undiscovered vulnerabilities")
    ap.add_argument("--ecosystems", default="pypi,npm", help="comma list: pypi,npm,go")
    ap.add_argument("--target-count", type=int, default=150, help="Number of packages to target per ecosystem")
    ap.add_argument("--out-json", default="out/novel_cve_candidates.json", help="Output JSON file for candidates")
    ap.add_argument("--out-all", default="out/novel_all_scans.json", help="Output JSON file for all scans")
    ap.add_argument("--policy", default="balanced", help="Typosentinel policy")
    ap.add_argument("--min-risk", type=float, default=0.3, help="Minimum risk score for investigation")
    
    args = ap.parse_args()
    ecosystems = [x.strip() for x in args.ecosystems.split(",") if x.strip()]
    
    print("🔬 NOVEL CVE DISCOVERY INITIATED")
    print("=" * 60)
    print(f"🎯 Target ecosystems: {', '.join(ecosystems)}")
    print(f"📦 Target count per ecosystem: {args.target_count}")
    print(f"⚠️  Minimum risk threshold: {args.min_risk}")
    print(f"🔍 Policy: {args.policy}")
    
    all_targets = []
    
    for ecosystem in ecosystems:
        print(f"\n🚀 Generating novel CVE targets for {ecosystem}...")
        targets = fetch_novel_targets(ecosystem, args.target_count)
        all_targets.extend(targets)
    
    print(f"\n🎯 Total novel CVE targets: {len(all_targets)}")
    
    # Scan all targets
    all_results = []
    novel_candidates = []
    high_priority_candidates = []
    
    for i, target in enumerate(all_targets):
        print(f"\n[{i+1}/{len(all_targets)}] Scanning {target['ecosystem']}: {target['name']}")
        
        try:
            result = scan(target["name"], target["ecosystem"], policy=args.policy)
            
            # Analyze metadata
            metadata_analysis = analyze_package_metadata(target)
            
            # Enhanced novel CVE detection
            is_candidate, reasons = enhanced_novel_cve_detection(target, result, metadata_analysis)
            
            result_data = {
                "ecosystem": target["ecosystem"],
                "name": target["name"],
                "version": getattr(result, 'version', 'unknown'),
                "decision": result.decision,
                "risk": result.risk,
                "latency": result.latency,
                "signals": result.signals,
                "stdout": result.stdout,
                "stderr": result.stderr,
                "reasons": reasons,
                "metadata_analysis": metadata_analysis,
                "scan_timestamp": datetime.now().isoformat()
            }
            
            all_results.append(result_data)
            
            if is_candidate:
                novel_candidates.append(result_data)
                
                # High priority: risk >= 0.7 or multiple concerning signals
                if (result.risk >= 0.7 or 
                    len(result.signals) >= 3 or 
                    metadata_analysis["suspicious_score"] >= 25):
                    high_priority_candidates.append(result_data)
                    print(f"   🚨 HIGH PRIORITY NOVEL CVE: {result.decision} (risk: {result.risk:.3f})")
                else:
                    print(f"   ⚠️  Novel CVE candidate: {result.decision} (risk: {result.risk:.3f})")
                
                print(f"   📋 Reasons: {', '.join(reasons[:3])}...")
                if result.signals:
                    print(f"   🔍 Signals: {', '.join(result.signals[:5])}")
            else:
                print(f"   ✅ Clean: {result.decision} (risk: {result.risk:.3f})")
                
        except Exception as e:
            print(f"   ❌ Scan failed: {e}")
            continue
    
    print(f"\n📊 NOVEL CVE DISCOVERY SUMMARY:")
    print("=" * 50)
    print(f"   📦 Total packages scanned: {len(all_results)}")
    print(f"   🔬 Novel CVE candidates: {len(novel_candidates)}")
    print(f"   🚨 High priority candidates: {len(high_priority_candidates)}")
    print(f"   ✅ Clean packages: {len(all_results) - len(novel_candidates)}")
    print(f"   🎯 Discovery rate: {len(novel_candidates)/len(all_results)*100:.1f}%")
    
    # Save results
    out_all = Path(args.out_all)
    out_all.parent.mkdir(parents=True, exist_ok=True)
    out_all.write_text(json.dumps(all_results, indent=2), encoding="utf-8")
    print(f"   💾 All results saved to: {args.out_all}")
    
    out_c = Path(args.out_json)
    out_c.parent.mkdir(parents=True, exist_ok=True)
    out_c.write_text(json.dumps(novel_candidates, indent=2), encoding="utf-8")
    print(f"   🔬 Novel CVE candidates saved to: {args.out_json}")
    
    if high_priority_candidates:
        print(f"\n🚨 HIGH PRIORITY NOVEL CVE CANDIDATES:")
        for candidate in high_priority_candidates[:10]:  # Show top 10
            print(f"   🎯 {candidate['ecosystem']}: {candidate['name']}")
            print(f"      Risk: {candidate['risk']:.3f} | Signals: {len(candidate['signals'])}")
            print(f"      Reasons: {', '.join(candidate['reasons'][:2])}")
            print()
    
    if novel_candidates:
        print(f"\n🎉 DISCOVERY SUCCESS! Found {len(novel_candidates)} potential novel CVEs")
        print(f"🔍 Next steps:")
        print(f"   1. Investigate high priority candidates manually")
        print(f"   2. Perform deep malware analysis on suspicious packages")
        print(f"   3. Check for code injection, data exfiltration, or crypto mining")
        print(f"   4. Verify if these are truly novel (not in existing CVE databases)")
        print(f"   5. Prepare CVE reports for confirmed vulnerabilities")
    else:
        print(f"\n😞 No novel CVE candidates found. Consider:")
        print(f"   - Lowering risk threshold (--min-risk)")
        print(f"   - Increasing target count")
        print(f"   - Trying different time periods")
        print(f"   - Expanding to more ecosystems")

if __name__ == "__main__":
    main()