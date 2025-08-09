#!/usr/bin/env python3
"""
Aggressive CVE Hunter - Targets known vulnerability patterns and suspicious packages
"""

import os, sys, json, argparse, time
from pathlib import Path
from typing import List, Dict, Any, Tuple
import random

from hunter.fetchers.pypi import fetch_recent_pypi, fetch_pypi_auto
from hunter.fetchers.npm import fetch_npm_meta, fetch_npm_auto
from hunter.scanner import scan
from hunter.rules import is_cve_candidate

# Known vulnerable package patterns and typosquatting targets
POPULAR_TARGETS = {
    "pypi": [
        "requests", "urllib3", "certifi", "setuptools", "pip", "wheel", "six", "python-dateutil",
        "pyyaml", "click", "jinja2", "markupsafe", "werkzeug", "flask", "django", "numpy",
        "pandas", "matplotlib", "scipy", "scikit-learn", "tensorflow", "torch", "pytorch",
        "opencv-python", "pillow", "beautifulsoup4", "lxml", "selenium", "scrapy",
        "boto3", "botocore", "awscli", "google-cloud", "azure", "kubernetes",
        "sqlalchemy", "psycopg2", "pymongo", "redis", "celery", "gunicorn",
        "pytest", "tox", "black", "flake8", "mypy", "isort", "pre-commit"
    ],
    "npm": [
        "react", "vue", "angular", "express", "lodash", "axios", "moment", "chalk",
        "commander", "yargs", "inquirer", "fs-extra", "glob", "rimraf", "mkdirp",
        "webpack", "babel", "eslint", "prettier", "typescript", "jest", "mocha",
        "jquery", "bootstrap", "d3", "three", "socket.io", "ws", "cors",
        "passport", "bcrypt", "jsonwebtoken", "helmet", "morgan", "compression",
        "nodemon", "pm2", "forever", "concurrently", "cross-env", "dotenv"
    ]
}

# Typosquatting patterns to generate
TYPO_PATTERNS = [
    # Character substitution
    lambda name: name.replace('o', '0'),  # o -> 0
    lambda name: name.replace('i', '1'),  # i -> 1
    lambda name: name.replace('l', '1'),  # l -> 1
    lambda name: name.replace('e', '3'),  # e -> 3
    lambda name: name.replace('a', '@'),  # a -> @
    lambda name: name.replace('s', '$'),  # s -> $
    
    # Character addition
    lambda name: name + 's',
    lambda name: name + 'x',
    lambda name: name + '2',
    lambda name: name + '-dev',
    lambda name: name + '-test',
    lambda name: name + '-utils',
    lambda name: name + '-lib',
    lambda name: name + '-py',
    lambda name: name + '-js',
    
    # Character removal
    lambda name: name[:-1] if len(name) > 3 else name,
    lambda name: name.replace('e', '') if 'e' in name else name,
    lambda name: name.replace('a', '') if 'a' in name else name,
    
    # Character swapping
    lambda name: name[:2] + name[3] + name[2] + name[4:] if len(name) > 4 else name,
    lambda name: name[1] + name[0] + name[2:] if len(name) > 2 else name,
    
    # Hyphen/underscore variations
    lambda name: name.replace('-', '_'),
    lambda name: name.replace('_', '-'),
    lambda name: name.replace('-', ''),
    lambda name: name.replace('_', ''),
    
    # Common misspellings
    lambda name: name.replace('qu', 'q'),
    lambda name: name.replace('ph', 'f'),
    lambda name: name.replace('ck', 'k'),
    lambda name: name.replace('th', 't'),
]

def generate_typosquatting_candidates(target_packages: List[str], count: int = 50) -> List[str]:
    """Generate potential typosquatting package names"""
    candidates = set()
    
    for _ in range(count):
        target = random.choice(target_packages)
        pattern = random.choice(TYPO_PATTERNS)
        try:
            candidate = pattern(target)
            if candidate != target and len(candidate) > 2:
                candidates.add(candidate)
        except:
            continue
    
    return list(candidates)

def generate_suspicious_patterns() -> List[str]:
    """Generate suspicious package name patterns"""
    suspicious = []
    
    # Common malware patterns
    prefixes = ["lib", "py", "node", "js", "test", "dev", "util", "tool", "helper"]
    suffixes = ["lib", "utils", "tools", "dev", "test", "py", "js", "kit", "pack"]
    bases = ["crypto", "bitcoin", "wallet", "miner", "hash", "secure", "auth", "token"]
    
    for prefix in prefixes[:5]:
        for base in bases[:3]:
            suspicious.append(f"{prefix}-{base}")
            suspicious.append(f"{prefix}{base}")
    
    for base in bases[:3]:
        for suffix in suffixes[:5]:
            suspicious.append(f"{base}-{suffix}")
            suspicious.append(f"{base}{suffix}")
    
    # Recent package patterns (version 0.0.x, 0.1.x)
    recent_patterns = [
        "quick-install", "fast-setup", "auto-config", "easy-deploy",
        "secure-hash", "crypto-utils", "wallet-gen", "key-manager",
        "data-fetch", "api-client", "web-scraper", "bot-framework"
    ]
    
    suspicious.extend(recent_patterns)
    return suspicious

def enhanced_cve_rules(package: Dict[str, Any], scan_result) -> Tuple[bool, List[str]]:
    """Enhanced CVE candidate detection rules"""
    reasons = []
    
    # Original rules
    is_candidate, original_reasons = is_cve_candidate(package, scan_result)
    reasons.extend(original_reasons)
    
    # Enhanced rules for aggressive hunting
    if scan_result.decision == "review" and scan_result.risk >= 0.7:
        reasons.append("Medium-high risk flagged for review")
    
    if scan_result.decision == "block":
        reasons.append("Package blocked by Typosentinel")
    
    # Check for suspicious signals
    signals = set(scan_result.signals)
    high_risk_signals = {"typosquatting", "homoglyph", "keyboard", "levenshtein_distance", "jaro_winkler"}
    if signals.intersection(high_risk_signals):
        reasons.append(f"High-risk signals detected: {', '.join(signals.intersection(high_risk_signals))}")
    
    # Check for missing metadata (common in malicious packages)
    if hasattr(scan_result, 'stdout') and "missing_metadata" in scan_result.stdout:
        reasons.append("Missing package metadata")
    
    # Check for recent uploads with suspicious patterns
    name = package.get("name", "").lower()
    suspicious_keywords = ["crypto", "bitcoin", "wallet", "miner", "secure", "auth", "token", "hack", "exploit"]
    if any(keyword in name for keyword in suspicious_keywords):
        reasons.append("Contains suspicious keywords")
    
    return (len(reasons) > 0, reasons)

def main():
    ap = argparse.ArgumentParser(description="Aggressive CVE Hunter - Target known vulnerability patterns")
    ap.add_argument("--ecosystems", default="pypi,npm", help="comma list: pypi,npm,go")
    ap.add_argument("--target-count", type=int, default=100, help="Number of packages to target per ecosystem")
    ap.add_argument("--typo-count", type=int, default=50, help="Number of typosquatting candidates to generate")
    ap.add_argument("--out-json", default="out/aggressive_cve_candidates.json", help="Output JSON file for candidates")
    ap.add_argument("--out-all", default="out/aggressive_all_scans.json", help="Output JSON file for all scans")
    ap.add_argument("--policy", default="paranoid", help="Typosentinel policy")
    
    args = ap.parse_args()
    ecosystems = [x.strip() for x in args.ecosystems.split(",") if x.strip()]
    
    print("🎯 AGGRESSIVE CVE HUNTING INITIATED")
    print(f"🔍 Target ecosystems: {', '.join(ecosystems)}")
    print(f"📦 Target count per ecosystem: {args.target_count}")
    print(f"🎭 Typosquatting candidates: {args.typo_count}")
    
    all_targets = []
    
    for ecosystem in ecosystems:
        print(f"\n🚀 Generating targets for {ecosystem}...")
        
        if ecosystem == "pypi":
            # Generate typosquatting candidates
            typo_candidates = generate_typosquatting_candidates(POPULAR_TARGETS["pypi"], args.typo_count)
            print(f"   🎭 Generated {len(typo_candidates)} typosquatting candidates")
            
            # Add suspicious patterns
            suspicious = generate_suspicious_patterns()
            print(f"   ⚠️  Generated {len(suspicious)} suspicious patterns")
            
            # Fetch recent packages
            try:
                recent = fetch_recent_pypi(limit=args.target_count // 2)
                print(f"   📅 Fetched {len(recent)} recent packages")
            except Exception as e:
                print(f"   ❌ Failed to fetch recent PyPI packages: {e}")
                recent = []
            
            targets = typo_candidates + suspicious + recent
            
        elif ecosystem == "npm":
            # Generate typosquatting candidates
            typo_candidates = generate_typosquatting_candidates(POPULAR_TARGETS["npm"], args.typo_count)
            print(f"   🎭 Generated {len(typo_candidates)} typosquatting candidates")
            
            # Add suspicious patterns
            suspicious = generate_suspicious_patterns()
            print(f"   ⚠️  Generated {len(suspicious)} suspicious patterns")
            
            targets = typo_candidates + suspicious
        
        # Add ecosystem prefix to targets
        for target in targets[:args.target_count]:
            all_targets.append({"ecosystem": ecosystem, "name": target})
    
    print(f"\n🎯 Total targets to scan: {len(all_targets)}")
    
    # Scan all targets
    all_results = []
    candidates = []
    
    for i, target in enumerate(all_targets):
        print(f"\n[{i+1}/{len(all_targets)}] Scanning {target['ecosystem']}: {target['name']}")
        
        try:
            result = scan(target["name"], target["ecosystem"], policy=args.policy)
            
            # Enhanced candidate detection
            is_candidate, reasons = enhanced_cve_rules(target, result)
            
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
                "reasons": reasons
            }
            
            all_results.append(result_data)
            
            if is_candidate:
                candidates.append(result_data)
                print(f"   🚨 CVE CANDIDATE: {result.decision} (risk: {result.risk:.3f})")
                print(f"   📋 Reasons: {', '.join(reasons)}")
            else:
                print(f"   ✅ Clean: {result.decision} (risk: {result.risk:.3f})")
                
        except Exception as e:
            print(f"   ❌ Scan failed: {e}")
            continue
    
    print(f"\n📊 AGGRESSIVE HUNT SUMMARY:")
    print(f"   📦 Total packages scanned: {len(all_results)}")
    print(f"   🚨 CVE candidates found: {len(candidates)}")
    print(f"   ✅ Clean packages: {len(all_results) - len(candidates)}")
    print(f"   🎯 Success rate: {len(candidates)/len(all_results)*100:.1f}% candidates")
    
    # Save results
    out_all = Path(args.out_all)
    out_all.parent.mkdir(parents=True, exist_ok=True)
    out_all.write_text(json.dumps(all_results, indent=2), encoding="utf-8")
    print(f"   💾 All results saved to: {args.out_all}")
    
    out_c = Path(args.out_json)
    out_c.parent.mkdir(parents=True, exist_ok=True)
    out_c.write_text(json.dumps(candidates, indent=2), encoding="utf-8")
    print(f"   🎯 CVE candidates saved to: {args.out_json}")
    
    if candidates:
        print(f"\n🎉 SUCCESS! Found {len(candidates)} CVE candidates:")
        for candidate in candidates[:5]:  # Show first 5
            print(f"   🚨 {candidate['ecosystem']}: {candidate['name']} (risk: {candidate['risk']:.3f})")
            print(f"      Reasons: {', '.join(candidate['reasons'])}")
    else:
        print(f"\n😞 No CVE candidates found. Consider:")
        print(f"   - Increasing target count (--target-count)")
        print(f"   - Adding more ecosystems")
        print(f"   - Checking different time periods")

if __name__ == "__main__":
    main()