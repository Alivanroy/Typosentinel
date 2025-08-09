#!/usr/bin/env python3
"""
Focused investigation of the most promising novel CVE candidates
"""

import os, sys, json, requests, time
from pathlib import Path
from typing import List, Dict, Any
from datetime import datetime

# High-priority candidates from our novel CVE hunt
HIGH_PRIORITY_CANDIDATES = [
    # Version confusion attacks
    {"name": "lodash-v2", "ecosystem": "npm", "risk": 0.72, "type": "version_confusion"},
    {"name": "lodash-v3", "ecosystem": "npm", "risk": 0.72, "type": "version_confusion"},
    {"name": "react-v2", "ecosystem": "npm", "risk": 0.72, "type": "version_confusion"},
    {"name": "express-v2", "ecosystem": "npm", "risk": 0.72, "type": "version_confusion"},
    {"name": "axios-v2", "ecosystem": "npm", "risk": 0.72, "type": "version_confusion"},
    
    # Dependency confusion attacks
    {"name": "google-config", "ecosystem": "pypi", "risk": 0.0, "type": "dependency_confusion"},
    {"name": "microsoft-utils", "ecosystem": "pypi", "risk": 0.0, "type": "dependency_confusion"},
    {"name": "amazon-tools", "ecosystem": "pypi", "risk": 0.0, "type": "dependency_confusion"},
    
    # Suspicious recent packages (we'll check for real recent ones)
    {"name": "crypto-miner-js", "ecosystem": "npm", "risk": 0.0, "type": "suspicious_recent"},
    {"name": "bitcoin-wallet", "ecosystem": "npm", "risk": 0.0, "type": "suspicious_recent"},
]

def check_package_exists(name: str, ecosystem: str) -> Dict[str, Any]:
    """Check if a package exists and get its metadata"""
    result = {
        "name": name,
        "ecosystem": ecosystem,
        "exists": False,
        "metadata": {},
        "error": None
    }
    
    try:
        if ecosystem == "npm":
            url = f"https://registry.npmjs.org/{name}"
            response = requests.get(url, timeout=10)
            if response.status_code == 200:
                result["exists"] = True
                data = response.json()
                result["metadata"] = {
                    "description": data.get("description", ""),
                    "version": data.get("dist-tags", {}).get("latest", "unknown"),
                    "author": data.get("author", {}),
                    "maintainers": data.get("maintainers", []),
                    "created": data.get("time", {}).get("created", ""),
                    "modified": data.get("time", {}).get("modified", ""),
                    "downloads": "unknown",  # Would need separate API call
                    "dependencies": data.get("versions", {}).get(data.get("dist-tags", {}).get("latest", ""), {}).get("dependencies", {}),
                    "scripts": data.get("versions", {}).get(data.get("dist-tags", {}).get("latest", ""), {}).get("scripts", {}),
                    "repository": data.get("repository", {}),
                    "homepage": data.get("homepage", ""),
                    "keywords": data.get("keywords", [])
                }
            elif response.status_code == 404:
                result["error"] = "Package not found (404)"
            else:
                result["error"] = f"HTTP {response.status_code}"
                
        elif ecosystem == "pypi":
            url = f"https://pypi.org/pypi/{name}/json"
            response = requests.get(url, timeout=10)
            if response.status_code == 200:
                result["exists"] = True
                data = response.json()
                info = data.get("info", {})
                result["metadata"] = {
                    "description": info.get("summary", ""),
                    "version": info.get("version", "unknown"),
                    "author": info.get("author", ""),
                    "author_email": info.get("author_email", ""),
                    "maintainer": info.get("maintainer", ""),
                    "created": "unknown",  # Would need separate API call
                    "modified": "unknown",
                    "downloads": "unknown",  # Would need separate API call
                    "dependencies": info.get("requires_dist", []),
                    "classifiers": info.get("classifiers", []),
                    "keywords": info.get("keywords", ""),
                    "home_page": info.get("home_page", ""),
                    "project_urls": info.get("project_urls", {})
                }
            elif response.status_code == 404:
                result["error"] = "Package not found (404)"
            else:
                result["error"] = f"HTTP {response.status_code}"
                
    except Exception as e:
        result["error"] = str(e)
    
    return result

def analyze_package_for_threats(package_info: Dict[str, Any]) -> Dict[str, Any]:
    """Analyze package metadata for potential threats"""
    analysis = {
        "threat_score": 0,
        "threats": [],
        "warnings": [],
        "recommendations": []
    }
    
    if not package_info["exists"]:
        return analysis
    
    metadata = package_info["metadata"]
    name = package_info["name"]
    
    # Check for missing or suspicious metadata
    description = metadata.get("description", "").strip()
    if not description:
        analysis["warnings"].append("Missing package description")
        analysis["threat_score"] += 5
    elif len(description) < 10:
        analysis["warnings"].append("Very short package description")
        analysis["threat_score"] += 3
    
    # Check for suspicious keywords in description
    suspicious_keywords = [
        "crypto", "mining", "bitcoin", "ethereum", "wallet", "private", "key",
        "password", "token", "secret", "admin", "root", "shell", "exec",
        "download", "upload", "send", "post", "fetch", "request"
    ]
    
    desc_lower = description.lower()
    found_suspicious = [kw for kw in suspicious_keywords if kw in desc_lower]
    if found_suspicious:
        analysis["threats"].append(f"Suspicious keywords in description: {', '.join(found_suspicious)}")
        analysis["threat_score"] += len(found_suspicious) * 2
    
    # Check for version confusion patterns
    if any(v in name for v in ["v2", "v3", "next", "beta", "alpha", "rc"]):
        analysis["threats"].append("Potential version confusion attack")
        analysis["threat_score"] += 10
    
    # Check for dependency confusion patterns
    company_names = ["google", "microsoft", "amazon", "apple", "meta", "netflix", "uber", "airbnb"]
    if any(company in name.lower() for company in company_names):
        analysis["threats"].append("Potential dependency confusion attack")
        analysis["threat_score"] += 15
    
    # Check for suspicious scripts (npm only)
    if package_info["ecosystem"] == "npm":
        scripts = metadata.get("scripts", {})
        suspicious_scripts = []
        for script_name, script_content in scripts.items():
            if any(cmd in script_content.lower() for cmd in ["curl", "wget", "nc", "netcat", "bash", "sh", "powershell"]):
                suspicious_scripts.append(f"{script_name}: {script_content}")
        
        if suspicious_scripts:
            analysis["threats"].append(f"Suspicious scripts: {suspicious_scripts}")
            analysis["threat_score"] += 20
    
    # Check for suspicious dependencies
    deps = metadata.get("dependencies", {})
    if isinstance(deps, dict):
        suspicious_deps = []
        for dep_name in deps.keys():
            if any(susp in dep_name.lower() for susp in ["crypto", "mining", "shell", "exec", "request"]):
                suspicious_deps.append(dep_name)
        
        if suspicious_deps:
            analysis["threats"].append(f"Suspicious dependencies: {', '.join(suspicious_deps)}")
            analysis["threat_score"] += len(suspicious_deps) * 3
    
    # Check for recent creation (potential for quick malicious uploads)
    created = metadata.get("created", "")
    if created:
        try:
            from datetime import datetime, timedelta
            created_date = datetime.fromisoformat(created.replace('Z', '+00:00'))
            if datetime.now().replace(tzinfo=created_date.tzinfo) - created_date < timedelta(days=7):
                analysis["warnings"].append("Package created very recently (< 7 days)")
                analysis["threat_score"] += 5
        except:
            pass
    
    # Generate recommendations
    if analysis["threat_score"] >= 20:
        analysis["recommendations"].append("HIGH RISK: Perform deep malware analysis")
        analysis["recommendations"].append("Check package source code for malicious patterns")
        analysis["recommendations"].append("Verify package legitimacy with official sources")
    elif analysis["threat_score"] >= 10:
        analysis["recommendations"].append("MEDIUM RISK: Manual review recommended")
        analysis["recommendations"].append("Check package reputation and download statistics")
    elif analysis["threat_score"] >= 5:
        analysis["recommendations"].append("LOW RISK: Monitor for suspicious activity")
    
    return analysis

def main():
    print("🔍 FOCUSED NOVEL CVE INVESTIGATION")
    print("=" * 60)
    
    results = []
    novel_cves_found = []
    
    for i, candidate in enumerate(HIGH_PRIORITY_CANDIDATES):
        print(f"\n[{i+1}/{len(HIGH_PRIORITY_CANDIDATES)}] Investigating {candidate['ecosystem']}: {candidate['name']}")
        
        # Check if package exists
        package_info = check_package_exists(candidate["name"], candidate["ecosystem"])
        
        if package_info["exists"]:
            print(f"   ✅ Package EXISTS - analyzing for threats...")
            
            # Analyze for threats
            threat_analysis = analyze_package_for_threats(package_info)
            
            result = {
                **candidate,
                "package_info": package_info,
                "threat_analysis": threat_analysis,
                "investigation_timestamp": datetime.now().isoformat()
            }
            
            results.append(result)
            
            # Check if this is a potential novel CVE
            if threat_analysis["threat_score"] >= 10:
                novel_cves_found.append(result)
                print(f"   🚨 POTENTIAL NOVEL CVE FOUND!")
                print(f"      Threat Score: {threat_analysis['threat_score']}")
                print(f"      Threats: {len(threat_analysis['threats'])}")
                print(f"      Warnings: {len(threat_analysis['warnings'])}")
                
                if threat_analysis["threats"]:
                    print(f"      Top Threats:")
                    for threat in threat_analysis["threats"][:3]:
                        print(f"        - {threat}")
                        
            else:
                print(f"   ✅ Low threat score: {threat_analysis['threat_score']}")
                
        else:
            print(f"   ❌ Package does not exist: {package_info.get('error', 'Unknown error')}")
            result = {
                **candidate,
                "package_info": package_info,
                "threat_analysis": {"threat_score": 0, "threats": [], "warnings": [], "recommendations": []},
                "investigation_timestamp": datetime.now().isoformat()
            }
            results.append(result)
    
    # Save results
    out_dir = Path("out")
    out_dir.mkdir(exist_ok=True)
    
    # Save all results
    with open(out_dir / "focused_investigation_results.json", "w") as f:
        json.dump(results, f, indent=2)
    
    # Save novel CVEs
    with open(out_dir / "novel_cves_discovered.json", "w") as f:
        json.dump(novel_cves_found, f, indent=2)
    
    print(f"\n📊 INVESTIGATION SUMMARY:")
    print("=" * 50)
    print(f"   📦 Total packages investigated: {len(HIGH_PRIORITY_CANDIDATES)}")
    print(f"   ✅ Existing packages found: {sum(1 for r in results if r['package_info']['exists'])}")
    print(f"   🚨 Potential novel CVEs: {len(novel_cves_found)}")
    print(f"   ❌ Non-existent packages: {sum(1 for r in results if not r['package_info']['exists'])}")
    
    if novel_cves_found:
        print(f"\n🎉 NOVEL CVE CANDIDATES DISCOVERED:")
        for cve in novel_cves_found:
            print(f"   🎯 {cve['ecosystem']}: {cve['name']}")
            print(f"      Type: {cve['type']}")
            print(f"      Threat Score: {cve['threat_analysis']['threat_score']}")
            print(f"      Description: {cve['package_info']['metadata'].get('description', 'No description')[:100]}...")
            print()
        
        print(f"🔍 NEXT STEPS:")
        print(f"   1. Download and analyze source code of high-threat packages")
        print(f"   2. Check for malicious code patterns (crypto mining, data exfiltration)")
        print(f"   3. Verify if these vulnerabilities are already known")
        print(f"   4. Prepare CVE reports for confirmed novel vulnerabilities")
        print(f"   5. Report to package registries for takedown if malicious")
        
    else:
        print(f"\n😞 No high-threat novel CVEs found in this batch.")
        print(f"   Consider investigating more recent packages or different attack vectors.")
    
    print(f"\n💾 Results saved to:")
    print(f"   - out/focused_investigation_results.json")
    print(f"   - out/novel_cves_discovered.json")

if __name__ == "__main__":
    main()