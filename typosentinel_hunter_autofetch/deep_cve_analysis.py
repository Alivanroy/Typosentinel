#!/usr/bin/env python3
"""
Deep CVE Analysis - Investigate specific packages for novel vulnerabilities
"""

import os, sys, json, requests, tempfile, shutil, subprocess
from pathlib import Path
from typing import List, Dict, Any, Tuple
from datetime import datetime
import tarfile, zipfile
import re

# Import our malware analyzer
sys.path.append(str(Path(__file__).parent))
from malware_multi_ecosystem import MultiEcosystemMalwareAnalyzer

class DeepCVEAnalyzer:
    def __init__(self):
        self.malware_analyzer = MultiEcosystemMalwareAnalyzer()
        self.temp_dir = None
        
    def download_package(self, name: str, ecosystem: str) -> Tuple[bool, str, Dict]:
        """Download package for analysis"""
        try:
            if ecosystem == "npm":
                return self._download_npm_package(name)
            elif ecosystem == "pypi":
                return self._download_pypi_package(name)
            else:
                return False, f"Unsupported ecosystem: {ecosystem}", {}
        except Exception as e:
            return False, f"Download failed: {e}", {}
    
    def _download_npm_package(self, name: str) -> Tuple[bool, str, Dict]:
        """Download npm package"""
        # Get package metadata
        registry_url = f"https://registry.npmjs.org/{name}"
        response = requests.get(registry_url, timeout=30)
        if response.status_code != 200:
            return False, f"Failed to get package metadata: {response.status_code}", {}
        
        data = response.json()
        
        # Try to get latest version from dist-tags first
        latest_version = data.get("dist-tags", {}).get("latest")
        
        # If no dist-tags, try to get the latest version from versions
        if not latest_version:
            versions = data.get("versions", {})
            if versions:
                # Get the last version (assuming they're sorted)
                latest_version = list(versions.keys())[-1]
            else:
                return False, "No versions found", {}
        
        # Get download URL
        version_data = data.get("versions", {}).get(latest_version, {})
        tarball_url = version_data.get("dist", {}).get("tarball")
        if not tarball_url:
            return False, f"No tarball URL found for version {latest_version}", {}
        
        # Download tarball
        self.temp_dir = tempfile.mkdtemp()
        tarball_path = Path(self.temp_dir) / f"{name}-{latest_version}.tgz"
        
        response = requests.get(tarball_url, timeout=60)
        if response.status_code != 200:
            return False, f"Failed to download tarball: {response.status_code}", {}
        
        with open(tarball_path, 'wb') as f:
            f.write(response.content)
        
        # Extract tarball
        extract_dir = Path(self.temp_dir) / "extracted"
        extract_dir.mkdir()
        
        with tarfile.open(tarball_path, 'r:gz') as tar:
            tar.extractall(extract_dir)
        
        return True, str(extract_dir), {
            "version": latest_version,
            "size": len(response.content),
            "tarball_url": tarball_url,
            "metadata": version_data
        }
    
    def _download_pypi_package(self, name: str) -> Tuple[bool, str, Dict]:
        """Download PyPI package"""
        # Get package metadata
        api_url = f"https://pypi.org/pypi/{name}/json"
        response = requests.get(api_url, timeout=30)
        if response.status_code != 200:
            return False, f"Failed to get package metadata: {response.status_code}", {}
        
        data = response.json()
        info = data.get("info", {})
        version = info.get("version")
        
        # Find source distribution
        urls = data.get("urls", [])
        source_url = None
        for url_info in urls:
            if url_info.get("packagetype") == "sdist":
                source_url = url_info.get("url")
                break
        
        if not source_url:
            return False, "No source distribution found", {}
        
        # Download source
        self.temp_dir = tempfile.mkdtemp()
        filename = source_url.split("/")[-1]
        file_path = Path(self.temp_dir) / filename
        
        response = requests.get(source_url, timeout=60)
        if response.status_code != 200:
            return False, f"Failed to download source: {response.status_code}", {}
        
        with open(file_path, 'wb') as f:
            f.write(response.content)
        
        # Extract archive
        extract_dir = Path(self.temp_dir) / "extracted"
        extract_dir.mkdir()
        
        if filename.endswith('.tar.gz') or filename.endswith('.tgz'):
            with tarfile.open(file_path, 'r:gz') as tar:
                tar.extractall(extract_dir)
        elif filename.endswith('.zip'):
            with zipfile.ZipFile(file_path, 'r') as zip_file:
                zip_file.extractall(extract_dir)
        else:
            return False, f"Unsupported archive format: {filename}", {}
        
        return True, str(extract_dir), {
            "version": version,
            "size": len(response.content),
            "download_url": source_url,
            "metadata": info
        }
    
    def analyze_source_code(self, source_dir: str, ecosystem: str) -> Dict[str, Any]:
        """Perform deep source code analysis"""
        analysis = {
            "file_count": 0,
            "total_size": 0,
            "suspicious_files": [],
            "code_patterns": {
                "crypto_mining": [],
                "data_exfiltration": [],
                "system_access": [],
                "obfuscation": [],
                "network_activity": [],
                "credential_theft": []
            },
            "malware_analysis": {},
            "novel_threats": []
        }
        
        source_path = Path(source_dir)
        
        # Count files and size
        for file_path in source_path.rglob("*"):
            if file_path.is_file():
                analysis["file_count"] += 1
                analysis["total_size"] += file_path.stat().st_size
        
        # Use our malware analyzer
        try:
            success, malware_results = self.malware_analyzer.analyze_package(source_dir, ecosystem)
            analysis["malware_analysis"] = malware_results if success else {"error": "Malware analysis failed"}
        except Exception as e:
            analysis["malware_analysis"] = {"error": str(e)}
        
        # Additional deep analysis patterns
        self._analyze_suspicious_patterns(source_path, analysis)
        self._analyze_novel_threat_patterns(source_path, analysis, ecosystem)
        
        return analysis
    
    def _analyze_suspicious_patterns(self, source_path: Path, analysis: Dict):
        """Analyze for suspicious code patterns"""
        suspicious_extensions = {'.js', '.ts', '.py', '.sh', '.bat', '.ps1', '.php'}
        
        for file_path in source_path.rglob("*"):
            if file_path.is_file() and file_path.suffix.lower() in suspicious_extensions:
                try:
                    content = file_path.read_text(encoding='utf-8', errors='ignore')
                    
                    # Check for crypto mining patterns
                    crypto_patterns = [
                        r'mining|miner|hashrate|stratum|pool\.', 
                        r'bitcoin|ethereum|monero|litecoin|dogecoin',
                        r'wallet|address|private.*key|seed.*phrase',
                        r'cryptonight|scrypt|sha256|blake2b'
                    ]
                    
                    for pattern in crypto_patterns:
                        if re.search(pattern, content, re.IGNORECASE):
                            analysis["code_patterns"]["crypto_mining"].append({
                                "file": str(file_path.relative_to(source_path)),
                                "pattern": pattern,
                                "matches": len(re.findall(pattern, content, re.IGNORECASE))
                            })
                    
                    # Check for data exfiltration
                    exfil_patterns = [
                        r'fetch|axios|request|http\.get|urllib',
                        r'upload|send.*data|post.*request',
                        r'webhook|api\..*\.com|discord\.com|telegram',
                        r'base64|btoa|atob|encode|decode'
                    ]
                    
                    for pattern in exfil_patterns:
                        if re.search(pattern, content, re.IGNORECASE):
                            analysis["code_patterns"]["data_exfiltration"].append({
                                "file": str(file_path.relative_to(source_path)),
                                "pattern": pattern,
                                "matches": len(re.findall(pattern, content, re.IGNORECASE))
                            })
                    
                    # Check for system access
                    system_patterns = [
                        r'exec|spawn|shell|system|subprocess',
                        r'eval|Function|setTimeout|setInterval',
                        r'process\.env|os\.environ|getenv',
                        r'fs\.read|fs\.write|file.*read|file.*write'
                    ]
                    
                    for pattern in system_patterns:
                        if re.search(pattern, content, re.IGNORECASE):
                            analysis["code_patterns"]["system_access"].append({
                                "file": str(file_path.relative_to(source_path)),
                                "pattern": pattern,
                                "matches": len(re.findall(pattern, content, re.IGNORECASE))
                            })
                    
                except Exception as e:
                    analysis["suspicious_files"].append({
                        "file": str(file_path.relative_to(source_path)),
                        "error": str(e)
                    })
    
    def _analyze_novel_threat_patterns(self, source_path: Path, analysis: Dict, ecosystem: str):
        """Look for novel threat patterns that might indicate new CVE types"""
        novel_patterns = []
        
        for file_path in source_path.rglob("*"):
            if file_path.is_file():
                try:
                    content = file_path.read_text(encoding='utf-8', errors='ignore')
                    
                    # Check for supply chain attacks
                    if re.search(r'postinstall|preinstall|install.*script', content, re.IGNORECASE):
                        novel_patterns.append({
                            "type": "supply_chain_attack",
                            "file": str(file_path.relative_to(source_path)),
                            "description": "Suspicious install scripts that could modify system"
                        })
                    
                    # Check for dependency confusion
                    if re.search(r'internal|private|corp|company.*config', content, re.IGNORECASE):
                        novel_patterns.append({
                            "type": "dependency_confusion",
                            "file": str(file_path.relative_to(source_path)),
                            "description": "References to internal/private packages"
                        })
                    
                    # Check for typosquatting indicators
                    popular_packages = ['react', 'lodash', 'express', 'axios', 'moment', 'chalk']
                    for pkg in popular_packages:
                        if pkg in file_path.name.lower() and pkg != file_path.stem.lower():
                            novel_patterns.append({
                                "type": "typosquatting",
                                "file": str(file_path.relative_to(source_path)),
                                "description": f"Potential typosquatting of popular package: {pkg}"
                            })
                    
                    # Check for version confusion
                    if re.search(r'v\d+|version.*\d+|latest|next|beta|alpha', content, re.IGNORECASE):
                        novel_patterns.append({
                            "type": "version_confusion",
                            "file": str(file_path.relative_to(source_path)),
                            "description": "Version-related content that could confuse users"
                        })
                    
                except Exception:
                    pass
        
        analysis["novel_threats"] = novel_patterns
    
    def cleanup(self):
        """Clean up temporary files"""
        if self.temp_dir and Path(self.temp_dir).exists():
            shutil.rmtree(self.temp_dir)

def main():
    print("🔬 DEEP CVE ANALYSIS - INVESTIGATING NOVEL THREATS")
    print("=" * 70)
    
    # Target the package we found
    target_package = {
        "name": "react-v2",
        "ecosystem": "npm"
    }
    
    analyzer = DeepCVEAnalyzer()
    
    try:
        print(f"🎯 Analyzing {target_package['ecosystem']}: {target_package['name']}")
        
        # Download package
        print("📥 Downloading package...")
        success, source_dir, download_info = analyzer.download_package(
            target_package["name"], 
            target_package["ecosystem"]
        )
        
        if not success:
            print(f"❌ Download failed: {source_dir}")
            return
        
        print(f"✅ Downloaded successfully")
        print(f"   Version: {download_info.get('version', 'unknown')}")
        print(f"   Size: {download_info.get('size', 0):,} bytes")
        
        # Analyze source code
        print("🔍 Performing deep source code analysis...")
        analysis = analyzer.analyze_source_code(source_dir, target_package["ecosystem"])
        
        print(f"📊 Analysis Results:")
        print(f"   Files analyzed: {analysis['file_count']}")
        print(f"   Total size: {analysis['total_size']:,} bytes")
        print(f"   Suspicious files: {len(analysis['suspicious_files'])}")
        
        # Check for threats
        total_threats = sum(len(patterns) for patterns in analysis["code_patterns"].values())
        novel_threats = len(analysis["novel_threats"])
        
        print(f"\n🚨 THREAT ANALYSIS:")
        print(f"   Suspicious code patterns: {total_threats}")
        print(f"   Novel threat indicators: {novel_threats}")
        
        # Detailed threat breakdown
        for category, patterns in analysis["code_patterns"].items():
            if patterns:
                print(f"\n   {category.upper()}: {len(patterns)} matches")
                for pattern in patterns[:3]:  # Show top 3
                    print(f"     - {pattern['file']}: {pattern['pattern']} ({pattern['matches']} matches)")
        
        # Novel threats
        if analysis["novel_threats"]:
            print(f"\n🆕 NOVEL THREAT PATTERNS:")
            threat_types = {}
            for threat in analysis["novel_threats"]:
                threat_type = threat["type"]
                if threat_type not in threat_types:
                    threat_types[threat_type] = []
                threat_types[threat_type].append(threat)
            
            for threat_type, threats in threat_types.items():
                print(f"   {threat_type.upper()}: {len(threats)} indicators")
                for threat in threats[:2]:  # Show top 2
                    print(f"     - {threat['file']}: {threat['description']}")
        
        # Malware analysis results
        if "error" not in analysis["malware_analysis"]:
            malware = analysis["malware_analysis"]
            print(f"\n🦠 MALWARE ANALYSIS:")
            print(f"   Critical findings: {malware.get('critical', 0)}")
            print(f"   High risk findings: {malware.get('high', 0)}")
            print(f"   Medium risk findings: {malware.get('medium', 0)}")
            print(f"   Low risk findings: {malware.get('low', 0)}")
        
        # Save detailed results
        result = {
            "package": target_package,
            "download_info": download_info,
            "analysis": analysis,
            "analysis_timestamp": datetime.now().isoformat()
        }
        
        out_dir = Path("out")
        out_dir.mkdir(exist_ok=True)
        
        with open(out_dir / f"deep_analysis_{target_package['name']}.json", "w") as f:
            json.dump(result, f, indent=2)
        
        # Determine if this is a novel CVE
        is_novel_cve = False
        cve_reasons = []
        
        if total_threats >= 5:
            is_novel_cve = True
            cve_reasons.append(f"High number of suspicious code patterns ({total_threats})")
        
        if novel_threats >= 3:
            is_novel_cve = True
            cve_reasons.append(f"Multiple novel threat indicators ({novel_threats})")
        
        if analysis["malware_analysis"].get("critical", 0) > 0:
            is_novel_cve = True
            cve_reasons.append("Critical malware patterns detected")
        
        if analysis["malware_analysis"].get("high", 0) >= 2:
            is_novel_cve = True
            cve_reasons.append("Multiple high-risk malware patterns")
        
        print(f"\n🎯 NOVEL CVE ASSESSMENT:")
        if is_novel_cve:
            print(f"   🚨 POTENTIAL NOVEL CVE CONFIRMED!")
            print(f"   📋 Evidence:")
            for reason in cve_reasons:
                print(f"     - {reason}")
            
            print(f"\n📝 RECOMMENDED ACTIONS:")
            print(f"   1. Report to npm security team")
            print(f"   2. Request CVE assignment from MITRE")
            print(f"   3. Prepare detailed vulnerability report")
            print(f"   4. Notify security community")
            print(f"   5. Monitor for similar packages")
            
        else:
            print(f"   ✅ No strong evidence of novel CVE")
            print(f"   📋 Package appears to be low risk")
        
        print(f"\n💾 Detailed analysis saved to: out/deep_analysis_{target_package['name']}.json")
        
    finally:
        analyzer.cleanup()

if __name__ == "__main__":
    main()