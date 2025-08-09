#!/usr/bin/env python3
"""
Verification Analyzer for express2 and webpack2 packages
Performs deep analysis to confirm malicious nature
"""

import json
import requests
import tempfile
import tarfile
import os
import re
import subprocess
import hashlib
from datetime import datetime
import ast
import sys

class PackageVerificationAnalyzer:
    def __init__(self):
        self.results = {
            "analysis_timestamp": datetime.now().isoformat(),
            "packages_analyzed": [],
            "verification_results": {}
        }
        
        # Enhanced malicious patterns for verification
        self.malicious_patterns = {
            "code_injection": [
                r"Function\s*\(",
                r"eval\s*\(",
                r"setTimeout\s*\(\s*['\"]",
                r"setInterval\s*\(\s*['\"]",
                r"new\s+Function\s*\(",
                r"\.constructor\s*\(",
                r"globalThis\[",
                r"window\[.*\]\s*\("
            ],
            "command_execution": [
                r"exec\s*\(",
                r"execSync\s*\(",
                r"spawn\s*\(",
                r"system\s*\(",
                r"child_process",
                r"require\s*\(\s*['\"]child_process['\"]",
                r"process\.exec",
                r"shell\s*=\s*True"
            ],
            "network_exfiltration": [
                r"XMLHttpRequest",
                r"fetch\s*\(",
                r"axios\.",
                r"http\.request",
                r"https\.request",
                r"net\.connect",
                r"require\s*\(\s*['\"]https?['\"]",
                r"WebSocket\s*\(",
                r"\.send\s*\(",
                r"\.post\s*\("
            ],
            "file_operations": [
                r"fs\.writeFile",
                r"fs\.readFile",
                r"fs\.unlink",
                r"fs\.mkdir",
                r"require\s*\(\s*['\"]fs['\"]",
                r"open\s*\(",
                r"\.write\s*\(",
                r"\.read\s*\("
            ],
            "obfuscation": [
                r"\\u[0-9a-fA-F]{4}",
                r"\\x[0-9a-fA-F]{2}",
                r"String\.fromCharCode",
                r"atob\s*\(",
                r"btoa\s*\(",
                r"unescape\s*\(",
                r"decodeURIComponent\s*\(",
                r"Buffer\.from.*base64"
            ],
            "crypto_mining": [
                r"crypto.*mine",
                r"bitcoin",
                r"ethereum",
                r"monero",
                r"coinhive",
                r"cryptonight",
                r"stratum",
                r"mining.*pool"
            ],
            "suspicious_domains": [
                r"\.tk\b",
                r"\.ml\b", 
                r"\.ga\b",
                r"\.cf\b",
                r"pastebin\.com",
                r"bit\.ly",
                r"tinyurl\.com",
                r"[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}"
            ]
        }
    
    def get_package_info(self, package_name, registry="npm"):
        """Get package metadata from registry"""
        try:
            if registry == "npm":
                url = f"https://registry.npmjs.org/{package_name}"
            else:
                url = f"https://pypi.org/pypi/{package_name}/json"
            
            response = requests.get(url, timeout=10)
            if response.status_code == 200:
                return response.json()
            else:
                print(f"Package {package_name} not found in {registry} registry")
                return None
        except Exception as e:
            print(f"Error fetching package info for {package_name}: {e}")
            return None
    
    def download_package_source(self, package_name, registry="npm"):
        """Download and extract package source code"""
        try:
            package_info = self.get_package_info(package_name, registry)
            if not package_info:
                return None
            
            if registry == "npm":
                latest_version = package_info.get("dist-tags", {}).get("latest")
                if not latest_version:
                    return None
                tarball_url = package_info["versions"][latest_version]["dist"]["tarball"]
            else:
                # PyPI handling would go here
                return None
            
            # Download tarball
            response = requests.get(tarball_url, timeout=30)
            if response.status_code != 200:
                return None
            
            # Create temporary directory
            temp_dir = tempfile.mkdtemp()
            tarball_path = os.path.join(temp_dir, f"{package_name}.tgz")
            
            # Save tarball
            with open(tarball_path, 'wb') as f:
                f.write(response.content)
            
            # Extract tarball
            extract_dir = os.path.join(temp_dir, "extracted")
            os.makedirs(extract_dir, exist_ok=True)
            
            with tarfile.open(tarball_path, 'r:gz') as tar:
                tar.extractall(extract_dir)
            
            return extract_dir
            
        except Exception as e:
            print(f"Error downloading package {package_name}: {e}")
            return None
    
    def analyze_file_content(self, file_path):
        """Analyze individual file for malicious patterns"""
        threats = []
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            # Check for malicious patterns
            for category, patterns in self.malicious_patterns.items():
                for pattern in patterns:
                    matches = re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE)
                    for match in matches:
                        line_num = content[:match.start()].count('\n') + 1
                        threats.append({
                            "type": category,
                            "pattern": pattern,
                            "match": match.group(),
                            "line": line_num,
                            "context": self.get_context(content, match.start(), match.end())
                        })
            
            return threats
            
        except Exception as e:
            print(f"Error analyzing file {file_path}: {e}")
            return []
    
    def get_context(self, content, start, end, context_lines=2):
        """Get context around a match"""
        lines = content.split('\n')
        match_line = content[:start].count('\n')
        
        start_line = max(0, match_line - context_lines)
        end_line = min(len(lines), match_line + context_lines + 1)
        
        context = []
        for i in range(start_line, end_line):
            prefix = ">>> " if i == match_line else "    "
            context.append(f"{prefix}{i+1}: {lines[i]}")
        
        return '\n'.join(context)
    
    def analyze_package_structure(self, extract_dir):
        """Analyze package structure for suspicious elements"""
        suspicious_elements = []
        
        try:
            for root, dirs, files in os.walk(extract_dir):
                for file in files:
                    file_path = os.path.join(root, file)
                    rel_path = os.path.relpath(file_path, extract_dir)
                    
                    # Check for suspicious file names
                    if any(suspicious in file.lower() for suspicious in 
                           ['backdoor', 'malware', 'trojan', 'keylog', 'stealer', 'miner']):
                        suspicious_elements.append({
                            "type": "suspicious_filename",
                            "file": rel_path,
                            "reason": "Suspicious filename pattern"
                        })
                    
                    # Check for executable files in unexpected locations
                    if file.endswith(('.exe', '.bat', '.sh', '.cmd')) and 'bin' not in root:
                        suspicious_elements.append({
                            "type": "unexpected_executable",
                            "file": rel_path,
                            "reason": "Executable file in unexpected location"
                        })
                    
                    # Check for hidden files
                    if file.startswith('.') and file not in ['.gitignore', '.npmignore', '.editorconfig']:
                        suspicious_elements.append({
                            "type": "hidden_file",
                            "file": rel_path,
                            "reason": "Unexpected hidden file"
                        })
        
        except Exception as e:
            print(f"Error analyzing package structure: {e}")
        
        return suspicious_elements
    
    def verify_package(self, package_name, registry="npm"):
        """Perform comprehensive verification of a package"""
        print(f"\n🔍 Verifying package: {package_name} ({registry})")
        
        verification_result = {
            "package_name": package_name,
            "registry": registry,
            "analysis_timestamp": datetime.now().isoformat(),
            "package_info": None,
            "threats_found": [],
            "suspicious_elements": [],
            "total_threats": 0,
            "threat_score": 0,
            "is_malicious": False,
            "confidence": 0.0
        }
        
        # Get package metadata
        package_info = self.get_package_info(package_name, registry)
        if not package_info:
            verification_result["error"] = "Package not found or inaccessible"
            return verification_result
        
        verification_result["package_info"] = {
            "name": package_info.get("name"),
            "version": package_info.get("dist-tags", {}).get("latest") if registry == "npm" else None,
            "description": package_info.get("description"),
            "author": package_info.get("author"),
            "maintainers": len(package_info.get("maintainers", [])) if registry == "npm" else None,
            "created": package_info.get("time", {}).get("created") if registry == "npm" else None,
            "modified": package_info.get("time", {}).get("modified") if registry == "npm" else None
        }
        
        # Download and analyze source code
        extract_dir = self.download_package_source(package_name, registry)
        if not extract_dir:
            verification_result["error"] = "Failed to download package source"
            return verification_result
        
        try:
            # Analyze package structure
            verification_result["suspicious_elements"] = self.analyze_package_structure(extract_dir)
            
            # Analyze all files
            all_threats = []
            file_count = 0
            
            for root, dirs, files in os.walk(extract_dir):
                for file in files:
                    if file.endswith(('.js', '.ts', '.json', '.py', '.sh', '.bat')):
                        file_path = os.path.join(root, file)
                        rel_path = os.path.relpath(file_path, extract_dir)
                        
                        threats = self.analyze_file_content(file_path)
                        if threats:
                            all_threats.extend([{**threat, "file": rel_path} for threat in threats])
                        
                        file_count += 1
            
            verification_result["threats_found"] = all_threats
            verification_result["total_threats"] = len(all_threats)
            verification_result["files_analyzed"] = file_count
            
            # Calculate threat score
            threat_score = self.calculate_threat_score(all_threats, verification_result["suspicious_elements"])
            verification_result["threat_score"] = threat_score
            
            # Determine if malicious
            verification_result["is_malicious"] = threat_score > 50
            verification_result["confidence"] = min(threat_score / 100.0, 1.0)
            
            # Cleanup
            import shutil
            shutil.rmtree(os.path.dirname(extract_dir))
            
        except Exception as e:
            verification_result["error"] = f"Analysis failed: {e}"
        
        return verification_result
    
    def calculate_threat_score(self, threats, suspicious_elements):
        """Calculate overall threat score"""
        score = 0
        
        # Score based on threat types
        threat_weights = {
            "code_injection": 15,
            "command_execution": 20,
            "network_exfiltration": 18,
            "file_operations": 10,
            "obfuscation": 8,
            "crypto_mining": 25,
            "suspicious_domains": 12
        }
        
        threat_counts = {}
        for threat in threats:
            threat_type = threat["type"]
            threat_counts[threat_type] = threat_counts.get(threat_type, 0) + 1
        
        for threat_type, count in threat_counts.items():
            weight = threat_weights.get(threat_type, 5)
            score += min(count * weight, weight * 3)  # Cap per category
        
        # Score based on suspicious elements
        for element in suspicious_elements:
            if element["type"] == "suspicious_filename":
                score += 15
            elif element["type"] == "unexpected_executable":
                score += 10
            elif element["type"] == "hidden_file":
                score += 5
        
        return min(score, 100)  # Cap at 100
    
    def run_verification(self):
        """Run verification on target packages"""
        target_packages = [
            ("express2", "npm"),
            ("webpack2", "npm")
        ]
        
        print("🚨 Starting Package Verification Analysis")
        print("=" * 60)
        
        for package_name, registry in target_packages:
            result = self.verify_package(package_name, registry)
            self.results["verification_results"][package_name] = result
            self.results["packages_analyzed"].append(package_name)
            
            # Print summary
            print(f"\n📊 VERIFICATION SUMMARY: {package_name}")
            print("-" * 40)
            print(f"Malicious: {'YES' if result.get('is_malicious', False) else 'NO'}")
            print(f"Threat Score: {result.get('threat_score', 0)}/100")
            print(f"Confidence: {result.get('confidence', 0):.2%}")
            print(f"Total Threats: {result.get('total_threats', 0)}")
            print(f"Files Analyzed: {result.get('files_analyzed', 0)}")
            
            if result.get('threats_found'):
                print(f"\nTop Threat Categories:")
                threat_summary = {}
                for threat in result['threats_found'][:10]:  # Show top 10
                    threat_type = threat['type']
                    threat_summary[threat_type] = threat_summary.get(threat_type, 0) + 1
                
                for threat_type, count in sorted(threat_summary.items(), key=lambda x: x[1], reverse=True):
                    print(f"  - {threat_type}: {count} instances")
        
        # Save results
        output_file = "package_verification_results.json"
        with open(output_file, 'w') as f:
            json.dump(self.results, f, indent=2)
        
        print(f"\n✅ Verification complete. Results saved to {output_file}")
        
        return self.results

if __name__ == "__main__":
    analyzer = PackageVerificationAnalyzer()
    results = analyzer.run_verification()
    
    # Print final summary
    print("\n" + "=" * 60)
    print("🎯 FINAL VERIFICATION RESULTS")
    print("=" * 60)
    
    for package_name, result in results["verification_results"].items():
        status = "🚨 MALICIOUS" if result.get("is_malicious", False) else "✅ CLEAN"
        score = result.get("threat_score", 0)
        print(f"{package_name}: {status} (Score: {score}/100)")