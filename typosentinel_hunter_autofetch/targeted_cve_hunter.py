#!/usr/bin/env python3
"""
Targeted CVE Hunter - Focuses on packages with known vulnerability patterns
and recently disclosed issues to find novel CVEs
"""

import json
import requests
import subprocess
import tempfile
import os
import re
import time
from datetime import datetime, timedelta
from pathlib import Path
import xml.etree.ElementTree as ET

class TargetedCVEHunter:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Targeted-CVE-Hunter/1.0 (Security Research)'
        })
        
    def get_packages_with_recent_security_updates(self, ecosystem='npm', days=30):
        """Find packages that had recent security updates"""
        packages = []
        
        if ecosystem == 'npm':
            try:
                # Search for packages with security-related keywords in recent updates
                security_keywords = ['security', 'vulnerability', 'cve', 'fix', 'patch', 'exploit']
                
                for keyword in security_keywords:
                    url = f"https://registry.npmjs.org/-/v1/search"
                    params = {
                        'text': f'{keyword} updated:>=' + (datetime.now() - timedelta(days=days)).strftime('%Y-%m-%d'),
                        'size': 20,
                        'quality': 0.1,
                        'popularity': 0.1
                    }
                    
                    response = self.session.get(url, params=params, timeout=30)
                    if response.status_code == 200:
                        data = response.json()
                        for pkg in data.get('objects', []):
                            package_info = pkg.get('package', {})
                            packages.append({
                                'name': package_info.get('name'),
                                'version': package_info.get('version'),
                                'description': package_info.get('description', ''),
                                'ecosystem': 'npm',
                                'keyword': keyword,
                                'score': pkg.get('score', {})
                            })
                            
            except Exception as e:
                print(f"Error fetching npm security packages: {e}")
                
        return packages
    
    def get_packages_with_suspicious_patterns(self, ecosystem='npm'):
        """Find packages with suspicious naming or behavior patterns"""
        suspicious_packages = []
        
        # Patterns that might indicate malicious or vulnerable packages
        suspicious_patterns = [
            'crypto-miner', 'bitcoin-wallet', 'password-stealer',
            'keylogger', 'backdoor', 'trojan', 'malware',
            'exploit', 'payload', 'shell', 'reverse-shell'
        ]
        
        for pattern in suspicious_patterns:
            try:
                if ecosystem == 'npm':
                    url = f"https://registry.npmjs.org/-/v1/search"
                    params = {
                        'text': pattern,
                        'size': 10
                    }
                    
                    response = self.session.get(url, params=params, timeout=30)
                    if response.status_code == 200:
                        data = response.json()
                        for pkg in data.get('objects', []):
                            package_info = pkg.get('package', {})
                            suspicious_packages.append({
                                'name': package_info.get('name'),
                                'version': package_info.get('version'),
                                'description': package_info.get('description', ''),
                                'ecosystem': 'npm',
                                'suspicious_pattern': pattern,
                                'maintainers': len(package_info.get('maintainers', []))
                            })
                            
            except Exception as e:
                print(f"Error searching for pattern {pattern}: {e}")
                
        return suspicious_packages
    
    def analyze_package_for_novel_vulnerabilities(self, package_name, ecosystem):
        """Analyze a package for potential novel vulnerabilities"""
        analysis = {
            'package_name': package_name,
            'ecosystem': ecosystem,
            'novel_vulnerabilities': [],
            'risk_indicators': [],
            'metadata_analysis': {},
            'source_analysis': {},
            'novel_cve_score': 0
        }
        
        try:
            # Get package metadata
            metadata = self.get_detailed_metadata(package_name, ecosystem)
            analysis['metadata_analysis'] = metadata
            
            if not metadata:
                return analysis
                
            # Check for risk indicators in metadata
            risk_indicators = self.analyze_metadata_risks(metadata)
            analysis['risk_indicators'] = risk_indicators
            
            # Download and analyze source code
            source_analysis = self.analyze_source_for_novel_patterns(package_name, ecosystem)
            analysis['source_analysis'] = source_analysis
            
            # Look for novel vulnerability patterns
            novel_vulns = self.detect_novel_vulnerability_patterns(source_analysis, metadata)
            analysis['novel_vulnerabilities'] = novel_vulns
            
            # Calculate novel CVE score
            analysis['novel_cve_score'] = self.calculate_novel_cve_score(
                risk_indicators, novel_vulns, metadata
            )
            
        except Exception as e:
            analysis['error'] = str(e)
            
        return analysis
    
    def get_detailed_metadata(self, package_name, ecosystem):
        """Get detailed package metadata"""
        try:
            if ecosystem == 'npm':
                url = f"https://registry.npmjs.org/{package_name}"
                response = self.session.get(url, timeout=30)
                if response.status_code == 200:
                    data = response.json()
                    latest_version = data.get('dist-tags', {}).get('latest', '')
                    version_data = data.get('versions', {}).get(latest_version, {})
                    
                    return {
                        'name': package_name,
                        'version': latest_version,
                        'description': data.get('description', ''),
                        'scripts': version_data.get('scripts', {}),
                        'dependencies': version_data.get('dependencies', {}),
                        'devDependencies': version_data.get('devDependencies', {}),
                        'maintainers': data.get('maintainers', []),
                        'repository': data.get('repository', {}),
                        'homepage': data.get('homepage', ''),
                        'created': data.get('time', {}).get('created', ''),
                        'modified': data.get('time', {}).get('modified', ''),
                        'versions': list(data.get('versions', {}).keys()),
                        'keywords': data.get('keywords', []),
                        'license': data.get('license', ''),
                        'dist': version_data.get('dist', {})
                    }
                    
        except Exception as e:
            print(f"Error getting metadata for {package_name}: {e}")
            
        return None
    
    def analyze_metadata_risks(self, metadata):
        """Analyze metadata for risk indicators"""
        risks = []
        
        if not metadata:
            return risks
            
        # Check scripts for suspicious commands
        scripts = metadata.get('scripts', {})
        for script_name, script_content in scripts.items():
            if any(suspicious in script_content.lower() for suspicious in [
                'curl', 'wget', 'nc ', 'netcat', 'bash -c', 'sh -c',
                'eval', 'base64', 'python -c', 'node -e'
            ]):
                risks.append({
                    'type': 'suspicious_script',
                    'script': script_name,
                    'content': script_content,
                    'severity': 'high'
                })
        
        # Check for suspicious dependencies
        deps = metadata.get('dependencies', {})
        suspicious_deps = [
            'child_process', 'fs-extra', 'shelljs', 'node-cmd',
            'exec', 'spawn', 'crypto-js', 'bitcoin'
        ]
        
        for dep in deps:
            if any(sus in dep.lower() for sus in suspicious_deps):
                risks.append({
                    'type': 'suspicious_dependency',
                    'dependency': dep,
                    'version': deps[dep],
                    'severity': 'medium'
                })
        
        # Check maintainer count
        maintainers = metadata.get('maintainers', [])
        if len(maintainers) == 1:
            risks.append({
                'type': 'single_maintainer',
                'maintainer': maintainers[0] if maintainers else 'unknown',
                'severity': 'low'
            })
        
        # Check for missing security metadata
        if not metadata.get('repository'):
            risks.append({
                'type': 'missing_repository',
                'severity': 'medium'
            })
            
        if not metadata.get('license'):
            risks.append({
                'type': 'missing_license',
                'severity': 'low'
            })
        
        return risks
    
    def analyze_source_for_novel_patterns(self, package_name, ecosystem):
        """Analyze source code for novel vulnerability patterns"""
        analysis = {
            'files_analyzed': 0,
            'suspicious_patterns': [],
            'obfuscation_detected': False,
            'network_activity': [],
            'file_operations': [],
            'crypto_operations': []
        }
        
        try:
            with tempfile.TemporaryDirectory() as temp_dir:
                # Download package
                if ecosystem == 'npm':
                    result = subprocess.run([
                        'npm', 'pack', package_name
                    ], cwd=temp_dir, capture_output=True, text=True, timeout=60)
                    
                    if result.returncode == 0:
                        import tarfile
                        tgz_files = list(Path(temp_dir).glob('*.tgz'))
                        if tgz_files:
                            with tarfile.open(tgz_files[0], 'r:gz') as tar:
                                tar.extractall(temp_dir)
                
                # Analyze files
                for root, dirs, files in os.walk(temp_dir):
                    for file in files:
                        if file.endswith(('.js', '.ts', '.py')):
                            file_path = os.path.join(root, file)
                            analysis['files_analyzed'] += 1
                            
                            try:
                                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                                    content = f.read()
                                
                                # Check for novel patterns
                                self.check_novel_patterns(content, file_path, analysis)
                                
                            except Exception as e:
                                continue
                                
        except Exception as e:
            analysis['error'] = str(e)
            
        return analysis
    
    def check_novel_patterns(self, content, file_path, analysis):
        """Check for novel vulnerability patterns in source code"""
        
        # Pattern 1: Hidden network requests
        hidden_network_patterns = [
            r'fetch\s*\(\s*["\'][^"\']*\.onion[^"\']*["\']',  # Tor hidden services
            r'XMLHttpRequest.*open\s*\([^)]*["\'][^"\']*\d+\.\d+\.\d+\.\d+[^"\']*["\']',  # Direct IP requests
            r'WebSocket\s*\([^)]*["\'][^"\']*\.bit[^"\']*["\']',  # Blockchain domains
        ]
        
        for pattern in hidden_network_patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                analysis['network_activity'].append({
                    'type': 'hidden_network_request',
                    'pattern': pattern,
                    'match': match.group(),
                    'file': file_path,
                    'line': content[:match.start()].count('\n') + 1
                })
        
        # Pattern 2: Steganography or data hiding
        steganography_patterns = [
            r'canvas\.getImageData',  # Canvas manipulation for hiding data
            r'btoa\s*\(\s*atob',  # Double base64 encoding
            r'String\.fromCharCode\s*\(\s*\d+(?:\s*,\s*\d+){10,}',  # Character code obfuscation
        ]
        
        for pattern in steganography_patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                analysis['suspicious_patterns'].append({
                    'type': 'steganography',
                    'pattern': pattern,
                    'match': match.group(),
                    'file': file_path,
                    'line': content[:match.start()].count('\n') + 1
                })
        
        # Pattern 3: Time-based or conditional malware
        conditional_patterns = [
            r'new\s+Date\(\)\.getTime\(\)\s*[><=]\s*\d{13}',  # Time-based activation
            r'Math\.random\(\)\s*[><=]\s*0\.\d+',  # Probability-based execution
            r'process\.env\.[A-Z_]+\s*===\s*["\'][^"\']+["\']',  # Environment-based activation
        ]
        
        for pattern in conditional_patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                analysis['suspicious_patterns'].append({
                    'type': 'conditional_execution',
                    'pattern': pattern,
                    'match': match.group(),
                    'file': file_path,
                    'line': content[:match.start()].count('\n') + 1
                })
        
        # Pattern 4: Advanced obfuscation
        if content.count('\\x') > 20 or content.count('\\u') > 20:
            analysis['obfuscation_detected'] = True
            analysis['suspicious_patterns'].append({
                'type': 'advanced_obfuscation',
                'file': file_path,
                'hex_count': content.count('\\x'),
                'unicode_count': content.count('\\u')
            })
        
        # Pattern 5: Cryptocurrency mining indicators
        crypto_patterns = [
            r'stratum\+tcp://',  # Mining pool connection
            r'getblocktemplate',  # Bitcoin mining
            r'cryptonight',  # Monero mining algorithm
            r'ethash',  # Ethereum mining
        ]
        
        for pattern in crypto_patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                analysis['crypto_operations'].append({
                    'type': 'crypto_mining',
                    'pattern': pattern,
                    'match': match.group(),
                    'file': file_path,
                    'line': content[:match.start()].count('\n') + 1
                })
    
    def detect_novel_vulnerability_patterns(self, source_analysis, metadata):
        """Detect novel vulnerability patterns"""
        novel_vulns = []
        
        # Novel pattern 1: Supply chain poisoning
        if (len(source_analysis.get('network_activity', [])) > 0 and
            len(metadata.get('maintainers', [])) == 1):
            novel_vulns.append({
                'type': 'supply_chain_poisoning',
                'description': 'Single maintainer package with hidden network requests',
                'severity': 9,
                'evidence': {
                    'network_requests': len(source_analysis.get('network_activity', [])),
                    'maintainers': len(metadata.get('maintainers', []))
                }
            })
        
        # Novel pattern 2: Conditional malware activation
        conditional_patterns = [p for p in source_analysis.get('suspicious_patterns', []) 
                              if p.get('type') == 'conditional_execution']
        if len(conditional_patterns) > 2:
            novel_vulns.append({
                'type': 'conditional_malware',
                'description': 'Multiple conditional execution patterns detected',
                'severity': 8,
                'evidence': {
                    'conditional_patterns': len(conditional_patterns),
                    'patterns': conditional_patterns[:3]
                }
            })
        
        # Novel pattern 3: Steganographic data exfiltration
        stego_patterns = [p for p in source_analysis.get('suspicious_patterns', []) 
                         if p.get('type') == 'steganography']
        if len(stego_patterns) > 0:
            novel_vulns.append({
                'type': 'steganographic_exfiltration',
                'description': 'Potential data hiding using steganography',
                'severity': 7,
                'evidence': {
                    'steganography_patterns': len(stego_patterns),
                    'patterns': stego_patterns
                }
            })
        
        # Novel pattern 4: Advanced persistent threat (APT) indicators
        if (source_analysis.get('obfuscation_detected') and
            len(source_analysis.get('crypto_operations', [])) > 0):
            novel_vulns.append({
                'type': 'apt_indicators',
                'description': 'Advanced obfuscation combined with crypto operations',
                'severity': 8,
                'evidence': {
                    'obfuscation': source_analysis.get('obfuscation_detected'),
                    'crypto_operations': len(source_analysis.get('crypto_operations', []))
                }
            })
        
        return novel_vulns
    
    def calculate_novel_cve_score(self, risk_indicators, novel_vulns, metadata):
        """Calculate score for novel CVE potential"""
        score = 0
        
        # Base score from novel vulnerabilities
        for vuln in novel_vulns:
            score += vuln.get('severity', 0) * 10
        
        # Risk indicators
        high_risk_count = len([r for r in risk_indicators if r.get('severity') == 'high'])
        medium_risk_count = len([r for r in risk_indicators if r.get('severity') == 'medium'])
        
        score += high_risk_count * 15
        score += medium_risk_count * 8
        
        # Package popularity (higher impact)
        versions = metadata.get('versions', [])
        if len(versions) > 10:
            score += 20
        
        return min(score, 100)
    
    def hunt_targeted_cves(self):
        """Main function to hunt for targeted CVEs"""
        print("🎯 Starting Targeted CVE Hunter...")
        
        all_candidates = []
        
        # 1. Get packages with recent security updates
        print("\n📋 Finding packages with recent security updates...")
        security_packages = self.get_packages_with_recent_security_updates('npm', days=60)
        print(f"Found {len(security_packages)} packages with security-related updates")
        
        # 2. Get packages with suspicious patterns
        print("\n🔍 Finding packages with suspicious patterns...")
        suspicious_packages = self.get_packages_with_suspicious_patterns('npm')
        print(f"Found {len(suspicious_packages)} packages with suspicious patterns")
        
        # 3. Combine and deduplicate
        all_packages = []
        seen_names = set()
        
        for pkg in security_packages + suspicious_packages:
            if pkg['name'] not in seen_names:
                all_packages.append(pkg)
                seen_names.add(pkg['name'])
        
        print(f"\n🔬 Analyzing {len(all_packages)} unique packages...")
        
        # 4. Analyze each package
        for i, pkg in enumerate(all_packages[:20]):  # Limit to first 20 for demo
            package_name = pkg['name']
            ecosystem = pkg['ecosystem']
            
            print(f"  [{i+1}/{min(len(all_packages), 20)}] Analyzing {package_name}...")
            
            try:
                analysis = self.analyze_package_for_novel_vulnerabilities(package_name, ecosystem)
                
                if analysis['novel_cve_score'] >= 40:
                    all_candidates.append(analysis)
                    print(f"    🚨 Novel CVE candidate (score: {analysis['novel_cve_score']})")
                    
                    # Print novel vulnerabilities found
                    for vuln in analysis.get('novel_vulnerabilities', []):
                        print(f"      - {vuln['type']}: {vuln['description']}")
                        
            except Exception as e:
                print(f"    ❌ Error: {e}")
        
        # Save results
        with open('targeted_cve_candidates.json', 'w') as f:
            json.dump(all_candidates, f, indent=2, default=str)
        
        print(f"\n✅ Targeted CVE hunting complete!")
        print(f"🚨 Novel CVE candidates found: {len(all_candidates)}")
        
        if all_candidates:
            print("\n🔥 Top novel CVE candidates:")
            for candidate in sorted(all_candidates, key=lambda x: x['novel_cve_score'], reverse=True):
                print(f"  • {candidate['package_name']} - Score: {candidate['novel_cve_score']}")
                for vuln in candidate.get('novel_vulnerabilities', [])[:2]:
                    print(f"    - {vuln['type']} (severity: {vuln['severity']})")
        
        return all_candidates

if __name__ == "__main__":
    hunter = TargetedCVEHunter()
    candidates = hunter.hunt_targeted_cves()