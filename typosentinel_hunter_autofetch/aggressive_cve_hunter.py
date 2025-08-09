#!/usr/bin/env python3
"""
Aggressive CVE Hunter - Searches for packages with known vulnerability patterns,
recent security advisories, and potential zero-day vulnerabilities
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
import ast
import hashlib

class AggressiveCVEHunter:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Aggressive-CVE-Hunter/1.0 (Security Research)'
        })
        
    def get_packages_from_security_advisories(self):
        """Get packages mentioned in recent security advisories"""
        packages = []
        
        try:
            # Search for packages mentioned in GitHub security advisories
            url = "https://api.github.com/advisories"
            params = {
                'per_page': 100,
                'ecosystem': 'npm',
                'severity': 'high,critical'
            }
            
            response = self.session.get(url, params=params, timeout=30)
            if response.status_code == 200:
                advisories = response.json()
                
                for advisory in advisories:
                    for vuln in advisory.get('vulnerabilities', []):
                        package_info = vuln.get('package', {})
                        if package_info.get('name'):
                            packages.append({
                                'name': package_info.get('name'),
                                'ecosystem': package_info.get('ecosystem', 'npm'),
                                'advisory_id': advisory.get('ghsa_id'),
                                'severity': advisory.get('severity'),
                                'summary': advisory.get('summary', ''),
                                'published': advisory.get('published_at'),
                                'source': 'github_advisory'
                            })
                            
        except Exception as e:
            print(f"Error fetching GitHub advisories: {e}")
            
        return packages
    
    def get_packages_with_high_download_variance(self):
        """Find packages with unusual download patterns (potential supply chain attacks)"""
        packages = []
        
        try:
            # Get popular packages and check for unusual patterns
            popular_packages = [
                'lodash', 'express', 'react', 'axios', 'moment', 'chalk',
                'commander', 'debug', 'request', 'async', 'underscore',
                'jquery', 'bootstrap', 'vue', 'angular', 'webpack'
            ]
            
            for pkg_name in popular_packages:
                try:
                    # Get package info
                    url = f"https://registry.npmjs.org/{pkg_name}"
                    response = self.session.get(url, timeout=30)
                    
                    if response.status_code == 200:
                        data = response.json()
                        versions = data.get('versions', {})
                        
                        # Look for suspicious version patterns
                        version_list = list(versions.keys())
                        if len(version_list) > 5:
                            # Check for versions with suspicious patterns
                            for version in version_list[-10:]:  # Check last 10 versions
                                version_data = versions.get(version, {})
                                
                                # Check for suspicious scripts or dependencies
                                scripts = version_data.get('scripts', {})
                                deps = version_data.get('dependencies', {})
                                
                                suspicious_indicators = 0
                                
                                # Check scripts
                                for script_name, script_content in scripts.items():
                                    if any(pattern in script_content.lower() for pattern in [
                                        'curl', 'wget', 'base64', 'eval', 'exec'
                                    ]):
                                        suspicious_indicators += 1
                                
                                # Check dependencies
                                for dep in deps:
                                    if any(pattern in dep.lower() for pattern in [
                                        'crypto', 'bitcoin', 'miner', 'shell'
                                    ]):
                                        suspicious_indicators += 1
                                
                                if suspicious_indicators > 0:
                                    packages.append({
                                        'name': pkg_name,
                                        'version': version,
                                        'ecosystem': 'npm',
                                        'suspicious_indicators': suspicious_indicators,
                                        'scripts': scripts,
                                        'source': 'download_variance'
                                    })
                                    
                except Exception as e:
                    continue
                    
        except Exception as e:
            print(f"Error checking download variance: {e}")
            
        return packages
    
    def get_packages_with_known_vuln_patterns(self):
        """Get packages that match known vulnerability patterns"""
        packages = []
        
        # Patterns based on known CVEs
        vuln_patterns = [
            # Prototype pollution
            {'pattern': 'prototype', 'type': 'prototype_pollution'},
            {'pattern': '__proto__', 'type': 'prototype_pollution'},
            
            # Path traversal
            {'pattern': '../', 'type': 'path_traversal'},
            {'pattern': '..\\', 'type': 'path_traversal'},
            
            # Command injection
            {'pattern': 'child_process', 'type': 'command_injection'},
            {'pattern': 'exec', 'type': 'command_injection'},
            
            # Deserialization
            {'pattern': 'serialize', 'type': 'deserialization'},
            {'pattern': 'pickle', 'type': 'deserialization'},
            
            # XSS/Injection
            {'pattern': 'innerHTML', 'type': 'xss'},
            {'pattern': 'eval', 'type': 'code_injection'},
        ]
        
        for pattern_info in vuln_patterns:
            try:
                # Search npm for packages containing these patterns
                url = "https://registry.npmjs.org/-/v1/search"
                params = {
                    'text': pattern_info['pattern'],
                    'size': 20,
                    'quality': 0.1
                }
                
                response = self.session.get(url, params=params, timeout=30)
                if response.status_code == 200:
                    data = response.json()
                    
                    for pkg in data.get('objects', []):
                        package_info = pkg.get('package', {})
                        packages.append({
                            'name': package_info.get('name'),
                            'version': package_info.get('version'),
                            'ecosystem': 'npm',
                            'vuln_pattern': pattern_info['pattern'],
                            'vuln_type': pattern_info['type'],
                            'description': package_info.get('description', ''),
                            'source': 'vuln_pattern'
                        })
                        
            except Exception as e:
                continue
                
        return packages
    
    def analyze_package_for_zero_day(self, package_name, ecosystem):
        """Deep analysis for potential zero-day vulnerabilities"""
        analysis = {
            'package_name': package_name,
            'ecosystem': ecosystem,
            'zero_day_indicators': [],
            'vulnerability_score': 0,
            'risk_factors': [],
            'code_analysis': {}
        }
        
        try:
            # Get package metadata
            metadata = self.get_package_metadata(package_name, ecosystem)
            if not metadata:
                return analysis
            
            # Analyze metadata for risk factors
            risk_factors = self.analyze_metadata_for_risks(metadata)
            analysis['risk_factors'] = risk_factors
            
            # Download and analyze source code
            code_analysis = self.deep_code_analysis(package_name, ecosystem)
            analysis['code_analysis'] = code_analysis
            
            # Look for zero-day indicators
            zero_day_indicators = self.detect_zero_day_patterns(code_analysis, metadata)
            analysis['zero_day_indicators'] = zero_day_indicators
            
            # Calculate vulnerability score
            analysis['vulnerability_score'] = self.calculate_vulnerability_score(
                risk_factors, zero_day_indicators, code_analysis
            )
            
        except Exception as e:
            analysis['error'] = str(e)
            
        return analysis
    
    def get_package_metadata(self, package_name, ecosystem):
        """Get comprehensive package metadata"""
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
                        'created': data.get('time', {}).get('created', ''),
                        'modified': data.get('time', {}).get('modified', ''),
                        'versions': list(data.get('versions', {}).keys()),
                        'keywords': data.get('keywords', []),
                        'license': data.get('license', ''),
                        'dist': version_data.get('dist', {}),
                        'engines': version_data.get('engines', {}),
                        'bin': version_data.get('bin', {}),
                        'main': version_data.get('main', ''),
                        'files': version_data.get('files', [])
                    }
                    
        except Exception as e:
            print(f"Error getting metadata for {package_name}: {e}")
            
        return None
    
    def analyze_metadata_for_risks(self, metadata):
        """Analyze metadata for risk indicators"""
        risks = []
        
        if not metadata:
            return risks
        
        # Check for suspicious scripts
        scripts = metadata.get('scripts', {})
        for script_name, script_content in scripts.items():
            # High-risk script patterns
            high_risk_patterns = [
                r'curl\s+[^|]*\|\s*sh',  # Pipe to shell
                r'wget\s+[^|]*\|\s*sh',  # Pipe to shell
                r'eval\s*\(\s*process\.env',  # Environment variable evaluation
                r'child_process\.exec\s*\(',  # Process execution
                r'fs\.writeFileSync.*\.js',  # Writing JS files
                r'require\s*\(\s*["\']child_process["\']',  # Child process require
            ]
            
            for pattern in high_risk_patterns:
                if re.search(pattern, script_content, re.IGNORECASE):
                    risks.append({
                        'type': 'high_risk_script',
                        'script': script_name,
                        'pattern': pattern,
                        'content': script_content,
                        'severity': 9
                    })
        
        # Check for suspicious dependencies
        deps = metadata.get('dependencies', {})
        suspicious_deps = [
            'child_process', 'fs-extra', 'shelljs', 'node-cmd',
            'crypto-js', 'bitcoin', 'monero', 'miner'
        ]
        
        for dep in deps:
            if any(sus in dep.lower() for sus in suspicious_deps):
                risks.append({
                    'type': 'suspicious_dependency',
                    'dependency': dep,
                    'version': deps[dep],
                    'severity': 6
                })
        
        # Check for binary files
        bin_files = metadata.get('bin', {})
        if bin_files:
            risks.append({
                'type': 'binary_files',
                'binaries': list(bin_files.keys()),
                'severity': 4
            })
        
        # Check maintainer trust
        maintainers = metadata.get('maintainers', [])
        if len(maintainers) == 1:
            risks.append({
                'type': 'single_maintainer',
                'maintainer': maintainers[0].get('name', 'unknown') if maintainers else 'unknown',
                'severity': 3
            })
        
        return risks
    
    def deep_code_analysis(self, package_name, ecosystem):
        """Perform deep static analysis of package source code"""
        analysis = {
            'files_analyzed': 0,
            'dangerous_functions': [],
            'network_calls': [],
            'file_operations': [],
            'crypto_operations': [],
            'obfuscation_indicators': [],
            'ast_analysis': {}
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
                
                # Analyze JavaScript/TypeScript files
                for root, dirs, files in os.walk(temp_dir):
                    for file in files:
                        if file.endswith(('.js', '.ts')) and not file.endswith('.d.ts'):
                            file_path = os.path.join(root, file)
                            analysis['files_analyzed'] += 1
                            
                            try:
                                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                                    content = f.read()
                                
                                # Analyze for dangerous patterns
                                self.analyze_js_content(content, file_path, analysis)
                                
                            except Exception as e:
                                continue
                                
        except Exception as e:
            analysis['error'] = str(e)
            
        return analysis
    
    def analyze_js_content(self, content, file_path, analysis):
        """Analyze JavaScript content for vulnerabilities"""
        
        # Dangerous function calls
        dangerous_patterns = [
            (r'eval\s*\(', 'eval_usage'),
            (r'Function\s*\(', 'function_constructor'),
            (r'setTimeout\s*\(\s*["\'][^"\']*["\']', 'settimeout_string'),
            (r'setInterval\s*\(\s*["\'][^"\']*["\']', 'setinterval_string'),
            (r'document\.write\s*\(', 'document_write'),
            (r'innerHTML\s*=', 'innerhtml_assignment'),
            (r'outerHTML\s*=', 'outerhtml_assignment'),
        ]
        
        for pattern, vuln_type in dangerous_patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                analysis['dangerous_functions'].append({
                    'type': vuln_type,
                    'pattern': pattern,
                    'match': match.group(),
                    'file': file_path,
                    'line': content[:match.start()].count('\n') + 1
                })
        
        # Network operations
        network_patterns = [
            (r'fetch\s*\(', 'fetch_call'),
            (r'XMLHttpRequest', 'xhr_usage'),
            (r'WebSocket\s*\(', 'websocket_usage'),
            (r'require\s*\(\s*["\']https?["\']', 'http_require'),
        ]
        
        for pattern, net_type in network_patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                analysis['network_calls'].append({
                    'type': net_type,
                    'pattern': pattern,
                    'match': match.group(),
                    'file': file_path,
                    'line': content[:match.start()].count('\n') + 1
                })
        
        # File operations
        file_patterns = [
            (r'fs\.writeFile', 'file_write'),
            (r'fs\.readFile', 'file_read'),
            (r'fs\.unlink', 'file_delete'),
            (r'fs\.mkdir', 'directory_create'),
        ]
        
        for pattern, file_type in file_patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                analysis['file_operations'].append({
                    'type': file_type,
                    'pattern': pattern,
                    'match': match.group(),
                    'file': file_path,
                    'line': content[:match.start()].count('\n') + 1
                })
        
        # Obfuscation indicators
        if content.count('\\x') > 10:
            analysis['obfuscation_indicators'].append({
                'type': 'hex_encoding',
                'count': content.count('\\x'),
                'file': file_path
            })
        
        if content.count('\\u') > 10:
            analysis['obfuscation_indicators'].append({
                'type': 'unicode_encoding',
                'count': content.count('\\u'),
                'file': file_path
            })
        
        # Check for minified/obfuscated code
        lines = content.split('\n')
        avg_line_length = sum(len(line) for line in lines) / len(lines) if lines else 0
        if avg_line_length > 200:
            analysis['obfuscation_indicators'].append({
                'type': 'long_lines',
                'avg_length': avg_line_length,
                'file': file_path
            })
    
    def detect_zero_day_patterns(self, code_analysis, metadata):
        """Detect patterns that might indicate zero-day vulnerabilities"""
        indicators = []
        
        # Pattern 1: Dangerous functions with user input
        dangerous_funcs = code_analysis.get('dangerous_functions', [])
        if len(dangerous_funcs) > 3:
            indicators.append({
                'type': 'multiple_dangerous_functions',
                'count': len(dangerous_funcs),
                'functions': [f['type'] for f in dangerous_funcs[:5]],
                'severity': 8
            })
        
        # Pattern 2: Network calls with file operations
        network_calls = code_analysis.get('network_calls', [])
        file_ops = code_analysis.get('file_operations', [])
        
        if len(network_calls) > 0 and len(file_ops) > 0:
            indicators.append({
                'type': 'network_file_combination',
                'network_calls': len(network_calls),
                'file_operations': len(file_ops),
                'severity': 7
            })
        
        # Pattern 3: Heavy obfuscation
        obfuscation = code_analysis.get('obfuscation_indicators', [])
        if len(obfuscation) > 2:
            indicators.append({
                'type': 'heavy_obfuscation',
                'indicators': len(obfuscation),
                'types': [o['type'] for o in obfuscation],
                'severity': 6
            })
        
        # Pattern 4: Suspicious scripts with dangerous functions
        scripts = metadata.get('scripts', {})
        if scripts and dangerous_funcs:
            indicators.append({
                'type': 'scripts_with_dangerous_functions',
                'script_count': len(scripts),
                'dangerous_function_count': len(dangerous_funcs),
                'severity': 7
            })
        
        return indicators
    
    def calculate_vulnerability_score(self, risk_factors, zero_day_indicators, code_analysis):
        """Calculate overall vulnerability score"""
        score = 0
        
        # Risk factors scoring
        for risk in risk_factors:
            score += risk.get('severity', 0) * 5
        
        # Zero-day indicators scoring
        for indicator in zero_day_indicators:
            score += indicator.get('severity', 0) * 8
        
        # Code analysis scoring
        dangerous_count = len(code_analysis.get('dangerous_functions', []))
        score += min(dangerous_count * 3, 30)
        
        network_count = len(code_analysis.get('network_calls', []))
        score += min(network_count * 2, 20)
        
        obfuscation_count = len(code_analysis.get('obfuscation_indicators', []))
        score += min(obfuscation_count * 5, 25)
        
        return min(score, 100)
    
    def hunt_aggressive_cves(self):
        """Main function for aggressive CVE hunting"""
        print("🔥 Starting Aggressive CVE Hunter...")
        
        all_candidates = []
        
        # 1. Get packages from security advisories
        print("\n📋 Getting packages from security advisories...")
        advisory_packages = self.get_packages_from_security_advisories()
        print(f"Found {len(advisory_packages)} packages from advisories")
        
        # 2. Get packages with download variance
        print("\n📊 Checking popular packages for anomalies...")
        variance_packages = self.get_packages_with_high_download_variance()
        print(f"Found {len(variance_packages)} packages with suspicious patterns")
        
        # 3. Get packages with known vulnerability patterns
        print("\n🎯 Finding packages with vulnerability patterns...")
        pattern_packages = self.get_packages_with_known_vuln_patterns()
        print(f"Found {len(pattern_packages)} packages with vulnerability patterns")
        
        # 4. Combine and deduplicate
        all_packages = []
        seen_names = set()
        
        for pkg_list in [advisory_packages, variance_packages, pattern_packages]:
            for pkg in pkg_list:
                pkg_name = pkg.get('name', '')
                if pkg_name and pkg_name not in seen_names:
                    all_packages.append(pkg)
                    seen_names.add(pkg_name)
        
        print(f"\n🔬 Analyzing {len(all_packages)} unique packages for zero-day vulnerabilities...")
        
        # 5. Deep analysis
        high_risk_candidates = []
        
        for i, pkg in enumerate(all_packages[:25]):  # Limit to 25 for performance
            package_name = pkg.get('name', '')
            ecosystem = pkg.get('ecosystem', 'npm')
            
            print(f"  [{i+1}/{min(len(all_packages), 25)}] Deep analysis: {package_name}...")
            
            try:
                analysis = self.analyze_package_for_zero_day(package_name, ecosystem)
                
                if analysis['vulnerability_score'] >= 50:
                    all_candidates.append(analysis)
                    
                    if analysis['vulnerability_score'] >= 70:
                        high_risk_candidates.append(analysis)
                        print(f"    🚨 HIGH RISK (score: {analysis['vulnerability_score']})")
                        
                        # Print key findings
                        for indicator in analysis.get('zero_day_indicators', [])[:2]:
                            print(f"      - {indicator['type']} (severity: {indicator['severity']})")
                    
                    elif analysis['vulnerability_score'] >= 50:
                        print(f"    ⚠️  Medium risk (score: {analysis['vulnerability_score']})")
                        
            except Exception as e:
                print(f"    ❌ Error: {e}")
        
        # Save results
        with open('aggressive_cve_candidates.json', 'w') as f:
            json.dump(all_candidates, f, indent=2, default=str)
        
        with open('high_risk_zero_day_candidates.json', 'w') as f:
            json.dump(high_risk_candidates, f, indent=2, default=str)
        
        print(f"\n✅ Aggressive CVE hunting complete!")
        print(f"🚨 Total vulnerability candidates: {len(all_candidates)}")
        print(f"🔥 High-risk zero-day candidates: {len(high_risk_candidates)}")
        
        if high_risk_candidates:
            print("\n🔥 TOP HIGH-RISK CANDIDATES:")
            for candidate in sorted(high_risk_candidates, key=lambda x: x['vulnerability_score'], reverse=True):
                print(f"  • {candidate['package_name']} - Score: {candidate['vulnerability_score']}")
                for indicator in candidate.get('zero_day_indicators', [])[:2]:
                    print(f"    - {indicator['type']} (severity: {indicator['severity']})")
        
        return all_candidates, high_risk_candidates

if __name__ == "__main__":
    hunter = AggressiveCVEHunter()
    candidates, high_risk = hunter.hunt_aggressive_cves()