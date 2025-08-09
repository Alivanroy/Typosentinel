#!/usr/bin/env python3
"""
Real CVE Hunter - Focuses on finding actual vulnerabilities in legitimate packages
that could be novel CVEs, rather than just typosquatting packages.
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
import shutil
import zipfile
import tarfile

class RealCVEHunter:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'CVE-Hunter/1.0 (Security Research)'
        })
        
    def get_recently_updated_packages(self, ecosystem='npm', days=7, limit=50):
        """Get recently updated packages that might have new vulnerabilities"""
        packages = []
        
        if ecosystem == 'npm':
            # Get recently updated npm packages
            try:
                # Search for packages updated in the last week
                url = f"https://registry.npmjs.org/-/v1/search"
                params = {
                    'text': 'updated:>=' + (datetime.now() - timedelta(days=days)).strftime('%Y-%m-%d'),
                    'size': limit,
                    'quality': 0.1,  # Lower quality threshold to catch more packages
                    'popularity': 0.1,
                    'maintenance': 0.1
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
                            'updated': package_info.get('date'),
                            'maintainers': len(package_info.get('maintainers', [])),
                            'keywords': package_info.get('keywords', [])
                        })
            except Exception as e:
                print(f"Error fetching npm packages: {e}")
                
        elif ecosystem == 'pypi':
            # Get recently updated PyPI packages
            try:
                # Use PyPI's RSS feed for recent updates
                url = "https://pypi.org/rss/updates.xml"
                response = self.session.get(url, timeout=30)
                
                if response.status_code == 200:
                    # Parse RSS to get package names
                    import xml.etree.ElementTree as ET
                    root = ET.fromstring(response.content)
                    
                    count = 0
                    for item in root.findall('.//item')[:limit]:
                        title = item.find('title').text if item.find('title') is not None else ''
                        if ' ' in title:
                            pkg_name = title.split(' ')[0]
                            packages.append({
                                'name': pkg_name,
                                'ecosystem': 'pypi',
                                'description': item.find('description').text if item.find('description') is not None else '',
                                'updated': item.find('pubDate').text if item.find('pubDate') is not None else ''
                            })
                            count += 1
                            if count >= limit:
                                break
            except Exception as e:
                print(f"Error fetching PyPI packages: {e}")
                
        return packages
    
    def get_package_metadata(self, package_name, ecosystem):
        """Get detailed metadata for a package"""
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
                        'homepage': data.get('homepage', ''),
                        'repository': data.get('repository', {}),
                        'maintainers': data.get('maintainers', []),
                        'scripts': version_data.get('scripts', {}),
                        'dependencies': version_data.get('dependencies', {}),
                        'devDependencies': version_data.get('devDependencies', {}),
                        'created': data.get('time', {}).get('created', ''),
                        'modified': data.get('time', {}).get('modified', ''),
                        'versions_count': len(data.get('versions', {})),
                        'dist': version_data.get('dist', {}),
                        'keywords': data.get('keywords', [])
                    }
                    
            elif ecosystem == 'pypi':
                url = f"https://pypi.org/pypi/{package_name}/json"
                response = self.session.get(url, timeout=30)
                if response.status_code == 200:
                    data = response.json()
                    info = data.get('info', {})
                    
                    return {
                        'name': package_name,
                        'version': info.get('version', ''),
                        'description': info.get('summary', ''),
                        'homepage': info.get('home_page', ''),
                        'author': info.get('author', ''),
                        'maintainer': info.get('maintainer', ''),
                        'keywords': info.get('keywords', ''),
                        'classifiers': info.get('classifiers', []),
                        'requires_dist': info.get('requires_dist', []),
                        'urls': data.get('urls', [])
                    }
        except Exception as e:
            print(f"Error getting metadata for {package_name}: {e}")
            
        return None
    
    def identify_vulnerability_patterns(self, package_metadata):
        """Identify patterns that might indicate vulnerabilities"""
        risk_factors = []
        
        if not package_metadata:
            return risk_factors
            
        # Check for suspicious scripts in npm packages
        scripts = package_metadata.get('scripts', {})
        if scripts:
            for script_name, script_content in scripts.items():
                if any(pattern in script_content.lower() for pattern in [
                    'curl', 'wget', 'eval', 'exec', 'system', 'spawn',
                    'child_process', 'fs.unlink', 'rm -rf', 'sudo'
                ]):
                    risk_factors.append(f"Suspicious script: {script_name} - {script_content}")
        
        # Check for suspicious dependencies
        deps = package_metadata.get('dependencies', {})
        suspicious_deps = ['child_process', 'fs-extra', 'shelljs', 'node-cmd']
        for dep in deps:
            if any(sus in dep.lower() for sus in suspicious_deps):
                risk_factors.append(f"Suspicious dependency: {dep}")
        
        # Check for missing security metadata
        if not package_metadata.get('repository'):
            risk_factors.append("Missing repository information")
            
        if not package_metadata.get('homepage'):
            risk_factors.append("Missing homepage")
            
        # Check for version inconsistencies
        version = package_metadata.get('version', '')
        if version.startswith('0.0.') or version.startswith('1.0.0'):
            risk_factors.append(f"Suspicious version: {version}")
            
        return risk_factors
    
    def download_and_analyze_package(self, package_name, ecosystem):
        """Download package and perform static analysis"""
        analysis_results = {
            'package_name': package_name,
            'ecosystem': ecosystem,
            'vulnerabilities': [],
            'suspicious_files': [],
            'security_issues': []
        }
        
        try:
            with tempfile.TemporaryDirectory() as temp_dir:
                if ecosystem == 'npm':
                    # Download npm package
                    result = subprocess.run([
                        'npm', 'pack', package_name
                    ], cwd=temp_dir, capture_output=True, text=True, timeout=60)
                    
                    if result.returncode == 0:
                        # Extract the tarball
                        tgz_files = list(Path(temp_dir).glob('*.tgz'))
                        if tgz_files:
                            with tarfile.open(tgz_files[0], 'r:gz') as tar:
                                tar.extractall(temp_dir)
                                
                elif ecosystem == 'pypi':
                    # Download PyPI package
                    result = subprocess.run([
                        'pip', 'download', '--no-deps', '--no-binary', ':all:', package_name
                    ], cwd=temp_dir, capture_output=True, text=True, timeout=60)
                    
                    if result.returncode == 0:
                        # Extract downloaded files
                        for file_path in Path(temp_dir).iterdir():
                            if file_path.suffix in ['.tar.gz', '.zip']:
                                if file_path.suffix == '.zip':
                                    with zipfile.ZipFile(file_path, 'r') as zip_ref:
                                        zip_ref.extractall(temp_dir)
                                else:
                                    with tarfile.open(file_path, 'r:gz') as tar:
                                        tar.extractall(temp_dir)
                
                # Analyze extracted files
                analysis_results.update(self.analyze_source_code(temp_dir))
                
        except Exception as e:
            analysis_results['error'] = str(e)
            
        return analysis_results
    
    def analyze_source_code(self, source_dir):
        """Analyze source code for potential vulnerabilities"""
        vulnerabilities = []
        suspicious_files = []
        security_issues = []
        
        # Vulnerability patterns to look for
        vuln_patterns = {
            'command_injection': [
                r'exec\s*\(',
                r'system\s*\(',
                r'spawn\s*\(',
                r'child_process\.',
                r'shell=True',
                r'subprocess\.call',
                r'os\.system'
            ],
            'path_traversal': [
                r'\.\./\.\.',
                r'\.\.\\\.\.\\',
                r'path\.join\([^)]*\.\.[^)]*\)',
                r'open\([^)]*\.\.[^)]*\)'
            ],
            'code_injection': [
                r'eval\s*\(',
                r'Function\s*\(',
                r'new\s+Function',
                r'exec\s*\(',
                r'compile\s*\(',
                r'__import__'
            ],
            'crypto_issues': [
                r'md5\s*\(',
                r'sha1\s*\(',
                r'DES\s*\(',
                r'RC4\s*\(',
                r'random\.random\(\)',
                r'Math\.random\(\)'
            ],
            'hardcoded_secrets': [
                r'password\s*=\s*["\'][^"\']{8,}["\']',
                r'api_key\s*=\s*["\'][^"\']{20,}["\']',
                r'secret\s*=\s*["\'][^"\']{16,}["\']',
                r'token\s*=\s*["\'][^"\']{20,}["\']'
            ]
        }
        
        try:
            for root, dirs, files in os.walk(source_dir):
                for file in files:
                    file_path = os.path.join(root, file)
                    
                    # Skip binary files and common non-source files
                    if any(file.endswith(ext) for ext in ['.pyc', '.so', '.dll', '.exe', '.bin']):
                        continue
                        
                    try:
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()
                            
                        # Check for vulnerability patterns
                        for vuln_type, patterns in vuln_patterns.items():
                            for pattern in patterns:
                                matches = re.finditer(pattern, content, re.IGNORECASE)
                                for match in matches:
                                    line_num = content[:match.start()].count('\n') + 1
                                    vulnerabilities.append({
                                        'type': vuln_type,
                                        'file': file_path,
                                        'line': line_num,
                                        'pattern': pattern,
                                        'match': match.group(),
                                        'context': content[max(0, match.start()-50):match.end()+50]
                                    })
                        
                        # Check for suspicious file characteristics
                        if len(content) > 100000:  # Very large files
                            suspicious_files.append(f"Large file: {file_path} ({len(content)} chars)")
                            
                        if content.count('eval') > 5:  # Multiple eval calls
                            suspicious_files.append(f"Multiple eval calls: {file_path}")
                            
                        # Check for obfuscated code
                        if re.search(r'\\x[0-9a-fA-F]{2}', content) and content.count('\\x') > 10:
                            suspicious_files.append(f"Hex-encoded content: {file_path}")
                            
                    except Exception as e:
                        security_issues.append(f"Could not analyze {file_path}: {e}")
                        
        except Exception as e:
            security_issues.append(f"Error analyzing source code: {e}")
            
        return {
            'vulnerabilities': vulnerabilities,
            'suspicious_files': suspicious_files,
            'security_issues': security_issues
        }
    
    def calculate_cve_likelihood(self, package_metadata, analysis_results, risk_factors):
        """Calculate likelihood that this represents a novel CVE"""
        score = 0
        reasons = []
        
        # High-impact vulnerability types
        high_impact_vulns = ['command_injection', 'code_injection', 'path_traversal']
        medium_impact_vulns = ['crypto_issues', 'hardcoded_secrets']
        
        vuln_counts = {}
        for vuln in analysis_results.get('vulnerabilities', []):
            vuln_type = vuln['type']
            vuln_counts[vuln_type] = vuln_counts.get(vuln_type, 0) + 1
        
        # Score based on vulnerability types and counts
        for vuln_type, count in vuln_counts.items():
            if vuln_type in high_impact_vulns:
                score += count * 30
                reasons.append(f"{count} {vuln_type} vulnerabilities found")
            elif vuln_type in medium_impact_vulns:
                score += count * 15
                reasons.append(f"{count} {vuln_type} issues found")
        
        # Package popularity (more popular = higher impact if vulnerable)
        if package_metadata:
            versions_count = package_metadata.get('versions_count', 0)
            if versions_count > 50:
                score += 20
                reasons.append(f"Popular package ({versions_count} versions)")
            elif versions_count > 10:
                score += 10
                reasons.append(f"Moderately popular package ({versions_count} versions)")
        
        # Suspicious files
        suspicious_count = len(analysis_results.get('suspicious_files', []))
        if suspicious_count > 0:
            score += suspicious_count * 5
            reasons.append(f"{suspicious_count} suspicious files")
        
        # Risk factors from metadata
        score += len(risk_factors) * 3
        if risk_factors:
            reasons.append(f"{len(risk_factors)} metadata risk factors")
        
        return min(score, 100), reasons
    
    def hunt_real_cves(self, ecosystems=['npm', 'pypi'], packages_per_ecosystem=25):
        """Main function to hunt for real CVEs"""
        print("🔍 Starting Real CVE Hunter...")
        print(f"Target ecosystems: {ecosystems}")
        print(f"Packages per ecosystem: {packages_per_ecosystem}")
        
        all_candidates = []
        
        for ecosystem in ecosystems:
            print(f"\n📦 Analyzing {ecosystem} packages...")
            
            # Get recently updated packages
            packages = self.get_recently_updated_packages(ecosystem, days=30, limit=packages_per_ecosystem)
            print(f"Found {len(packages)} recently updated packages")
            
            for i, pkg_info in enumerate(packages):
                package_name = pkg_info['name']
                print(f"  [{i+1}/{len(packages)}] Analyzing {package_name}...")
                
                try:
                    # Get detailed metadata
                    metadata = self.get_package_metadata(package_name, ecosystem)
                    if not metadata:
                        continue
                    
                    # Identify risk factors
                    risk_factors = self.identify_vulnerability_patterns(metadata)
                    
                    # Download and analyze if there are risk factors
                    if risk_factors or True:  # Analyze all for now
                        analysis_results = self.download_and_analyze_package(package_name, ecosystem)
                        
                        # Calculate CVE likelihood
                        cve_score, reasons = self.calculate_cve_likelihood(metadata, analysis_results, risk_factors)
                        
                        if cve_score > 30:  # Threshold for potential CVE
                            candidate = {
                                'package_name': package_name,
                                'ecosystem': ecosystem,
                                'cve_likelihood_score': cve_score,
                                'reasons': reasons,
                                'metadata': metadata,
                                'risk_factors': risk_factors,
                                'analysis_results': analysis_results,
                                'analysis_timestamp': datetime.now().isoformat()
                            }
                            all_candidates.append(candidate)
                            print(f"    ⚠️  Potential CVE candidate (score: {cve_score})")
                        
                except Exception as e:
                    print(f"    ❌ Error analyzing {package_name}: {e}")
                    continue
        
        # Sort by CVE likelihood score
        all_candidates.sort(key=lambda x: x['cve_likelihood_score'], reverse=True)
        
        # Save results
        with open('real_cve_candidates.json', 'w') as f:
            json.dump(all_candidates, f, indent=2, default=str)
        
        # Save high-priority candidates
        high_priority = [c for c in all_candidates if c['cve_likelihood_score'] >= 60]
        with open('high_priority_cve_candidates.json', 'w') as f:
            json.dump(high_priority, f, indent=2, default=str)
        
        print(f"\n✅ Analysis complete!")
        print(f"📊 Total candidates found: {len(all_candidates)}")
        print(f"🚨 High-priority candidates (score ≥ 60): {len(high_priority)}")
        
        if high_priority:
            print("\n🔥 Top CVE candidates:")
            for candidate in high_priority[:5]:
                print(f"  • {candidate['package_name']} ({candidate['ecosystem']}) - Score: {candidate['cve_likelihood_score']}")
                print(f"    Reasons: {', '.join(candidate['reasons'][:3])}")
        
        return all_candidates

if __name__ == "__main__":
    hunter = RealCVEHunter()
    candidates = hunter.hunt_real_cves(ecosystems=['npm', 'pypi'], packages_per_ecosystem=20)