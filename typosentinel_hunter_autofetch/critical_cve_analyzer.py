#!/usr/bin/env python3
"""
Critical CVE Analyzer - Deep analysis of the most dangerous packages found
"""

import json
import requests
import subprocess
import tempfile
import os
import tarfile
import zipfile
import re
from datetime import datetime
from pathlib import Path

class CriticalCVEAnalyzer:
    def __init__(self):
        self.critical_packages = []
        self.analysis_results = []
        
    def load_critical_packages(self, json_file):
        """Load packages with risk >= 0.95 for deep analysis"""
        with open(json_file, 'r') as f:
            data = json.load(f)
        
        # Filter for critical packages (risk >= 0.95)
        self.critical_packages = [
            pkg for pkg in data 
            if pkg.get('combined_risk', 0) >= 0.95
        ]
        
        print(f"Found {len(self.critical_packages)} critical packages for analysis")
        return self.critical_packages
    
    def get_package_metadata(self, package_name, ecosystem):
        """Get detailed package metadata"""
        try:
            if ecosystem == "npm":
                url = f"https://registry.npmjs.org/{package_name}"
            elif ecosystem == "pypi":
                url = f"https://pypi.org/pypi/{package_name}/json"
            else:
                return None
                
            response = requests.get(url, timeout=10)
            if response.status_code == 200:
                return response.json()
        except Exception as e:
            print(f"Error fetching metadata for {package_name}: {e}")
        return None
    
    def download_package(self, package_name, ecosystem, version=None):
        """Download package for analysis"""
        try:
            metadata = self.get_package_metadata(package_name, ecosystem)
            if not metadata:
                return None
                
            if ecosystem == "npm":
                if not version:
                    version = metadata.get('dist-tags', {}).get('latest')
                    if not version and 'versions' in metadata:
                        versions = list(metadata['versions'].keys())
                        version = versions[-1] if versions else None
                
                if version and version in metadata.get('versions', {}):
                    tarball_url = metadata['versions'][version]['dist']['tarball']
                    
                    # Download tarball
                    response = requests.get(tarball_url, timeout=30)
                    if response.status_code == 200:
                        temp_dir = tempfile.mkdtemp()
                        tarball_path = os.path.join(temp_dir, f"{package_name}.tgz")
                        
                        with open(tarball_path, 'wb') as f:
                            f.write(response.content)
                        
                        # Extract tarball
                        extract_dir = os.path.join(temp_dir, "extracted")
                        os.makedirs(extract_dir, exist_ok=True)
                        
                        with tarfile.open(tarball_path, 'r:gz') as tar:
                            tar.extractall(extract_dir)
                        
                        return extract_dir
                        
            elif ecosystem == "pypi":
                if not version:
                    version = metadata.get('info', {}).get('version')
                
                if version:
                    # Try to get source distribution
                    urls = metadata.get('urls', [])
                    source_url = None
                    
                    for url_info in urls:
                        if url_info.get('packagetype') == 'sdist':
                            source_url = url_info.get('url')
                            break
                    
                    if source_url:
                        response = requests.get(source_url, timeout=30)
                        if response.status_code == 200:
                            temp_dir = tempfile.mkdtemp()
                            
                            if source_url.endswith('.tar.gz'):
                                archive_path = os.path.join(temp_dir, f"{package_name}.tar.gz")
                                with open(archive_path, 'wb') as f:
                                    f.write(response.content)
                                
                                extract_dir = os.path.join(temp_dir, "extracted")
                                os.makedirs(extract_dir, exist_ok=True)
                                
                                with tarfile.open(archive_path, 'r:gz') as tar:
                                    tar.extractall(extract_dir)
                                
                                return extract_dir
                            elif source_url.endswith('.zip'):
                                archive_path = os.path.join(temp_dir, f"{package_name}.zip")
                                with open(archive_path, 'wb') as f:
                                    f.write(response.content)
                                
                                extract_dir = os.path.join(temp_dir, "extracted")
                                os.makedirs(extract_dir, exist_ok=True)
                                
                                with zipfile.ZipFile(archive_path, 'r') as zip_ref:
                                    zip_ref.extractall(extract_dir)
                                
                                return extract_dir
                                
        except Exception as e:
            print(f"Error downloading {package_name}: {e}")
        
        return None
    
    def analyze_source_code(self, extract_dir, package_name):
        """Analyze source code for malicious patterns"""
        malicious_patterns = {
            'crypto_mining': [
                r'stratum\+tcp://',
                r'mining.*pool',
                r'hashrate',
                r'cryptocurrency',
                r'bitcoin.*mining',
                r'ethereum.*mining',
                r'monero.*mining'
            ],
            'data_exfiltration': [
                r'fetch\(["\']https?://[^"\']*\)',
                r'XMLHttpRequest',
                r'navigator\.userAgent',
                r'document\.cookie',
                r'localStorage',
                r'sessionStorage',
                r'btoa\(',
                r'atob\(',
                r'eval\(',
                r'Function\(',
                r'require\(["\']child_process["\']',
                r'exec\(',
                r'spawn\('
            ],
            'backdoor': [
                r'shell_exec',
                r'system\(',
                r'passthru\(',
                r'exec\(',
                r'popen\(',
                r'subprocess\.',
                r'os\.system',
                r'os\.popen',
                r'commands\.',
                r'getattr\(',
                r'setattr\(',
                r'__import__\(',
                r'globals\(\)',
                r'locals\(\)'
            ],
            'obfuscation': [
                r'\\x[0-9a-fA-F]{2}',
                r'\\u[0-9a-fA-F]{4}',
                r'String\.fromCharCode',
                r'unescape\(',
                r'decodeURIComponent\(',
                r'Buffer\.from.*base64',
                r'base64.*decode',
                r'rot13',
                r'caesar.*cipher'
            ]
        }
        
        threats = []
        suspicious_files = []
        
        try:
            for root, dirs, files in os.walk(extract_dir):
                for file in files:
                    if file.endswith(('.js', '.py', '.sh', '.bat', '.ps1', '.json', '.txt')):
                        file_path = os.path.join(root, file)
                        try:
                            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                                content = f.read()
                                
                                for threat_type, patterns in malicious_patterns.items():
                                    for pattern in patterns:
                                        if re.search(pattern, content, re.IGNORECASE):
                                            threats.append({
                                                'type': threat_type,
                                                'pattern': pattern,
                                                'file': file_path,
                                                'line_count': content.count('\n') + 1
                                            })
                                            
                                            if file_path not in suspicious_files:
                                                suspicious_files.append(file_path)
                        except Exception as e:
                            print(f"Error reading {file_path}: {e}")
        except Exception as e:
            print(f"Error analyzing source code: {e}")
        
        return {
            'threats': threats,
            'suspicious_files': suspicious_files,
            'total_threats': len(threats),
            'threat_types': list(set([t['type'] for t in threats]))
        }
    
    def check_package_reputation(self, package_name, ecosystem):
        """Check package reputation and history"""
        metadata = self.get_package_metadata(package_name, ecosystem)
        if not metadata:
            return {}
        
        reputation_info = {}
        
        if ecosystem == "npm":
            # Check creation date, downloads, maintainers
            time_info = metadata.get('time', {})
            created = time_info.get('created')
            modified = time_info.get('modified')
            
            reputation_info.update({
                'created': created,
                'modified': modified,
                'maintainers': len(metadata.get('maintainers', [])),
                'versions_count': len(metadata.get('versions', {})),
                'has_readme': bool(metadata.get('readme')),
                'has_description': bool(metadata.get('description')),
                'has_homepage': bool(metadata.get('homepage')),
                'has_repository': bool(metadata.get('repository')),
                'keywords': metadata.get('keywords', [])
            })
            
            # Check if recently created but high version
            if created:
                try:
                    created_date = datetime.fromisoformat(created.replace('Z', '+00:00'))
                    days_old = (datetime.now().astimezone() - created_date).days
                    latest_version = metadata.get('dist-tags', {}).get('latest', '0.0.0')
                    
                    reputation_info['days_old'] = days_old
                    reputation_info['latest_version'] = latest_version
                    
                    # Red flag: new package with high version number
                    if days_old < 30 and any(int(x) > 5 for x in latest_version.split('.') if x.isdigit()):
                        reputation_info['red_flags'] = reputation_info.get('red_flags', [])
                        reputation_info['red_flags'].append('New package with high version number')
                        
                except Exception as e:
                    print(f"Error parsing dates: {e}")
                    
        elif ecosystem == "pypi":
            info = metadata.get('info', {})
            reputation_info.update({
                'author': info.get('author'),
                'author_email': info.get('author_email'),
                'maintainer': info.get('maintainer'),
                'home_page': info.get('home_page'),
                'download_url': info.get('download_url'),
                'project_urls': info.get('project_urls', {}),
                'classifiers': info.get('classifiers', []),
                'keywords': info.get('keywords'),
                'license': info.get('license'),
                'description': info.get('description'),
                'summary': info.get('summary')
            })
        
        return reputation_info
    
    def analyze_package(self, package_info):
        """Perform comprehensive analysis of a single package"""
        package_name = package_info['name']
        ecosystem = package_info['ecosystem']
        
        print(f"\n🔍 Analyzing {ecosystem}:{package_name}")
        
        analysis = {
            'package_name': package_name,
            'ecosystem': ecosystem,
            'typosentinel_risk': package_info.get('combined_risk', 0),
            'typosentinel_decision': package_info.get('typosentinel_result', {}).get('decision'),
            'analysis_timestamp': datetime.now().isoformat()
        }
        
        # Get reputation info
        print("  📊 Checking reputation...")
        reputation = self.check_package_reputation(package_name, ecosystem)
        analysis['reputation'] = reputation
        
        # Download and analyze source code
        print("  📦 Downloading package...")
        extract_dir = self.download_package(package_name, ecosystem)
        
        if extract_dir:
            print("  🔬 Analyzing source code...")
            source_analysis = self.analyze_source_code(extract_dir, package_name)
            analysis['source_analysis'] = source_analysis
            
            # Cleanup
            try:
                import shutil
                shutil.rmtree(os.path.dirname(extract_dir))
            except:
                pass
        else:
            print("  ❌ Could not download package")
            analysis['source_analysis'] = {'error': 'Could not download package'}
        
        # Calculate final threat score
        threat_score = self.calculate_threat_score(analysis)
        analysis['final_threat_score'] = threat_score
        analysis['is_novel_cve'] = threat_score >= 80
        
        return analysis
    
    def calculate_threat_score(self, analysis):
        """Calculate final threat score based on all factors"""
        score = 0
        
        # Base score from Typosentinel
        typo_risk = analysis.get('typosentinel_risk', 0)
        score += typo_risk * 50  # Max 50 points
        
        # Source code analysis
        source = analysis.get('source_analysis', {})
        threat_count = source.get('total_threats', 0)
        score += min(threat_count * 10, 30)  # Max 30 points
        
        # Reputation factors
        reputation = analysis.get('reputation', {})
        
        # Missing metadata
        if not reputation.get('has_description', True):
            score += 5
        if not reputation.get('has_readme', True):
            score += 5
        if not reputation.get('has_repository', True):
            score += 5
        
        # Red flags
        red_flags = reputation.get('red_flags', [])
        score += len(red_flags) * 5
        
        # Age vs version mismatch
        days_old = reputation.get('days_old', 999)
        if days_old < 7:
            score += 10  # Very new package
        elif days_old < 30:
            score += 5   # New package
        
        return min(score, 100)  # Cap at 100
    
    def run_analysis(self, json_file, output_file):
        """Run complete analysis on critical packages"""
        print("🚀 Starting Critical CVE Analysis")
        
        # Load critical packages
        critical_packages = self.load_critical_packages(json_file)
        
        if not critical_packages:
            print("No critical packages found!")
            return
        
        # Analyze each package
        for i, package in enumerate(critical_packages[:10], 1):  # Limit to top 10
            print(f"\n[{i}/{min(len(critical_packages), 10)}]")
            try:
                analysis = self.analyze_package(package)
                self.analysis_results.append(analysis)
            except Exception as e:
                print(f"Error analyzing {package['name']}: {e}")
        
        # Sort by threat score
        self.analysis_results.sort(key=lambda x: x.get('final_threat_score', 0), reverse=True)
        
        # Save results
        with open(output_file, 'w') as f:
            json.dump(self.analysis_results, f, indent=2)
        
        # Print summary
        self.print_summary()
        
        return self.analysis_results
    
    def print_summary(self):
        """Print analysis summary"""
        print("\n" + "="*60)
        print("🎯 CRITICAL CVE ANALYSIS SUMMARY")
        print("="*60)
        
        novel_cves = [r for r in self.analysis_results if r.get('is_novel_cve', False)]
        
        print(f"📊 Total packages analyzed: {len(self.analysis_results)}")
        print(f"🚨 Novel CVE candidates: {len(novel_cves)}")
        
        if novel_cves:
            print("\n🔥 TOP NOVEL CVE CANDIDATES:")
            for i, cve in enumerate(novel_cves[:5], 1):
                name = cve['package_name']
                ecosystem = cve['ecosystem']
                score = cve['final_threat_score']
                threats = cve.get('source_analysis', {}).get('total_threats', 0)
                
                print(f"  {i}. {ecosystem}:{name}")
                print(f"     Threat Score: {score}/100")
                print(f"     Source Threats: {threats}")
                
                # Show specific threats
                threat_types = cve.get('source_analysis', {}).get('threat_types', [])
                if threat_types:
                    print(f"     Threat Types: {', '.join(threat_types)}")
                print()

if __name__ == "__main__":
    analyzer = CriticalCVEAnalyzer()
    
    # Run analysis on the comprehensive results
    results = analyzer.run_analysis(
        'potential_novel_cves.json',
        'critical_cve_analysis.json'
    )
    
    print(f"\n✅ Analysis complete! Results saved to critical_cve_analysis.json")