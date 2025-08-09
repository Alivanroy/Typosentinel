#!/usr/bin/env python3
"""
Comprehensive CVE Hunter - Find Real Novel CVEs
Searches for existing packages with potential undiscovered vulnerabilities
"""

import json
import requests
import time
from datetime import datetime, timedelta
from typing import Dict, List, Tuple, Any
import subprocess
import os
from hunter.scanner import scan

class ComprehensiveCVEHunter:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'CVE-Hunter/1.0 (Security Research)'
        })
        
    def search_recent_packages(self, ecosystem: str, days: int = 30, limit: int = 100) -> List[Dict]:
        """Search for recently updated packages"""
        packages = []
        
        if ecosystem == "npm":
            # Get recently updated npm packages
            url = "https://registry.npmjs.org/-/rss?descending=true&limit=1000"
            try:
                response = self.session.get(url, timeout=30)
                if response.status_code == 200:
                    # Parse RSS feed for recent packages
                    import xml.etree.ElementTree as ET
                    root = ET.fromstring(response.content)
                    
                    for item in root.findall('.//item')[:limit]:
                        title = item.find('title')
                        if title is not None:
                            package_name = title.text.strip()
                            packages.append({
                                'name': package_name,
                                'ecosystem': ecosystem,
                                'source': 'recent_updates'
                            })
            except Exception as e:
                print(f"Error fetching recent npm packages: {e}")
                
        elif ecosystem == "pypi":
            # Get recently updated PyPI packages
            url = "https://pypi.org/rss/updates.xml"
            try:
                response = self.session.get(url, timeout=30)
                if response.status_code == 200:
                    import xml.etree.ElementTree as ET
                    root = ET.fromstring(response.content)
                    
                    for item in root.findall('.//item')[:limit]:
                        title = item.find('title')
                        if title is not None:
                            # Extract package name from title like "package-name 1.0.0"
                            package_info = title.text.strip().split(' ')
                            if len(package_info) >= 2:
                                package_name = package_info[0]
                                packages.append({
                                    'name': package_name,
                                    'ecosystem': ecosystem,
                                    'source': 'recent_updates'
                                })
            except Exception as e:
                print(f"Error fetching recent PyPI packages: {e}")
        
        return packages
    
    def search_suspicious_patterns(self, ecosystem: str) -> List[Dict]:
        """Search for packages with suspicious naming patterns"""
        suspicious_packages = []
        
        # Common typosquatting targets
        popular_packages = {
            'npm': ['react', 'lodash', 'express', 'axios', 'moment', 'webpack', 'babel', 'eslint', 'jest', 'mocha'],
            'pypi': ['requests', 'numpy', 'pandas', 'django', 'flask', 'tensorflow', 'pytorch', 'scikit-learn', 'matplotlib', 'pillow']
        }
        
        # Suspicious patterns
        patterns = [
            '{}-v2', '{}-v3', '{}-next', '{}-beta', '{}-alpha', '{}-test', '{}-dev',
            '{}2', '{}3', 'new-{}', 'latest-{}', '{}-js', '{}-py', '{}-lib'
        ]
        
        for package in popular_packages.get(ecosystem, []):
            for pattern in patterns:
                suspicious_name = pattern.format(package)
                suspicious_packages.append({
                    'name': suspicious_name,
                    'ecosystem': ecosystem,
                    'source': 'typosquatting_pattern',
                    'target': package
                })
        
        # Add crypto/mining related suspicious names
        crypto_suspicious = [
            'bitcoin-miner', 'crypto-miner', 'eth-miner', 'monero-miner',
            'wallet-stealer', 'password-stealer', 'keylogger-js',
            'remote-access', 'backdoor-js', 'trojan-horse'
        ]
        
        for name in crypto_suspicious:
            suspicious_packages.append({
                'name': name,
                'ecosystem': ecosystem,
                'source': 'malware_pattern'
            })
            
        return suspicious_packages
    
    def check_package_exists(self, name: str, ecosystem: str) -> Tuple[bool, Dict]:
        """Check if a package exists and get its metadata"""
        try:
            if ecosystem == "npm":
                url = f"https://registry.npmjs.org/{name}"
                response = self.session.get(url, timeout=10)
                if response.status_code == 200:
                    data = response.json()
                    return True, data
                else:
                    return False, {}
            elif ecosystem == "pypi":
                url = f"https://pypi.org/pypi/{name}/json"
                response = self.session.get(url, timeout=10)
                if response.status_code == 200:
                    data = response.json()
                    return True, data
                else:
                    return False, {}
        except Exception as e:
            print(f"Error checking {ecosystem}:{name}: {e}")
            return False, {}
        
        return False, {}
    
    def analyze_package_metadata(self, metadata: Dict, ecosystem: str) -> Dict:
        """Analyze package metadata for suspicious characteristics"""
        analysis = {
            'threat_score': 0,
            'threats': [],
            'warnings': [],
            'red_flags': []
        }
        
        if ecosystem == "npm":
            # Check for suspicious scripts
            scripts = metadata.get('scripts', {})
            suspicious_scripts = ['postinstall', 'preinstall', 'install']
            for script in suspicious_scripts:
                if script in scripts:
                    script_content = scripts[script]
                    if any(keyword in script_content.lower() for keyword in ['curl', 'wget', 'eval', 'exec', 'child_process']):
                        analysis['threats'].append(f"Suspicious {script} script: {script_content}")
                        analysis['threat_score'] += 20
            
            # Check dependencies
            deps = metadata.get('dependencies', {})
            suspicious_deps = ['child_process', 'fs-extra', 'node-pty', 'keytar']
            for dep in suspicious_deps:
                if dep in deps:
                    analysis['warnings'].append(f"Potentially dangerous dependency: {dep}")
                    analysis['threat_score'] += 5
            
            # Check for missing description
            if not metadata.get('description'):
                analysis['warnings'].append("Missing package description")
                analysis['threat_score'] += 3
                
            # Check for recent creation with high version
            created = metadata.get('time', {}).get('created')
            if created:
                try:
                    created_date = datetime.fromisoformat(created.replace('Z', '+00:00'))
                    if created_date > datetime.now().replace(tzinfo=created_date.tzinfo) - timedelta(days=30):
                        latest_version = metadata.get('dist-tags', {}).get('latest', '0.0.1')
                        if not latest_version.startswith('0.'):
                            analysis['red_flags'].append("Recently created package with high version number")
                            analysis['threat_score'] += 15
                except:
                    pass
                    
        elif ecosystem == "pypi":
            info = metadata.get('info', {})
            
            # Check for suspicious keywords
            keywords = info.get('keywords', '') or ''
            suspicious_keywords = ['crypto', 'mining', 'bitcoin', 'stealer', 'keylog', 'backdoor']
            for keyword in suspicious_keywords:
                if keyword.lower() in keywords.lower():
                    analysis['threats'].append(f"Suspicious keyword: {keyword}")
                    analysis['threat_score'] += 10
            
            # Check description
            description = info.get('description', '') or info.get('summary', '')
            if not description:
                analysis['warnings'].append("Missing package description")
                analysis['threat_score'] += 3
            else:
                suspicious_desc = ['download', 'execute', 'remote', 'shell', 'command']
                for word in suspicious_desc:
                    if word in description.lower():
                        analysis['warnings'].append(f"Suspicious description content: {word}")
                        analysis['threat_score'] += 5
        
        return analysis
    
    def scan_with_typosentinel(self, name: str, ecosystem: str) -> Dict:
        """Scan package with Typosentinel"""
        try:
            result = scan(ecosystem, name, None, None)
            return {
                'ok': result.ok,
                'decision': result.decision,
                'risk': result.risk,
                'latency': result.latency,
                'signals': result.signals,
                'stdout': result.stdout,
                'stderr': result.stderr
            }
        except Exception as e:
            return {
                'ok': False,
                'error': str(e),
                'decision': 'error',
                'risk': 0.0,
                'signals': [],
                'stdout': '',
                'stderr': str(e)
            }
    
    def hunt_novel_cves(self, ecosystems: List[str] = ['npm', 'pypi'], 
                       target_count: int = 50) -> List[Dict]:
        """Main hunting function"""
        print("🔍 COMPREHENSIVE CVE HUNTER - SEARCHING FOR NOVEL VULNERABILITIES")
        print("=" * 80)
        
        all_candidates = []
        
        for ecosystem in ecosystems:
            print(f"\n🎯 Hunting in {ecosystem.upper()} ecosystem...")
            
            # Get recent packages
            print("📅 Searching recent packages...")
            recent_packages = self.search_recent_packages(ecosystem, days=7, limit=target_count//2)
            
            # Get suspicious patterns
            print("🚨 Searching suspicious patterns...")
            suspicious_packages = self.search_suspicious_patterns(ecosystem)
            
            # Combine and deduplicate
            all_packages = recent_packages + suspicious_packages
            unique_packages = {pkg['name']: pkg for pkg in all_packages}.values()
            
            print(f"📦 Found {len(unique_packages)} unique packages to investigate")
            
            # Check existence and analyze
            for i, pkg in enumerate(list(unique_packages)[:target_count]):
                print(f"🔬 Analyzing {i+1}/{min(target_count, len(unique_packages))}: {pkg['name']}")
                
                # Check if package exists
                exists, metadata = self.check_package_exists(pkg['name'], ecosystem)
                
                if exists:
                    # Analyze metadata
                    metadata_analysis = self.analyze_package_metadata(metadata, ecosystem)
                    
                    # Scan with Typosentinel
                    typo_result = self.scan_with_typosentinel(pkg['name'], ecosystem)
                    
                    # Calculate combined risk
                    typo_risk = typo_result.get('risk', 0.0)
                    metadata_risk = metadata_analysis['threat_score'] / 100.0
                    combined_risk = max(typo_risk, metadata_risk)
                    
                    # Only include if there's some risk
                    if combined_risk > 0.1 or metadata_analysis['threat_score'] > 5:
                        candidate = {
                            'name': pkg['name'],
                            'ecosystem': ecosystem,
                            'exists': True,
                            'typosentinel_result': typo_result,
                            'metadata_analysis': metadata_analysis,
                            'combined_risk': combined_risk,
                            'source': pkg.get('source', 'unknown'),
                            'target': pkg.get('target'),
                            'timestamp': datetime.now().isoformat()
                        }
                        all_candidates.append(candidate)
                        
                        if combined_risk > 0.5:
                            print(f"  🚨 HIGH RISK: {combined_risk:.3f}")
                        elif combined_risk > 0.3:
                            print(f"  ⚠️  MEDIUM RISK: {combined_risk:.3f}")
                        else:
                            print(f"  ℹ️  LOW RISK: {combined_risk:.3f}")
                
                # Rate limiting
                time.sleep(0.1)
        
        # Sort by risk
        all_candidates.sort(key=lambda x: x['combined_risk'], reverse=True)
        
        return all_candidates

def main():
    hunter = ComprehensiveCVEHunter()
    
    # Hunt for novel CVEs
    candidates = hunter.hunt_novel_cves(['npm', 'pypi'], target_count=100)
    
    # Save results
    output_file = "comprehensive_cve_results.json"
    with open(output_file, 'w') as f:
        json.dump(candidates, f, indent=2)
    
    print(f"\n📊 RESULTS SUMMARY")
    print("=" * 50)
    print(f"Total candidates found: {len(candidates)}")
    
    high_risk = [c for c in candidates if c['combined_risk'] > 0.5]
    medium_risk = [c for c in candidates if 0.3 <= c['combined_risk'] <= 0.5]
    low_risk = [c for c in candidates if c['combined_risk'] < 0.3]
    
    print(f"🚨 High risk (>0.5): {len(high_risk)}")
    print(f"⚠️  Medium risk (0.3-0.5): {len(medium_risk)}")
    print(f"ℹ️  Low risk (<0.3): {len(low_risk)}")
    
    if high_risk:
        print(f"\n🎯 TOP HIGH-RISK CANDIDATES:")
        for candidate in high_risk[:10]:
            print(f"  • {candidate['ecosystem']}:{candidate['name']} - Risk: {candidate['combined_risk']:.3f}")
            if candidate['metadata_analysis']['threats']:
                print(f"    Threats: {', '.join(candidate['metadata_analysis']['threats'][:2])}")
    
    print(f"\n💾 Results saved to: {output_file}")
    
    # Create a focused report for manual investigation
    novel_cves = [c for c in candidates if c['combined_risk'] > 0.4]
    if novel_cves:
        with open("potential_novel_cves.json", 'w') as f:
            json.dump(novel_cves, f, indent=2)
        print(f"🔍 {len(novel_cves)} potential novel CVEs saved to: potential_novel_cves.json")

if __name__ == "__main__":
    main()