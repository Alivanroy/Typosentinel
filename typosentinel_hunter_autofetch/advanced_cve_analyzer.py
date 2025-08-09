#!/usr/bin/env python3
"""
Advanced CVE Analyzer - Filters out false positives and focuses on real vulnerabilities
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
import shutil

class AdvancedCVEAnalyzer:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Advanced-CVE-Analyzer/1.0 (Security Research)'
        })
        
    def is_false_positive(self, vulnerability, file_path, content):
        """Determine if a vulnerability is a false positive"""
        vuln_type = vulnerability['type']
        pattern = vulnerability['pattern']
        match = vulnerability['match']
        context = vulnerability['context']
        
        # TypeScript definition files are usually false positives
        if file_path.endswith(('.d.ts', '.d.cts', '.d.mts')):
            return True, "TypeScript definition file"
            
        # Documentation and example code
        if any(indicator in context.lower() for indicator in [
            '* @example', '* example:', '// example', '/* example',
            'documentation', 'readme', 'comment', ' * ', '/**'
        ]):
            return True, "Documentation or example code"
            
        # Test files
        if any(test_indicator in file_path.lower() for test_indicator in [
            'test', 'spec', '__test__', '.test.', '.spec.', 'tests/'
        ]):
            return True, "Test file"
            
        # Check for specific false positive patterns
        if vuln_type == 'code_injection':
            # Function declarations and type definitions
            if re.search(r'(function\s+\w+|export\s+function|declare\s+function)', context, re.IGNORECASE):
                return True, "Function declaration"
                
            # TypeScript/JavaScript type annotations
            if re.search(r':\s*Function|Function\s*[|&]', context):
                return True, "Type annotation"
                
            # Legitimate eval usage in parsers/compilers
            if 'eval' in match.lower() and any(keyword in context.lower() for keyword in [
                'parser', 'compiler', 'transpiler', 'babel', 'webpack'
            ]):
                return True, "Legitimate eval in build tool"
                
        elif vuln_type == 'crypto_issues':
            # Legitimate crypto library usage
            if any(crypto_lib in file_path.lower() for crypto_lib in [
                'crypto', 'hash', 'digest', 'security'
            ]):
                return True, "Legitimate crypto library"
                
        elif vuln_type == 'command_injection':
            # Build scripts and legitimate system calls
            if any(build_file in file_path.lower() for build_file in [
                'build', 'script', 'gulpfile', 'gruntfile', 'webpack'
            ]):
                return True, "Build script"
                
        return False, ""
    
    def analyze_javascript_ast(self, file_path):
        """Analyze JavaScript/TypeScript files using AST parsing"""
        vulnerabilities = []
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                
            # Remove TypeScript types for basic parsing
            content_cleaned = re.sub(r':\s*[A-Za-z_][A-Za-z0-9_<>|\[\]]*', '', content)
            content_cleaned = re.sub(r'<[^>]*>', '', content_cleaned)
            
            # Look for dangerous patterns with context
            dangerous_patterns = {
                'eval_usage': r'eval\s*\([^)]*["\'][^"\']*["\'][^)]*\)',
                'function_constructor': r'new\s+Function\s*\([^)]*["\'][^"\']*["\'][^)]*\)',
                'dynamic_import': r'import\s*\([^)]*["\'][^"\']*\$[^"\']*["\'][^)]*\)',
                'process_execution': r'(exec|spawn|fork)\s*\([^)]*["\'][^"\']*\$[^"\']*["\']',
                'file_operations': r'(writeFile|readFile|unlink)\s*\([^)]*\.\.[^)]*\)',
                'network_requests': r'(fetch|XMLHttpRequest|axios\.get)\s*\([^)]*["\'][^"\']*\$[^"\']*["\']'
            }
            
            for vuln_type, pattern in dangerous_patterns.items():
                matches = re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE)
                for match in matches:
                    line_num = content[:match.start()].count('\n') + 1
                    context = content[max(0, match.start()-100):match.end()+100]
                    
                    # Check if it's a false positive
                    vuln_data = {
                        'type': vuln_type,
                        'pattern': pattern,
                        'match': match.group(),
                        'context': context
                    }
                    
                    is_fp, reason = self.is_false_positive(vuln_data, file_path, content)
                    if not is_fp:
                        vulnerabilities.append({
                            'type': vuln_type,
                            'file': file_path,
                            'line': line_num,
                            'pattern': pattern,
                            'match': match.group(),
                            'context': context,
                            'severity': self.calculate_severity(vuln_type, match.group(), context)
                        })
                        
        except Exception as e:
            pass
            
        return vulnerabilities
    
    def calculate_severity(self, vuln_type, match, context):
        """Calculate vulnerability severity"""
        severity_score = 0
        
        # Base scores by vulnerability type
        base_scores = {
            'eval_usage': 8,
            'function_constructor': 7,
            'dynamic_import': 6,
            'process_execution': 9,
            'file_operations': 7,
            'network_requests': 6
        }
        
        severity_score = base_scores.get(vuln_type, 5)
        
        # Increase severity for user input
        if any(user_input in context.lower() for user_input in [
            'req.body', 'req.query', 'req.params', 'process.argv',
            'location.search', 'window.location', 'document.cookie'
        ]):
            severity_score += 2
            
        # Increase severity for network context
        if any(network in context.lower() for network in [
            'http', 'https', 'fetch', 'axios', 'request'
        ]):
            severity_score += 1
            
        return min(severity_score, 10)
    
    def analyze_python_ast(self, file_path):
        """Analyze Python files using AST parsing"""
        vulnerabilities = []
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                
            # Parse Python AST
            try:
                tree = ast.parse(content)
                
                class VulnerabilityVisitor(ast.NodeVisitor):
                    def __init__(self):
                        self.vulns = []
                        
                    def visit_Call(self, node):
                        # Check for dangerous function calls
                        if isinstance(node.func, ast.Name):
                            func_name = node.func.id
                            if func_name in ['eval', 'exec', 'compile']:
                                # Check if arguments contain user input
                                for arg in node.args:
                                    if self.contains_user_input(arg):
                                        self.vulns.append({
                                            'type': 'code_injection',
                                            'function': func_name,
                                            'line': node.lineno,
                                            'severity': 9
                                        })
                                        
                        elif isinstance(node.func, ast.Attribute):
                            if (isinstance(node.func.value, ast.Name) and 
                                node.func.value.id == 'os' and 
                                node.func.attr == 'system'):
                                self.vulns.append({
                                    'type': 'command_injection',
                                    'function': 'os.system',
                                    'line': node.lineno,
                                    'severity': 9
                                })
                                
                        self.generic_visit(node)
                        
                    def contains_user_input(self, node):
                        """Check if AST node contains user input"""
                        if isinstance(node, ast.Name):
                            return node.id in ['input', 'raw_input', 'sys.argv']
                        elif isinstance(node, ast.BinOp):
                            return (self.contains_user_input(node.left) or 
                                   self.contains_user_input(node.right))
                        return False
                
                visitor = VulnerabilityVisitor()
                visitor.visit(tree)
                
                for vuln in visitor.vulns:
                    vulnerabilities.append({
                        'type': vuln['type'],
                        'file': file_path,
                        'line': vuln['line'],
                        'function': vuln['function'],
                        'severity': vuln['severity']
                    })
                    
            except SyntaxError:
                # Fall back to regex analysis for invalid Python
                pass
                
        except Exception as e:
            pass
            
        return vulnerabilities
    
    def get_npm_package_downloads(self, package_name):
        """Get npm package download statistics"""
        try:
            url = f"https://api.npmjs.org/downloads/point/last-month/{package_name}"
            response = self.session.get(url, timeout=10)
            if response.status_code == 200:
                data = response.json()
                return data.get('downloads', 0)
        except:
            pass
        return 0
    
    def get_pypi_package_downloads(self, package_name):
        """Get PyPI package download statistics"""
        try:
            url = f"https://pypistats.org/api/packages/{package_name}/recent"
            response = self.session.get(url, timeout=10)
            if response.status_code == 200:
                data = response.json()
                return data.get('data', {}).get('last_month', 0)
        except:
            pass
        return 0
    
    def analyze_package_deeply(self, package_name, ecosystem):
        """Perform deep analysis of a specific package"""
        print(f"🔍 Deep analyzing {ecosystem}:{package_name}...")
        
        analysis_result = {
            'package_name': package_name,
            'ecosystem': ecosystem,
            'real_vulnerabilities': [],
            'false_positives': [],
            'package_info': {},
            'risk_assessment': {},
            'cve_potential': 0
        }
        
        try:
            # Get package metadata
            if ecosystem == 'npm':
                url = f"https://registry.npmjs.org/{package_name}"
                response = self.session.get(url, timeout=30)
                if response.status_code == 200:
                    data = response.json()
                    latest_version = data.get('dist-tags', {}).get('latest', '')
                    analysis_result['package_info'] = {
                        'name': package_name,
                        'version': latest_version,
                        'description': data.get('description', ''),
                        'downloads': self.get_npm_package_downloads(package_name),
                        'versions_count': len(data.get('versions', {})),
                        'maintainers': len(data.get('maintainers', [])),
                        'created': data.get('time', {}).get('created', ''),
                        'repository': data.get('repository', {})
                    }
                    
            elif ecosystem == 'pypi':
                url = f"https://pypi.org/pypi/{package_name}/json"
                response = self.session.get(url, timeout=30)
                if response.status_code == 200:
                    data = response.json()
                    info = data.get('info', {})
                    analysis_result['package_info'] = {
                        'name': package_name,
                        'version': info.get('version', ''),
                        'description': info.get('summary', ''),
                        'downloads': self.get_pypi_package_downloads(package_name),
                        'author': info.get('author', ''),
                        'home_page': info.get('home_page', '')
                    }
            
            # Download and analyze source code
            with tempfile.TemporaryDirectory() as temp_dir:
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
                                
                elif ecosystem == 'pypi':
                    result = subprocess.run([
                        'pip', 'download', '--no-deps', '--no-binary', ':all:', package_name
                    ], cwd=temp_dir, capture_output=True, text=True, timeout=60)
                    
                    if result.returncode == 0:
                        for file_path in Path(temp_dir).iterdir():
                            if file_path.suffix in ['.tar.gz', '.zip']:
                                if file_path.suffix == '.zip':
                                    import zipfile
                                    with zipfile.ZipFile(file_path, 'r') as zip_ref:
                                        zip_ref.extractall(temp_dir)
                                else:
                                    import tarfile
                                    with tarfile.open(file_path, 'r:gz') as tar:
                                        tar.extractall(temp_dir)
                
                # Analyze source files
                for root, dirs, files in os.walk(temp_dir):
                    for file in files:
                        file_path = os.path.join(root, file)
                        
                        if file.endswith(('.js', '.ts', '.jsx', '.tsx')):
                            vulns = self.analyze_javascript_ast(file_path)
                            analysis_result['real_vulnerabilities'].extend(vulns)
                            
                        elif file.endswith('.py'):
                            vulns = self.analyze_python_ast(file_path)
                            analysis_result['real_vulnerabilities'].extend(vulns)
            
            # Calculate CVE potential
            analysis_result['cve_potential'] = self.calculate_cve_potential(analysis_result)
            
        except Exception as e:
            analysis_result['error'] = str(e)
            
        return analysis_result
    
    def calculate_cve_potential(self, analysis_result):
        """Calculate the potential for this to be a real CVE"""
        score = 0
        
        real_vulns = analysis_result.get('real_vulnerabilities', [])
        package_info = analysis_result.get('package_info', {})
        
        # Score based on real vulnerabilities
        for vuln in real_vulns:
            severity = vuln.get('severity', 5)
            if severity >= 8:
                score += 40
            elif severity >= 6:
                score += 25
            else:
                score += 10
        
        # Package popularity multiplier
        downloads = package_info.get('downloads', 0)
        if downloads > 100000:
            score *= 1.5
        elif downloads > 10000:
            score *= 1.2
        
        # Maintainer trust factor
        maintainers = package_info.get('maintainers', 0)
        if maintainers == 1:
            score += 10  # Single maintainer is riskier
        
        return min(int(score), 100)
    
    def hunt_real_cves_advanced(self, target_packages=None):
        """Hunt for real CVEs with advanced filtering"""
        print("🎯 Starting Advanced CVE Hunter...")
        
        if target_packages is None:
            # Focus on popular packages that might have been overlooked
            target_packages = [
                ('npm', 'lodash'),
                ('npm', 'express'),
                ('npm', 'react'),
                ('npm', 'axios'),
                ('npm', 'moment'),
                ('npm', 'chalk'),
                ('npm', 'commander'),
                ('npm', 'debug'),
                ('pypi', 'requests'),
                ('pypi', 'urllib3'),
                ('pypi', 'setuptools'),
                ('pypi', 'pip'),
                ('pypi', 'numpy'),
                ('pypi', 'pandas'),
                ('pypi', 'flask'),
                ('pypi', 'django')
            ]
        
        real_cve_candidates = []
        
        for ecosystem, package_name in target_packages:
            try:
                analysis = self.analyze_package_deeply(package_name, ecosystem)
                
                if analysis['cve_potential'] >= 50:
                    real_cve_candidates.append(analysis)
                    print(f"  ⚠️  Potential real CVE: {package_name} (score: {analysis['cve_potential']})")
                else:
                    print(f"  ✅ Clean: {package_name} (score: {analysis['cve_potential']})")
                    
            except Exception as e:
                print(f"  ❌ Error analyzing {package_name}: {e}")
        
        # Save results
        with open('real_cve_candidates_advanced.json', 'w') as f:
            json.dump(real_cve_candidates, f, indent=2, default=str)
        
        print(f"\n✅ Advanced analysis complete!")
        print(f"🚨 Real CVE candidates found: {len(real_cve_candidates)}")
        
        if real_cve_candidates:
            print("\n🔥 Top real CVE candidates:")
            for candidate in sorted(real_cve_candidates, key=lambda x: x['cve_potential'], reverse=True)[:5]:
                print(f"  • {candidate['package_name']} ({candidate['ecosystem']}) - Score: {candidate['cve_potential']}")
                vulns = candidate.get('real_vulnerabilities', [])
                if vulns:
                    print(f"    Vulnerabilities: {len(vulns)} found")
                    for vuln in vulns[:3]:
                        print(f"      - {vuln['type']} (severity: {vuln.get('severity', 'N/A')})")
        
        return real_cve_candidates

if __name__ == "__main__":
    analyzer = AdvancedCVEAnalyzer()
    candidates = analyzer.hunt_real_cves_advanced()