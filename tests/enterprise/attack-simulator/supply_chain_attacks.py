#!/usr/bin/env python3
"""
Supply Chain Attack Generator
Generates realistic supply chain compromise scenarios
"""

import random
import asyncio
from typing import List, Dict, Any
from faker import Faker
import json
from datetime import datetime, timedelta

class SupplyChainAttackGenerator:
    """Generates sophisticated supply chain attack scenarios"""
    
    def __init__(self):
        self.fake = Faker()
        
        # Real-world supply chain attack patterns
        self.attack_patterns = {
            'dependency_confusion': {
                'description': 'Upload malicious packages with names similar to internal dependencies',
                'techniques': ['namespace_confusion', 'version_confusion', 'typosquatting'],
                'targets': ['private_repositories', 'internal_packages']
            },
            'compromised_maintainer': {
                'description': 'Compromise legitimate maintainer accounts',
                'techniques': ['credential_theft', 'social_engineering', 'account_takeover'],
                'targets': ['popular_packages', 'critical_dependencies']
            },
            'malicious_update': {
                'description': 'Inject malicious code into legitimate package updates',
                'techniques': ['code_injection', 'backdoor_insertion', 'steganographic_payload'],
                'targets': ['auto_updating_systems', 'ci_cd_pipelines']
            },
            'build_system_compromise': {
                'description': 'Compromise the build and distribution infrastructure',
                'techniques': ['infrastructure_compromise', 'signing_key_theft', 'repository_poisoning'],
                'targets': ['package_registries', 'build_servers']
            }
        }
        
        # Popular packages that are often targeted
        self.high_value_targets = {
            'python': [
                'requests', 'urllib3', 'setuptools', 'pip', 'wheel', 'certifi',
                'six', 'python-dateutil', 'pytz', 'pyyaml', 'jinja2', 'click'
            ],
            'javascript': [
                'lodash', 'react', 'express', 'axios', 'moment', 'chalk',
                'commander', 'debug', 'fs-extra', 'glob', 'semver', 'yargs'
            ],
            'java': [
                'log4j-core', 'slf4j-api', 'jackson-core', 'commons-lang3',
                'guava', 'spring-core', 'junit', 'mockito-core'
            ]
        }
        
        # Enterprise environments and their characteristics
        self.enterprise_environments = {
            'financial_services': {
                'critical_packages': ['cryptography', 'pycryptodome', 'jwt', 'oauth'],
                'compliance_requirements': ['PCI-DSS', 'SOX', 'GDPR'],
                'risk_tolerance': 'very_low'
            },
            'healthcare': {
                'critical_packages': ['hl7', 'dicom', 'medical-imaging', 'patient-data'],
                'compliance_requirements': ['HIPAA', 'FDA', 'GDPR'],
                'risk_tolerance': 'very_low'
            },
            'technology': {
                'critical_packages': ['cloud-sdk', 'kubernetes', 'docker', 'terraform'],
                'compliance_requirements': ['SOC2', 'ISO27001'],
                'risk_tolerance': 'medium'
            },
            'government': {
                'critical_packages': ['security-tools', 'encryption', 'audit-logging'],
                'compliance_requirements': ['FedRAMP', 'FISMA', 'NIST'],
                'risk_tolerance': 'very_low'
            }
        }
    
    async def generate_dependency_confusion(self, count: int) -> List[Dict[str, Any]]:
        """Generate dependency confusion attack scenarios"""
        attacks = []
        
        for i in range(count):
            # Simulate internal package names
            internal_package = f"{self.fake.company().lower().replace(' ', '-')}-{self.fake.word()}"
            
            attack = {
                'name': internal_package,
                'type': 'dependency_confusion',
                'attack_vector': 'namespace_confusion',
                'target_environment': random.choice(list(self.enterprise_environments.keys())),
                'registry': random.choice(['pypi', 'npm', 'maven']),
                'version': f"{random.randint(10, 99)}.{random.randint(0, 9)}.{random.randint(0, 9)}",
                'internal_target': f"internal-{internal_package}",
                'metadata': {
                    'malicious_behaviors': ['credential_theft', 'environment_discovery'],
                    'target_applications': ['ci_cd_systems', 'build_environments'],
                    'evasion_techniques': ['legitimate_functionality', 'delayed_activation'],
                    'supply_chain_indicators': [''],
                    'backdoor_behaviors': ['remote_access'],
                    'c2_communication': ['encrypted_channels']
                }
            }
            attacks.append(attack)
        
        return attacks
    
    async def generate_malicious_updates(self, count: int) -> List[Dict[str, Any]]:
        """Generate malicious package update scenarios"""
        attacks = []
        
        for i in range(count):
            ecosystem = random.choice(['python', 'javascript', 'java'])
            target_package = random.choice(self.high_value_targets[ecosystem])
            
            # Generate realistic version progression
            base_version = f"{random.randint(1, 5)}.{random.randint(0, 20)}.{random.randint(0, 10)}"
            malicious_version = f"{random.randint(1, 5)}.{random.randint(0, 20)}.{random.randint(11, 99)}"
            
            attack = {
                'name': target_package,
                'type': 'malicious_update',
                'attack_vector': 'compromised_maintainer',
                'ecosystem': ecosystem,
                'legitimate_version': base_version,
                'malicious_version': malicious_version,
                'compromise_method': random.choice(['account_takeover', 'insider_threat', 'social_engineering']),
                'metadata': {
                    'malicious_behaviors': ['backdoor_installation', 'data_exfiltration', 'credential_theft'],
                    'target_applications': ['production_systems', 'development_environments'],
                    'evasion_techniques': ['version_pinning_bypass', 'gradual_rollout'],
                    'supply_chain_indicators': [''],
                    'long_term_persistence': [''],
                    'steganographic_c2': [''],
                    'second_stage_payloads': ['']
                }
            }
            attacks.append(attack)
        
        return attacks
    
    async def generate_compromised_maintainer_attacks(self, count: int) -> List[Dict[str, Any]]:
        """Generate compromised maintainer attack scenarios"""
        attacks = []
        
        for i in range(count):
            ecosystem = random.choice(['python', 'javascript', 'java'])
            target_package = random.choice(self.high_value_targets[ecosystem])
            
            attack = {
                'name': f"compromised-{target_package}-{i}",
                'type': 'compromised_maintainer',
                'target_package': target_package,
                'ecosystem': ecosystem,
                'compromise_vector': random.choice([
                    'credential_stuffing',
                    'phishing_attack',
                    'social_engineering',
                    'insider_threat',
                    'account_takeover'
                ]),
                'maintainer_count': random.randint(1, 5),
                'metadata': {
                    'malicious_behaviors': ['account_compromise', 'code_injection', 'backdoor_installation'],
                    'target_applications': ['package_ecosystems', 'developer_environments'],
                    'evasion_techniques': ['legitimate_commits', 'gradual_introduction'],
                    'supply_chain_indicators': [''],
                    'advanced_persistence': [''],
                    'c2_communication': ['encrypted_channels'],
                    'anti_forensics': ['']
                }
            }
            attacks.append(attack)
        
        return attacks
    
    async def generate_build_system_compromise(self, count: int) -> List[Dict[str, Any]]:
        """Generate build system compromise scenarios"""
        attacks = []
        
        build_systems = [
            'jenkins', 'github_actions', 'gitlab_ci', 'azure_devops',
            'travis_ci', 'circleci', 'bamboo', 'teamcity'
        ]
        
        for i in range(count):
            build_system = random.choice(build_systems)
            
            attack = {
                'name': f"build-compromise-{build_system}-{i}",
                'type': 'build_system_compromise',
                'target_system': build_system,
                'compromise_vector': random.choice([
                    'credential_theft',
                    'infrastructure_vulnerability',
                    'supply_chain_attack',
                    'insider_access'
                ]),
                'affected_projects': random.randint(10, 1000),
                'metadata': {
                    'malicious_behaviors': ['build_manipulation', 'artifact_poisoning', 'signing_key_theft'],
                    'target_applications': ['ci_cd_systems', 'build_infrastructure'],
                    'evasion_techniques': ['legitimate_build_process', 'conditional_payload'],
                    'supply_chain_indicators': [''],
                    'destructive_behaviors': ['build_corruption'],
                    'long_term_persistence': [''],
                    'second_stage_payloads': ['']
                }
            }
            attacks.append(attack)
        
        return attacks
    
    async def generate_registry_compromise(self, count: int) -> List[Dict[str, Any]]:
        """Generate package registry compromise scenarios"""
        attacks = []
        
        registries = [
            {'name': 'pypi', 'ecosystem': 'python'},
            {'name': 'npm', 'ecosystem': 'javascript'},
            {'name': 'maven_central', 'ecosystem': 'java'},
            {'name': 'nuget', 'ecosystem': 'dotnet'},
            {'name': 'rubygems', 'ecosystem': 'ruby'}
        ]
        
        for i in range(count):
            registry = random.choice(registries)
            
            attack = {
                'name': f"registry-compromise-{registry['name']}-{i}",
                'type': 'registry_compromise',
                'target_registry': registry['name'],
                'ecosystem': registry['ecosystem'],
                'compromise_scope': random.choice(['partial', 'full', 'targeted']),
                'affected_packages': random.randint(100, 10000),
                'metadata': {
                    'malicious_behaviors': ['package_manipulation', 'metadata_poisoning', 'distribution_compromise'],
                    'target_applications': ['package_ecosystems', 'developer_tools'],
                    'evasion_techniques': ['legitimate_infrastructure', 'gradual_poisoning'],
                    'supply_chain_indicators': [''],
                    'destructive_behaviors': ['ecosystem_disruption'],
                    'critical_infrastructure_targeting': [''],
                    'second_stage_payloads': ['']
                }
            }
            attacks.append(attack)
        
        return attacks
    
    async def generate_enterprise_targeted_attacks(self, target_environment: str, count: int) -> List[Dict[str, Any]]:
        """Generate attacks specifically targeting enterprise environments"""
        if target_environment not in self.enterprise_environments:
            target_environment = random.choice(list(self.enterprise_environments.keys()))
        
        env_data = self.enterprise_environments[target_environment]
        attacks = []
        
        for i in range(count):
            target_package = random.choice(env_data['critical_packages'])
            
            attack = {
                'name': f"enterprise-{target_environment}-{target_package}-{i}",
                'type': 'enterprise_targeted_attack',
                'target_environment': target_environment,
                'target_package': target_package,
                'compliance_impact': env_data['compliance_requirements'],
                'risk_level': 'critical' if env_data['risk_tolerance'] == 'very_low' else 'high',
                'attack_sophistication': 'nation_state_level',
                'metadata': {
                    'malicious_behaviors': ['compliance_violation', 'data_exfiltration', 'system_compromise'],
                    'target_applications': [target_environment, 'enterprise_systems'],
                    'evasion_techniques': ['compliance_mimicking', 'audit_evasion'],
                    'supply_chain_indicators': [''],
                    'long_term_persistence': [''],
                    'advanced_persistence': [''],
                    'critical_infrastructure_targeting': [''],
                    'anti_forensics': ['']
                }
            }
            attacks.append(attack)
        
        return attacks
    
    async def generate_coordinated_campaign(self, campaign_name: str, count: int) -> List[Dict[str, Any]]:
        """Generate a coordinated supply chain attack campaign"""
        attacks = []
        
        # Select multiple attack vectors for the campaign
        attack_types = random.sample(list(self.attack_patterns.keys()), random.randint(2, 4))
        
        for i in range(count):
            attack_type = random.choice(attack_types)
            pattern = self.attack_patterns[attack_type]
            
            attack = {
                'name': f"{campaign_name}-{attack_type}-{i}",
                'type': 'coordinated_campaign',
                'campaign_name': campaign_name,
                'attack_pattern': attack_type,
                'campaign_phase': random.randint(1, 5),
                'coordination_level': 'high',
                'techniques': pattern['techniques'],
                'targets': pattern['targets'],
                'metadata': {
                    'malicious_behaviors': ['coordinated_attack', 'multi_vector_compromise'],
                    'target_applications': ['enterprise_ecosystems', 'critical_infrastructure'],
                    'evasion_techniques': ['campaign_coordination', 'timing_distribution'],
                    'supply_chain_indicators': [campaign_name],
                    'long_term_persistence': [''],
                    'advanced_persistence': [''],
                    'c2_communication': ['campaign_coordination'],
                    'second_stage_payloads': ['']
                }
            }
            attacks.append(attack)
        
        return attacks
    
    async def generate_zero_day_supply_chain(self, count: int) -> List[Dict[str, Any]]:
        """Generate supply chain attacks leveraging zero-day vulnerabilities"""
        attacks = []
        
        for i in range(count):
            ecosystem = random.choice(['python', 'javascript', 'java'])
            target_package = random.choice(self.high_value_targets[ecosystem])
            
            attack = {
                'name': f"zero-day-supply-{target_package}-{i}",
                'type': 'zero_day_supply_chain',
                'target_package': target_package,
                'ecosystem': ecosystem,
                'zero_day_type': random.choice([
                    'package_manager_vulnerability',
                    'build_tool_vulnerability',
                    'registry_vulnerability',
                    'signing_infrastructure_vulnerability'
                ]),
                'cvss_score': round(random.uniform(8.0, 10.0), 1),
                'metadata': {
                    'zero_day_arsenal': [''],
                    'supply_chain_indicators': [''],
                    'malicious_behaviors': ['zero_day_exploitation', 'supply_chain_compromise'],
                    'target_applications': ['package_ecosystems', 'build_systems'],
                    'evasion_techniques': ['zero_day_stealth', 'infrastructure_abuse'],
                    'advanced_persistence': [''],
                    'critical_infrastructure_targeting': ['']
                }
            }
            attacks.append(attack)
        
        return attacks