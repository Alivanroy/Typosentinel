#!/usr/bin/env python3
"""
Advanced Typosquatting Generator
Generates realistic typosquatting packages with various sophistication levels
"""

import random
import string
import asyncio
from typing import List, Dict, Any
from faker import Faker
import json

class TyposquattingGenerator:
    """Generates sophisticated typosquatting attacks"""
    
    def __init__(self):
        self.fake = Faker()
        
        # Popular package names for typosquatting
        self.popular_packages = {
            'python': [
                'requests', 'numpy', 'pandas', 'django', 'flask', 'tensorflow',
                'pytorch', 'scikit-learn', 'matplotlib', 'seaborn', 'pillow',
                'beautifulsoup4', 'selenium', 'scrapy', 'fastapi', 'pydantic',
                'sqlalchemy', 'alembic', 'celery', 'redis', 'boto3', 'aws-cli'
            ],
            'javascript': [
                'react', 'angular', 'vue', 'express', 'lodash', 'moment',
                'axios', 'webpack', 'babel', 'eslint', 'prettier', 'jest',
                'mocha', 'chai', 'sinon', 'jquery', 'bootstrap', 'socket.io'
            ],
            'java': [
                'spring-boot', 'hibernate', 'jackson', 'junit', 'mockito',
                'slf4j', 'logback', 'apache-commons', 'guava', 'gson'
            ]
        }
        
        # Typosquatting techniques
        self.typo_techniques = [
            'character_substitution',
            'character_omission',
            'character_insertion',
            'character_transposition',
            'homoglyph_substitution',
            'subdomain_squatting',
            'combosquatting',
            'bitsquatting',
            'hyphenation',
            'pluralization'
        ]
        
        # Homoglyphs for sophisticated attacks
        self.homoglyphs = {
            'a': ['а', 'ɑ', 'α'],  # Cyrillic and Greek
            'e': ['е', 'ε'],
            'o': ['о', 'ο', '0'],
            'p': ['р', 'ρ'],
            'c': ['с', 'ϲ'],
            'x': ['х', 'χ'],
            'y': ['у', 'γ'],
            'i': ['і', 'ι', '1', 'l'],
            'n': ['п'],
            'm': ['м'],
            'h': ['һ'],
            'k': ['κ'],
            'v': ['ν'],
            'w': ['ω'],
            'z': ['ζ']
        }
    
    async def generate_basic_typos(self, count: int) -> List[Dict[str, Any]]:
        """Generate basic typosquatting packages"""
        packages = []
        
        for _ in range(count):
            original = random.choice(self.popular_packages['python'])
            technique = random.choice(self.typo_techniques[:4])  # Basic techniques only
            
            typo_name = self._apply_typo_technique(original, technique)
            
            package = {
                'name': typo_name,
                'original_target': original,
                'technique': technique,
                'registry': 'pypi',
                'version': f"{random.randint(1,5)}.{random.randint(0,9)}.{random.randint(0,9)}",
                'sophistication_level': 'basic',
                'metadata': {
                    'malicious_behaviors': ['credential_theft'],
                    'target_applications': ['development_tools'],
                    'evasion_techniques': []
                }
            }
            packages.append(package)
        
        return packages
    
    async def generate_advanced_typos(self, count: int) -> List[Dict[str, Any]]:
        """Generate advanced typosquatting packages with evasion techniques"""
        packages = []
        
        for _ in range(count):
            original = random.choice(self.popular_packages['python'])
            technique = random.choice(self.typo_techniques)
            
            typo_name = self._apply_typo_technique(original, technique)
            
            package = {
                'name': typo_name,
                'original_target': original,
                'technique': technique,
                'registry': random.choice(['pypi', 'npm', 'maven']),
                'version': f"{random.randint(1,5)}.{random.randint(0,9)}.{random.randint(0,9)}",
                'sophistication_level': 'advanced',
                'metadata': {
                    'malicious_behaviors': ['credential_theft', 'data_exfiltration'],
                    'target_applications': ['development_tools', 'ci_cd_systems'],
                    'evasion_techniques': ['obfuscation', 'delayed_execution'],
                    'backdoor_behaviors': ['remote_access'],
                    'c2_communication': ['encrypted_channels']
                }
            }
            packages.append(package)
        
        return packages
    
    async def generate_sophisticated_typos(self, count: int) -> List[Dict[str, Any]]:
        """Generate sophisticated typosquatting packages with AI-like generation"""
        packages = []
        
        for _ in range(count):
            original = random.choice(self.popular_packages['python'])
            
            # Use multiple techniques for sophistication
            techniques = random.sample(self.typo_techniques, random.randint(2, 4))
            typo_name = original
            
            for technique in techniques:
                typo_name = self._apply_typo_technique(typo_name, technique)
            
            package = {
                'name': typo_name,
                'original_target': original,
                'techniques': techniques,
                'registry': random.choice(['pypi', 'npm', 'maven']),
                'version': f"{random.randint(1,5)}.{random.randint(0,9)}.{random.randint(0,9)}",
                'sophistication_level': 'sophisticated',
                'metadata': {
                    'malicious_behaviors': ['credential_theft', 'data_exfiltration', 'system_compromise'],
                    'target_applications': ['development_tools', 'ci_cd_systems', 'production_systems'],
                    'evasion_techniques': ['obfuscation', 'delayed_execution', 'anti_analysis'],
                    'backdoor_behaviors': ['remote_access', 'persistence'],
                    'c2_communication': ['encrypted_channels', 'domain_generation'],
                    'long_term_persistence': [''],
                    'steganographic_c2': [''],
                    'anti_forensics': ['']
                }
            }
            packages.append(package)
        
        return packages
    
    def _apply_typo_technique(self, original: str, technique: str) -> str:
        """Apply a specific typosquatting technique to a package name"""
        if technique == 'character_substitution':
            return self._character_substitution(original)
        elif technique == 'character_omission':
            return self._character_omission(original)
        elif technique == 'character_insertion':
            return self._character_insertion(original)
        elif technique == 'character_transposition':
            return self._character_transposition(original)
        elif technique == 'homoglyph_substitution':
            return self._homoglyph_substitution(original)
        elif technique == 'subdomain_squatting':
            return self._subdomain_squatting(original)
        elif technique == 'combosquatting':
            return self._combosquatting(original)
        elif technique == 'bitsquatting':
            return self._bitsquatting(original)
        elif technique == 'hyphenation':
            return self._hyphenation(original)
        elif technique == 'pluralization':
            return self._pluralization(original)
        else:
            return original
    
    def _character_substitution(self, name: str) -> str:
        """Substitute a random character"""
        if len(name) < 2:
            return name
        
        pos = random.randint(0, len(name) - 1)
        new_char = random.choice(string.ascii_lowercase)
        return name[:pos] + new_char + name[pos+1:]
    
    def _character_omission(self, name: str) -> str:
        """Omit a random character"""
        if len(name) < 3:
            return name
        
        pos = random.randint(1, len(name) - 2)  # Don't remove first or last
        return name[:pos] + name[pos+1:]
    
    def _character_insertion(self, name: str) -> str:
        """Insert a random character"""
        pos = random.randint(0, len(name))
        new_char = random.choice(string.ascii_lowercase)
        return name[:pos] + new_char + name[pos:]
    
    def _character_transposition(self, name: str) -> str:
        """Transpose two adjacent characters"""
        if len(name) < 2:
            return name
        
        pos = random.randint(0, len(name) - 2)
        chars = list(name)
        chars[pos], chars[pos + 1] = chars[pos + 1], chars[pos]
        return ''.join(chars)
    
    def _homoglyph_substitution(self, name: str) -> str:
        """Substitute characters with homoglyphs"""
        result = []
        for char in name:
            if char in self.homoglyphs and random.random() < 0.3:
                result.append(random.choice(self.homoglyphs[char]))
            else:
                result.append(char)
        return ''.join(result)
    
    def _subdomain_squatting(self, name: str) -> str:
        """Create subdomain-like variations"""
        prefixes = ['lib', 'py', 'js', 'node', 'api', 'core', 'util']
        suffixes = ['lib', 'py', 'js', 'api', 'core', 'util', 'tools']
        
        if random.random() < 0.5:
            return random.choice(prefixes) + '-' + name
        else:
            return name + '-' + random.choice(suffixes)
    
    def _combosquatting(self, name: str) -> str:
        """Combine with common words"""
        words = ['secure', 'safe', 'fast', 'easy', 'simple', 'advanced', 'pro', 'plus']
        word = random.choice(words)
        
        if random.random() < 0.5:
            return word + name
        else:
            return name + word
    
    def _bitsquatting(self, name: str) -> str:
        """Simulate bit-flipping errors"""
        if not name:
            return name
        
        pos = random.randint(0, len(name) - 1)
        char = name[pos]
        
        # Simple bit-flip simulation
        ascii_val = ord(char)
        bit_pos = random.randint(0, 6)  # 7 bits for ASCII
        flipped_val = ascii_val ^ (1 << bit_pos)
        
        # Ensure it's still a valid character
        if 32 <= flipped_val <= 126:
            new_char = chr(flipped_val)
            return name[:pos] + new_char + name[pos+1:]
        
        return name
    
    def _hyphenation(self, name: str) -> str:
        """Add hyphens in various positions"""
        if len(name) < 3:
            return name
        
        # Insert hyphen at random position (not at start or end)
        pos = random.randint(1, len(name) - 1)
        return name[:pos] + '-' + name[pos:]
    
    def _pluralization(self, name: str) -> str:
        """Add plural forms or variations"""
        suffixes = ['s', 'es', 'ies', 'er', 'ed', 'ing']
        return name + random.choice(suffixes)
    
    async def generate_campaign_packages(self, campaign_name: str, count: int) -> List[Dict[str, Any]]:
        """Generate a coordinated campaign of typosquatting packages"""
        packages = []
        
        # Select target packages for this campaign
        targets = random.sample(self.popular_packages['python'], min(count, len(self.popular_packages['python'])))
        
        for i, target in enumerate(targets):
            # Use consistent techniques within a campaign
            technique = random.choice(self.typo_techniques)
            typo_name = self._apply_typo_technique(target, technique)
            
            package = {
                'name': typo_name,
                'original_target': target,
                'technique': technique,
                'campaign': campaign_name,
                'campaign_sequence': i + 1,
                'registry': 'pypi',
                'version': f"1.{i}.0",
                'sophistication_level': 'campaign',
                'metadata': {
                    'malicious_behaviors': ['credential_theft', 'data_exfiltration'],
                    'target_applications': ['development_tools'],
                    'campaign_indicators': [campaign_name],
                    'c2_communication': ['encrypted_channels'],
                    'long_term_persistence': ['']
                }
            }
            packages.append(package)
        
        return packages