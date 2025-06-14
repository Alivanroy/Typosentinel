#!/usr/bin/env python3
"""
Dataset Generation for TypoSentinel ML Models

This script generates synthetic training datasets for testing and development
of the semantic similarity and malicious package classification models.
"""

import os
import json
import random
import string
from typing import List, Dict, Any
from datetime import datetime, timedelta
import argparse

class SyntheticDataGenerator:
    """Generate synthetic package data for training."""
    
    def __init__(self):
        # Popular package names for generating variants
        self.popular_packages = {
            'npm': [
                'react', 'vue', 'angular', 'lodash', 'express', 'axios', 'moment',
                'webpack', 'babel', 'typescript', 'eslint', 'jest', 'prettier',
                'jquery', 'bootstrap', 'socket.io', 'chalk', 'commander', 'inquirer',
                'fs-extra', 'glob', 'rimraf', 'mkdirp', 'yargs', 'dotenv'
            ],
            'pypi': [
                'requests', 'numpy', 'pandas', 'flask', 'django', 'tensorflow',
                'pytorch', 'scikit-learn', 'matplotlib', 'pillow', 'beautifulsoup4',
                'selenium', 'pytest', 'click', 'jinja2', 'sqlalchemy', 'redis',
                'celery', 'gunicorn', 'psycopg2', 'pymongo', 'boto3', 'pyyaml'
            ],
            'go': [
                'gin', 'mux', 'testify', 'logrus', 'cobra', 'viper', 'gorm',
                'redis', 'jwt-go', 'uuid', 'validator', 'zap', 'chi', 'echo'
            ]
        }
        
        # Common typosquatting techniques
        self.typo_techniques = [
            self._character_substitution,
            self._character_omission,
            self._character_insertion,
            self._character_transposition,
            self._hyphen_underscore_swap,
            self._domain_squatting,
            self._combosquatting
        ]
        
        # Suspicious keywords for malicious packages
        self.suspicious_keywords = [
            'bitcoin', 'crypto', 'wallet', 'mining', 'hack', 'crack',
            'password', 'steal', 'phish', 'malware', 'virus', 'trojan',
            'keylogger', 'backdoor', 'exploit', 'payload'
        ]
        
        # Generic/suspicious descriptions
        self.suspicious_descriptions = [
            'A simple utility package',
            'Helper functions for development',
            'Useful tools and utilities',
            'Development utilities',
            'Common helper functions',
            'Utility library',
            'Helper package',
            'Development tools'
        ]
        
        # Legitimate author names
        self.legitimate_authors = [
            'Facebook', 'Google', 'Microsoft', 'Netflix', 'Airbnb',
            'John Doe', 'Jane Smith', 'Alex Johnson', 'Sarah Wilson',
            'Mike Brown', 'Emily Davis', 'Chris Lee', 'Anna Taylor'
        ]
        
        # Suspicious author patterns
        self.suspicious_authors = [
            'user123', 'dev456', 'coder789', 'anonymous', 'unknown',
            'test_user', 'temp_dev', 'random_coder', 'fake_author'
        ]
    
    def _character_substitution(self, name: str) -> List[str]:
        """Generate variants using character substitution."""
        variants = []
        substitutions = {
            'o': ['0', 'ο'], '0': ['o', 'ο'], 'i': ['1', 'l', 'ι'], 
            '1': ['i', 'l', 'ι'], 'l': ['1', 'i', 'ι'], 'e': ['3', 'ε'],
            'a': ['@', 'α'], 's': ['$', 'ς'], 'g': ['9', 'γ'],
            'u': ['υ'], 'n': ['η'], 'r': ['ρ'], 'p': ['ρ']
        }
        
        for char, replacements in substitutions.items():
            if char in name.lower():
                for replacement in replacements:
                    variant = name.lower().replace(char, replacement, 1)
                    variants.append(variant)
        
        return variants[:3]  # Limit variants
    
    def _character_omission(self, name: str) -> List[str]:
        """Generate variants by omitting characters."""
        variants = []
        if len(name) > 3:
            for i in range(1, len(name) - 1):
                variant = name[:i] + name[i+1:]
                variants.append(variant)
        return variants[:2]
    
    def _character_insertion(self, name: str) -> List[str]:
        """Generate variants by inserting characters."""
        variants = []
        chars_to_insert = ['s', 'e', 'r', 't', 'a']
        
        for i in range(len(name) + 1):
            for char in chars_to_insert[:2]:  # Limit insertions
                variant = name[:i] + char + name[i:]
                variants.append(variant)
        
        return variants[:3]
    
    def _character_transposition(self, name: str) -> List[str]:
        """Generate variants by swapping adjacent characters."""
        variants = []
        for i in range(len(name) - 1):
            chars = list(name)
            chars[i], chars[i + 1] = chars[i + 1], chars[i]
            variants.append(''.join(chars))
        return variants[:2]
    
    def _hyphen_underscore_swap(self, name: str) -> List[str]:
        """Generate variants by swapping hyphens and underscores."""
        variants = []
        if '-' in name:
            variants.append(name.replace('-', '_'))
            variants.append(name.replace('-', ''))
        if '_' in name:
            variants.append(name.replace('_', '-'))
            variants.append(name.replace('_', ''))
        return variants
    
    def _domain_squatting(self, name: str) -> List[str]:
        """Generate variants using domain squatting techniques."""
        variants = []
        # Add common prefixes/suffixes
        prefixes = ['lib', 'node', 'js', 'py', 'go']
        suffixes = ['js', 'lib', 'util', 'utils', 'tool', 'tools']
        
        for prefix in prefixes[:2]:
            variants.append(f"{prefix}-{name}")
            variants.append(f"{prefix}{name}")
        
        for suffix in suffixes[:2]:
            variants.append(f"{name}-{suffix}")
            variants.append(f"{name}{suffix}")
        
        return variants[:4]
    
    def _combosquatting(self, name: str) -> List[str]:
        """Generate variants by combining with common words."""
        variants = []
        common_words = ['core', 'base', 'main', 'new', 'old', 'alt']
        
        for word in common_words[:3]:
            variants.append(f"{name}{word}")
            variants.append(f"{word}{name}")
        
        return variants[:4]
    
    def generate_typosquatting_variants(self, package_name: str, count: int = 10) -> List[str]:
        """Generate typosquatting variants using multiple techniques."""
        all_variants = []
        
        for technique in self.typo_techniques:
            variants = technique(package_name)
            all_variants.extend(variants)
        
        # Remove duplicates and original name
        unique_variants = list(set(all_variants))
        if package_name in unique_variants:
            unique_variants.remove(package_name)
        
        return unique_variants[:count]
    
    def generate_random_package_name(self, length: int = None) -> str:
        """Generate a random package name."""
        if length is None:
            length = random.randint(5, 15)
        
        # Mix of consonants and vowels for more realistic names
        consonants = 'bcdfghjklmnpqrstvwxyz'
        vowels = 'aeiou'
        
        name = ''
        for i in range(length):
            if i % 2 == 0:
                name += random.choice(consonants)
            else:
                name += random.choice(vowels)
        
        return name
    
    def create_package_data(self, name: str, registry: str, is_malicious: bool = False) -> Dict[str, Any]:
        """Create synthetic package metadata."""
        now = datetime.now()
        
        # Generate realistic creation and update dates
        if is_malicious:
            # Malicious packages tend to be newer
            creation_days_ago = random.randint(1, 90)
            update_days_ago = random.randint(0, creation_days_ago)
            downloads = random.randint(0, 1000)  # Lower downloads
            author = random.choice(self.suspicious_authors)
            description = random.choice(self.suspicious_descriptions)
            
            # Sometimes add suspicious keywords
            if random.random() < 0.3:
                description += f" with {random.choice(self.suspicious_keywords)}"
        else:
            # Legitimate packages have longer history
            creation_days_ago = random.randint(30, 1095)  # 1 month to 3 years
            update_days_ago = random.randint(0, 30)
            downloads = random.randint(1000, 1000000)  # Higher downloads
            author = random.choice(self.legitimate_authors)
            description = f"A {registry} package for {name} functionality"
        
        creation_date = (now - timedelta(days=creation_days_ago)).isoformat()
        last_updated = (now - timedelta(days=update_days_ago)).isoformat()
        
        # Generate dependencies
        num_deps = random.randint(0, 10) if not is_malicious else random.randint(0, 3)
        dependencies = []
        if num_deps > 0:
            available_deps = self.popular_packages.get(registry, [])
            dependencies = random.sample(available_deps, min(num_deps, len(available_deps)))
        
        # Generate keywords
        keywords = []
        if random.random() < 0.7:  # 70% chance of having keywords
            keyword_pool = ['utility', 'helper', 'tool', 'library', 'framework', 'api']
            if is_malicious and random.random() < 0.2:
                keyword_pool.extend(self.suspicious_keywords[:3])
            keywords = random.sample(keyword_pool, random.randint(1, 4))
        
        return {
            'name': name,
            'registry': registry,
            'version': f"{random.randint(0, 5)}.{random.randint(0, 20)}.{random.randint(0, 10)}",
            'description': description,
            'author': author,
            'downloads': downloads,
            'creation_date': creation_date,
            'last_updated': last_updated,
            'dependencies': dependencies,
            'keywords': keywords,
            'license': random.choice(['MIT', 'Apache-2.0', 'GPL-3.0', 'BSD-3-Clause', '']),
            'homepage': f"https://github.com/{author.lower().replace(' ', '')}/{name}" if random.random() < 0.6 else '',
            'repository': f"https://github.com/{author.lower().replace(' ', '')}/{name}" if random.random() < 0.8 else '',
            'size': random.randint(1000, 100000)
        }
    
    def generate_dataset(self, num_packages: int = 1000, malicious_ratio: float = 0.3) -> tuple[List[Dict], List[int]]:
        """Generate a complete synthetic dataset."""
        packages = []
        labels = []
        
        num_malicious = int(num_packages * malicious_ratio)
        num_benign = num_packages - num_malicious
        
        print(f"Generating {num_packages} packages ({num_benign} benign, {num_malicious} malicious)...")
        
        # Generate benign packages
        for registry, package_list in self.popular_packages.items():
            registry_count = num_benign // len(self.popular_packages)
            
            # Add popular packages
            for i, package_name in enumerate(package_list):
                if len([p for p in packages if not labels[packages.index(p)] if p in packages]) >= registry_count:
                    break
                
                package_data = self.create_package_data(package_name, registry, is_malicious=False)
                packages.append(package_data)
                labels.append(0)  # Benign
            
            # Add some random benign packages
            remaining = registry_count - len([p for p in packages[-len(package_list):]])
            for _ in range(remaining):
                random_name = self.generate_random_package_name()
                package_data = self.create_package_data(random_name, registry, is_malicious=False)
                packages.append(package_data)
                labels.append(0)  # Benign
        
        # Generate malicious packages (typosquatting variants)
        malicious_generated = 0
        for registry, package_list in self.popular_packages.items():
            if malicious_generated >= num_malicious:
                break
            
            for package_name in package_list:
                if malicious_generated >= num_malicious:
                    break
                
                # Generate typosquatting variants
                variants = self.generate_typosquatting_variants(package_name, 3)
                for variant in variants:
                    if malicious_generated >= num_malicious:
                        break
                    
                    package_data = self.create_package_data(variant, registry, is_malicious=True)
                    packages.append(package_data)
                    labels.append(1)  # Malicious
                    malicious_generated += 1
        
        # Generate additional random malicious packages
        while malicious_generated < num_malicious:
            registry = random.choice(list(self.popular_packages.keys()))
            random_name = self.generate_random_package_name()
            
            # Make it more obviously malicious
            if random.random() < 0.5:
                random_name += random.choice(['hack', 'crack', 'steal', 'fake'])
            
            package_data = self.create_package_data(random_name, registry, is_malicious=True)
            packages.append(package_data)
            labels.append(1)  # Malicious
            malicious_generated += 1
        
        # Shuffle the dataset
        combined = list(zip(packages, labels))
        random.shuffle(combined)
        packages, labels = zip(*combined)
        
        print(f"Generated {len(packages)} packages ({labels.count(0)} benign, {labels.count(1)} malicious)")
        return list(packages), list(labels)
    
    def save_dataset(self, packages: List[Dict], labels: List[int], filename: str):
        """Save dataset to JSON file."""
        dataset = {
            'metadata': {
                'generated_at': datetime.now().isoformat(),
                'total_packages': len(packages),
                'benign_packages': labels.count(0),
                'malicious_packages': labels.count(1),
                'malicious_ratio': labels.count(1) / len(labels)
            },
            'packages': packages,
            'labels': labels
        }
        
        with open(filename, 'w') as f:
            json.dump(dataset, f, indent=2)
        
        print(f"Dataset saved to {filename}")
    
    def load_dataset(self, filename: str) -> tuple[List[Dict], List[int]]:
        """Load dataset from JSON file."""
        with open(filename, 'r') as f:
            dataset = json.load(f)
        
        print(f"Loaded dataset with {len(dataset['packages'])} packages")
        print(f"Metadata: {dataset['metadata']}")
        
        return dataset['packages'], dataset['labels']

def main():
    """Main function for dataset generation."""
    parser = argparse.ArgumentParser(description='Generate synthetic training dataset for TypoSentinel')
    parser.add_argument('--num-packages', type=int, default=1000, help='Number of packages to generate')
    parser.add_argument('--malicious-ratio', type=float, default=0.3, help='Ratio of malicious packages (0.0-1.0)')
    parser.add_argument('--output', type=str, default='training_dataset.json', help='Output filename')
    parser.add_argument('--seed', type=int, help='Random seed for reproducibility')
    
    args = parser.parse_args()
    
    if args.seed:
        random.seed(args.seed)
        print(f"Using random seed: {args.seed}")
    
    # Generate dataset
    generator = SyntheticDataGenerator()
    packages, labels = generator.generate_dataset(
        num_packages=args.num_packages,
        malicious_ratio=args.malicious_ratio
    )
    
    # Save dataset
    generator.save_dataset(packages, labels, args.output)
    
    # Print some statistics
    print("\nDataset Statistics:")
    print(f"Total packages: {len(packages)}")
    print(f"Benign packages: {labels.count(0)} ({labels.count(0)/len(labels)*100:.1f}%)")
    print(f"Malicious packages: {labels.count(1)} ({labels.count(1)/len(labels)*100:.1f}%)")
    
    # Show some examples
    print("\nExample packages:")
    for i in range(min(5, len(packages))):
        pkg = packages[i]
        label = "Malicious" if labels[i] else "Benign"
        print(f"  {pkg['name']} ({pkg['registry']}) - {label}")

if __name__ == "__main__":
    main()