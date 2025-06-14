#!/usr/bin/env python3
"""
Training Script for TypoSentinel ML Models

This script trains both the semantic similarity model and malicious package classifier
using real package data from various registries.
"""

import os
import sys
import json
import logging
import asyncio
import aiohttp
from typing import List, Dict, Any, Tuple
from datetime import datetime, timedelta
import random
import argparse

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from models.semantic_similarity import SemanticSimilarityModel, PackageFeatures as SimilarityPackageFeatures
from models.malicious_classifier import MaliciousPackageClassifier, PackageFeatures as ClassifierPackageFeatures

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class DataCollector:
    """Collect training data from package registries."""
    
    def __init__(self):
        self.session = None
        self.known_malicious = [
            # Known malicious packages for training
            'event-stream', 'eslint-scope', 'getcookies', 'rc',
            'flatmap-stream', 'crossenv', 'python3-dateutil',
            'jeIlyfish', 'urllib4', 'diango', 'djago',
            'python-dateutil', 'setup-tools', 'pip-tools'
        ]
        
        self.popular_packages = {
            'npm': [
                'react', 'lodash', 'express', 'axios', 'moment',
                'webpack', 'babel-core', 'typescript', 'eslint',
                'jest', 'prettier', 'vue', 'angular', 'jquery'
            ],
            'pypi': [
                'requests', 'numpy', 'pandas', 'flask', 'django',
                'tensorflow', 'pytorch', 'scikit-learn', 'matplotlib',
                'pillow', 'beautifulsoup4', 'selenium', 'pytest'
            ],
            'go': [
                'github.com/gin-gonic/gin', 'github.com/gorilla/mux',
                'github.com/stretchr/testify', 'github.com/sirupsen/logrus',
                'github.com/spf13/cobra', 'github.com/golang/protobuf'
            ]
        }
    
    async def __aenter__(self):
        self.session = aiohttp.ClientSession()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()
    
    async def fetch_npm_package(self, package_name: str) -> Dict[str, Any]:
        """Fetch package metadata from npm registry."""
        try:
            url = f"https://registry.npmjs.org/{package_name}"
            async with self.session.get(url) as response:
                if response.status == 200:
                    data = await response.json()
                    latest_version = data.get('dist-tags', {}).get('latest', '')
                    version_data = data.get('versions', {}).get(latest_version, {})
                    
                    return {
                        'name': package_name,
                        'registry': 'npm',
                        'version': latest_version,
                        'description': data.get('description', ''),
                        'author': self._extract_author(data.get('author', {})),
                        'downloads': await self._get_npm_downloads(package_name),
                        'creation_date': data.get('time', {}).get('created', ''),
                        'last_updated': data.get('time', {}).get('modified', ''),
                        'dependencies': list(version_data.get('dependencies', {}).keys()),
                        'keywords': data.get('keywords', []),
                        'license': data.get('license', ''),
                        'homepage': data.get('homepage', ''),
                        'repository': self._extract_repo_url(data.get('repository', {})),
                        'size': 0  # Would need additional API call
                    }
        except Exception as e:
            logger.error(f"Error fetching npm package {package_name}: {e}")
            return None
    
    async def fetch_pypi_package(self, package_name: str) -> Dict[str, Any]:
        """Fetch package metadata from PyPI."""
        try:
            url = f"https://pypi.org/pypi/{package_name}/json"
            async with self.session.get(url) as response:
                if response.status == 200:
                    data = await response.json()
                    info = data.get('info', {})
                    
                    return {
                        'name': package_name,
                        'registry': 'pypi',
                        'version': info.get('version', ''),
                        'description': info.get('summary', ''),
                        'author': info.get('author', ''),
                        'downloads': 0,  # PyPI doesn't provide download stats in this API
                        'creation_date': '',  # Not available in this API
                        'last_updated': '',
                        'dependencies': [],  # Would need to parse requirements
                        'keywords': info.get('keywords', '').split(',') if info.get('keywords') else [],
                        'license': info.get('license', ''),
                        'homepage': info.get('home_page', ''),
                        'repository': info.get('project_url', ''),
                        'size': 0
                    }
        except Exception as e:
            logger.error(f"Error fetching PyPI package {package_name}: {e}")
            return None
    
    async def _get_npm_downloads(self, package_name: str) -> int:
        """Get npm package download count."""
        try:
            url = f"https://api.npmjs.org/downloads/point/last-month/{package_name}"
            async with self.session.get(url) as response:
                if response.status == 200:
                    data = await response.json()
                    return data.get('downloads', 0)
        except Exception:
            pass
        return 0
    
    def _extract_author(self, author_data) -> str:
        """Extract author name from various formats."""
        if isinstance(author_data, str):
            return author_data
        elif isinstance(author_data, dict):
            return author_data.get('name', '')
        return ''
    
    def _extract_repo_url(self, repo_data) -> str:
        """Extract repository URL from various formats."""
        if isinstance(repo_data, str):
            return repo_data
        elif isinstance(repo_data, dict):
            return repo_data.get('url', '')
        return ''
    
    def generate_typosquatting_variants(self, package_name: str, count: int = 5) -> List[str]:
        """Generate typosquatting variants of a package name."""
        variants = []
        
        # Character substitution
        substitutions = {
            'o': '0', '0': 'o', 'i': '1', '1': 'i', 'l': '1',
            'e': '3', 'a': '@', 's': '$', 'g': '9'
        }
        
        for char, replacement in substitutions.items():
            if char in package_name and len(variants) < count:
                variant = package_name.replace(char, replacement, 1)
                variants.append(variant)
        
        # Character omission
        if len(package_name) > 3 and len(variants) < count:
            for i in range(1, len(package_name) - 1):
                variant = package_name[:i] + package_name[i+1:]
                variants.append(variant)
                if len(variants) >= count:
                    break
        
        # Character addition
        if len(variants) < count:
            for i in range(len(package_name)):
                variant = package_name[:i] + package_name[i] + package_name[i:]
                variants.append(variant)
                if len(variants) >= count:
                    break
        
        # Hyphen/underscore variations
        if '-' in package_name and len(variants) < count:
            variants.append(package_name.replace('-', '_'))
        if '_' in package_name and len(variants) < count:
            variants.append(package_name.replace('_', '-'))
        
        return variants[:count]
    
    async def collect_training_data(self, num_packages: int = 1000) -> Tuple[List[Dict], List[int]]:
        """Collect training data for malicious package classification."""
        packages = []
        labels = []  # 0 = benign, 1 = malicious
        
        logger.info(f"Collecting training data for {num_packages} packages...")
        
        # Collect popular packages (benign)
        benign_count = 0
        for registry, package_list in self.popular_packages.items():
            for package_name in package_list:
                if benign_count >= num_packages // 2:
                    break
                
                if registry == 'npm':
                    package_data = await self.fetch_npm_package(package_name)
                elif registry == 'pypi':
                    package_data = await self.fetch_pypi_package(package_name)
                else:
                    continue  # Skip Go packages for now
                
                if package_data:
                    packages.append(package_data)
                    labels.append(0)  # Benign
                    benign_count += 1
                
                # Add some delay to be respectful to APIs
                await asyncio.sleep(0.1)
        
        # Generate typosquatting variants (potentially malicious)
        malicious_count = 0
        for registry, package_list in self.popular_packages.items():
            for package_name in package_list[:10]:  # Use subset for variants
                if malicious_count >= num_packages // 4:
                    break
                
                variants = self.generate_typosquatting_variants(package_name, 3)
                for variant in variants:
                    if malicious_count >= num_packages // 4:
                        break
                    
                    # Create synthetic malicious package data
                    package_data = {
                        'name': variant,
                        'registry': registry,
                        'version': '1.0.0',
                        'description': f'A {package_name} package',  # Generic description
                        'author': 'unknown',
                        'downloads': random.randint(0, 100),  # Low downloads
                        'creation_date': (datetime.now() - timedelta(days=random.randint(1, 30))).isoformat(),
                        'last_updated': (datetime.now() - timedelta(days=random.randint(1, 10))).isoformat(),
                        'dependencies': [],
                        'keywords': [],
                        'license': '',
                        'homepage': '',
                        'repository': '',
                        'size': random.randint(1000, 10000)
                    }
                    
                    packages.append(package_data)
                    labels.append(1)  # Malicious
                    malicious_count += 1
        
        # Add known malicious packages
        for package_name in self.known_malicious:
            if len(packages) >= num_packages:
                break
            
            # Try to fetch real data, otherwise create synthetic
            package_data = await self.fetch_npm_package(package_name)
            if not package_data:
                package_data = {
                    'name': package_name,
                    'registry': 'npm',
                    'version': '1.0.0',
                    'description': 'Malicious package',
                    'author': 'unknown',
                    'downloads': 0,
                    'creation_date': (datetime.now() - timedelta(days=365)).isoformat(),
                    'last_updated': (datetime.now() - timedelta(days=300)).isoformat(),
                    'dependencies': [],
                    'keywords': [],
                    'license': '',
                    'homepage': '',
                    'repository': '',
                    'size': 5000
                }
            
            packages.append(package_data)
            labels.append(1)  # Malicious
        
        logger.info(f"Collected {len(packages)} packages ({labels.count(0)} benign, {labels.count(1)} malicious)")
        return packages, labels

class ModelTrainer:
    """Train and evaluate ML models."""
    
    def __init__(self, model_dir: str = "models"):
        self.model_dir = model_dir
        os.makedirs(model_dir, exist_ok=True)
    
    def train_semantic_similarity(self, packages: List[Dict]) -> SemanticSimilarityModel:
        """Train the semantic similarity model."""
        logger.info("Training semantic similarity model...")
        
        # Convert to PackageFeatures
        package_features = []
        for pkg_data in packages:
            features = SimilarityPackageFeatures(
                name=pkg_data['name'],
                registry=pkg_data['registry'],
                version=pkg_data.get('version', ''),
                description=pkg_data.get('description', ''),
                author=pkg_data.get('author', ''),
                downloads=pkg_data.get('downloads', 0),
                creation_date=pkg_data.get('creation_date', ''),
                last_updated=pkg_data.get('last_updated', ''),
                dependencies=pkg_data.get('dependencies', []),
                keywords=pkg_data.get('keywords', []),
                license=pkg_data.get('license', ''),
                homepage=pkg_data.get('homepage', ''),
                repository=pkg_data.get('repository', ''),
                size=pkg_data.get('size', 0)
            )
            package_features.append(features)
        
        # Initialize and train model
        index_path = os.path.join(self.model_dir, "faiss_index.bin")
        embeddings_path = os.path.join(self.model_dir, "embeddings.pkl")
        model = SemanticSimilarityModel(index_path=index_path, embeddings_path=embeddings_path)
        model.add_packages(package_features)
        
        logger.info(f"Semantic similarity model trained with {len(package_features)} packages")
        return model
    
    def train_malicious_classifier(self, packages: List[Dict], labels: List[int]) -> MaliciousPackageClassifier:
        """Train the malicious package classifier."""
        logger.info("Training malicious package classifier...")
        
        # Convert to PackageFeatures
        package_features = []
        for pkg_data in packages:
            features = ClassifierPackageFeatures(
                name=pkg_data['name'],
                registry=pkg_data['registry'],
                version=pkg_data.get('version', ''),
                description=pkg_data.get('description', ''),
                author=pkg_data.get('author', ''),
                downloads=pkg_data.get('downloads', 0),
                creation_date=pkg_data.get('creation_date', ''),
                last_updated=pkg_data.get('last_updated', ''),
                dependencies=pkg_data.get('dependencies', []),
                keywords=pkg_data.get('keywords', []),
                license=pkg_data.get('license', ''),
                homepage=pkg_data.get('homepage', ''),
                repository=pkg_data.get('repository', ''),
                size=pkg_data.get('size', 0)
            )
            package_features.append(features)
        
        # Initialize and train model
        classifier = MaliciousPackageClassifier(model_dir=self.model_dir)
        classifier.train(package_features, labels)
        
        logger.info(f"Malicious classifier trained with {len(package_features)} packages")
        return classifier
    
    def evaluate_models(self, similarity_model: SemanticSimilarityModel, 
                       classifier: MaliciousPackageClassifier,
                       test_packages: List[Dict], test_labels: List[int]):
        """Evaluate trained models."""
        logger.info("Evaluating models...")
        
        # Test semantic similarity
        logger.info("Testing semantic similarity...")
        test_cases = [
            ('react', ['preact', 'react-dom', 'vue']),
            ('lodash', ['underscore', 'ramda', 'jquery']),
            ('express', ['koa', 'fastify', 'hapi'])
        ]
        
        for package_name, expected_similar in test_cases:
            similar = similarity_model.find_similar(package_name, top_k=5)
            logger.info(f"Similar to '{package_name}': {[name for name, score in similar]}")
        
        # Test malicious classifier
        logger.info("Testing malicious classifier...")
        correct_predictions = 0
        
        for i, pkg_data in enumerate(test_packages[:50]):  # Test subset
            features = ClassifierPackageFeatures(
                name=pkg_data['name'],
                registry=pkg_data['registry'],
                version=pkg_data.get('version', ''),
                description=pkg_data.get('description', ''),
                author=pkg_data.get('author', ''),
                downloads=pkg_data.get('downloads', 0),
                creation_date=pkg_data.get('creation_date', ''),
                last_updated=pkg_data.get('last_updated', ''),
                dependencies=pkg_data.get('dependencies', []),
                keywords=pkg_data.get('keywords', []),
                license=pkg_data.get('license', ''),
                homepage=pkg_data.get('homepage', ''),
                repository=pkg_data.get('repository', ''),
                size=pkg_data.get('size', 0)
            )
            
            result = classifier.predict(features)
            predicted = 1 if result['is_malicious'] else 0
            actual = test_labels[i]
            
            if predicted == actual:
                correct_predictions += 1
            
            if i < 10:  # Show first 10 predictions
                logger.info(f"Package: {pkg_data['name']}, Predicted: {predicted}, Actual: {actual}, Score: {result['score']:.3f}")
        
        accuracy = correct_predictions / min(50, len(test_packages))
        logger.info(f"Classifier accuracy on test set: {accuracy:.3f}")

async def main():
    """Main training function."""
    parser = argparse.ArgumentParser(description='Train TypoSentinel ML models')
    parser.add_argument('--num-packages', type=int, default=500, help='Number of packages to collect for training')
    parser.add_argument('--model-dir', type=str, default='models', help='Directory to save models')
    parser.add_argument('--data-file', type=str, help='Load training data from file instead of collecting')
    parser.add_argument('--save-data', type=str, help='Save collected training data to file')
    
    args = parser.parse_args()
    
    # Collect or load training data
    if args.data_file and os.path.exists(args.data_file):
        logger.info(f"Loading training data from {args.data_file}")
        with open(args.data_file, 'r') as f:
            data = json.load(f)
            packages = data['packages']
            labels = data['labels']
    else:
        async with DataCollector() as collector:
            packages, labels = await collector.collect_training_data(args.num_packages)
        
        # Save data if requested
        if args.save_data:
            logger.info(f"Saving training data to {args.save_data}")
            with open(args.save_data, 'w') as f:
                json.dump({'packages': packages, 'labels': labels}, f, indent=2)
    
    # Split data for training and testing
    split_idx = int(len(packages) * 0.8)
    train_packages = packages[:split_idx]
    train_labels = labels[:split_idx]
    test_packages = packages[split_idx:]
    test_labels = labels[split_idx:]
    
    # Train models
    trainer = ModelTrainer(args.model_dir)
    
    # Train semantic similarity model
    similarity_model = trainer.train_semantic_similarity(train_packages)
    
    # Train malicious classifier
    classifier = trainer.train_malicious_classifier(train_packages, train_labels)
    
    # Evaluate models
    trainer.evaluate_models(similarity_model, classifier, test_packages, test_labels)
    
    logger.info("Training completed successfully!")

if __name__ == "__main__":
    asyncio.run(main())