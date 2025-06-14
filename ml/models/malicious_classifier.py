#!/usr/bin/env python3
"""
Malicious Package Classifier for TypoSentinel

This module implements multi-modal malicious package detection using
Random Forest, Isolation Forest, and TF-IDF vectorization.
"""

import os
import pickle
import logging
import re
from typing import List, Dict, Tuple, Optional, Any
from dataclasses import dataclass
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix
import joblib
from datetime import datetime, timedelta

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class PackageFeatures:
    """Store package metadata and features for analysis."""
    name: str
    registry: str
    version: str = ""
    description: str = ""
    author: str = ""
    downloads: int = 0
    creation_date: str = ""
    last_updated: str = ""
    dependencies: List[str] = None
    keywords: List[str] = None
    license: str = ""
    homepage: str = ""
    repository: str = ""
    size: int = 0
    
    def __post_init__(self):
        if self.dependencies is None:
            self.dependencies = []
        if self.keywords is None:
            self.keywords = []

class MaliciousPackageClassifier:
    """Multi-modal malicious package classifier."""
    
    def __init__(self, model_dir: str = "models"):
        """
        Initialize the malicious package classifier.
        
        Args:
            model_dir: Directory to save/load models
        """
        self.model_dir = model_dir
        os.makedirs(model_dir, exist_ok=True)
        
        # Initialize models
        self.rf_classifier = RandomForestClassifier(
            n_estimators=100,
            max_depth=10,
            random_state=42,
            class_weight='balanced'
        )
        
        self.isolation_forest = IsolationForest(
            contamination=0.1,
            random_state=42
        )
        
        self.tfidf_vectorizer = TfidfVectorizer(
            max_features=1000,
            stop_words='english',
            ngram_range=(1, 2)
        )
        
        self.scaler = StandardScaler()
        
        # Model state
        self.is_trained = False
        self.feature_names = []
        
        # Load existing models if available
        self._load_models()
    
    def _load_models(self) -> bool:
        """Load existing trained models."""
        try:
            model_files = {
                'rf_classifier': os.path.join(self.model_dir, 'rf_classifier.pkl'),
                'isolation_forest': os.path.join(self.model_dir, 'isolation_forest.pkl'),
                'tfidf_vectorizer': os.path.join(self.model_dir, 'tfidf_vectorizer.pkl'),
                'scaler': os.path.join(self.model_dir, 'scaler.pkl'),
                'metadata': os.path.join(self.model_dir, 'model_metadata.pkl')
            }
            
            # Check if all model files exist
            if all(os.path.exists(path) for path in model_files.values()):
                logger.info("Loading existing models...")
                
                self.rf_classifier = joblib.load(model_files['rf_classifier'])
                self.isolation_forest = joblib.load(model_files['isolation_forest'])
                self.tfidf_vectorizer = joblib.load(model_files['tfidf_vectorizer'])
                self.scaler = joblib.load(model_files['scaler'])
                
                with open(model_files['metadata'], 'rb') as f:
                    metadata = pickle.load(f)
                    self.feature_names = metadata['feature_names']
                    self.is_trained = metadata['is_trained']
                
                logger.info("Models loaded successfully")
                return True
        except Exception as e:
            logger.warning(f"Failed to load existing models: {e}")
        
        return False
    
    def _save_models(self):
        """Save trained models to disk."""
        try:
            model_files = {
                'rf_classifier': os.path.join(self.model_dir, 'rf_classifier.pkl'),
                'isolation_forest': os.path.join(self.model_dir, 'isolation_forest.pkl'),
                'tfidf_vectorizer': os.path.join(self.model_dir, 'tfidf_vectorizer.pkl'),
                'scaler': os.path.join(self.model_dir, 'scaler.pkl'),
                'metadata': os.path.join(self.model_dir, 'model_metadata.pkl')
            }
            
            joblib.dump(self.rf_classifier, model_files['rf_classifier'])
            joblib.dump(self.isolation_forest, model_files['isolation_forest'])
            joblib.dump(self.tfidf_vectorizer, model_files['tfidf_vectorizer'])
            joblib.dump(self.scaler, model_files['scaler'])
            
            metadata = {
                'feature_names': self.feature_names,
                'is_trained': self.is_trained,
                'trained_at': datetime.now().isoformat()
            }
            
            with open(model_files['metadata'], 'wb') as f:
                pickle.dump(metadata, f)
            
            logger.info("Models saved successfully")
        except Exception as e:
            logger.error(f"Failed to save models: {e}")
    
    def extract_features(self, package: PackageFeatures) -> Dict[str, Any]:
        """Extract features from a package for classification."""
        features = {}
        
        # Basic package information features
        features['name_length'] = len(package.name)
        features['has_version'] = 1 if package.version else 0
        features['has_description'] = 1 if package.description else 0
        features['has_author'] = 1 if package.author else 0
        features['has_license'] = 1 if package.license else 0
        features['has_homepage'] = 1 if package.homepage else 0
        features['has_repository'] = 1 if package.repository else 0
        
        # Download and popularity features
        features['downloads'] = package.downloads
        features['log_downloads'] = np.log1p(package.downloads)
        features['size'] = package.size
        features['log_size'] = np.log1p(package.size)
        
        # Dependency features
        features['num_dependencies'] = len(package.dependencies)
        features['has_dependencies'] = 1 if package.dependencies else 0
        
        # Keyword features
        features['num_keywords'] = len(package.keywords)
        features['has_keywords'] = 1 if package.keywords else 0
        
        # Date features
        features.update(self._extract_date_features(package))
        
        # Name pattern features
        features.update(self._extract_name_features(package.name))
        
        # Description features
        features.update(self._extract_description_features(package.description))
        
        # Author features
        features.update(self._extract_author_features(package.author))
        
        # Repository features
        features.update(self._extract_repository_features(package.repository))
        
        # Suspicious pattern features
        features.update(self._extract_suspicious_patterns(package))
        
        return features
    
    def _extract_date_features(self, package: PackageFeatures) -> Dict[str, Any]:
        """Extract date-related features."""
        features = {}
        
        try:
            if package.creation_date:
                creation_date = datetime.fromisoformat(package.creation_date.replace('Z', '+00:00'))
                now = datetime.now()
                
                features['days_since_creation'] = (now - creation_date).days
                features['is_very_new'] = 1 if (now - creation_date).days < 30 else 0
                features['is_recently_created'] = 1 if (now - creation_date).days < 90 else 0
            else:
                features['days_since_creation'] = -1
                features['is_very_new'] = 0
                features['is_recently_created'] = 0
            
            if package.last_updated:
                last_updated = datetime.fromisoformat(package.last_updated.replace('Z', '+00:00'))
                now = datetime.now()
                
                features['days_since_update'] = (now - last_updated).days
                features['is_recently_updated'] = 1 if (now - last_updated).days < 30 else 0
            else:
                features['days_since_update'] = -1
                features['is_recently_updated'] = 0
        except Exception:
            # Handle date parsing errors
            features['days_since_creation'] = -1
            features['is_very_new'] = 0
            features['is_recently_created'] = 0
            features['days_since_update'] = -1
            features['is_recently_updated'] = 0
        
        return features
    
    def _extract_name_features(self, name: str) -> Dict[str, Any]:
        """Extract features from package name."""
        features = {}
        
        # Basic name characteristics
        features['name_has_numbers'] = 1 if re.search(r'\d', name) else 0
        features['name_has_special_chars'] = 1 if re.search(r'[^a-zA-Z0-9\-_.]', name) else 0
        features['name_has_uppercase'] = 1 if re.search(r'[A-Z]', name) else 0
        features['name_num_parts'] = len(re.split(r'[-_.]', name))
        
        # Suspicious name patterns
        features['name_has_typo_chars'] = 1 if re.search(r'[0o1il]', name.lower()) else 0
        features['name_excessive_chars'] = 1 if re.search(r'(.)\1{2,}', name) else 0
        features['name_random_like'] = 1 if self._is_random_like(name) else 0
        
        # Common malicious patterns
        suspicious_patterns = [
            r'test.*', r'.*test', r'temp.*', r'.*temp',
            r'fake.*', r'.*fake', r'mock.*', r'.*mock',
            r'demo.*', r'.*demo', r'sample.*', r'.*sample'
        ]
        
        features['name_suspicious_pattern'] = 1 if any(
            re.match(pattern, name.lower()) for pattern in suspicious_patterns
        ) else 0
        
        return features
    
    def _extract_description_features(self, description: str) -> Dict[str, Any]:
        """Extract features from package description."""
        features = {}
        
        if not description:
            features['desc_length'] = 0
            features['desc_has_suspicious_words'] = 0
            features['desc_has_urls'] = 0
            features['desc_is_generic'] = 0
            return features
        
        features['desc_length'] = len(description)
        
        # Suspicious words in description
        suspicious_words = [
            'bitcoin', 'crypto', 'wallet', 'mining', 'hack', 'crack',
            'password', 'steal', 'phish', 'malware', 'virus', 'trojan'
        ]
        
        features['desc_has_suspicious_words'] = 1 if any(
            word in description.lower() for word in suspicious_words
        ) else 0
        
        # URLs in description
        features['desc_has_urls'] = 1 if re.search(r'https?://', description) else 0
        
        # Generic descriptions
        generic_patterns = [
            r'^test.*', r'^demo.*', r'^sample.*',
            r'^a \w+ package$', r'^\w+ package$'
        ]
        
        features['desc_is_generic'] = 1 if any(
            re.match(pattern, description.lower()) for pattern in generic_patterns
        ) else 0
        
        return features
    
    def _extract_author_features(self, author: str) -> Dict[str, Any]:
        """Extract features from package author."""
        features = {}
        
        if not author:
            features['author_suspicious'] = 0
            features['author_has_email'] = 0
            return features
        
        # Suspicious author patterns
        features['author_suspicious'] = 1 if any([
            len(author) < 3,
            re.match(r'^[a-z]+\d+$', author.lower()),  # username + numbers
            author.lower() in ['test', 'admin', 'user', 'anonymous']
        ]) else 0
        
        features['author_has_email'] = 1 if '@' in author else 0
        
        return features
    
    def _extract_repository_features(self, repository: str) -> Dict[str, Any]:
        """Extract features from repository URL."""
        features = {}
        
        if not repository:
            features['repo_is_github'] = 0
            features['repo_is_suspicious'] = 0
            return features
        
        features['repo_is_github'] = 1 if 'github.com' in repository.lower() else 0
        
        # Suspicious repository patterns
        features['repo_is_suspicious'] = 1 if any([
            'bit.ly' in repository.lower(),
            'tinyurl' in repository.lower(),
            repository.count('/') < 2,  # Too short URL
            re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', repository)  # IP address
        ]) else 0
        
        return features
    
    def _extract_suspicious_patterns(self, package: PackageFeatures) -> Dict[str, Any]:
        """Extract suspicious pattern features."""
        features = {}
        
        # Low download count for established packages
        features['low_downloads_old_package'] = 1 if (
            package.downloads < 100 and 
            package.creation_date and 
            self._days_since_creation(package.creation_date) > 365
        ) else 0
        
        # No description but has dependencies
        features['no_desc_has_deps'] = 1 if (
            not package.description and len(package.dependencies) > 0
        ) else 0
        
        # Suspicious version patterns
        if package.version:
            features['version_suspicious'] = 1 if any([
                package.version.count('.') > 3,
                re.search(r'[a-zA-Z]', package.version) and not re.search(r'(alpha|beta|rc|pre)', package.version.lower()),
                package.version.startswith('0.0.')
            ]) else 0
        else:
            features['version_suspicious'] = 0
        
        return features
    
    def _is_random_like(self, name: str) -> bool:
        """Check if a name looks randomly generated."""
        # Simple heuristic: check for lack of vowels or consonants
        vowels = set('aeiou')
        consonants = set('bcdfghjklmnpqrstvwxyz')
        
        name_lower = name.lower()
        has_vowels = any(c in vowels for c in name_lower)
        has_consonants = any(c in consonants for c in name_lower)
        
        # If name has only vowels or only consonants, it might be random
        if not has_vowels or not has_consonants:
            return True
        
        # Check for excessive alternating patterns
        if len(name) > 6 and re.search(r'([a-z])\1{2,}', name_lower):
            return True
        
        return False
    
    def _days_since_creation(self, creation_date: str) -> int:
        """Calculate days since package creation."""
        try:
            created = datetime.fromisoformat(creation_date.replace('Z', '+00:00'))
            return (datetime.now() - created).days
        except Exception:
            return -1
    
    def train(self, packages: List[PackageFeatures], labels: List[int]):
        """Train the classifier on labeled data."""
        if len(packages) != len(labels):
            raise ValueError("Number of packages must match number of labels")
        
        logger.info(f"Training classifier on {len(packages)} packages...")
        
        # Extract features
        feature_dicts = [self.extract_features(pkg) for pkg in packages]
        
        # Convert to DataFrame for easier handling
        df = pd.DataFrame(feature_dicts)
        
        # Store feature names
        self.feature_names = list(df.columns)
        
        # Fill missing values
        df = df.fillna(0)
        
        # Scale features
        X_scaled = self.scaler.fit_transform(df)
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X_scaled, labels, test_size=0.2, random_state=42, stratify=labels
        )
        
        # Train Random Forest
        self.rf_classifier.fit(X_train, y_train)
        
        # Train Isolation Forest (unsupervised)
        self.isolation_forest.fit(X_train)
        
        # Train TF-IDF on descriptions
        descriptions = [pkg.description or "" for pkg in packages]
        self.tfidf_vectorizer.fit(descriptions)
        
        # Evaluate
        y_pred = self.rf_classifier.predict(X_test)
        logger.info("Classification Report:")
        logger.info(classification_report(y_test, y_pred))
        
        self.is_trained = True
        self._save_models()
        
        logger.info("Training completed successfully")
    
    def predict(self, package: PackageFeatures) -> Dict[str, Any]:
        """Predict if a package is malicious."""
        if not self.is_trained:
            raise ValueError("Model must be trained before making predictions")
        
        # Extract features
        features = self.extract_features(package)
        
        # Convert to DataFrame and ensure all features are present
        df = pd.DataFrame([features])
        
        # Add missing features with default values
        for feature_name in self.feature_names:
            if feature_name not in df.columns:
                df[feature_name] = 0
        
        # Reorder columns to match training data
        df = df[self.feature_names]
        
        # Fill missing values
        df = df.fillna(0)
        
        # Scale features
        X_scaled = self.scaler.transform(df)
        
        # Random Forest prediction
        rf_prob = self.rf_classifier.predict_proba(X_scaled)[0]
        rf_prediction = self.rf_classifier.predict(X_scaled)[0]
        
        # Isolation Forest prediction (anomaly detection)
        isolation_score = self.isolation_forest.decision_function(X_scaled)[0]
        isolation_prediction = self.isolation_forest.predict(X_scaled)[0]  # -1 for anomaly, 1 for normal
        
        # TF-IDF analysis of description
        description = package.description or ""
        tfidf_features = self.tfidf_vectorizer.transform([description])
        
        # Combine predictions
        malicious_probability = rf_prob[1] if len(rf_prob) > 1 else 0.0
        
        # Adjust probability based on isolation forest
        if isolation_prediction == -1:  # Anomaly detected
            malicious_probability = min(1.0, malicious_probability + 0.2)
        
        # Determine final prediction
        is_malicious = malicious_probability > 0.5
        
        # Calculate confidence
        confidence = max(malicious_probability, 1 - malicious_probability)
        
        # Generate reasons
        reasons = self._generate_reasons(features, malicious_probability, isolation_prediction)
        
        return {
            'is_malicious': is_malicious,
            'score': malicious_probability,
            'confidence': confidence,
            'reasons': reasons,
            'features': features,
            'rf_prediction': int(rf_prediction),
            'rf_probability': malicious_probability,
            'isolation_score': float(isolation_score),
            'isolation_anomaly': isolation_prediction == -1
        }
    
    def _generate_reasons(self, features: Dict[str, Any], 
                         malicious_prob: float, isolation_pred: int) -> List[str]:
        """Generate human-readable reasons for the prediction."""
        reasons = []
        
        if malicious_prob > 0.7:
            reasons.append(f"High malicious probability: {malicious_prob:.2f}")
        
        if isolation_pred == -1:
            reasons.append("Package features are anomalous compared to normal packages")
        
        # Check specific suspicious features
        if features.get('is_very_new', 0) == 1:
            reasons.append("Package was created very recently (less than 30 days)")
        
        if features.get('low_downloads_old_package', 0) == 1:
            reasons.append("Old package with suspiciously low download count")
        
        if features.get('name_suspicious_pattern', 0) == 1:
            reasons.append("Package name matches suspicious patterns")
        
        if features.get('desc_has_suspicious_words', 0) == 1:
            reasons.append("Description contains suspicious keywords")
        
        if features.get('author_suspicious', 0) == 1:
            reasons.append("Author information appears suspicious")
        
        if features.get('repo_is_suspicious', 0) == 1:
            reasons.append("Repository URL appears suspicious")
        
        if features.get('no_desc_has_deps', 0) == 1:
            reasons.append("Package has dependencies but no description")
        
        if not reasons:
            if malicious_prob > 0.5:
                reasons.append("Multiple suspicious indicators detected")
            else:
                reasons.append("Package appears to be legitimate")
        
        return reasons
    
    def batch_predict(self, packages: List[PackageFeatures]) -> List[Dict[str, Any]]:
        """Predict maliciousness for multiple packages."""
        return [self.predict(pkg) for pkg in packages]
    
    def get_feature_importance(self) -> Dict[str, float]:
        """Get feature importance from the Random Forest model."""
        if not self.is_trained:
            raise ValueError("Model must be trained before getting feature importance")
        
        importance = self.rf_classifier.feature_importances_
        return dict(zip(self.feature_names, importance))
    
    def get_model_stats(self) -> Dict[str, Any]:
        """Get model statistics and information."""
        return {
            'is_trained': self.is_trained,
            'num_features': len(self.feature_names),
            'feature_names': self.feature_names,
            'rf_n_estimators': self.rf_classifier.n_estimators,
            'isolation_contamination': self.isolation_forest.contamination,
            'tfidf_max_features': self.tfidf_vectorizer.max_features
        }

# Example usage and testing
if __name__ == "__main__":
    # Initialize classifier
    classifier = MaliciousPackageClassifier()
    
    # Example training data (in practice, this would come from a labeled dataset)
    training_packages = [
        # Legitimate packages
        PackageFeatures(
            name="react", registry="npm", version="18.2.0",
            description="A JavaScript library for building user interfaces",
            author="React Team", downloads=50000000,
            creation_date="2013-05-29T00:00:00Z",
            license="MIT", homepage="https://reactjs.org",
            repository="https://github.com/facebook/react"
        ),
        PackageFeatures(
            name="lodash", registry="npm", version="4.17.21",
            description="Lodash modular utilities",
            author="John-David Dalton", downloads=40000000,
            creation_date="2012-04-23T00:00:00Z",
            license="MIT"
        ),
        # Suspicious packages
        PackageFeatures(
            name="reactt", registry="npm", version="1.0.0",
            description="test package",
            author="user123", downloads=5,
            creation_date="2024-01-01T00:00:00Z"
        ),
        PackageFeatures(
            name="crypto-wallet-stealer", registry="npm", version="0.0.1",
            description="Bitcoin wallet mining tool",
            author="hacker", downloads=0,
            creation_date="2024-01-15T00:00:00Z"
        )
    ]
    
    # Labels: 0 = legitimate, 1 = malicious
    labels = [0, 0, 1, 1]
    
    # Train the classifier
    classifier.train(training_packages, labels)
    
    # Test predictions
    test_packages = [
        PackageFeatures(
            name="vue", registry="npm", version="3.3.4",
            description="The progressive JavaScript framework",
            author="Evan You", downloads=30000000,
            creation_date="2014-02-01T00:00:00Z",
            license="MIT"
        ),
        PackageFeatures(
            name="test-malware", registry="npm", version="0.0.1",
            description="hack your system",
            author="anon", downloads=1,
            creation_date="2024-01-20T00:00:00Z"
        )
    ]
    
    for pkg in test_packages:
        result = classifier.predict(pkg)
        print(f"\nPackage: {pkg.name}")
        print(f"Malicious: {result['is_malicious']}")
        print(f"Score: {result['score']:.3f}")
        print(f"Confidence: {result['confidence']:.3f}")
        print(f"Reasons: {', '.join(result['reasons'])}")
    
    # Print feature importance
    importance = classifier.get_feature_importance()
    print("\nTop 10 most important features:")
    for feature, score in sorted(importance.items(), key=lambda x: x[1], reverse=True)[:10]:
        print(f"  {feature}: {score:.3f}")