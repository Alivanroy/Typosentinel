#!/usr/bin/env python3
"""
Model Evaluation Script for TypoSentinel

This script evaluates the performance of trained ML models
using various metrics and test cases.
"""

import os
import sys
import json
import logging
import numpy as np
from typing import List, Dict, Any, Tuple
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score, precision_recall_curve
import matplotlib.pyplot as plt
import seaborn as sns
from datetime import datetime
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

class ModelEvaluator:
    """Evaluate ML model performance."""
    
    def __init__(self, model_dir: str = "models", output_dir: str = "evaluation_results"):
        self.model_dir = model_dir
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)
        
        # Load models
        self.similarity_model = None
        self.classifier = None
        self._load_models()
    
    def _load_models(self):
        """Load trained models."""
        try:
            logger.info("Loading semantic similarity model...")
            self.similarity_model = SemanticSimilarityModel(model_dir=self.model_dir)
            logger.info("Semantic similarity model loaded successfully")
        except Exception as e:
            logger.error(f"Failed to load semantic similarity model: {e}")
        
        try:
            logger.info("Loading malicious classifier...")
            self.classifier = MaliciousPackageClassifier(model_dir=self.model_dir)
            if not self.classifier.is_trained:
                logger.warning("Malicious classifier is not trained")
            else:
                logger.info("Malicious classifier loaded successfully")
        except Exception as e:
            logger.error(f"Failed to load malicious classifier: {e}")
    
    def evaluate_semantic_similarity(self) -> Dict[str, Any]:
        """Evaluate semantic similarity model."""
        if not self.similarity_model:
            logger.error("Semantic similarity model not available")
            return {}
        
        logger.info("Evaluating semantic similarity model...")
        
        # Test cases for semantic similarity
        test_cases = [
            {
                'query': 'react',
                'expected_similar': ['preact', 'vue', 'angular'],
                'expected_dissimilar': ['numpy', 'pandas', 'flask']
            },
            {
                'query': 'lodash',
                'expected_similar': ['underscore', 'ramda'],
                'expected_dissimilar': ['react', 'express']
            },
            {
                'query': 'express',
                'expected_similar': ['koa', 'fastify', 'hapi'],
                'expected_dissimilar': ['react', 'lodash']
            },
            {
                'query': 'numpy',
                'expected_similar': ['pandas', 'scipy', 'matplotlib'],
                'expected_dissimilar': ['react', 'express']
            },
            {
                'query': 'flask',
                'expected_similar': ['django', 'fastapi'],
                'expected_dissimilar': ['numpy', 'react']
            }
        ]
        
        results = {
            'test_cases': [],
            'average_precision': 0.0,
            'average_recall': 0.0
        }
        
        total_precision = 0.0
        total_recall = 0.0
        
        for test_case in test_cases:
            query = test_case['query']
            expected_similar = test_case['expected_similar']
            expected_dissimilar = test_case['expected_dissimilar']
            
            # Find similar packages
            similar_packages = self.similarity_model.find_similar(
                query, top_k=10, threshold=0.5
            )
            
            found_names = [name for name, score in similar_packages]
            
            # Calculate precision and recall
            true_positives = len(set(found_names) & set(expected_similar))
            false_positives = len(set(found_names) & set(expected_dissimilar))
            false_negatives = len(set(expected_similar) - set(found_names))
            
            precision = true_positives / (true_positives + false_positives) if (true_positives + false_positives) > 0 else 0
            recall = true_positives / (true_positives + false_negatives) if (true_positives + false_negatives) > 0 else 0
            
            test_result = {
                'query': query,
                'found_similar': found_names,
                'expected_similar': expected_similar,
                'precision': precision,
                'recall': recall,
                'scores': [score for name, score in similar_packages]
            }
            
            results['test_cases'].append(test_result)
            total_precision += precision
            total_recall += recall
            
            logger.info(f"Query: {query}, Precision: {precision:.3f}, Recall: {recall:.3f}")
        
        results['average_precision'] = total_precision / len(test_cases)
        results['average_recall'] = total_recall / len(test_cases)
        
        logger.info(f"Average Precision: {results['average_precision']:.3f}")
        logger.info(f"Average Recall: {results['average_recall']:.3f}")
        
        return results
    
    def evaluate_malicious_classifier(self, test_data: List[Dict], test_labels: List[int]) -> Dict[str, Any]:
        """Evaluate malicious package classifier."""
        if not self.classifier or not self.classifier.is_trained:
            logger.error("Malicious classifier not available or not trained")
            return {}
        
        logger.info(f"Evaluating malicious classifier on {len(test_data)} packages...")
        
        predictions = []
        probabilities = []
        
        for pkg_data in test_data:
            # Convert to PackageFeatures
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
            
            result = self.classifier.predict(features)
            predictions.append(1 if result['is_malicious'] else 0)
            probabilities.append(result['score'])
        
        # Calculate metrics
        accuracy = sum(1 for p, t in zip(predictions, test_labels) if p == t) / len(test_labels)
        
        # Classification report
        class_report = classification_report(
            test_labels, predictions, 
            target_names=['Benign', 'Malicious'],
            output_dict=True
        )
        
        # Confusion matrix
        conf_matrix = confusion_matrix(test_labels, predictions)
        
        # ROC AUC
        try:
            roc_auc = roc_auc_score(test_labels, probabilities)
        except ValueError:
            roc_auc = 0.0
        
        results = {
            'accuracy': accuracy,
            'classification_report': class_report,
            'confusion_matrix': conf_matrix.tolist(),
            'roc_auc': roc_auc,
            'predictions': predictions,
            'probabilities': probabilities,
            'test_labels': test_labels
        }
        
        logger.info(f"Accuracy: {accuracy:.3f}")
        logger.info(f"ROC AUC: {roc_auc:.3f}")
        logger.info(f"Precision (Malicious): {class_report['Malicious']['precision']:.3f}")
        logger.info(f"Recall (Malicious): {class_report['Malicious']['recall']:.3f}")
        
        return results
    
    def test_typosquatting_detection(self) -> Dict[str, Any]:
        """Test typosquatting detection capabilities."""
        logger.info("Testing typosquatting detection...")
        
        # Known typosquatting pairs
        typosquatting_pairs = [
            ('react', 'reactt'),
            ('react', 'reakt'),
            ('lodash', 'lodahs'),
            ('lodash', 'l0dash'),
            ('express', 'expresss'),
            ('express', 'expres'),
            ('numpy', 'nunpy'),
            ('numpy', 'numpi'),
            ('flask', 'flaskk'),
            ('flask', 'fIask')
        ]
        
        results = {
            'similarity_scores': [],
            'malicious_predictions': [],
            'detection_rate': 0.0
        }
        
        detected_count = 0
        
        for original, typosquat in typosquatting_pairs:
            # Test semantic similarity
            similarity_score = 0.0
            if self.similarity_model:
                similarity_score = self.similarity_model.calculate_similarity(original, typosquat)
            
            # Test malicious classification
            is_malicious = False
            malicious_score = 0.0
            if self.classifier and self.classifier.is_trained:
                features = ClassifierPackageFeatures(
                    name=typosquat,
                    registry='npm',
                    version='1.0.0',
                    description=f'A {original} package',
                    author='unknown',
                    downloads=10,
                    creation_date='2024-01-01T00:00:00',
                    last_updated='2024-01-01T00:00:00'
                )
                
                result = self.classifier.predict(features)
                is_malicious = result['is_malicious']
                malicious_score = result['score']
            
            # Consider detected if high similarity OR classified as malicious
            detected = similarity_score > 0.8 or is_malicious
            if detected:
                detected_count += 1
            
            results['similarity_scores'].append({
                'original': original,
                'typosquat': typosquat,
                'similarity': similarity_score
            })
            
            results['malicious_predictions'].append({
                'original': original,
                'typosquat': typosquat,
                'is_malicious': is_malicious,
                'score': malicious_score
            })
            
            logger.info(f"{original} -> {typosquat}: Similarity={similarity_score:.3f}, Malicious={is_malicious} ({malicious_score:.3f})")
        
        results['detection_rate'] = detected_count / len(typosquatting_pairs)
        logger.info(f"Typosquatting detection rate: {results['detection_rate']:.3f}")
        
        return results
    
    def generate_plots(self, classifier_results: Dict[str, Any]):
        """Generate evaluation plots."""
        if not classifier_results:
            return
        
        logger.info("Generating evaluation plots...")
        
        # Confusion Matrix
        plt.figure(figsize=(8, 6))
        conf_matrix = np.array(classifier_results['confusion_matrix'])
        sns.heatmap(conf_matrix, annot=True, fmt='d', cmap='Blues',
                   xticklabels=['Benign', 'Malicious'],
                   yticklabels=['Benign', 'Malicious'])
        plt.title('Confusion Matrix')
        plt.ylabel('True Label')
        plt.xlabel('Predicted Label')
        plt.tight_layout()
        plt.savefig(os.path.join(self.output_dir, 'confusion_matrix.png'))
        plt.close()
        
        # ROC Curve
        if classifier_results['roc_auc'] > 0:
            from sklearn.metrics import roc_curve
            fpr, tpr, _ = roc_curve(classifier_results['test_labels'], 
                                  classifier_results['probabilities'])
            
            plt.figure(figsize=(8, 6))
            plt.plot(fpr, tpr, label=f'ROC Curve (AUC = {classifier_results["roc_auc"]:.3f})')
            plt.plot([0, 1], [0, 1], 'k--', label='Random')
            plt.xlabel('False Positive Rate')
            plt.ylabel('True Positive Rate')
            plt.title('ROC Curve')
            plt.legend()
            plt.grid(True)
            plt.tight_layout()
            plt.savefig(os.path.join(self.output_dir, 'roc_curve.png'))
            plt.close()
        
        # Precision-Recall Curve
        precision, recall, _ = precision_recall_curve(
            classifier_results['test_labels'], 
            classifier_results['probabilities']
        )
        
        plt.figure(figsize=(8, 6))
        plt.plot(recall, precision, label='Precision-Recall Curve')
        plt.xlabel('Recall')
        plt.ylabel('Precision')
        plt.title('Precision-Recall Curve')
        plt.legend()
        plt.grid(True)
        plt.tight_layout()
        plt.savefig(os.path.join(self.output_dir, 'precision_recall_curve.png'))
        plt.close()
        
        logger.info(f"Plots saved to {self.output_dir}")
    
    def save_results(self, results: Dict[str, Any], filename: str = "evaluation_results.json"):
        """Save evaluation results to file."""
        results['evaluation_timestamp'] = datetime.now().isoformat()
        
        filepath = os.path.join(self.output_dir, filename)
        with open(filepath, 'w') as f:
            json.dump(results, f, indent=2, default=str)
        
        logger.info(f"Results saved to {filepath}")
    
    def run_full_evaluation(self, test_data_file: str = None) -> Dict[str, Any]:
        """Run complete model evaluation."""
        logger.info("Starting full model evaluation...")
        
        results = {
            'semantic_similarity': {},
            'malicious_classifier': {},
            'typosquatting_detection': {}
        }
        
        # Evaluate semantic similarity
        if self.similarity_model:
            results['semantic_similarity'] = self.evaluate_semantic_similarity()
        
        # Evaluate malicious classifier
        if self.classifier and self.classifier.is_trained and test_data_file:
            if os.path.exists(test_data_file):
                with open(test_data_file, 'r') as f:
                    test_dataset = json.load(f)
                
                test_data = test_dataset['packages']
                test_labels = test_dataset['labels']
                
                results['malicious_classifier'] = self.evaluate_malicious_classifier(
                    test_data, test_labels
                )
                
                # Generate plots
                self.generate_plots(results['malicious_classifier'])
        
        # Test typosquatting detection
        results['typosquatting_detection'] = self.test_typosquatting_detection()
        
        # Save results
        self.save_results(results)
        
        logger.info("Full evaluation completed")
        return results

def main():
    """Main evaluation function."""
    parser = argparse.ArgumentParser(description='Evaluate TypoSentinel ML models')
    parser.add_argument('--model-dir', type=str, default='models', help='Directory containing trained models')
    parser.add_argument('--test-data', type=str, help='Test dataset file (JSON)')
    parser.add_argument('--output-dir', type=str, default='evaluation_results', help='Output directory for results')
    
    args = parser.parse_args()
    
    # Run evaluation
    evaluator = ModelEvaluator(args.model_dir, args.output_dir)
    results = evaluator.run_full_evaluation(args.test_data)
    
    # Print summary
    print("\n=== Evaluation Summary ===")
    
    if 'semantic_similarity' in results and results['semantic_similarity']:
        sim_results = results['semantic_similarity']
        print(f"Semantic Similarity - Precision: {sim_results['average_precision']:.3f}, Recall: {sim_results['average_recall']:.3f}")
    
    if 'malicious_classifier' in results and results['malicious_classifier']:
        mal_results = results['malicious_classifier']
        print(f"Malicious Classifier - Accuracy: {mal_results['accuracy']:.3f}, ROC AUC: {mal_results['roc_auc']:.3f}")
    
    if 'typosquatting_detection' in results and results['typosquatting_detection']:
        typo_results = results['typosquatting_detection']
        print(f"Typosquatting Detection Rate: {typo_results['detection_rate']:.3f}")
    
    print(f"\nDetailed results saved to {args.output_dir}")

if __name__ == "__main__":
    main()