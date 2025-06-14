#!/usr/bin/env python3
"""
Continuous Learning System for Typosentinel
Automatically retrain models with new feedback data
"""

import asyncio
import json
import logging
import os
import time
from datetime import datetime, timedelta
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass
import numpy as np
from sklearn.metrics import precision_score, recall_score, f1_score, accuracy_score
from sklearn.model_selection import train_test_split
import joblib
import sqlite3
import aiofiles

from ..models.ensemble_detector import EnsembleDetector, PackageData

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Configuration constants
MIN_FEEDBACK_THRESHOLD = 100
PERFORMANCE_THRESHOLD = 0.85
RETRAIN_INTERVAL_HOURS = 24
MAX_TRAINING_SAMPLES = 10000

@dataclass
class FeedbackData:
    package_name: str
    registry: str
    predicted_risk: float
    actual_risk: float
    analyst_feedback: str
    confidence: float
    timestamp: datetime
    package_data: PackageData

@dataclass
class ModelPerformance:
    accuracy: float
    precision: float
    recall: float
    f1_score: float
    timestamp: datetime
    model_version: str

class FeedbackCollector:
    """Collect and manage feedback from human analysts"""
    
    def __init__(self, db_path: str = "feedback.db"):
        self.db_path = db_path
        self._init_database()
    
    def _init_database(self):
        """Initialize SQLite database for feedback storage"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS feedback (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                package_name TEXT NOT NULL,
                registry TEXT NOT NULL,
                predicted_risk REAL NOT NULL,
                actual_risk REAL NOT NULL,
                analyst_feedback TEXT,
                confidence REAL NOT NULL,
                timestamp TEXT NOT NULL,
                package_data TEXT NOT NULL,
                processed BOOLEAN DEFAULT FALSE
            )
        """)
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS model_performance (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                accuracy REAL NOT NULL,
                precision_val REAL NOT NULL,
                recall_val REAL NOT NULL,
                f1_score REAL NOT NULL,
                timestamp TEXT NOT NULL,
                model_version TEXT NOT NULL
            )
        """)
        
        conn.commit()
        conn.close()
    
    async def add_feedback(self, feedback: FeedbackData):
        """Add new feedback to the database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        package_data_json = json.dumps({
            'name': feedback.package_data.name,
            'registry': feedback.package_data.registry,
            'version': feedback.package_data.version,
            'metadata': feedback.package_data.metadata,
            'source_code': feedback.package_data.source_code,
            'dependencies': feedback.package_data.dependencies,
            'download_count': feedback.package_data.download_count,
            'author_info': feedback.package_data.author_info
        })
        
        cursor.execute("""
            INSERT INTO feedback (
                package_name, registry, predicted_risk, actual_risk,
                analyst_feedback, confidence, timestamp, package_data
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            feedback.package_name,
            feedback.registry,
            feedback.predicted_risk,
            feedback.actual_risk,
            feedback.analyst_feedback,
            feedback.confidence,
            feedback.timestamp.isoformat(),
            package_data_json
        ))
        
        conn.commit()
        conn.close()
        
        logger.info(f"Added feedback for package {feedback.package_name}")
    
    async def get_new_feedback(self, limit: int = 1000) -> List[FeedbackData]:
        """Get unprocessed feedback from the database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT package_name, registry, predicted_risk, actual_risk,
                   analyst_feedback, confidence, timestamp, package_data
            FROM feedback
            WHERE processed = FALSE
            ORDER BY timestamp DESC
            LIMIT ?
        """, (limit,))
        
        rows = cursor.fetchall()
        feedback_list = []
        
        for row in rows:
            package_data_dict = json.loads(row[7])
            package_data = PackageData(
                name=package_data_dict['name'],
                registry=package_data_dict['registry'],
                version=package_data_dict['version'],
                metadata=package_data_dict['metadata'],
                source_code=package_data_dict.get('source_code'),
                dependencies=package_data_dict.get('dependencies'),
                download_count=package_data_dict.get('download_count'),
                author_info=package_data_dict.get('author_info')
            )
            
            feedback = FeedbackData(
                package_name=row[0],
                registry=row[1],
                predicted_risk=row[2],
                actual_risk=row[3],
                analyst_feedback=row[4],
                confidence=row[5],
                timestamp=datetime.fromisoformat(row[6]),
                package_data=package_data
            )
            feedback_list.append(feedback)
        
        conn.close()
        return feedback_list
    
    async def mark_feedback_processed(self, package_names: List[str]):
        """Mark feedback as processed"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        placeholders = ','.join(['?' for _ in package_names])
        cursor.execute(f"""
            UPDATE feedback
            SET processed = TRUE
            WHERE package_name IN ({placeholders})
        """, package_names)
        
        conn.commit()
        conn.close()
    
    async def get_feedback_stats(self) -> Dict:
        """Get feedback statistics"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("SELECT COUNT(*) FROM feedback")
        total_feedback = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM feedback WHERE processed = FALSE")
        unprocessed_feedback = cursor.fetchone()[0]
        
        cursor.execute("""
            SELECT AVG(ABS(predicted_risk - actual_risk))
            FROM feedback
            WHERE processed = TRUE
        """)
        avg_error = cursor.fetchone()[0] or 0.0
        
        conn.close()
        
        return {
            'total_feedback': total_feedback,
            'unprocessed_feedback': unprocessed_feedback,
            'average_prediction_error': avg_error
        }

class ModelStore:
    """Manage model storage and versioning"""
    
    def __init__(self, models_dir: str = "models"):
        self.models_dir = models_dir
        os.makedirs(models_dir, exist_ok=True)
    
    def save_model(self, model_name: str, model, version: str = None):
        """Save a model with versioning"""
        if version is None:
            version = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        model_path = os.path.join(self.models_dir, f"{model_name}_{version}.joblib")
        joblib.dump(model, model_path)
        
        # Also save as latest
        latest_path = os.path.join(self.models_dir, f"{model_name}_latest.joblib")
        joblib.dump(model, latest_path)
        
        logger.info(f"Saved model {model_name} version {version}")
        return version
    
    def load_model(self, model_name: str, version: str = "latest"):
        """Load a specific model version"""
        model_path = os.path.join(self.models_dir, f"{model_name}_{version}.joblib")
        
        if not os.path.exists(model_path):
            raise FileNotFoundError(f"Model {model_name} version {version} not found")
        
        return joblib.load(model_path)
    
    def list_model_versions(self, model_name: str) -> List[str]:
        """List all versions of a model"""
        versions = []
        for filename in os.listdir(self.models_dir):
            if filename.startswith(f"{model_name}_") and filename.endswith(".joblib"):
                version = filename.replace(f"{model_name}_", "").replace(".joblib", "")
                if version != "latest":
                    versions.append(version)
        return sorted(versions, reverse=True)

class ContinuousLearner:
    """Main continuous learning orchestrator"""
    
    def __init__(self, models_dir: str = "models", db_path: str = "feedback.db"):
        self.model_store = ModelStore(models_dir)
        self.feedback_collector = FeedbackCollector(db_path)
        self.current_detector = None
        self.last_retrain_time = None
        
    async def initialize(self):
        """Initialize the continuous learner"""
        try:
            # Try to load existing detector
            self.current_detector = self.model_store.load_model('ensemble_detector')
            logger.info("Loaded existing ensemble detector")
        except FileNotFoundError:
            # Create new detector if none exists
            self.current_detector = EnsembleDetector()
            logger.info("Created new ensemble detector")
    
    async def start_continuous_learning(self):
        """Start the continuous learning loop"""
        logger.info("Starting continuous learning system")
        
        while True:
            try:
                await self.learning_cycle()
                await asyncio.sleep(3600)  # Check every hour
            except Exception as e:
                logger.error(f"Error in learning cycle: {e}")
                await asyncio.sleep(1800)  # Wait 30 minutes on error
    
    async def learning_cycle(self):
        """Execute one learning cycle"""
        # Check if it's time to retrain
        if self._should_retrain():
            await self.retrain_models()
        
        # Log current statistics
        stats = await self.feedback_collector.get_feedback_stats()
        logger.info(f"Feedback stats: {stats}")
    
    def _should_retrain(self) -> bool:
        """Determine if models should be retrained"""
        # Check time since last retrain
        if self.last_retrain_time is None:
            return True
        
        time_since_retrain = datetime.now() - self.last_retrain_time
        if time_since_retrain > timedelta(hours=RETRAIN_INTERVAL_HOURS):
            return True
        
        return False
    
    async def retrain_models(self):
        """Retrain models with new feedback data"""
        logger.info("Starting model retraining")
        
        # Collect feedback data
        feedback_data = await self.feedback_collector.get_new_feedback()
        
        if len(feedback_data) < MIN_FEEDBACK_THRESHOLD:
            logger.info(f"Insufficient feedback data: {len(feedback_data)} < {MIN_FEEDBACK_THRESHOLD}")
            return
        
        # Prepare training data
        training_data = self._prepare_training_data(feedback_data)
        
        # Create new detector for training
        new_detector = EnsembleDetector()
        
        # Train the malicious classifier
        await self._retrain_malicious_classifier(new_detector, training_data)
        
        # Update similarity model with new packages
        await self._update_similarity_model(new_detector, feedback_data)
        
        # Validate the new model
        performance = await self._validate_model(new_detector, training_data)
        
        if performance.f1_score > PERFORMANCE_THRESHOLD:
            # Save the new model
            version = self.model_store.save_model('ensemble_detector', new_detector)
            self.current_detector = new_detector
            
            # Record performance
            await self._record_performance(performance, version)
            
            # Mark feedback as processed
            package_names = [f.package_name for f in feedback_data]
            await self.feedback_collector.mark_feedback_processed(package_names)
            
            self.last_retrain_time = datetime.now()
            logger.info(f"Model retrained successfully. F1 score: {performance.f1_score:.3f}")
        else:
            logger.warning(f"New model performance below threshold: {performance.f1_score:.3f} < {PERFORMANCE_THRESHOLD}")
    
    def _prepare_training_data(self, feedback_data: List[FeedbackData]) -> List[Tuple[PackageData, bool]]:
        """Prepare training data from feedback"""
        training_data = []
        
        for feedback in feedback_data:
            # Convert actual risk to binary classification
            is_malicious = feedback.actual_risk > 50.0
            training_data.append((feedback.package_data, is_malicious))
        
        # Limit training data size
        if len(training_data) > MAX_TRAINING_SAMPLES:
            training_data = training_data[:MAX_TRAINING_SAMPLES]
        
        return training_data
    
    async def _retrain_malicious_classifier(self, detector: EnsembleDetector, training_data: List[Tuple[PackageData, bool]]):
        """Retrain the malicious package classifier"""
        logger.info(f"Retraining malicious classifier with {len(training_data)} samples")
        detector.malicious_classifier.train(training_data)
    
    async def _update_similarity_model(self, detector: EnsembleDetector, feedback_data: List[FeedbackData]):
        """Update similarity model with new legitimate packages"""
        # Extract legitimate package names (low actual risk)
        legitimate_packages = [
            f.package_name for f in feedback_data
            if f.actual_risk < 30.0  # Consider low-risk packages as legitimate
        ]
        
        if legitimate_packages:
            # Load existing known packages and add new ones
            existing_packages = list(detector.similarity_model.known_packages)
            all_packages = list(set(existing_packages + legitimate_packages))
            detector.similarity_model.load_known_packages(all_packages)
            logger.info(f"Updated similarity model with {len(legitimate_packages)} new legitimate packages")
    
    async def _validate_model(self, detector: EnsembleDetector, training_data: List[Tuple[PackageData, bool]]) -> ModelPerformance:
        """Validate model performance on test data"""
        # Split data for validation
        train_data, test_data = train_test_split(training_data, test_size=0.2, random_state=42)
        
        # Get predictions on test set
        y_true = []
        y_pred = []
        
        for package_data, is_malicious in test_data:
            assessment = detector.analyze_package(package_data)
            predicted_malicious = assessment.risk_score > 50.0
            
            y_true.append(is_malicious)
            y_pred.append(predicted_malicious)
        
        # Calculate metrics
        accuracy = accuracy_score(y_true, y_pred)
        precision = precision_score(y_true, y_pred, zero_division=0)
        recall = recall_score(y_true, y_pred, zero_division=0)
        f1 = f1_score(y_true, y_pred, zero_division=0)
        
        return ModelPerformance(
            accuracy=accuracy,
            precision=precision,
            recall=recall,
            f1_score=f1,
            timestamp=datetime.now(),
            model_version="retrained"
        )
    
    async def _record_performance(self, performance: ModelPerformance, version: str):
        """Record model performance in database"""
        conn = sqlite3.connect(self.feedback_collector.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            INSERT INTO model_performance (
                accuracy, precision_val, recall_val, f1_score, timestamp, model_version
            ) VALUES (?, ?, ?, ?, ?, ?)
        """, (
            performance.accuracy,
            performance.precision,
            performance.recall,
            performance.f1_score,
            performance.timestamp.isoformat(),
            version
        ))
        
        conn.commit()
        conn.close()
    
    async def get_model_performance_history(self) -> List[ModelPerformance]:
        """Get historical model performance data"""
        conn = sqlite3.connect(self.feedback_collector.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT accuracy, precision_val, recall_val, f1_score, timestamp, model_version
            FROM model_performance
            ORDER BY timestamp DESC
            LIMIT 50
        """)
        
        rows = cursor.fetchall()
        performance_history = []
        
        for row in rows:
            performance = ModelPerformance(
                accuracy=row[0],
                precision=row[1],
                recall=row[2],
                f1_score=row[3],
                timestamp=datetime.fromisoformat(row[4]),
                model_version=row[5]
            )
            performance_history.append(performance)
        
        conn.close()
        return performance_history
    
    async def add_analyst_feedback(self, package_name: str, registry: str, 
                                 predicted_risk: float, actual_risk: float,
                                 analyst_notes: str, package_data: PackageData):
        """Add feedback from human analyst"""
        feedback = FeedbackData(
            package_name=package_name,
            registry=registry,
            predicted_risk=predicted_risk,
            actual_risk=actual_risk,
            analyst_feedback=analyst_notes,
            confidence=0.9,  # High confidence for human feedback
            timestamp=datetime.now(),
            package_data=package_data
        )
        
        await self.feedback_collector.add_feedback(feedback)
        logger.info(f"Added analyst feedback for {package_name}")

async def main():
    """Test the continuous learning system"""
    learner = ContinuousLearner()
    await learner.initialize()
    
    # Simulate some feedback data
    test_package = PackageData(
        name="test-package",
        registry="npm",
        version="1.0.0",
        metadata={"description": "Test package"},
        source_code="console.log('hello');",
        dependencies=[],
        download_count=1000
    )
    
    # Add some test feedback
    await learner.add_analyst_feedback(
        package_name="test-package",
        registry="npm",
        predicted_risk=30.0,
        actual_risk=10.0,
        analyst_notes="False positive - package is legitimate",
        package_data=test_package
    )
    
    # Get feedback stats
    stats = await learner.feedback_collector.get_feedback_stats()
    print(f"Feedback statistics: {stats}")
    
    # Get performance history
    history = await learner.get_model_performance_history()
    print(f"Performance history: {len(history)} records")
    
    print("Continuous learning system test completed")

if __name__ == "__main__":
    asyncio.run(main())