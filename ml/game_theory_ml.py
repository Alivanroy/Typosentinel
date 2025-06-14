#!/usr/bin/env python3
"""
Game Theory Machine Learning Module for TypoSentinel

This module provides machine learning capabilities for game theory-based risk assessment,
including Nash equilibrium prediction, supplier risk modeling, and ROI optimization.

Implements US-013: Game Theory-Based Risk Assessment
"""

import numpy as np
import pandas as pd
from typing import Dict, List, Tuple, Optional, Any
import json
import logging
from datetime import datetime, timedelta
from dataclasses import dataclass, asdict
from sklearn.ensemble import RandomForestRegressor, GradientBoostingClassifier
from sklearn.neural_network import MLPRegressor
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import mean_squared_error, accuracy_score, classification_report
import joblib
import scipy.optimize as opt
from scipy.stats import norm
import warnings
warnings.filterwarnings('ignore')

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class GameTheoryFeatures:
    """Features for game theory ML models"""
    player_id: str
    player_type: str
    trust_score: float
    penalty_score: float
    vulnerability_score: float
    threat_exposure: float
    compliance_score: float
    revenue: float
    security_budget: float
    operational_cost: float
    downtime_cost: float
    reputation_value: float
    market_share: float
    industry: str
    historical_incidents: int
    avg_incident_cost: float
    time_since_last_incident: int  # days
    strategy_effectiveness: List[float]
    strategy_costs: List[float]
    risk_reduction_potential: List[float]
    
class GameTheoryMLEngine:
    """Machine Learning engine for game theory risk assessment"""
    
    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or self._default_config()
        self.models = {}
        self.scalers = {}
        self.encoders = {}
        self.feature_importance = {}
        self.model_performance = {}
        
        # Initialize models
        self._initialize_models()
        
    def _default_config(self) -> Dict[str, Any]:
        """Default configuration for ML models"""
        return {
            'nash_equilibrium': {
                'model_type': 'neural_network',
                'hidden_layers': (100, 50, 25),
                'max_iter': 1000,
                'random_state': 42
            },
            'supplier_risk': {
                'model_type': 'random_forest',
                'n_estimators': 100,
                'max_depth': 10,
                'random_state': 42
            },
            'roi_optimization': {
                'model_type': 'gradient_boosting',
                'n_estimators': 100,
                'learning_rate': 0.1,
                'max_depth': 6,
                'random_state': 42
            },
            'penalty_prediction': {
                'model_type': 'random_forest',
                'n_estimators': 50,
                'max_depth': 8,
                'random_state': 42
            }
        }
    
    def _initialize_models(self):
        """Initialize ML models"""
        # Nash Equilibrium Predictor
        nash_config = self.config['nash_equilibrium']
        self.models['nash_equilibrium'] = MLPRegressor(
            hidden_layer_sizes=nash_config['hidden_layers'],
            max_iter=nash_config['max_iter'],
            random_state=nash_config['random_state']
        )
        
        # Supplier Risk Classifier
        supplier_config = self.config['supplier_risk']
        self.models['supplier_risk'] = RandomForestRegressor(
            n_estimators=supplier_config['n_estimators'],
            max_depth=supplier_config['max_depth'],
            random_state=supplier_config['random_state']
        )
        
        # ROI Optimization Model
        roi_config = self.config['roi_optimization']
        self.models['roi_optimization'] = GradientBoostingClassifier(
            n_estimators=roi_config['n_estimators'],
            learning_rate=roi_config['learning_rate'],
            max_depth=roi_config['max_depth'],
            random_state=roi_config['random_state']
        )
        
        # Penalty Prediction Model
        penalty_config = self.config['penalty_prediction']
        self.models['penalty_prediction'] = RandomForestRegressor(
            n_estimators=penalty_config['n_estimators'],
            max_depth=penalty_config['max_depth'],
            random_state=penalty_config['random_state']
        )
        
        # Initialize scalers and encoders
        for model_name in self.models.keys():
            self.scalers[model_name] = StandardScaler()
            self.encoders[model_name] = LabelEncoder()
    
    def prepare_features(self, features: GameTheoryFeatures) -> np.ndarray:
        """Prepare features for ML models"""
        # Convert to numerical features
        numerical_features = [
            features.trust_score,
            features.penalty_score,
            features.vulnerability_score,
            features.threat_exposure,
            features.compliance_score,
            features.revenue,
            features.security_budget,
            features.operational_cost,
            features.downtime_cost,
            features.reputation_value,
            features.market_share,
            features.historical_incidents,
            features.avg_incident_cost,
            features.time_since_last_incident,
        ]
        
        # Add strategy statistics
        if features.strategy_effectiveness:
            numerical_features.extend([
                np.mean(features.strategy_effectiveness),
                np.std(features.strategy_effectiveness),
                np.max(features.strategy_effectiveness),
                np.min(features.strategy_effectiveness)
            ])
        else:
            numerical_features.extend([0, 0, 0, 0])
            
        if features.strategy_costs:
            numerical_features.extend([
                np.mean(features.strategy_costs),
                np.std(features.strategy_costs),
                np.max(features.strategy_costs),
                np.min(features.strategy_costs)
            ])
        else:
            numerical_features.extend([0, 0, 0, 0])
            
        if features.risk_reduction_potential:
            numerical_features.extend([
                np.mean(features.risk_reduction_potential),
                np.std(features.risk_reduction_potential),
                np.max(features.risk_reduction_potential),
                np.min(features.risk_reduction_potential)
            ])
        else:
            numerical_features.extend([0, 0, 0, 0])
        
        # Encode categorical features
        player_type_encoded = self._encode_player_type(features.player_type)
        industry_encoded = self._encode_industry(features.industry)
        
        # Combine all features
        all_features = numerical_features + [player_type_encoded, industry_encoded]
        
        return np.array(all_features).reshape(1, -1)
    
    def _encode_player_type(self, player_type: str) -> int:
        """Encode player type to numerical value"""
        type_mapping = {
            'defender': 0,
            'attacker': 1,
            'supplier': 2,
            'organization': 3
        }
        return type_mapping.get(player_type.lower(), 0)
    
    def _encode_industry(self, industry: str) -> int:
        """Encode industry to numerical value"""
        industry_mapping = {
            'technology': 0,
            'finance': 1,
            'healthcare': 2,
            'manufacturing': 3,
            'retail': 4,
            'government': 5,
            'education': 6,
            'other': 7
        }
        return industry_mapping.get(industry.lower(), 7)
    
    def predict_nash_equilibrium(self, features: GameTheoryFeatures) -> Dict[str, Any]:
        """Predict Nash equilibrium strategies using ML"""
        try:
            X = self.prepare_features(features)
            
            # Check if model is trained
            if not hasattr(self.models['nash_equilibrium'], 'coefs_'):
                logger.warning("Nash equilibrium model not trained, using analytical approach")
                return self._analytical_nash_equilibrium(features)
            
            # Scale features
            X_scaled = self.scalers['nash_equilibrium'].transform(X)
            
            # Predict equilibrium probabilities
            predictions = self.models['nash_equilibrium'].predict(X_scaled)
            
            # Convert to strategy probabilities (assuming 3 strategies)
            num_strategies = 3
            strategies = self._softmax(predictions[:num_strategies])
            
            # Calculate expected payoffs
            payoffs = self._calculate_expected_payoffs(features, strategies)
            
            # Calculate stability and convergence metrics
            stability = self._calculate_stability(strategies)
            
            return {
                'strategies': strategies.tolist(),
                'payoffs': payoffs,
                'stability': stability,
                'converged': stability > 0.8,
                'confidence': min(stability, 0.95),
                'method': 'ml_prediction'
            }
            
        except Exception as e:
            logger.error(f"Error in Nash equilibrium prediction: {e}")
            return self._analytical_nash_equilibrium(features)
    
    def _analytical_nash_equilibrium(self, features: GameTheoryFeatures) -> Dict[str, Any]:
        """Fallback analytical Nash equilibrium calculation"""
        # Simple analytical approach for demonstration
        # In practice, this would use more sophisticated game theory algorithms
        
        # Create payoff matrix based on features
        payoff_matrix = self._create_payoff_matrix(features)
        
        # Find mixed strategy Nash equilibrium using linear programming
        strategies = self._solve_mixed_strategy(payoff_matrix)
        
        # Calculate payoffs
        payoffs = {
            'player': np.dot(strategies, np.diag(payoff_matrix)),
            'opponent': np.dot(strategies, np.diag(payoff_matrix.T))
        }
        
        return {
            'strategies': strategies.tolist(),
            'payoffs': payoffs,
            'stability': 0.7,  # Default stability
            'converged': True,
            'confidence': 0.8,
            'method': 'analytical'
        }
    
    def assess_supplier_risk_ml(self, features: GameTheoryFeatures) -> Dict[str, Any]:
        """ML-based supplier risk assessment"""
        try:
            X = self.prepare_features(features)
            
            # Check if model is trained
            if not hasattr(self.models['supplier_risk'], 'feature_importances_'):
                logger.warning("Supplier risk model not trained, using heuristic approach")
                return self._heuristic_supplier_risk(features)
            
            # Scale features
            X_scaled = self.scalers['supplier_risk'].transform(X)
            
            # Predict risk score
            risk_score = self.models['supplier_risk'].predict(X_scaled)[0]
            
            # Calculate game theory score
            game_theory_score = self._calculate_game_theory_score(features, risk_score)
            
            # Determine recommended action
            recommended_action = self._determine_action(game_theory_score)
            
            # Calculate confidence based on model performance
            confidence = self.model_performance.get('supplier_risk', {}).get('accuracy', 0.8)
            
            return {
                'risk_score': max(0, min(100, risk_score)),
                'game_theory_score': max(0, min(100, game_theory_score)),
                'trust_level': features.trust_score,
                'recommended_action': recommended_action,
                'confidence': confidence,
                'risk_factors': self._identify_risk_factors(features),
                'method': 'ml_prediction'
            }
            
        except Exception as e:
            logger.error(f"Error in supplier risk assessment: {e}")
            return self._heuristic_supplier_risk(features)
    
    def optimize_roi_ml(self, features: GameTheoryFeatures, 
                       investment_options: List[Dict[str, Any]]) -> Dict[str, Any]:
        """ML-based ROI optimization"""
        try:
            best_roi = -float('inf')
            best_option = None
            best_analysis = None
            
            for option in investment_options:
                # Create features for this investment option
                option_features = self._create_investment_features(features, option)
                X = self.prepare_features(option_features)
                
                # Predict ROI if model is trained
                if hasattr(self.models['roi_optimization'], 'feature_importances_'):
                    X_scaled = self.scalers['roi_optimization'].transform(X)
                    roi_prediction = self.models['roi_optimization'].predict_proba(X_scaled)[0]
                    roi = np.mean(roi_prediction)  # Average probability as ROI indicator
                else:
                    roi = self._calculate_analytical_roi(features, option)
                
                if roi > best_roi:
                    best_roi = roi
                    best_option = option
                    best_analysis = self._detailed_roi_analysis(features, option, roi)
            
            return best_analysis
            
        except Exception as e:
            logger.error(f"Error in ROI optimization: {e}")
            return self._fallback_roi_analysis(features, investment_options)
    
    def predict_penalty_progression(self, features: GameTheoryFeatures, 
                                  incident_severity: str) -> Dict[str, Any]:
        """Predict penalty progression for malicious actors"""
        try:
            # Create incident features
            incident_features = self._create_incident_features(features, incident_severity)
            X = self.prepare_features(incident_features)
            
            # Predict penalty if model is trained
            if hasattr(self.models['penalty_prediction'], 'feature_importances_'):
                X_scaled = self.scalers['penalty_prediction'].transform(X)
                penalty_prediction = self.models['penalty_prediction'].predict(X_scaled)[0]
            else:
                penalty_prediction = self._calculate_analytical_penalty(features, incident_severity)
            
            # Calculate progressive penalty system
            current_penalty = features.penalty_score
            new_penalty = current_penalty + penalty_prediction
            
            # Calculate new trust score
            new_trust_score = max(0, 1.0 - (new_penalty / 100.0))
            
            # Predict future penalties
            future_penalties = self._predict_future_penalties(features, penalty_prediction)
            
            return {
                'current_penalty': current_penalty,
                'penalty_increase': penalty_prediction,
                'new_penalty': new_penalty,
                'new_trust_score': new_trust_score,
                'future_penalties': future_penalties,
                'severity_impact': self._calculate_severity_impact(incident_severity),
                'recommendation': self._penalty_recommendation(new_penalty, new_trust_score)
            }
            
        except Exception as e:
            logger.error(f"Error in penalty prediction: {e}")
            return self._fallback_penalty_analysis(features, incident_severity)
    
    def train_models(self, training_data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Train all ML models with provided data"""
        results = {}
        
        try:
            # Prepare training data
            X, y_nash, y_risk, y_roi, y_penalty = self._prepare_training_data(training_data)
            
            # Train Nash equilibrium model
            if len(y_nash) > 0:
                results['nash_equilibrium'] = self._train_nash_model(X, y_nash)
            
            # Train supplier risk model
            if len(y_risk) > 0:
                results['supplier_risk'] = self._train_risk_model(X, y_risk)
            
            # Train ROI optimization model
            if len(y_roi) > 0:
                results['roi_optimization'] = self._train_roi_model(X, y_roi)
            
            # Train penalty prediction model
            if len(y_penalty) > 0:
                results['penalty_prediction'] = self._train_penalty_model(X, y_penalty)
            
            logger.info("Model training completed successfully")
            return results
            
        except Exception as e:
            logger.error(f"Error in model training: {e}")
            return {'error': str(e)}
    
    def save_models(self, model_dir: str) -> bool:
        """Save trained models to disk"""
        try:
            for model_name, model in self.models.items():
                model_path = f"{model_dir}/{model_name}_model.joblib"
                scaler_path = f"{model_dir}/{model_name}_scaler.joblib"
                
                joblib.dump(model, model_path)
                joblib.dump(self.scalers[model_name], scaler_path)
            
            # Save configuration and performance metrics
            config_path = f"{model_dir}/config.json"
            with open(config_path, 'w') as f:
                json.dump({
                    'config': self.config,
                    'performance': self.model_performance,
                    'feature_importance': self.feature_importance
                }, f, indent=2)
            
            logger.info(f"Models saved to {model_dir}")
            return True
            
        except Exception as e:
            logger.error(f"Error saving models: {e}")
            return False
    
    def load_models(self, model_dir: str) -> bool:
        """Load trained models from disk"""
        try:
            for model_name in self.models.keys():
                model_path = f"{model_dir}/{model_name}_model.joblib"
                scaler_path = f"{model_dir}/{model_name}_scaler.joblib"
                
                self.models[model_name] = joblib.load(model_path)
                self.scalers[model_name] = joblib.load(scaler_path)
            
            # Load configuration and performance metrics
            config_path = f"{model_dir}/config.json"
            with open(config_path, 'r') as f:
                data = json.load(f)
                self.config = data.get('config', self.config)
                self.model_performance = data.get('performance', {})
                self.feature_importance = data.get('feature_importance', {})
            
            logger.info(f"Models loaded from {model_dir}")
            return True
            
        except Exception as e:
            logger.error(f"Error loading models: {e}")
            return False
    
    # Helper methods
    
    def _softmax(self, x: np.ndarray) -> np.ndarray:
        """Apply softmax function to convert to probabilities"""
        exp_x = np.exp(x - np.max(x))
        return exp_x / np.sum(exp_x)
    
    def _calculate_expected_payoffs(self, features: GameTheoryFeatures, 
                                  strategies: np.ndarray) -> Dict[str, float]:
        """Calculate expected payoffs for given strategies"""
        # Simplified payoff calculation
        base_payoff = features.revenue * 0.01  # 1% of revenue as base
        risk_adjustment = (100 - features.vulnerability_score) * 0.01
        trust_bonus = features.trust_score * base_payoff * 0.1
        
        player_payoff = base_payoff * risk_adjustment + trust_bonus
        opponent_payoff = base_payoff * (1 - risk_adjustment)
        
        return {
            'player': player_payoff,
            'opponent': opponent_payoff
        }
    
    def _calculate_stability(self, strategies: np.ndarray) -> float:
        """Calculate stability of mixed strategy"""
        # Stability based on entropy (more uniform = more stable)
        entropy = -np.sum(strategies * np.log(strategies + 1e-10))
        max_entropy = np.log(len(strategies))
        return entropy / max_entropy
    
    def _create_payoff_matrix(self, features: GameTheoryFeatures) -> np.ndarray:
        """Create payoff matrix based on features"""
        # Simplified 3x3 payoff matrix
        base_values = np.array([
            [10, -5, -20],
            [8, 5, -10],
            [0, 0, 0]
        ])
        
        # Adjust based on trust score and other factors
        trust_multiplier = features.trust_score
        risk_multiplier = 1.0 - (features.vulnerability_score / 100.0)
        
        return base_values * trust_multiplier * risk_multiplier
    
    def _solve_mixed_strategy(self, payoff_matrix: np.ndarray) -> np.ndarray:
        """Solve for mixed strategy Nash equilibrium"""
        # Simplified approach - in practice would use more sophisticated algorithms
        n = payoff_matrix.shape[0]
        
        # Use optimization to find equilibrium
        def objective(x):
            return -np.sum(x * np.diag(payoff_matrix))
        
        constraints = [
            {'type': 'eq', 'fun': lambda x: np.sum(x) - 1},  # Probabilities sum to 1
        ]
        bounds = [(0, 1) for _ in range(n)]  # Probabilities between 0 and 1
        
        result = opt.minimize(objective, np.ones(n)/n, method='SLSQP', 
                            bounds=bounds, constraints=constraints)
        
        return result.x if result.success else np.ones(n)/n
    
    def _heuristic_supplier_risk(self, features: GameTheoryFeatures) -> Dict[str, Any]:
        """Heuristic supplier risk assessment"""
        # Calculate risk score based on weighted factors
        vulnerability_weight = 0.3
        threat_weight = 0.2
        penalty_weight = 0.3
        trust_weight = 0.2
        
        risk_score = (
            vulnerability_weight * features.vulnerability_score +
            threat_weight * features.threat_exposure +
            penalty_weight * features.penalty_score +
            trust_weight * (100 - features.trust_score * 100)
        )
        
        game_theory_score = max(0, 100 - risk_score)
        
        return {
            'risk_score': max(0, min(100, risk_score)),
            'game_theory_score': max(0, min(100, game_theory_score)),
            'trust_level': features.trust_score,
            'recommended_action': self._determine_action(game_theory_score),
            'confidence': 0.7,
            'method': 'heuristic'
        }
    
    def _calculate_game_theory_score(self, features: GameTheoryFeatures, 
                                   risk_score: float) -> float:
        """Calculate game theory score"""
        base_score = 100 - risk_score
        trust_bonus = features.trust_score * 20
        compliance_bonus = features.compliance_score * 0.2
        penalty_penalty = features.penalty_score
        
        score = base_score + trust_bonus + compliance_bonus - penalty_penalty
        return max(0, min(100, score))
    
    def _determine_action(self, game_theory_score: float) -> str:
        """Determine recommended action based on score"""
        if game_theory_score >= 80:
            return "Continue partnership with standard monitoring"
        elif game_theory_score >= 60:
            return "Continue with enhanced monitoring and verification"
        elif game_theory_score >= 40:
            return "Require security improvements before continuing"
        elif game_theory_score >= 20:
            return "Consider alternative suppliers"
        else:
            return "Terminate partnership immediately"
    
    def _identify_risk_factors(self, features: GameTheoryFeatures) -> List[str]:
        """Identify key risk factors"""
        risk_factors = []
        
        if features.vulnerability_score > 70:
            risk_factors.append("High vulnerability score")
        if features.threat_exposure > 60:
            risk_factors.append("High threat exposure")
        if features.penalty_score > 50:
            risk_factors.append("High penalty score")
        if features.trust_score < 0.5:
            risk_factors.append("Low trust score")
        if features.compliance_score < 60:
            risk_factors.append("Poor compliance score")
        if features.historical_incidents > 5:
            risk_factors.append("High number of historical incidents")
        
        return risk_factors
    
    def _create_investment_features(self, base_features: GameTheoryFeatures, 
                                  option: Dict[str, Any]) -> GameTheoryFeatures:
        """Create features for investment option analysis"""
        # Copy base features and modify based on investment option
        new_features = GameTheoryFeatures(**asdict(base_features))
        
        # Adjust features based on investment
        cost = option.get('cost', 0)
        effectiveness = option.get('effectiveness', 0)
        risk_reduction = option.get('risk_reduction', 0)
        
        # Update security budget and risk scores
        new_features.security_budget += cost
        new_features.vulnerability_score = max(0, new_features.vulnerability_score - risk_reduction)
        new_features.threat_exposure = max(0, new_features.threat_exposure - (effectiveness * 10))
        
        return new_features
    
    def _calculate_analytical_roi(self, features: GameTheoryFeatures, 
                                option: Dict[str, Any]) -> float:
        """Calculate ROI analytically"""
        investment = option.get('cost', 0)
        effectiveness = option.get('effectiveness', 0)
        risk_reduction = option.get('risk_reduction', 0)
        
        # Calculate expected return
        risk_reduction_value = risk_reduction * features.revenue * 0.01
        operational_savings = effectiveness * features.operational_cost * 0.05
        reputation_value = risk_reduction * features.reputation_value * 0.02
        
        expected_return = risk_reduction_value + operational_savings + reputation_value
        
        if investment == 0:
            return 0
        
        return (expected_return - investment) / investment
    
    def _detailed_roi_analysis(self, features: GameTheoryFeatures, 
                             option: Dict[str, Any], roi: float) -> Dict[str, Any]:
        """Perform detailed ROI analysis"""
        investment = option.get('cost', 0)
        effectiveness = option.get('effectiveness', 0)
        risk_reduction = option.get('risk_reduction', 0)
        
        # Calculate components
        risk_reduction_value = risk_reduction * features.revenue * 0.01
        operational_savings = effectiveness * features.operational_cost * 0.05
        reputation_value = risk_reduction * features.reputation_value * 0.02
        
        expected_return = risk_reduction_value + operational_savings + reputation_value
        
        # Calculate payback period
        annual_return = expected_return
        payback_years = investment / annual_return if annual_return > 0 else float('inf')
        
        # Calculate NPV
        discount_rate = 0.1
        npv = -investment
        for year in range(1, 6):
            npv += annual_return / ((1 + discount_rate) ** year)
        
        return {
            'investment': investment,
            'expected_return': expected_return,
            'risk_reduction': risk_reduction,
            'payback_period_years': payback_years,
            'net_present_value': npv,
            'internal_rate_return': roi,
            'recommendation': "Recommended" if roi > 0.15 else "Not recommended",
            'confidence': 0.8
        }
    
    def _fallback_roi_analysis(self, features: GameTheoryFeatures, 
                             investment_options: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Fallback ROI analysis"""
        if not investment_options:
            return {'error': 'No investment options provided'}
        
        # Simple heuristic: choose option with best risk_reduction/cost ratio
        best_option = max(investment_options, 
                         key=lambda x: x.get('risk_reduction', 0) / max(x.get('cost', 1), 1))
        
        return self._detailed_roi_analysis(features, best_option, 0.1)
    
    def _create_incident_features(self, base_features: GameTheoryFeatures, 
                                severity: str) -> GameTheoryFeatures:
        """Create features for incident analysis"""
        new_features = GameTheoryFeatures(**asdict(base_features))
        
        # Adjust features based on incident severity
        severity_impact = {
            'low': 1.0,
            'medium': 2.0,
            'high': 4.0,
            'critical': 8.0
        }
        
        impact = severity_impact.get(severity.lower(), 2.0)
        new_features.historical_incidents += 1
        new_features.vulnerability_score = min(100, new_features.vulnerability_score + impact * 5)
        new_features.threat_exposure = min(100, new_features.threat_exposure + impact * 3)
        
        return new_features
    
    def _calculate_analytical_penalty(self, features: GameTheoryFeatures, 
                                    severity: str) -> float:
        """Calculate penalty analytically"""
        base_penalty = 10.0  # Base penalty
        
        severity_multiplier = {
            'low': 1.0,
            'medium': 2.0,
            'high': 4.0,
            'critical': 8.0
        }
        
        # Progressive multiplier based on history
        history_multiplier = 1.0 + (features.historical_incidents * 0.5)
        
        # Trust score affects penalty
        trust_multiplier = 2.0 - features.trust_score
        
        penalty = (base_penalty * 
                  severity_multiplier.get(severity.lower(), 2.0) * 
                  history_multiplier * 
                  trust_multiplier)
        
        return penalty
    
    def _predict_future_penalties(self, features: GameTheoryFeatures, 
                                current_penalty: float) -> List[float]:
        """Predict future penalty progression"""
        future_penalties = []
        penalty = current_penalty
        decay_rate = 0.1  # 10% decay per period
        
        for period in range(1, 13):  # Next 12 periods
            penalty *= (1 - decay_rate)
            future_penalties.append(penalty)
        
        return future_penalties
    
    def _calculate_severity_impact(self, severity: str) -> Dict[str, float]:
        """Calculate impact of incident severity"""
        severity_impacts = {
            'low': {'trust_impact': -0.05, 'reputation_impact': -0.02, 'cost_multiplier': 1.0},
            'medium': {'trust_impact': -0.1, 'reputation_impact': -0.05, 'cost_multiplier': 2.0},
            'high': {'trust_impact': -0.2, 'reputation_impact': -0.1, 'cost_multiplier': 4.0},
            'critical': {'trust_impact': -0.4, 'reputation_impact': -0.2, 'cost_multiplier': 8.0}
        }
        
        return severity_impacts.get(severity.lower(), severity_impacts['medium'])
    
    def _penalty_recommendation(self, penalty_score: float, trust_score: float) -> str:
        """Generate penalty recommendation"""
        if penalty_score > 80:
            return "Immediate termination recommended"
        elif penalty_score > 60:
            return "Severe restrictions and monitoring required"
        elif penalty_score > 40:
            return "Enhanced monitoring and corrective actions required"
        elif penalty_score > 20:
            return "Increased monitoring recommended"
        else:
            return "Standard monitoring sufficient"
    
    def _fallback_penalty_analysis(self, features: GameTheoryFeatures, 
                                 severity: str) -> Dict[str, Any]:
        """Fallback penalty analysis"""
        penalty_increase = self._calculate_analytical_penalty(features, severity)
        new_penalty = features.penalty_score + penalty_increase
        new_trust_score = max(0, 1.0 - (new_penalty / 100.0))
        
        return {
            'current_penalty': features.penalty_score,
            'penalty_increase': penalty_increase,
            'new_penalty': new_penalty,
            'new_trust_score': new_trust_score,
            'future_penalties': self._predict_future_penalties(features, penalty_increase),
            'severity_impact': self._calculate_severity_impact(severity),
            'recommendation': self._penalty_recommendation(new_penalty, new_trust_score),
            'method': 'analytical'
        }
    
    def _prepare_training_data(self, training_data: List[Dict[str, Any]]) -> Tuple:
        """Prepare training data for all models"""
        X = []
        y_nash = []
        y_risk = []
        y_roi = []
        y_penalty = []
        
        for data_point in training_data:
            features = GameTheoryFeatures(**data_point['features'])
            X.append(self.prepare_features(features).flatten())
            
            if 'nash_equilibrium' in data_point:
                y_nash.append(data_point['nash_equilibrium'])
            
            if 'risk_score' in data_point:
                y_risk.append(data_point['risk_score'])
            
            if 'roi' in data_point:
                y_roi.append(1 if data_point['roi'] > 0.15 else 0)  # Binary classification
            
            if 'penalty' in data_point:
                y_penalty.append(data_point['penalty'])
        
        return np.array(X), y_nash, y_risk, y_roi, y_penalty
    
    def _train_nash_model(self, X: np.ndarray, y: List) -> Dict[str, Any]:
        """Train Nash equilibrium model"""
        if len(y) < 10:  # Need minimum samples
            return {'error': 'Insufficient training data'}
        
        # Prepare target data (flatten if needed)
        y_array = np.array(y)
        if y_array.ndim > 1:
            y_array = y_array.reshape(len(y), -1)
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(X, y_array, test_size=0.2, random_state=42)
        
        # Scale features
        X_train_scaled = self.scalers['nash_equilibrium'].fit_transform(X_train)
        X_test_scaled = self.scalers['nash_equilibrium'].transform(X_test)
        
        # Train model
        self.models['nash_equilibrium'].fit(X_train_scaled, y_train)
        
        # Evaluate
        y_pred = self.models['nash_equilibrium'].predict(X_test_scaled)
        mse = mean_squared_error(y_test, y_pred)
        
        self.model_performance['nash_equilibrium'] = {'mse': mse}
        
        return {'mse': mse, 'samples': len(y)}
    
    def _train_risk_model(self, X: np.ndarray, y: List) -> Dict[str, Any]:
        """Train supplier risk model"""
        if len(y) < 10:
            return {'error': 'Insufficient training data'}
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
        
        # Scale features
        X_train_scaled = self.scalers['supplier_risk'].fit_transform(X_train)
        X_test_scaled = self.scalers['supplier_risk'].transform(X_test)
        
        # Train model
        self.models['supplier_risk'].fit(X_train_scaled, y_train)
        
        # Evaluate
        y_pred = self.models['supplier_risk'].predict(X_test_scaled)
        mse = mean_squared_error(y_test, y_pred)
        
        # Feature importance
        self.feature_importance['supplier_risk'] = self.models['supplier_risk'].feature_importances_.tolist()
        self.model_performance['supplier_risk'] = {'mse': mse, 'accuracy': 1.0 - (mse / 100.0)}
        
        return {'mse': mse, 'samples': len(y)}
    
    def _train_roi_model(self, X: np.ndarray, y: List) -> Dict[str, Any]:
        """Train ROI optimization model"""
        if len(y) < 10:
            return {'error': 'Insufficient training data'}
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
        
        # Scale features
        X_train_scaled = self.scalers['roi_optimization'].fit_transform(X_train)
        X_test_scaled = self.scalers['roi_optimization'].transform(X_test)
        
        # Train model
        self.models['roi_optimization'].fit(X_train_scaled, y_train)
        
        # Evaluate
        y_pred = self.models['roi_optimization'].predict(X_test_scaled)
        accuracy = accuracy_score(y_test, y_pred)
        
        # Feature importance
        self.feature_importance['roi_optimization'] = self.models['roi_optimization'].feature_importances_.tolist()
        self.model_performance['roi_optimization'] = {'accuracy': accuracy}
        
        return {'accuracy': accuracy, 'samples': len(y)}
    
    def _train_penalty_model(self, X: np.ndarray, y: List) -> Dict[str, Any]:
        """Train penalty prediction model"""
        if len(y) < 10:
            return {'error': 'Insufficient training data'}
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
        
        # Scale features
        X_train_scaled = self.scalers['penalty_prediction'].fit_transform(X_train)
        X_test_scaled = self.scalers['penalty_prediction'].transform(X_test)
        
        # Train model
        self.models['penalty_prediction'].fit(X_train_scaled, y_train)
        
        # Evaluate
        y_pred = self.models['penalty_prediction'].predict(X_test_scaled)
        mse = mean_squared_error(y_test, y_pred)
        
        # Feature importance
        self.feature_importance['penalty_prediction'] = self.models['penalty_prediction'].feature_importances_.tolist()
        self.model_performance['penalty_prediction'] = {'mse': mse}
        
        return {'mse': mse, 'samples': len(y)}


def main():
    """Main function for testing"""
    # Initialize ML engine
    engine = GameTheoryMLEngine()
    
    # Create sample features
    features = GameTheoryFeatures(
        player_id="test_org",
        player_type="organization",
        trust_score=0.8,
        penalty_score=10.0,
        vulnerability_score=30.0,
        threat_exposure=40.0,
        compliance_score=75.0,
        revenue=1000000.0,
        security_budget=100000.0,
        operational_cost=500000.0,
        downtime_cost=50000.0,
        reputation_value=200000.0,
        market_share=0.15,
        industry="technology",
        historical_incidents=2,
        avg_incident_cost=25000.0,
        time_since_last_incident=90,
        strategy_effectiveness=[0.6, 0.8, 0.95],
        strategy_costs=[10000, 50000, 100000],
        risk_reduction_potential=[30, 60, 85]
    )
    
    # Test Nash equilibrium prediction
    print("Testing Nash Equilibrium Prediction:")
    nash_result = engine.predict_nash_equilibrium(features)
    print(json.dumps(nash_result, indent=2))
    
    # Test supplier risk assessment
    print("\nTesting Supplier Risk Assessment:")
    risk_result = engine.assess_supplier_risk_ml(features)
    print(json.dumps(risk_result, indent=2))
    
    # Test ROI optimization
    print("\nTesting ROI Optimization:")
    investment_options = [
        {'id': 'firewall', 'name': 'Next-Gen Firewall', 'cost': 25000, 'effectiveness': 0.7, 'risk_reduction': 40},
        {'id': 'siem', 'name': 'SIEM Solution', 'cost': 50000, 'effectiveness': 0.8, 'risk_reduction': 55}
    ]
    roi_result = engine.optimize_roi_ml(features, investment_options)
    print(json.dumps(roi_result, indent=2))
    
    # Test penalty prediction
    print("\nTesting Penalty Prediction:")
    penalty_result = engine.predict_penalty_progression(features, "high")
    print(json.dumps(penalty_result, indent=2))


if __name__ == "__main__":
    main()