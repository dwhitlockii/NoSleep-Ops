"""
Advanced Anomaly Detection Engine
Uses multiple ML algorithms to detect security anomalies in real-time
"""

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.svm import OneClassSVM
from sklearn.preprocessing import StandardScaler
from sklearn.decomposition import PCA
from sklearn.cluster import DBSCAN
import joblib
import json
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Tuple, Optional
import re
import hashlib

class AnomalyDetector:
    """
    Multi-algorithm anomaly detection for cybersecurity events
    """
    
    def __init__(self, model_path: str = "ml_models"):
        self.model_path = model_path
        self.models = {}
        self.scalers = {}
        self.feature_extractors = {}
        self.is_trained = False
        self.logger = self._setup_logging()
        
        # Algorithm configurations
        self.algorithms = {
            'isolation_forest': {
                'model': IsolationForest(contamination=0.1, random_state=42),
                'threshold': -0.5
            },
            'one_class_svm': {
                'model': OneClassSVM(gamma='scale', nu=0.1),
                'threshold': 0
            },
            'dbscan': {
                'model': DBSCAN(eps=0.5, min_samples=5),
                'threshold': -1  # -1 indicates outlier in DBSCAN
            }
        }
        
        self._initialize_models()
    
    def _setup_logging(self) -> logging.Logger:
        """Setup logging for the anomaly detector"""
        logger = logging.getLogger('AnomalyDetector')
        logger.setLevel(logging.INFO)
        
        if not logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            handler.setFormatter(formatter)
            logger.addHandler(handler)
        
        return logger
    
    def _initialize_models(self):
        """Initialize ML models and scalers"""
        for name, config in self.algorithms.items():
            self.models[name] = config['model']
            self.scalers[name] = StandardScaler()
    
    def extract_features(self, log_entry: Dict) -> np.ndarray:
        """
        Extract numerical features from log entries for ML processing
        """
        features = []
        
        # Temporal features
        timestamp = log_entry.get('timestamp', datetime.now())
        if isinstance(timestamp, str):
            try:
                timestamp = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
            except:
                timestamp = datetime.now()
        
        features.extend([
            timestamp.hour,  # Hour of day
            timestamp.weekday(),  # Day of week
            timestamp.minute,  # Minute of hour
        ])
        
        # IP-based features
        source_ip = log_entry.get('source_ip', '0.0.0.0')
        ip_parts = source_ip.split('.')
        if len(ip_parts) == 4:
            try:
                features.extend([int(part) for part in ip_parts])
            except:
                features.extend([0, 0, 0, 0])
        else:
            features.extend([0, 0, 0, 0])
        
        # Attack type encoding
        attack_type = log_entry.get('attack_type', 'UNKNOWN')
        attack_hash = int(hashlib.md5(attack_type.encode()).hexdigest()[:8], 16) % 1000
        features.append(attack_hash)
        
        # Port-based features
        port = log_entry.get('port', 0)
        if isinstance(port, str):
            try:
                port = int(port)
            except:
                port = 0
        features.append(port)
        
        # String-based features (length, character distribution)
        message = log_entry.get('message', '')
        features.extend([
            len(message),  # Message length
            message.count('/'),  # Path separators
            message.count('?'),  # Query parameters
            message.count('&'),  # Parameter separators
            message.count('='),  # Assignments
            message.count('<'),  # Potential XSS
            message.count('>'),  # Potential XSS
            message.count('\''),  # SQL injection indicators
            message.count('"'),   # SQL injection indicators
            message.count(';'),   # Command injection
        ])
        
        # Frequency-based features (requires historical data)
        ip_frequency = self._get_ip_frequency(source_ip)
        features.append(ip_frequency)
        
        return np.array(features, dtype=float)
    
    def _get_ip_frequency(self, ip: str) -> float:
        """Get historical frequency of IP address (simplified)"""
        # In a real implementation, this would query historical data
        # For now, return a random frequency based on IP hash
        ip_hash = int(hashlib.md5(ip.encode()).hexdigest()[:8], 16)
        return (ip_hash % 100) / 100.0
    
    def train(self, training_data: List[Dict]) -> Dict:
        """
        Train anomaly detection models on historical data
        """
        self.logger.info(f"Training anomaly detection models on {len(training_data)} samples")
        
        # Extract features from training data
        features = []
        for entry in training_data:
            feature_vector = self.extract_features(entry)
            features.append(feature_vector)
        
        if not features:
            raise ValueError("No features extracted from training data")
        
        X = np.array(features)
        
        # Train each algorithm
        training_results = {}
        
        for name, config in self.algorithms.items():
            try:
                # Scale features
                X_scaled = self.scalers[name].fit_transform(X)
                
                # Train model
                if name == 'dbscan':
                    # DBSCAN doesn't have fit method, just transform
                    labels = self.models[name].fit_predict(X_scaled)
                    outlier_ratio = np.sum(labels == -1) / len(labels)
                    training_results[name] = {
                        'status': 'success',
                        'outlier_ratio': outlier_ratio,
                        'samples': len(X_scaled)
                    }
                else:
                    self.models[name].fit(X_scaled)
                    training_results[name] = {
                        'status': 'success',
                        'samples': len(X_scaled)
                    }
                
                self.logger.info(f"Successfully trained {name} model")
                
            except Exception as e:
                self.logger.error(f"Failed to train {name}: {str(e)}")
                training_results[name] = {
                    'status': 'failed',
                    'error': str(e)
                }
        
        self.is_trained = True
        return training_results
    
    def detect_anomaly(self, log_entry: Dict) -> Dict:
        """
        Detect if a log entry is anomalous using ensemble of algorithms
        """
        if not self.is_trained:
            # Train on synthetic data if not trained
            self._train_on_synthetic_data()
        
        # Extract features
        feature_vector = self.extract_features(log_entry)
        X = feature_vector.reshape(1, -1)
        
        # Get predictions from each algorithm
        predictions = {}
        anomaly_scores = {}
        
        for name, config in self.algorithms.items():
            try:
                # Scale features
                X_scaled = self.scalers[name].transform(X)
                
                if name == 'dbscan':
                    # For DBSCAN, we need to fit_predict on the single point
                    # This is not ideal, but for demonstration purposes
                    label = self.models[name].fit_predict(X_scaled)[0]
                    is_anomaly = label == -1
                    score = -1.0 if is_anomaly else 1.0
                elif name == 'isolation_forest':
                    score = self.models[name].decision_function(X_scaled)[0]
                    is_anomaly = score < config['threshold']
                elif name == 'one_class_svm':
                    prediction = self.models[name].predict(X_scaled)[0]
                    score = self.models[name].decision_function(X_scaled)[0]
                    is_anomaly = prediction == -1
                
                predictions[name] = is_anomaly
                anomaly_scores[name] = float(score)
                
            except Exception as e:
                self.logger.error(f"Error in {name} prediction: {str(e)}")
                predictions[name] = False
                anomaly_scores[name] = 0.0
        
        # Ensemble decision (majority vote)
        anomaly_votes = sum(predictions.values())
        is_anomaly = anomaly_votes >= 2  # At least 2 out of 3 algorithms
        
        # Calculate confidence score
        confidence = anomaly_votes / len(predictions)
        
        # Determine severity based on ensemble agreement
        if anomaly_votes == 3:
            severity = "CRITICAL"
        elif anomaly_votes == 2:
            severity = "HIGH"
        elif anomaly_votes == 1:
            severity = "MEDIUM"
        else:
            severity = "LOW"
        
        return {
            'is_anomaly': is_anomaly,
            'confidence': confidence,
            'severity': severity,
            'algorithm_predictions': predictions,
            'anomaly_scores': anomaly_scores,
            'feature_vector': feature_vector.tolist(),
            'timestamp': datetime.now().isoformat()
        }
    
    def _train_on_synthetic_data(self):
        """Train models on synthetic normal traffic data"""
        self.logger.info("Training on synthetic data...")
        
        # Generate synthetic normal traffic patterns
        synthetic_data = []
        for i in range(1000):
            synthetic_entry = {
                'timestamp': datetime.now() - timedelta(hours=i % 24),
                'source_ip': f"192.168.1.{i % 254 + 1}",
                'attack_type': 'NORMAL_TRAFFIC',
                'port': 80 if i % 2 == 0 else 443,
                'message': f"GET /index.html HTTP/1.1 User-Agent: Browser{i % 10}"
            }
            synthetic_data.append(synthetic_entry)
        
        self.train(synthetic_data)
    
    def get_model_stats(self) -> Dict:
        """Get statistics about trained models"""
        stats = {
            'is_trained': self.is_trained,
            'algorithms': list(self.algorithms.keys()),
            'feature_count': None
        }
        
        if self.is_trained and self.scalers:
            # Get feature count from first scaler
            first_scaler = list(self.scalers.values())[0]
            if hasattr(first_scaler, 'n_features_in_'):
                stats['feature_count'] = first_scaler.n_features_in_
        
        return stats
    
    def save_models(self, path: str = None):
        """Save trained models to disk"""
        if not self.is_trained:
            raise ValueError("Models must be trained before saving")
        
        save_path = path or self.model_path
        
        try:
            # Save each model and scaler
            for name in self.algorithms.keys():
                model_file = f"{save_path}/{name}_model.joblib"
                scaler_file = f"{save_path}/{name}_scaler.joblib"
                
                joblib.dump(self.models[name], model_file)
                joblib.dump(self.scalers[name], scaler_file)
            
            self.logger.info(f"Models saved to {save_path}")
            
        except Exception as e:
            self.logger.error(f"Failed to save models: {str(e)}")
            raise
    
    def load_models(self, path: str = None):
        """Load trained models from disk"""
        load_path = path or self.model_path
        
        try:
            for name in self.algorithms.keys():
                model_file = f"{load_path}/{name}_model.joblib"
                scaler_file = f"{load_path}/{name}_scaler.joblib"
                
                self.models[name] = joblib.load(model_file)
                self.scalers[name] = joblib.load(scaler_file)
            
            self.is_trained = True
            self.logger.info(f"Models loaded from {load_path}")
            
        except Exception as e:
            self.logger.error(f"Failed to load models: {str(e)}")
            raise 