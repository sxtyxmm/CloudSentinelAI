"""
Anomaly detection engine using multiple ML algorithms
"""
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from typing import Dict, List, Tuple, Any
import joblib
import os
from datetime import datetime

from app.core.config import settings


class AnomalyDetector:
    """
    Anomaly detection using Isolation Forest and other algorithms
    """
    
    def __init__(self, model_path: str = None):
        self.model_path = model_path or settings.MODEL_PATH
        self.scaler = StandardScaler()
        self.isolation_forest = None
        self.feature_names = []
        self.is_trained = False
        
    def extract_features(self, log_data: Dict[str, Any]) -> Dict[str, float]:
        """
        Extract relevant features from log data for anomaly detection
        """
        features = {}
        
        # Time-based features
        event_time = log_data.get('event_time', datetime.now())
        if isinstance(event_time, str):
            event_time = datetime.fromisoformat(event_time.replace('Z', '+00:00'))
        
        features['hour_of_day'] = event_time.hour
        features['day_of_week'] = event_time.weekday()
        features['is_weekend'] = 1 if event_time.weekday() >= 5 else 0
        features['is_business_hours'] = 1 if 9 <= event_time.hour <= 17 else 0
        
        # User behavior features
        features['user_id_hash'] = hash(log_data.get('user_id', '')) % 10000
        features['ip_hash'] = hash(log_data.get('ip_address', '')) % 10000
        
        # Event type features
        event_type = log_data.get('event_type', 'unknown')
        features['is_login_event'] = 1 if 'login' in event_type.lower() else 0
        features['is_access_event'] = 1 if 'access' in event_type.lower() else 0
        features['is_modify_event'] = 1 if 'modify' in event_type.lower() or 'update' in event_type.lower() else 0
        features['is_delete_event'] = 1 if 'delete' in event_type.lower() else 0
        
        # Geographic features
        geo = log_data.get('geo_location', {})
        features['country_hash'] = hash(geo.get('country', 'unknown')) % 1000
        features['is_known_country'] = 1 if geo.get('country') in ['US', 'GB', 'CA', 'AU'] else 0
        
        # Success/Failure indicators
        features['is_failed_attempt'] = 1 if log_data.get('status') == 'failed' else 0
        
        return features
    
    def train(self, training_data: List[Dict[str, Any]], contamination: float = 0.1):
        """
        Train the anomaly detection model
        
        Args:
            training_data: List of log entries
            contamination: Expected proportion of anomalies in training data
        """
        # Extract features from training data
        feature_list = []
        for log in training_data:
            features = self.extract_features(log)
            feature_list.append(features)
        
        df = pd.DataFrame(feature_list)
        self.feature_names = df.columns.tolist()
        
        # Scale features
        X = self.scaler.fit_transform(df)
        
        # Train Isolation Forest
        self.isolation_forest = IsolationForest(
            contamination=contamination,
            random_state=42,
            n_estimators=100
        )
        self.isolation_forest.fit(X)
        self.is_trained = True
        
        return {
            'model_type': 'isolation_forest',
            'n_samples': len(training_data),
            'n_features': len(self.feature_names),
            'contamination': contamination
        }
    
    def predict(self, log_data: Dict[str, Any]) -> Tuple[bool, float]:
        """
        Predict if a log entry is anomalous
        
        Returns:
            Tuple of (is_anomaly, anomaly_score)
        """
        if not self.is_trained:
            # If model not trained, return conservative prediction
            return False, 0.5
        
        # Extract features
        features = self.extract_features(log_data)
        
        # Ensure all expected features are present
        feature_vector = [features.get(name, 0) for name in self.feature_names]
        X = np.array([feature_vector])
        
        # Scale features
        X_scaled = self.scaler.transform(X)
        
        # Predict
        prediction = self.isolation_forest.predict(X_scaled)[0]
        anomaly_score = self.isolation_forest.score_samples(X_scaled)[0]
        
        # Convert to interpretable format
        is_anomaly = prediction == -1
        # Convert score to 0-1 range (higher = more anomalous)
        normalized_score = 1.0 / (1.0 + np.exp(anomaly_score))
        
        return is_anomaly, float(normalized_score)
    
    def save_model(self, model_name: str = "anomaly_detector"):
        """Save the trained model to disk"""
        if not self.is_trained:
            raise ValueError("Model must be trained before saving")
        
        os.makedirs(self.model_path, exist_ok=True)
        
        model_data = {
            'isolation_forest': self.isolation_forest,
            'scaler': self.scaler,
            'feature_names': self.feature_names
        }
        
        filepath = os.path.join(self.model_path, f"{model_name}.joblib")
        joblib.dump(model_data, filepath)
        return filepath
    
    def load_model(self, model_name: str = "anomaly_detector"):
        """Load a trained model from disk"""
        filepath = os.path.join(self.model_path, f"{model_name}.joblib")
        
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"Model file not found: {filepath}")
        
        model_data = joblib.load(filepath)
        self.isolation_forest = model_data['isolation_forest']
        self.scaler = model_data['scaler']
        self.feature_names = model_data['feature_names']
        self.is_trained = True
        
        return True


class ThreatScorer:
    """
    Calculate threat severity scores based on multiple factors
    """
    
    @staticmethod
    def calculate_threat_score(
        anomaly_score: float,
        event_type: str,
        user_context: Dict[str, Any],
        external_intelligence: Dict[str, Any] = None
    ) -> Tuple[float, str]:
        """
        Calculate comprehensive threat score
        
        Returns:
            Tuple of (threat_score, severity_level)
        """
        base_score = anomaly_score
        
        # Event type severity multipliers
        event_multipliers = {
            'login': 1.0,
            'access': 1.2,
            'modify': 1.5,
            'delete': 1.8,
            'privilege': 2.0,
            'admin': 2.0
        }
        
        multiplier = 1.0
        for event_key, mult in event_multipliers.items():
            if event_key in event_type.lower():
                multiplier = max(multiplier, mult)
        
        # Apply multiplier
        threat_score = base_score * multiplier
        
        # Check external intelligence
        if external_intelligence:
            if external_intelligence.get('is_malicious_ip'):
                threat_score = min(1.0, threat_score * 1.5)
            if external_intelligence.get('is_known_threat_actor'):
                threat_score = min(1.0, threat_score * 1.8)
        
        # Determine severity
        if threat_score >= 0.8:
            severity = "critical"
        elif threat_score >= 0.6:
            severity = "high"
        elif threat_score >= 0.4:
            severity = "medium"
        else:
            severity = "low"
        
        return min(1.0, threat_score), severity
