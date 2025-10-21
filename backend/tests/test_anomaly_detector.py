"""
Tests for anomaly detection module
"""
import pytest
from datetime import datetime
from app.ml.anomaly_detector import AnomalyDetector, ThreatScorer


def test_anomaly_detector_initialization():
    """Test anomaly detector initialization"""
    detector = AnomalyDetector()
    assert detector.scaler is not None
    assert detector.is_trained is False


def test_feature_extraction():
    """Test feature extraction from log data"""
    detector = AnomalyDetector()
    
    log_data = {
        'event_time': datetime.now(),
        'user_id': 'test_user',
        'ip_address': '192.168.1.1',
        'event_type': 'login',
        'geo_location': {'country': 'US'},
        'status': 'success'
    }
    
    features = detector.extract_features(log_data)
    
    assert 'hour_of_day' in features
    assert 'day_of_week' in features
    assert 'is_login_event' in features
    assert features['is_login_event'] == 1


def test_threat_scorer():
    """Test threat score calculation"""
    threat_score, severity = ThreatScorer.calculate_threat_score(
        anomaly_score=0.8,
        event_type='admin_access',
        user_context={},
        external_intelligence=None
    )
    
    assert 0 <= threat_score <= 1.0
    assert severity in ['critical', 'high', 'medium', 'low']
    assert severity == 'critical'  # Should be critical due to high score


def test_threat_scorer_with_malicious_ip():
    """Test threat score with malicious IP intelligence"""
    threat_score, severity = ThreatScorer.calculate_threat_score(
        anomaly_score=0.6,
        event_type='access',
        user_context={},
        external_intelligence={'is_malicious_ip': True}
    )
    
    # Score should be increased due to malicious IP
    assert threat_score > 0.6
    assert severity in ['critical', 'high']


def test_anomaly_detector_training():
    """Test model training"""
    detector = AnomalyDetector()
    
    # Create sample training data
    training_data = []
    for i in range(100):
        training_data.append({
            'event_time': datetime.now(),
            'user_id': f'user_{i % 10}',
            'ip_address': f'192.168.1.{i % 255}',
            'event_type': 'login' if i % 2 == 0 else 'access',
            'geo_location': {'country': 'US'},
            'status': 'success'
        })
    
    info = detector.train(training_data, contamination=0.1)
    
    assert detector.is_trained is True
    assert info['n_samples'] == 100
    assert info['model_type'] == 'isolation_forest'


def test_anomaly_detection():
    """Test anomaly detection on trained model"""
    detector = AnomalyDetector()
    
    # Train with normal data
    training_data = []
    for i in range(100):
        training_data.append({
            'event_time': datetime.now(),
            'user_id': 'normal_user',
            'ip_address': '192.168.1.1',
            'event_type': 'login',
            'geo_location': {'country': 'US'},
            'status': 'success'
        })
    
    detector.train(training_data)
    
    # Test with normal log
    normal_log = training_data[0]
    is_anomaly, score = detector.predict(normal_log)
    
    # Normal log should have low anomaly score
    assert isinstance(is_anomaly, bool)
    assert isinstance(score, float)
    assert 0 <= score <= 1.0
