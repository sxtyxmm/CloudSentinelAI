"""
Explainable AI Service using SHAP and LIME
Provides interpretability for ML model predictions
"""
import numpy as np
from typing import Dict, List, Any, Optional
import structlog

logger = structlog.get_logger()


class ExplainableAIService:
    """
    Service for explaining ML model predictions
    """
    
    def __init__(self):
        self.feature_importance_cache = {}
    
    def explain_prediction(
        self,
        alert_id: str,
        prediction_score: float,
        features: Dict[str, float],
        model_type: str = "isolation_forest"
    ) -> Dict[str, Any]:
        """
        Explain why a prediction was made
        
        Args:
            alert_id: Alert identifier
            prediction_score: Anomaly score from model
            features: Feature values used for prediction
            model_type: Type of model used
            
        Returns:
            Dict with explanation details
        """
        logger.info(f"Generating explanation for alert {alert_id}")
        
        # Calculate feature contributions (simplified)
        contributions = self._calculate_feature_contributions(features, prediction_score)
        
        # Generate human-readable explanation
        explanation = self._generate_explanation(contributions, prediction_score)
        
        return {
            'alert_id': alert_id,
            'prediction_score': prediction_score,
            'model_type': model_type,
            'explanation': explanation,
            'feature_contributions': contributions,
            'top_factors': self._get_top_factors(contributions, n=5),
            'interpretation': self._interpret_score(prediction_score)
        }
    
    def _calculate_feature_contributions(
        self,
        features: Dict[str, float],
        prediction_score: float
    ) -> Dict[str, float]:
        """
        Calculate how much each feature contributed to the prediction
        
        This is a simplified version. In production with SHAP:
        - Use shap.TreeExplainer for tree-based models
        - Use shap.KernelExplainer for other models
        - Calculate actual SHAP values
        """
        contributions = {}
        
        # Feature importance weights (simplified)
        # In production, these would come from SHAP analysis
        importance_weights = {
            'hour_of_day': 0.15,
            'day_of_week': 0.10,
            'is_weekend': 0.08,
            'is_business_hours': 0.12,
            'is_login_event': 0.20,
            'is_access_event': 0.15,
            'is_modify_event': 0.18,
            'is_delete_event': 0.22,
            'is_failed_attempt': 0.25,
            'is_known_country': 0.14,
            'country_hash': 0.08,
            'user_id_hash': 0.10,
            'ip_hash': 0.12
        }
        
        # Calculate contribution for each feature
        total_weight = sum(importance_weights.get(k, 0.05) for k in features.keys())
        
        for feature_name, feature_value in features.items():
            # Normalize feature value
            normalized_value = self._normalize_feature_value(feature_name, feature_value)
            
            # Calculate contribution
            weight = importance_weights.get(feature_name, 0.05)
            contribution = (weight / total_weight) * normalized_value * prediction_score
            
            contributions[feature_name] = round(contribution, 4)
        
        return contributions
    
    def _normalize_feature_value(self, feature_name: str, value: float) -> float:
        """
        Normalize feature value to 0-1 range
        """
        # Binary features
        if feature_name.startswith('is_'):
            return float(value)
        
        # Hour of day (0-23)
        if feature_name == 'hour_of_day':
            # Unusual hours (late night/early morning) have higher values
            if value < 6 or value > 22:
                return 0.8
            elif 9 <= value <= 17:
                return 0.2
            else:
                return 0.5
        
        # Day of week (0-6)
        if feature_name == 'day_of_week':
            # Weekend has higher value
            return 0.7 if value >= 5 else 0.3
        
        # Hash values - normalize to 0-1
        if feature_name.endswith('_hash'):
            return min(abs(value) / 10000, 1.0)
        
        return min(abs(value), 1.0)
    
    def _generate_explanation(
        self,
        contributions: Dict[str, float],
        prediction_score: float
    ) -> str:
        """
        Generate human-readable explanation
        """
        # Get top contributing factors
        top_factors = sorted(
            contributions.items(),
            key=lambda x: abs(x[1]),
            reverse=True
        )[:3]
        
        explanation_parts = []
        
        if prediction_score >= 0.8:
            explanation_parts.append("This alert has a CRITICAL threat level.")
        elif prediction_score >= 0.6:
            explanation_parts.append("This alert has a HIGH threat level.")
        elif prediction_score >= 0.4:
            explanation_parts.append("This alert has a MEDIUM threat level.")
        else:
            explanation_parts.append("This alert has a LOW threat level.")
        
        explanation_parts.append("\nKey contributing factors:")
        
        for feature_name, contribution in top_factors:
            factor_explanation = self._explain_feature(feature_name, contribution)
            explanation_parts.append(f"• {factor_explanation}")
        
        return "\n".join(explanation_parts)
    
    def _explain_feature(self, feature_name: str, contribution: float) -> str:
        """
        Explain a specific feature's contribution
        """
        feature_explanations = {
            'is_login_event': 'Login activity pattern',
            'is_failed_attempt': 'Failed authentication attempts',
            'is_delete_event': 'Delete operations detected',
            'is_modify_event': 'Modification operations',
            'hour_of_day': 'Time of day (unusual hours increase risk)',
            'is_weekend': 'Weekend activity (often suspicious)',
            'is_business_hours': 'Outside business hours',
            'is_known_country': 'Geographic location',
            'country_hash': 'Country change pattern',
            'user_id_hash': 'User behavior deviation',
            'ip_hash': 'IP address pattern'
        }
        
        explanation = feature_explanations.get(feature_name, feature_name)
        
        if contribution > 0.1:
            return f"{explanation} (strong indicator, +{abs(contribution):.2f})"
        elif contribution > 0.05:
            return f"{explanation} (moderate indicator, +{abs(contribution):.2f})"
        else:
            return f"{explanation} (minor indicator, +{abs(contribution):.2f})"
    
    def _get_top_factors(
        self,
        contributions: Dict[str, float],
        n: int = 5
    ) -> List[Dict[str, Any]]:
        """
        Get top N contributing factors
        """
        sorted_contributions = sorted(
            contributions.items(),
            key=lambda x: abs(x[1]),
            reverse=True
        )[:n]
        
        return [
            {
                'feature': feature,
                'contribution': contribution,
                'explanation': self._explain_feature(feature, contribution)
            }
            for feature, contribution in sorted_contributions
        ]
    
    def _interpret_score(self, prediction_score: float) -> str:
        """
        Interpret the prediction score
        """
        if prediction_score >= 0.9:
            return "Extremely high confidence - immediate action recommended"
        elif prediction_score >= 0.8:
            return "Very high confidence - urgent investigation required"
        elif prediction_score >= 0.7:
            return "High confidence - investigation recommended"
        elif prediction_score >= 0.6:
            return "Moderate-high confidence - monitor closely"
        elif prediction_score >= 0.5:
            return "Moderate confidence - review when possible"
        elif prediction_score >= 0.4:
            return "Low-moderate confidence - may be benign"
        else:
            return "Low confidence - likely benign activity"
    
    def get_model_global_explanation(self) -> Dict[str, Any]:
        """
        Get global explanation of model behavior
        """
        return {
            'model_description': 'Isolation Forest anomaly detection model',
            'how_it_works': [
                'The model learns normal behavior patterns from historical data',
                'It isolates anomalies by randomly partitioning the data',
                'Anomalies are isolated with fewer partitions than normal points',
                'The anomaly score represents how easy it was to isolate the data point'
            ],
            'feature_importance': {
                'most_important': [
                    'Failed login attempts',
                    'Delete operations',
                    'Modification events',
                    'Login events from unusual locations'
                ],
                'moderately_important': [
                    'Time of day patterns',
                    'Geographic location',
                    'User behavior changes'
                ],
                'less_important': [
                    'Day of week',
                    'Business hours indicator'
                ]
            },
            'what_model_looks_for': [
                'Unusual time patterns (late night access)',
                'Geographic anomalies (sudden location changes)',
                'Failed authentication attempts',
                'Unusual administrative actions',
                'Data modification or deletion patterns',
                'Access from unknown or suspicious IPs'
            ],
            'limitations': [
                'May generate false positives for legitimate unusual behavior',
                'Requires sufficient training data to learn normal patterns',
                'Cannot detect threats that mimic normal behavior',
                'Performance depends on data quality and feature engineering'
            ]
        }


class ThreatExplanationService:
    """
    Service for explaining specific threat types
    """
    
    def explain_threat_category(self, category: str) -> Dict[str, Any]:
        """
        Provide detailed explanation for a threat category
        """
        explanations = {
            'account_takeover': {
                'description': 'Unauthorized access to a user account',
                'indicators': [
                    'Login from unusual geographic location',
                    'Multiple failed login attempts followed by success',
                    'Access from previously unseen IP addresses',
                    'Unusual time of access',
                    'Rapid geographic shifts (impossible travel)'
                ],
                'severity_factors': [
                    'Administrative or privileged accounts',
                    'Access to sensitive data',
                    'Changes to account settings',
                    'Access from known malicious IPs'
                ],
                'recommended_actions': [
                    'Immediately disable the compromised account',
                    'Force password reset',
                    'Review account activity logs',
                    'Check for unauthorized changes',
                    'Enable MFA if not already active'
                ]
            },
            'data_exfiltration': {
                'description': 'Unauthorized transfer of data outside the organization',
                'indicators': [
                    'Large volume data downloads',
                    'Unusual file access patterns',
                    'Access to multiple sensitive files rapidly',
                    'Data transfers to external locations',
                    'Use of data export APIs'
                ],
                'severity_factors': [
                    'Volume of data accessed',
                    'Sensitivity of accessed data',
                    'Use of encryption or obfuscation',
                    'Access during non-business hours'
                ],
                'recommended_actions': [
                    'Block ongoing data transfers',
                    'Revoke access credentials',
                    'Identify all accessed data',
                    'Notify security team and legal',
                    'Preserve evidence for investigation'
                ]
            },
            'privilege_escalation': {
                'description': 'Attempt to gain elevated privileges',
                'indicators': [
                    'Unauthorized role changes',
                    'Attempts to access admin functions',
                    'Exploitation of vulnerabilities',
                    'Use of stolen credentials',
                    'Suspicious API calls for privilege management'
                ],
                'severity_factors': [
                    'Level of privileges gained',
                    'Account type (service vs user)',
                    'Access to production systems',
                    'Persistence mechanisms created'
                ],
                'recommended_actions': [
                    'Immediately revoke elevated privileges',
                    'Audit all recent privilege changes',
                    'Check for backdoors or persistence',
                    'Review access logs',
                    'Implement additional monitoring'
                ]
            },
            'suspicious_login': {
                'description': 'Login activity that deviates from normal patterns',
                'indicators': [
                    'Login from unusual location',
                    'Login at unusual time',
                    'Multiple failed attempts',
                    'New device or browser',
                    'Login after long period of inactivity'
                ],
                'severity_factors': [
                    'Account privilege level',
                    'Access to sensitive systems',
                    'Correlation with other suspicious activity',
                    'Source IP reputation'
                ],
                'recommended_actions': [
                    'Verify login with user',
                    'Require additional authentication',
                    'Monitor subsequent activity',
                    'Check for compromised credentials',
                    'Update security policies if needed'
                ]
            }
        }
        
        return explanations.get(
            category,
            {
                'description': f'Threat category: {category}',
                'indicators': ['Pattern detected by anomaly detection model'],
                'severity_factors': ['Based on threat score and context'],
                'recommended_actions': ['Review alert details and investigate']
            }
        )
