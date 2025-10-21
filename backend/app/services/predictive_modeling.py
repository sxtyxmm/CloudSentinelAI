"""
Predictive Threat Modeling Service
Forecasts potential threats based on behavioral patterns
"""
import numpy as np
import pandas as pd
from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta
import structlog
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.database import ThreatAlert, CloudLog

logger = structlog.get_logger()


class PredictiveThreatService:
    """
    Service for predicting future threats
    """
    
    def __init__(self):
        self.risk_threshold = 0.6
    
    async def predict_user_risk(
        self,
        db: AsyncSession,
        user_id: str,
        days_history: int = 30
    ) -> Dict[str, Any]:
        """
        Predict risk score for a specific user
        
        Args:
            db: Database session
            user_id: User identifier
            days_history: Days of historical data to analyze
            
        Returns:
            Dict with risk prediction and factors
        """
        start_date = datetime.now() - timedelta(days=days_history)
        
        # Get user's historical alerts
        result = await db.execute(
            select(ThreatAlert).where(
                ThreatAlert.user_id == user_id,
                ThreatAlert.detected_at >= start_date
            )
        )
        alerts = result.scalars().all()
        
        # Calculate risk factors
        risk_factors = self._calculate_user_risk_factors(alerts)
        
        # Calculate overall risk score
        risk_score = self._calculate_risk_score(risk_factors)
        
        # Generate prediction
        prediction = self._generate_prediction(risk_score, risk_factors)
        
        return {
            'user_id': user_id,
            'risk_score': risk_score,
            'risk_level': self._categorize_risk(risk_score),
            'prediction': prediction,
            'risk_factors': risk_factors,
            'historical_alert_count': len(alerts),
            'analysis_period_days': days_history
        }
    
    def _calculate_user_risk_factors(self, alerts: List[ThreatAlert]) -> Dict[str, float]:
        """
        Calculate risk factors from historical alerts
        """
        if not alerts:
            return {
                'alert_frequency': 0.0,
                'severity_trend': 0.0,
                'false_positive_rate': 0.0,
                'critical_alert_ratio': 0.0,
                'unresolved_ratio': 0.0
            }
        
        # Alert frequency (alerts per day)
        time_span = (max(a.detected_at for a in alerts) - 
                    min(a.detected_at for a in alerts)).days + 1
        alert_frequency = len(alerts) / max(time_span, 1)
        
        # Severity trend (0-1, higher = getting worse)
        severity_weights = {'low': 1, 'medium': 2, 'high': 3, 'critical': 4}
        severity_scores = [severity_weights.get(a.severity, 0) for a in alerts]
        if len(severity_scores) >= 2:
            # Simple linear trend
            recent_avg = np.mean(severity_scores[-5:])
            older_avg = np.mean(severity_scores[:-5]) if len(severity_scores) > 5 else np.mean(severity_scores)
            severity_trend = (recent_avg - older_avg) / 4.0  # Normalize to 0-1
        else:
            severity_trend = 0.0
        
        # False positive rate
        false_positives = sum(1 for a in alerts if a.status == 'false_positive')
        false_positive_rate = false_positives / len(alerts)
        
        # Critical alert ratio
        critical_alerts = sum(1 for a in alerts if a.severity == 'critical')
        critical_alert_ratio = critical_alerts / len(alerts)
        
        # Unresolved ratio
        unresolved = sum(1 for a in alerts if a.status in ['open', 'investigating'])
        unresolved_ratio = unresolved / len(alerts)
        
        return {
            'alert_frequency': min(alert_frequency / 2.0, 1.0),  # Normalize (2+ alerts/day = 1.0)
            'severity_trend': max(min(severity_trend, 1.0), 0.0),
            'false_positive_rate': false_positive_rate,
            'critical_alert_ratio': critical_alert_ratio,
            'unresolved_ratio': unresolved_ratio
        }
    
    def _calculate_risk_score(self, risk_factors: Dict[str, float]) -> float:
        """
        Calculate overall risk score from factors
        """
        weights = {
            'alert_frequency': 0.25,
            'severity_trend': 0.20,
            'false_positive_rate': -0.10,  # Negative weight (FP reduces risk)
            'critical_alert_ratio': 0.30,
            'unresolved_ratio': 0.25
        }
        
        risk_score = sum(
            risk_factors.get(factor, 0) * weight
            for factor, weight in weights.items()
        )
        
        # Normalize to 0-1 range
        return max(min(risk_score, 1.0), 0.0)
    
    def _categorize_risk(self, risk_score: float) -> str:
        """
        Categorize risk level
        """
        if risk_score >= 0.8:
            return 'critical'
        elif risk_score >= 0.6:
            return 'high'
        elif risk_score >= 0.4:
            return 'medium'
        else:
            return 'low'
    
    def _generate_prediction(
        self,
        risk_score: float,
        risk_factors: Dict[str, float]
    ) -> Dict[str, Any]:
        """
        Generate prediction based on risk analysis
        """
        predictions = []
        
        if risk_score >= 0.8:
            predictions.append({
                'type': 'imminent_threat',
                'probability': 0.85,
                'timeframe': '24-48 hours',
                'description': 'High likelihood of security incident'
            })
        elif risk_score >= 0.6:
            predictions.append({
                'type': 'elevated_risk',
                'probability': 0.65,
                'timeframe': '1-7 days',
                'description': 'Increased risk of security incident'
            })
        
        # Specific predictions based on factors
        if risk_factors.get('severity_trend', 0) > 0.5:
            predictions.append({
                'type': 'escalating_threat',
                'probability': 0.70,
                'timeframe': '3-7 days',
                'description': 'Threat severity is increasing'
            })
        
        if risk_factors.get('unresolved_ratio', 0) > 0.7:
            predictions.append({
                'type': 'accumulating_risk',
                'probability': 0.60,
                'timeframe': '7-14 days',
                'description': 'Unresolved threats accumulating'
            })
        
        if risk_factors.get('critical_alert_ratio', 0) > 0.5:
            predictions.append({
                'type': 'high_impact_event',
                'probability': 0.75,
                'timeframe': '24-72 hours',
                'description': 'High probability of critical security event'
            })
        
        return {
            'predictions': predictions,
            'recommended_actions': self._get_recommended_actions(risk_score, risk_factors)
        }
    
    def _get_recommended_actions(
        self,
        risk_score: float,
        risk_factors: Dict[str, float]
    ) -> List[str]:
        """
        Get recommended actions based on risk assessment
        """
        actions = []
        
        if risk_score >= 0.8:
            actions.extend([
                'Immediate security review required',
                'Increase monitoring frequency',
                'Review and restrict user permissions',
                'Enable additional authentication factors',
                'Alert security team for immediate action'
            ])
        elif risk_score >= 0.6:
            actions.extend([
                'Schedule security review within 24 hours',
                'Review recent user activity',
                'Verify user credentials',
                'Monitor user sessions closely'
            ])
        
        if risk_factors.get('unresolved_ratio', 0) > 0.5:
            actions.append('Prioritize resolution of open alerts')
        
        if risk_factors.get('critical_alert_ratio', 0) > 0.3:
            actions.append('Investigate critical alerts immediately')
        
        return actions
    
    async def forecast_threat_trends(
        self,
        db: AsyncSession,
        forecast_days: int = 7,
        lookback_days: int = 30
    ) -> Dict[str, Any]:
        """
        Forecast threat trends for the organization
        """
        start_date = datetime.now() - timedelta(days=lookback_days)
        
        # Get historical alerts grouped by day
        result = await db.execute(
            select(
                func.date(ThreatAlert.detected_at).label('date'),
                func.count(ThreatAlert.id).label('count'),
                ThreatAlert.severity
            ).where(
                ThreatAlert.detected_at >= start_date
            ).group_by(
                func.date(ThreatAlert.detected_at),
                ThreatAlert.severity
            ).order_by(
                func.date(ThreatAlert.detected_at)
            )
        )
        
        daily_counts = result.all()
        
        # Simple forecasting (moving average)
        forecast = self._simple_forecast(daily_counts, forecast_days)
        
        return {
            'forecast_period_days': forecast_days,
            'historical_period_days': lookback_days,
            'forecast': forecast,
            'trend': self._identify_trend(daily_counts)
        }
    
    def _simple_forecast(
        self,
        historical_data: List[Any],
        forecast_days: int
    ) -> List[Dict[str, Any]]:
        """
        Simple moving average forecast
        """
        if not historical_data:
            return []
        
        # Calculate average daily alerts
        total_alerts = sum(row.count for row in historical_data)
        avg_daily = total_alerts / len(historical_data)
        
        # Generate forecast
        forecast = []
        base_date = datetime.now().date()
        
        for i in range(1, forecast_days + 1):
            forecast_date = base_date + timedelta(days=i)
            # Simple forecast with slight random variation
            predicted_count = int(avg_daily * (1 + (np.random.rand() - 0.5) * 0.2))
            
            forecast.append({
                'date': forecast_date.isoformat(),
                'predicted_alert_count': max(predicted_count, 0),
                'confidence': 0.7 - (i * 0.05)  # Confidence decreases with time
            })
        
        return forecast
    
    def _identify_trend(self, daily_counts: List[Any]) -> str:
        """
        Identify overall trend direction
        """
        if len(daily_counts) < 2:
            return 'stable'
        
        # Calculate simple trend
        counts = [row.count for row in daily_counts]
        if len(counts) >= 7:
            recent_avg = np.mean(counts[-7:])
            older_avg = np.mean(counts[:-7])
            
            if recent_avg > older_avg * 1.2:
                return 'increasing'
            elif recent_avg < older_avg * 0.8:
                return 'decreasing'
        
        return 'stable'
    
    async def identify_high_risk_users(
        self,
        db: AsyncSession,
        limit: int = 10,
        days_history: int = 30
    ) -> List[Dict[str, Any]]:
        """
        Identify users with highest predicted risk
        """
        start_date = datetime.now() - timedelta(days=days_history)
        
        # Get all users with alerts
        result = await db.execute(
            select(ThreatAlert.user_id).where(
                ThreatAlert.detected_at >= start_date,
                ThreatAlert.user_id.isnot(None)
            ).distinct()
        )
        
        user_ids = [row[0] for row in result.all()]
        
        # Calculate risk for each user
        risk_assessments = []
        for user_id in user_ids[:50]:  # Limit to avoid excessive computation
            risk_data = await self.predict_user_risk(db, user_id, days_history)
            risk_assessments.append(risk_data)
        
        # Sort by risk score
        risk_assessments.sort(key=lambda x: x['risk_score'], reverse=True)
        
        return risk_assessments[:limit]
