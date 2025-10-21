"""
Explainability endpoints for AI/ML predictions
"""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from typing import Dict, Any

from app.core.database import get_db
from app.core.security import get_current_user
from app.models.database import ThreatAlert
from app.services.explainable_ai import ExplainableAIService, ThreatExplanationService
from app.ml.anomaly_detector import AnomalyDetector

router = APIRouter()
explainable_service = ExplainableAIService()
threat_explanation_service = ThreatExplanationService()
anomaly_detector = AnomalyDetector()


@router.get("/alert/{alert_id}")
async def explain_alert(
    alert_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user)
) -> Dict[str, Any]:
    """
    Get explanation for why an alert was generated
    """
    # Get the alert
    result = await db.execute(
        select(ThreatAlert).where(ThreatAlert.id == alert_id)
    )
    alert = result.scalar_one_or_none()
    
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    
    # Extract features from alert
    features = anomaly_detector.extract_features({
        'event_time': alert.detected_at,
        'user_id': alert.user_id,
        'ip_address': alert.ip_address,
        'event_type': alert.category,
        'geo_location': alert.geo_location or {},
        'status': alert.status
    })
    
    # Get explanation
    explanation = explainable_service.explain_prediction(
        alert_id=alert.alert_id,
        prediction_score=alert.threat_score,
        features=features,
        model_type='isolation_forest'
    )
    
    # Add threat category explanation
    category_explanation = threat_explanation_service.explain_threat_category(
        alert.category
    )
    
    return {
        'alert': {
            'id': alert.id,
            'alert_id': alert.alert_id,
            'severity': alert.severity,
            'category': alert.category,
            'title': alert.title,
            'threat_score': alert.threat_score
        },
        'prediction_explanation': explanation,
        'threat_type_explanation': category_explanation
    }


@router.get("/model/global")
async def get_model_explanation(
    current_user: dict = Depends(get_current_user)
) -> Dict[str, Any]:
    """
    Get global explanation of how the ML model works
    """
    return explainable_service.get_model_global_explanation()


@router.get("/threat-category/{category}")
async def explain_threat_category(
    category: str,
    current_user: dict = Depends(get_current_user)
) -> Dict[str, Any]:
    """
    Get detailed explanation for a specific threat category
    """
    return threat_explanation_service.explain_threat_category(category)
