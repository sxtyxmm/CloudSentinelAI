"""
Predictive threat modeling endpoints
"""
from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession
from typing import Dict, Any

from app.core.database import get_db
from app.core.security import get_current_user
from app.services.predictive_modeling import PredictiveThreatService

router = APIRouter()
predictive_service = PredictiveThreatService()


@router.get("/user-risk/{user_id}")
async def predict_user_risk(
    user_id: str,
    days: int = Query(30, ge=7, le=90, description="Days of history to analyze"),
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user)
) -> Dict[str, Any]:
    """
    Predict risk score for a specific user
    """
    return await predictive_service.predict_user_risk(db, user_id, days)


@router.get("/high-risk-users")
async def get_high_risk_users(
    limit: int = Query(10, ge=1, le=50, description="Number of users to return"),
    days: int = Query(30, ge=7, le=90, description="Days of history to analyze"),
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user)
) -> Dict[str, Any]:
    """
    Get list of users with highest predicted risk
    """
    high_risk_users = await predictive_service.identify_high_risk_users(db, limit, days)
    
    return {
        'total_users': len(high_risk_users),
        'users': high_risk_users
    }


@router.get("/threat-forecast")
async def forecast_threats(
    forecast_days: int = Query(7, ge=1, le=30, description="Days to forecast"),
    lookback_days: int = Query(30, ge=7, le=90, description="Historical days to analyze"),
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user)
) -> Dict[str, Any]:
    """
    Forecast threat trends for the organization
    """
    return await predictive_service.forecast_threat_trends(db, forecast_days, lookback_days)
