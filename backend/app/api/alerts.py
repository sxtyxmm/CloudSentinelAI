"""
Alert management endpoints
"""
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_, func
from typing import List, Optional
from datetime import datetime, timedelta

from app.core.database import get_db
from app.core.security import get_current_user
from app.models.database import ThreatAlert, AnalystFeedback, AutomatedResponse
from app.models.schemas import (
    ThreatAlertResponse,
    ThreatAlertUpdate,
    AnalystFeedbackCreate,
    AnalystFeedbackResponse,
    AlertStatus
)
from app.services.threat_intelligence import NotificationService

router = APIRouter()
notification_service = NotificationService()


@router.get("/", response_model=List[ThreatAlertResponse])
async def list_alerts(
    skip: int = Query(0, ge=0),
    limit: int = Query(100, le=1000),
    severity: Optional[str] = None,
    status: Optional[str] = None,
    category: Optional[str] = None,
    start_date: Optional[datetime] = None,
    end_date: Optional[datetime] = None,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """List all alerts with filtering"""
    query = select(ThreatAlert)
    
    # Apply filters
    filters = []
    if severity:
        filters.append(ThreatAlert.severity == severity)
    if status:
        filters.append(ThreatAlert.status == status)
    if category:
        filters.append(ThreatAlert.category == category)
    if start_date:
        filters.append(ThreatAlert.detected_at >= start_date)
    if end_date:
        filters.append(ThreatAlert.detected_at <= end_date)
    
    if filters:
        query = query.where(and_(*filters))
    
    query = query.order_by(ThreatAlert.detected_at.desc()).offset(skip).limit(limit)
    
    result = await db.execute(query)
    alerts = result.scalars().all()
    
    return alerts


@router.get("/{alert_id}", response_model=ThreatAlertResponse)
async def get_alert(
    alert_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """Get a specific alert by ID"""
    result = await db.execute(
        select(ThreatAlert).where(ThreatAlert.id == alert_id)
    )
    alert = result.scalar_one_or_none()
    
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    
    return alert


@router.patch("/{alert_id}", response_model=ThreatAlertResponse)
async def update_alert(
    alert_id: int,
    alert_update: ThreatAlertUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """Update an alert status or assignment"""
    result = await db.execute(
        select(ThreatAlert).where(ThreatAlert.id == alert_id)
    )
    alert = result.scalar_one_or_none()
    
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    
    # Update fields
    if alert_update.status:
        alert.status = alert_update.status
        if alert_update.status == AlertStatus.RESOLVED:
            alert.resolved_at = datetime.now()
    
    if alert_update.assigned_to:
        alert.assigned_to = alert_update.assigned_to
    
    if alert_update.resolution_notes:
        alert.resolution_notes = alert_update.resolution_notes
    
    await db.commit()
    await db.refresh(alert)
    
    return alert


@router.post("/{alert_id}/feedback", response_model=AnalystFeedbackResponse)
async def submit_feedback(
    alert_id: int,
    feedback: AnalystFeedbackCreate,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """Submit analyst feedback on an alert"""
    # Verify alert exists
    result = await db.execute(
        select(ThreatAlert).where(ThreatAlert.id == alert_id)
    )
    alert = result.scalar_one_or_none()
    
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    
    # Create feedback
    db_feedback = AnalystFeedback(
        alert_id=alert_id,
        analyst_username=current_user["username"],
        is_true_positive=feedback.is_true_positive,
        feedback_notes=feedback.feedback_notes
    )
    
    db.add(db_feedback)
    
    # Update alert status based on feedback
    if not feedback.is_true_positive:
        alert.status = AlertStatus.FALSE_POSITIVE
    
    await db.commit()
    await db.refresh(db_feedback)
    
    return db_feedback


@router.get("/{alert_id}/responses")
async def get_alert_responses(
    alert_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """Get automated responses for an alert"""
    result = await db.execute(
        select(AutomatedResponse).where(AutomatedResponse.alert_id == alert_id)
    )
    responses = result.scalars().all()
    
    return responses


@router.post("/{alert_id}/notify")
async def send_alert_notification(
    alert_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """Send notification for an alert"""
    result = await db.execute(
        select(ThreatAlert).where(ThreatAlert.id == alert_id)
    )
    alert = result.scalar_one_or_none()
    
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    
    success = await notification_service.send_alert_notification(
        alert.alert_id,
        alert.severity,
        alert.title,
        alert.description or ""
    )
    
    return {"success": success, "alert_id": alert.alert_id}
