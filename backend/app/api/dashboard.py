"""
Dashboard analytics and statistics endpoints
"""
from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, and_
from typing import List, Optional
from datetime import datetime, timedelta

from app.core.database import get_db
from app.core.security import get_current_user
from app.models.database import ThreatAlert, CloudLog
from app.models.schemas import DashboardStats, ThreatTrend, TopThreats

router = APIRouter()


@router.get("/stats", response_model=DashboardStats)
async def get_dashboard_stats(
    start_date: Optional[datetime] = None,
    end_date: Optional[datetime] = None,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """Get overall dashboard statistics"""
    # Default to last 30 days if not specified
    if not start_date:
        start_date = datetime.now() - timedelta(days=30)
    if not end_date:
        end_date = datetime.now()
    
    # Total alerts
    total_result = await db.execute(
        select(func.count(ThreatAlert.id)).where(
            and_(
                ThreatAlert.detected_at >= start_date,
                ThreatAlert.detected_at <= end_date
            )
        )
    )
    total_alerts = total_result.scalar()
    
    # Alerts by severity
    critical_result = await db.execute(
        select(func.count(ThreatAlert.id)).where(
            and_(
                ThreatAlert.severity == 'critical',
                ThreatAlert.detected_at >= start_date,
                ThreatAlert.detected_at <= end_date
            )
        )
    )
    critical_alerts = critical_result.scalar()
    
    high_result = await db.execute(
        select(func.count(ThreatAlert.id)).where(
            and_(
                ThreatAlert.severity == 'high',
                ThreatAlert.detected_at >= start_date,
                ThreatAlert.detected_at <= end_date
            )
        )
    )
    high_alerts = high_result.scalar()
    
    medium_result = await db.execute(
        select(func.count(ThreatAlert.id)).where(
            and_(
                ThreatAlert.severity == 'medium',
                ThreatAlert.detected_at >= start_date,
                ThreatAlert.detected_at <= end_date
            )
        )
    )
    medium_alerts = medium_result.scalar()
    
    low_result = await db.execute(
        select(func.count(ThreatAlert.id)).where(
            and_(
                ThreatAlert.severity == 'low',
                ThreatAlert.detected_at >= start_date,
                ThreatAlert.detected_at <= end_date
            )
        )
    )
    low_alerts = low_result.scalar()
    
    # Alerts by status
    open_result = await db.execute(
        select(func.count(ThreatAlert.id)).where(
            and_(
                ThreatAlert.status == 'open',
                ThreatAlert.detected_at >= start_date,
                ThreatAlert.detected_at <= end_date
            )
        )
    )
    open_alerts = open_result.scalar()
    
    resolved_result = await db.execute(
        select(func.count(ThreatAlert.id)).where(
            and_(
                ThreatAlert.status == 'resolved',
                ThreatAlert.detected_at >= start_date,
                ThreatAlert.detected_at <= end_date
            )
        )
    )
    resolved_alerts = resolved_result.scalar()
    
    false_positive_result = await db.execute(
        select(func.count(ThreatAlert.id)).where(
            and_(
                ThreatAlert.status == 'false_positive',
                ThreatAlert.detected_at >= start_date,
                ThreatAlert.detected_at <= end_date
            )
        )
    )
    false_positives = false_positive_result.scalar()
    
    return DashboardStats(
        total_alerts=total_alerts,
        critical_alerts=critical_alerts,
        high_alerts=high_alerts,
        medium_alerts=medium_alerts,
        low_alerts=low_alerts,
        open_alerts=open_alerts,
        resolved_alerts=resolved_alerts,
        false_positives=false_positives
    )


@router.get("/trends", response_model=List[ThreatTrend])
async def get_threat_trends(
    days: int = Query(7, ge=1, le=90),
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """Get threat trends over time"""
    start_date = datetime.now() - timedelta(days=days)
    
    # Query for daily alert counts by severity
    result = await db.execute(
        select(
            func.date(ThreatAlert.detected_at).label('date'),
            ThreatAlert.severity,
            func.count(ThreatAlert.id).label('count')
        ).where(
            ThreatAlert.detected_at >= start_date
        ).group_by(
            func.date(ThreatAlert.detected_at),
            ThreatAlert.severity
        ).order_by(
            func.date(ThreatAlert.detected_at)
        )
    )
    
    trends = []
    for row in result:
        trends.append(ThreatTrend(
            date=str(row.date),
            count=row.count,
            severity=row.severity
        ))
    
    return trends


@router.get("/top-threats", response_model=List[TopThreats])
async def get_top_threats(
    limit: int = Query(10, ge=1, le=50),
    days: int = Query(30, ge=1, le=90),
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """Get top threat categories"""
    start_date = datetime.now() - timedelta(days=days)
    
    result = await db.execute(
        select(
            ThreatAlert.category,
            func.count(ThreatAlert.id).label('count')
        ).where(
            ThreatAlert.detected_at >= start_date
        ).group_by(
            ThreatAlert.category
        ).order_by(
            func.count(ThreatAlert.id).desc()
        ).limit(limit)
    )
    
    top_threats = []
    for row in result:
        top_threats.append(TopThreats(
            category=row.category,
            count=row.count
        ))
    
    return top_threats


@router.get("/activity-heatmap")
async def get_activity_heatmap(
    days: int = Query(7, ge=1, le=30),
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """Get activity heatmap data (hour of day vs day of week)"""
    start_date = datetime.now() - timedelta(days=days)
    
    result = await db.execute(
        select(ThreatAlert).where(
            ThreatAlert.detected_at >= start_date
        )
    )
    alerts = result.scalars().all()
    
    # Create heatmap data structure
    heatmap = [[0 for _ in range(24)] for _ in range(7)]
    
    for alert in alerts:
        day_of_week = alert.detected_at.weekday()
        hour = alert.detected_at.hour
        heatmap[day_of_week][hour] += 1
    
    return {
        "heatmap": heatmap,
        "days": ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"],
        "hours": list(range(24))
    }


@router.get("/geographic-distribution")
async def get_geographic_distribution(
    days: int = Query(30, ge=1, le=90),
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """Get geographic distribution of threats"""
    start_date = datetime.now() - timedelta(days=days)
    
    result = await db.execute(
        select(ThreatAlert).where(
            ThreatAlert.detected_at >= start_date
        )
    )
    alerts = result.scalars().all()
    
    # Count threats by country
    country_counts = {}
    for alert in alerts:
        if alert.geo_location and 'country' in alert.geo_location:
            country = alert.geo_location['country']
            country_counts[country] = country_counts.get(country, 0) + 1
    
    # Sort by count
    sorted_countries = sorted(
        country_counts.items(),
        key=lambda x: x[1],
        reverse=True
    )
    
    return {
        "countries": [
            {"country": country, "count": count}
            for country, count in sorted_countries[:20]  # Top 20
        ]
    }
