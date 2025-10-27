"""
SIEM Integration endpoints
"""
from fastapi import APIRouter, Depends, HTTPException, Body
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from typing import Dict, Any, List
from pydantic import BaseModel

from app.core.database import get_db
from app.core.security import get_current_user
from app.models.database import ThreatAlert
from app.services.siem_integration import SIEMIntegrationService

router = APIRouter()
siem_service = SIEMIntegrationService()


class SplunkConfig(BaseModel):
    url: str
    token: str


class ElasticConfig(BaseModel):
    index_name: str = 'cloudsentinel-alerts'


class SIEMExportRequest(BaseModel):
    alert_ids: List[int]
    siem_type: str  # splunk, elastic, cef, leef
    config: Dict[str, Any]


@router.post("/export/splunk")
async def export_to_splunk(
    config: SplunkConfig,
    alert_ids: List[int] = Body(...),
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user)
) -> Dict[str, Any]:
    """
    Export alerts to Splunk
    """
    # Verify admin role
    if current_user.get('role') != 'admin':
        raise HTTPException(status_code=403, detail="Admin access required")
    
    # Get alerts
    result = await db.execute(
        select(ThreatAlert).where(ThreatAlert.id.in_(alert_ids))
    )
    alerts = result.scalars().all()
    
    if not alerts:
        raise HTTPException(status_code=404, detail="No alerts found")
    
    # Export to Splunk
    export_result = await siem_service.export_batch_to_splunk(
        alerts,
        config.url,
        config.token
    )
    
    return export_result


@router.post("/export/elastic")
async def export_to_elastic(
    config: ElasticConfig,
    alert_ids: List[int] = Body(...),
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user)
) -> Dict[str, Any]:
    """
    Export alerts to Elastic SIEM
    """
    # Verify admin role
    if current_user.get('role') != 'admin':
        raise HTTPException(status_code=403, detail="Admin access required")
    
    # Get alerts
    result = await db.execute(
        select(ThreatAlert).where(ThreatAlert.id.in_(alert_ids))
    )
    alerts = result.scalars().all()
    
    if not alerts:
        raise HTTPException(status_code=404, detail="No alerts found")
    
    # Export to Elastic
    export_result = await siem_service.export_batch_to_elastic(
        alerts,
        config.index_name
    )
    
    return export_result


@router.post("/export/cef")
async def export_to_cef(
    alert_ids: List[int] = Body(...),
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user)
) -> Dict[str, Any]:
    """
    Export alerts in CEF (Common Event Format)
    Compatible with ArcSight and other CEF-compatible SIEMs
    """
    # Get alerts
    result = await db.execute(
        select(ThreatAlert).where(ThreatAlert.id.in_(alert_ids))
    )
    alerts = result.scalars().all()
    
    if not alerts:
        raise HTTPException(status_code=404, detail="No alerts found")
    
    # Generate CEF format
    cef_events = [siem_service.generate_cef_format(alert) for alert in alerts]
    
    return {
        'format': 'CEF',
        'total': len(cef_events),
        'events': cef_events
    }


@router.post("/export/leef")
async def export_to_leef(
    alert_ids: List[int] = Body(...),
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user)
) -> Dict[str, Any]:
    """
    Export alerts in LEEF (Log Event Extended Format)
    Compatible with IBM QRadar
    """
    # Get alerts
    result = await db.execute(
        select(ThreatAlert).where(ThreatAlert.id.in_(alert_ids))
    )
    alerts = result.scalars().all()
    
    if not alerts:
        raise HTTPException(status_code=404, detail="No alerts found")
    
    # Generate LEEF format
    leef_events = [siem_service.generate_leef_format(alert) for alert in alerts]
    
    return {
        'format': 'LEEF',
        'total': len(leef_events),
        'events': leef_events
    }


@router.post("/sync")
async def sync_to_siem(
    request: SIEMExportRequest,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user)
) -> Dict[str, Any]:
    """
    Generic sync endpoint for any SIEM type
    """
    # Verify admin role
    if current_user.get('role') != 'admin':
        raise HTTPException(status_code=403, detail="Admin access required")
    
    # Get alerts
    result = await db.execute(
        select(ThreatAlert).where(ThreatAlert.id.in_(request.alert_ids))
    )
    alerts = result.scalars().all()
    
    if not alerts:
        raise HTTPException(status_code=404, detail="No alerts found")
    
    # Sync to SIEM
    try:
        sync_result = await siem_service.sync_to_siem(
            alerts,
            request.siem_type,
            request.config
        )
        return sync_result
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/formats")
async def get_supported_formats(
    current_user: dict = Depends(get_current_user)
) -> Dict[str, Any]:
    """
    Get list of supported SIEM formats
    """
    return {
        'formats': [
            {
                'name': 'Splunk',
                'type': 'splunk',
                'description': 'Splunk HTTP Event Collector (HEC)',
                'config_required': ['url', 'token']
            },
            {
                'name': 'Elastic SIEM',
                'type': 'elastic',
                'description': 'Elasticsearch-based SIEM',
                'config_required': ['index_name']
            },
            {
                'name': 'CEF',
                'type': 'cef',
                'description': 'Common Event Format (ArcSight, etc.)',
                'config_required': []
            },
            {
                'name': 'LEEF',
                'type': 'leef',
                'description': 'Log Event Extended Format (QRadar)',
                'config_required': []
            }
        ]
    }
