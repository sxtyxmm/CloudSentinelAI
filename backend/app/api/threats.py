"""
Threat detection and log processing endpoints
"""
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from sqlalchemy.ext.asyncio import AsyncSession
from typing import List, Dict, Any

from app.core.database import get_db
from app.core.security import get_current_user
from app.models.schemas import CloudLogCreate, CloudLogResponse
from app.services.log_processor import LogProcessor, CloudLogIngestion
from app.services.threat_intelligence import NotificationService

router = APIRouter()
log_processor = LogProcessor()
log_ingestion = CloudLogIngestion()
notification_service = NotificationService()


async def process_and_notify(log_data: Dict[str, Any], db: AsyncSession):
    """Background task to process log and send notifications"""
    alert = await log_processor.process_log(log_data, db)
    
    if alert:
        # Send notification for high severity alerts
        if alert.severity in ['critical', 'high']:
            await notification_service.send_alert_notification(
                alert.alert_id,
                alert.severity,
                alert.title,
                alert.description or ""
            )


@router.post("/ingest/aws", response_model=Dict[str, Any])
async def ingest_aws_logs(
    events: List[Dict[str, Any]],
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """Ingest AWS CloudTrail logs"""
    processed_logs = await log_ingestion.ingest_aws_cloudtrail(events)
    
    # Process each log asynchronously
    for log_data in processed_logs:
        background_tasks.add_task(process_and_notify, log_data, db)
    
    return {
        "status": "accepted",
        "logs_count": len(processed_logs),
        "message": "Logs are being processed"
    }


@router.post("/ingest/azure", response_model=Dict[str, Any])
async def ingest_azure_logs(
    events: List[Dict[str, Any]],
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """Ingest Azure Monitor logs"""
    processed_logs = await log_ingestion.ingest_azure_monitor(events)
    
    for log_data in processed_logs:
        background_tasks.add_task(process_and_notify, log_data, db)
    
    return {
        "status": "accepted",
        "logs_count": len(processed_logs),
        "message": "Logs are being processed"
    }


@router.post("/ingest/gcp", response_model=Dict[str, Any])
async def ingest_gcp_logs(
    events: List[Dict[str, Any]],
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """Ingest GCP Cloud Logging logs"""
    processed_logs = await log_ingestion.ingest_gcp_logging(events)
    
    for log_data in processed_logs:
        background_tasks.add_task(process_and_notify, log_data, db)
    
    return {
        "status": "accepted",
        "logs_count": len(processed_logs),
        "message": "Logs are being processed"
    }


@router.post("/analyze", response_model=Dict[str, Any])
async def analyze_log(
    log_data: Dict[str, Any],
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """Analyze a single log entry for threats"""
    alert = await log_processor.process_log(log_data, db)
    
    if alert:
        return {
            "threat_detected": True,
            "alert_id": alert.alert_id,
            "severity": alert.severity,
            "category": alert.category,
            "threat_score": alert.threat_score
        }
    
    return {
        "threat_detected": False,
        "message": "No threats detected"
    }


@router.post("/check-ip/{ip_address}")
async def check_ip_reputation(
    ip_address: str,
    current_user: dict = Depends(get_current_user)
):
    """Check IP address reputation"""
    from app.services.threat_intelligence import ThreatIntelligenceService
    
    threat_intel = ThreatIntelligenceService()
    reputation = await threat_intel.check_ip_reputation(ip_address)
    
    return reputation
