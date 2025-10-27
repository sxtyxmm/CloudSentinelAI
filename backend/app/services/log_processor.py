"""
Log processing and ingestion service
"""
from datetime import datetime
from typing import Dict, List, Any, Optional
import structlog
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.database import CloudLog, ThreatAlert
from app.models.schemas import ThreatAlertCreate
from app.ml.anomaly_detector import AnomalyDetector, ThreatScorer
from app.services.threat_intelligence import ThreatIntelligenceService

logger = structlog.get_logger()


class LogProcessor:
    """
    Process incoming cloud logs and detect anomalies
    """
    
    def __init__(self):
        self.anomaly_detector = AnomalyDetector()
        self.threat_scorer = ThreatScorer()
        self.threat_intel = ThreatIntelligenceService()
        
        # Try to load pre-trained model
        try:
            self.anomaly_detector.load_model()
            logger.info("Loaded pre-trained anomaly detection model")
        except FileNotFoundError:
            logger.warning("No pre-trained model found, will use default thresholds")
    
    async def process_log(
        self,
        log_data: Dict[str, Any],
        db: AsyncSession
    ) -> Optional[ThreatAlert]:
        """
        Process a single log entry and detect threats
        
        Returns:
            ThreatAlert if a threat is detected, None otherwise
        """
        # Step 1: Run anomaly detection
        is_anomaly, anomaly_score = self.anomaly_detector.predict(log_data)
        
        # Store the log
        cloud_log = CloudLog(
            log_id=log_data.get('log_id', f"log_{datetime.now().timestamp()}"),
            source=log_data.get('source', 'unknown'),
            service=log_data.get('service', 'unknown'),
            event_type=log_data.get('event_type', 'unknown'),
            event_name=log_data.get('event_name', 'unknown'),
            user_id=log_data.get('user_id'),
            ip_address=log_data.get('ip_address'),
            raw_log=log_data,
            anomaly_score=anomaly_score,
            is_anomalous=is_anomaly,
            event_time=log_data.get('event_time', datetime.now())
        )
        
        db.add(cloud_log)
        
        # Step 2: If anomalous, perform deeper analysis
        if not is_anomaly or anomaly_score < 0.5:
            await db.commit()
            return None
        
        # Step 3: Enrich with threat intelligence
        external_intel = {}
        if log_data.get('ip_address'):
            ip_reputation = await self.threat_intel.check_ip_reputation(
                log_data['ip_address']
            )
            external_intel['ip_reputation'] = ip_reputation
        
        # Step 4: Calculate threat score
        threat_score, severity = self.threat_scorer.calculate_threat_score(
            anomaly_score=anomaly_score,
            event_type=log_data.get('event_type', ''),
            user_context=log_data,
            external_intelligence=external_intel.get('ip_reputation', {})
        )
        
        # Step 5: Categorize the threat
        category = self._categorize_threat(log_data, anomaly_score, external_intel)
        
        # Step 6: Get MITRE tactics
        mitre_tactics = await self.threat_intel.enrich_with_mitre_attack(
            self._extract_threat_indicators(log_data)
        )
        
        # Step 7: Create alert if threat score is significant
        if threat_score >= 0.5:
            alert = ThreatAlert(
                alert_id=f"alert_{datetime.now().timestamp()}",
                severity=severity,
                category=category,
                source=log_data.get('source', 'unknown'),
                title=self._generate_alert_title(category, log_data),
                description=self._generate_alert_description(log_data, anomaly_score),
                threat_score=threat_score,
                confidence=anomaly_score,
                indicators=self._extract_threat_indicators(log_data),
                affected_resources=log_data.get('resources', []),
                user_id=log_data.get('user_id'),
                ip_address=log_data.get('ip_address'),
                geo_location=log_data.get('geo_location'),
                mitre_tactics=mitre_tactics,
                external_references=external_intel,
                detected_at=datetime.now(),
                status='open'
            )
            
            db.add(alert)
            await db.commit()
            await db.refresh(alert)
            
            logger.info(
                f"Threat detected",
                alert_id=alert.alert_id,
                severity=severity,
                category=category
            )
            
            return alert
        
        await db.commit()
        return None
    
    def _categorize_threat(
        self,
        log_data: Dict[str, Any],
        anomaly_score: float,
        external_intel: Dict[str, Any]
    ) -> str:
        """Categorize the type of threat"""
        event_type = log_data.get('event_type', '').lower()
        
        # Check for specific patterns
        if 'login' in event_type and anomaly_score > 0.7:
            return 'suspicious_login'
        
        if log_data.get('geo_location', {}).get('country_change'):
            return 'account_takeover'
        
        if 'privilege' in event_type or 'admin' in event_type:
            return 'privilege_escalation'
        
        if 'download' in event_type or 'export' in event_type:
            return 'data_exfiltration'
        
        if external_intel.get('ip_reputation', {}).get('is_malicious'):
            return 'malicious_ip'
        
        return 'unusual_activity'
    
    def _extract_threat_indicators(self, log_data: Dict[str, Any]) -> Dict[str, Any]:
        """Extract indicators of compromise from log data"""
        indicators = {
            'event_type': log_data.get('event_type'),
            'ip_address': log_data.get('ip_address'),
            'user_agent': log_data.get('user_agent'),
            'failed_login': 'failed' in str(log_data.get('status', '')).lower(),
            'unusual_time': self._is_unusual_time(log_data.get('event_time')),
        }
        
        return indicators
    
    def _is_unusual_time(self, event_time: Optional[datetime]) -> bool:
        """Check if event occurred at unusual time"""
        if not event_time:
            return False
        
        # Business hours: 9 AM to 6 PM on weekdays
        is_business_hours = 9 <= event_time.hour <= 18
        is_weekday = event_time.weekday() < 5
        
        return not (is_business_hours and is_weekday)
    
    def _generate_alert_title(self, category: str, log_data: Dict[str, Any]) -> str:
        """Generate a descriptive alert title"""
        titles = {
            'suspicious_login': f"Suspicious login attempt from {log_data.get('ip_address', 'unknown IP')}",
            'account_takeover': f"Potential account takeover for user {log_data.get('user_id', 'unknown')}",
            'privilege_escalation': f"Privilege escalation attempt detected",
            'data_exfiltration': f"Potential data exfiltration detected",
            'malicious_ip': f"Activity from malicious IP {log_data.get('ip_address')}",
            'insider_threat': f"Insider threat activity detected",
            'unusual_activity': f"Unusual activity pattern detected"
        }
        
        return titles.get(category, "Security threat detected")
    
    def _generate_alert_description(
        self,
        log_data: Dict[str, Any],
        anomaly_score: float
    ) -> str:
        """Generate detailed alert description"""
        description = f"Anomalous activity detected with confidence score of {anomaly_score:.2f}.\n\n"
        description += f"Event: {log_data.get('event_type', 'unknown')}\n"
        description += f"User: {log_data.get('user_id', 'unknown')}\n"
        description += f"Source IP: {log_data.get('ip_address', 'unknown')}\n"
        description += f"Time: {log_data.get('event_time', 'unknown')}\n"
        
        if log_data.get('geo_location'):
            geo = log_data['geo_location']
            description += f"Location: {geo.get('city', 'unknown')}, {geo.get('country', 'unknown')}\n"
        
        return description


class CloudLogIngestion:
    """
    Service for ingesting logs from different cloud providers
    """
    
    async def ingest_aws_cloudtrail(self, events: List[Dict]) -> List[Dict]:
        """Process AWS CloudTrail events"""
        processed_logs = []
        
        for event in events:
            log = {
                'log_id': event.get('eventID'),
                'source': 'AWS',
                'service': 'CloudTrail',
                'event_type': event.get('eventName'),
                'event_name': event.get('eventName'),
                'user_id': event.get('userIdentity', {}).get('principalId'),
                'ip_address': event.get('sourceIPAddress'),
                'user_agent': event.get('userAgent'),
                'event_time': event.get('eventTime'),
                'resources': [r.get('ARN') for r in event.get('resources', [])],
                'raw_log': event
            }
            processed_logs.append(log)
        
        return processed_logs
    
    async def ingest_azure_monitor(self, events: List[Dict]) -> List[Dict]:
        """Process Azure Monitor events"""
        processed_logs = []
        
        for event in events:
            log = {
                'log_id': event.get('operationId'),
                'source': 'Azure',
                'service': 'Monitor',
                'event_type': event.get('operationName'),
                'event_name': event.get('operationName'),
                'user_id': event.get('caller'),
                'ip_address': event.get('httpRequest', {}).get('clientIpAddress'),
                'event_time': event.get('eventTimestamp'),
                'raw_log': event
            }
            processed_logs.append(log)
        
        return processed_logs
    
    async def ingest_gcp_logging(self, events: List[Dict]) -> List[Dict]:
        """Process GCP Cloud Logging events"""
        processed_logs = []
        
        for event in events:
            log = {
                'log_id': event.get('insertId'),
                'source': 'GCP',
                'service': 'CloudLogging',
                'event_type': event.get('protoPayload', {}).get('methodName'),
                'event_name': event.get('protoPayload', {}).get('methodName'),
                'user_id': event.get('protoPayload', {}).get('authenticationInfo', {}).get('principalEmail'),
                'ip_address': event.get('protoPayload', {}).get('requestMetadata', {}).get('callerIp'),
                'event_time': event.get('timestamp'),
                'raw_log': event
            }
            processed_logs.append(log)
        
        return processed_logs
