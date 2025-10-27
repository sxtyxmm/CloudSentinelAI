"""
SIEM Integration Service
Export alerts to Splunk, Elastic SIEM, and other security platforms
"""
import json
from typing import Dict, List, Any, Optional
from datetime import datetime
import structlog
import aiohttp
from elasticsearch import AsyncElasticsearch

from app.core.config import settings
from app.models.database import ThreatAlert

logger = structlog.get_logger()


class SIEMIntegrationService:
    """
    Service for integrating with SIEM platforms
    """
    
    def __init__(self):
        self.splunk_hec_url = None
        self.splunk_token = None
        self.elastic_url = settings.ELASTICSEARCH_URL
    
    async def export_to_splunk(
        self,
        alert: ThreatAlert,
        splunk_url: str,
        splunk_token: str
    ) -> bool:
        """
        Export alert to Splunk HEC (HTTP Event Collector)
        """
        try:
            # Format alert for Splunk
            event = self._format_alert_for_splunk(alert)
            
            headers = {
                'Authorization': f'Splunk {splunk_token}',
                'Content-Type': 'application/json'
            }
            
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    f"{splunk_url}/services/collector/event",
                    headers=headers,
                    json=event,
                    timeout=10
                ) as response:
                    if response.status == 200:
                        logger.info(f"Successfully exported alert {alert.alert_id} to Splunk")
                        return True
                    else:
                        logger.error(f"Failed to export to Splunk: {response.status}")
                        return False
        
        except Exception as e:
            logger.error(f"Error exporting to Splunk: {e}")
            return False
    
    def _format_alert_for_splunk(self, alert: ThreatAlert) -> Dict[str, Any]:
        """
        Format alert in Splunk HEC format
        """
        return {
            'time': alert.detected_at.timestamp(),
            'host': 'cloudsentinelai',
            'source': 'threat_detection',
            'sourcetype': 'security:alert',
            'event': {
                'alert_id': alert.alert_id,
                'severity': alert.severity,
                'category': alert.category,
                'title': alert.title,
                'description': alert.description,
                'threat_score': alert.threat_score,
                'confidence': alert.confidence,
                'user_id': alert.user_id,
                'ip_address': alert.ip_address,
                'source': alert.source,
                'status': alert.status,
                'indicators': alert.indicators,
                'affected_resources': alert.affected_resources,
                'geo_location': alert.geo_location,
                'mitre_tactics': alert.mitre_tactics,
                'detected_at': alert.detected_at.isoformat()
            }
        }
    
    async def export_to_elastic_siem(
        self,
        alert: ThreatAlert,
        index_name: str = 'cloudsentinel-alerts'
    ) -> bool:
        """
        Export alert to Elastic SIEM
        """
        try:
            # Create Elasticsearch client
            es = AsyncElasticsearch([self.elastic_url])
            
            # Format alert for Elastic
            document = self._format_alert_for_elastic(alert)
            
            # Index document
            result = await es.index(
                index=index_name,
                id=alert.alert_id,
                document=document
            )
            
            await es.close()
            
            if result['result'] in ['created', 'updated']:
                logger.info(f"Successfully exported alert {alert.alert_id} to Elastic")
                return True
            else:
                return False
        
        except Exception as e:
            logger.error(f"Error exporting to Elastic: {e}")
            return False
    
    def _format_alert_for_elastic(self, alert: ThreatAlert) -> Dict[str, Any]:
        """
        Format alert in ECS (Elastic Common Schema) format
        """
        return {
            '@timestamp': alert.detected_at.isoformat(),
            'event': {
                'kind': 'alert',
                'category': ['threat'],
                'type': [alert.category],
                'severity': self._map_severity_to_number(alert.severity),
                'risk_score': alert.threat_score * 100,
                'created': alert.created_at.isoformat() if alert.created_at else None,
                'module': 'cloudsentinelai',
                'dataset': 'threat_detection'
            },
            'message': alert.title,
            'cloud': {
                'provider': alert.source.lower() if alert.source else None
            },
            'threat': {
                'framework': 'MITRE ATT&CK',
                'tactic': {
                    'name': alert.mitre_tactics if alert.mitre_tactics else []
                }
            },
            'user': {
                'id': alert.user_id
            },
            'source': {
                'ip': alert.ip_address,
                'geo': alert.geo_location if alert.geo_location else {}
            },
            'tags': [alert.severity, alert.category, alert.source],
            'cloudsentinel': {
                'alert_id': alert.alert_id,
                'confidence': alert.confidence,
                'status': alert.status,
                'indicators': alert.indicators,
                'affected_resources': alert.affected_resources
            }
        }
    
    def _map_severity_to_number(self, severity: str) -> int:
        """Map severity to numeric value for ECS"""
        severity_map = {
            'low': 25,
            'medium': 50,
            'high': 75,
            'critical': 100
        }
        return severity_map.get(severity, 50)
    
    async def export_batch_to_splunk(
        self,
        alerts: List[ThreatAlert],
        splunk_url: str,
        splunk_token: str
    ) -> Dict[str, Any]:
        """
        Export multiple alerts to Splunk in batch
        """
        success_count = 0
        failure_count = 0
        
        for alert in alerts:
            success = await self.export_to_splunk(alert, splunk_url, splunk_token)
            if success:
                success_count += 1
            else:
                failure_count += 1
        
        return {
            'total': len(alerts),
            'successful': success_count,
            'failed': failure_count
        }
    
    async def export_batch_to_elastic(
        self,
        alerts: List[ThreatAlert],
        index_name: str = 'cloudsentinel-alerts'
    ) -> Dict[str, Any]:
        """
        Export multiple alerts to Elastic in batch
        """
        try:
            es = AsyncElasticsearch([self.elastic_url])
            
            # Prepare bulk operations
            operations = []
            for alert in alerts:
                operations.append({
                    'index': {
                        '_index': index_name,
                        '_id': alert.alert_id
                    }
                })
                operations.append(self._format_alert_for_elastic(alert))
            
            # Execute bulk operation
            result = await es.bulk(operations=operations)
            
            await es.close()
            
            success_count = sum(1 for item in result['items'] 
                              if item['index']['result'] in ['created', 'updated'])
            
            return {
                'total': len(alerts),
                'successful': success_count,
                'failed': len(alerts) - success_count
            }
        
        except Exception as e:
            logger.error(f"Error in batch export to Elastic: {e}")
            return {
                'total': len(alerts),
                'successful': 0,
                'failed': len(alerts),
                'error': str(e)
            }
    
    def generate_cef_format(self, alert: ThreatAlert) -> str:
        """
        Generate CEF (Common Event Format) string
        Used by many SIEM platforms including ArcSight
        """
        cef_header = (
            f"CEF:0|CloudSentinelAI|ThreatDetection|1.0|"
            f"{alert.category}|{alert.title}|"
            f"{self._map_severity_to_number(alert.severity)}|"
        )
        
        cef_extension = (
            f"act={alert.status} "
            f"src={alert.ip_address} "
            f"suser={alert.user_id} "
            f"cs1={alert.alert_id} "
            f"cs1Label=AlertID "
            f"cn1={alert.threat_score} "
            f"cn1Label=ThreatScore "
            f"msg={alert.description}"
        )
        
        return cef_header + cef_extension
    
    def generate_leef_format(self, alert: ThreatAlert) -> str:
        """
        Generate LEEF (Log Event Extended Format) string
        Used by IBM QRadar
        """
        return (
            f"LEEF:2.0|CloudSentinelAI|ThreatDetection|1.0|{alert.category}|"
            f"devTime={alert.detected_at.isoformat()}\t"
            f"severity={alert.severity}\t"
            f"src={alert.ip_address}\t"
            f"identSrc={alert.user_id}\t"
            f"usrName={alert.user_id}\t"
            f"cat={alert.category}\t"
            f"eventId={alert.alert_id}\t"
            f"threatScore={alert.threat_score}\t"
            f"confidence={alert.confidence}"
        )
    
    async def sync_to_siem(
        self,
        alerts: List[ThreatAlert],
        siem_type: str,
        config: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Generic sync method for different SIEM types
        
        Args:
            alerts: List of alerts to sync
            siem_type: Type of SIEM (splunk, elastic, cef, leef)
            config: SIEM-specific configuration
        """
        if siem_type == 'splunk':
            return await self.export_batch_to_splunk(
                alerts,
                config.get('url'),
                config.get('token')
            )
        elif siem_type == 'elastic':
            return await self.export_batch_to_elastic(
                alerts,
                config.get('index', 'cloudsentinel-alerts')
            )
        elif siem_type == 'cef':
            # For CEF, generate formatted strings
            cef_events = [self.generate_cef_format(alert) for alert in alerts]
            return {
                'format': 'CEF',
                'events': cef_events,
                'total': len(cef_events)
            }
        elif siem_type == 'leef':
            # For LEEF, generate formatted strings
            leef_events = [self.generate_leef_format(alert) for alert in alerts]
            return {
                'format': 'LEEF',
                'events': leef_events,
                'total': len(leef_events)
            }
        else:
            raise ValueError(f"Unsupported SIEM type: {siem_type}")
