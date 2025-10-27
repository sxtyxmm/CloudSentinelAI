"""
Threat intelligence service for external API integration
"""
import aiohttp
from typing import Dict, Optional, List
import structlog
from datetime import datetime

from app.core.config import settings

logger = structlog.get_logger()


class ThreatIntelligenceService:
    """
    Service for querying external threat intelligence sources
    """
    
    def __init__(self):
        self.virustotal_api_key = settings.VIRUSTOTAL_API_KEY
        self.shodan_api_key = settings.SHODAN_API_KEY
        
    async def check_ip_reputation(self, ip_address: str) -> Dict[str, any]:
        """
        Check IP address reputation across multiple sources
        """
        results = {
            'ip_address': ip_address,
            'is_malicious': False,
            'threat_score': 0.0,
            'sources': []
        }
        
        # Check VirusTotal
        if self.virustotal_api_key:
            vt_result = await self._check_virustotal_ip(ip_address)
            if vt_result:
                results['sources'].append(vt_result)
                if vt_result.get('malicious_count', 0) > 0:
                    results['is_malicious'] = True
                    results['threat_score'] = max(
                        results['threat_score'],
                        vt_result.get('malicious_count', 0) / max(vt_result.get('total_engines', 1), 1)
                    )
        
        # Check Shodan (for open ports and vulnerabilities)
        if self.shodan_api_key:
            shodan_result = await self._check_shodan_ip(ip_address)
            if shodan_result:
                results['sources'].append(shodan_result)
        
        return results
    
    async def _check_virustotal_ip(self, ip_address: str) -> Optional[Dict]:
        """Check IP against VirusTotal API"""
        if not self.virustotal_api_key:
            return None
        
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}"
        headers = {
            "x-apikey": self.virustotal_api_key
        }
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, headers=headers, timeout=10) as response:
                    if response.status == 200:
                        data = await response.json()
                        stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
                        return {
                            'source': 'virustotal',
                            'malicious_count': stats.get('malicious', 0),
                            'suspicious_count': stats.get('suspicious', 0),
                            'total_engines': sum(stats.values()),
                            'reputation': data.get('data', {}).get('attributes', {}).get('reputation', 0)
                        }
        except Exception as e:
            logger.error(f"Error checking VirusTotal: {e}")
        
        return None
    
    async def _check_shodan_ip(self, ip_address: str) -> Optional[Dict]:
        """Check IP against Shodan API"""
        if not self.shodan_api_key:
            return None
        
        url = f"https://api.shodan.io/shodan/host/{ip_address}"
        params = {
            "key": self.shodan_api_key
        }
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, params=params, timeout=10) as response:
                    if response.status == 200:
                        data = await response.json()
                        return {
                            'source': 'shodan',
                            'open_ports': data.get('ports', []),
                            'vulnerabilities': data.get('vulns', []),
                            'country': data.get('country_name'),
                            'organization': data.get('org')
                        }
        except Exception as e:
            logger.error(f"Error checking Shodan: {e}")
        
        return None
    
    async def enrich_with_mitre_attack(self, threat_indicators: Dict) -> List[str]:
        """
        Map threat indicators to MITRE ATT&CK tactics and techniques
        """
        tactics = []
        
        # Simple mapping based on common patterns
        if threat_indicators.get('failed_login'):
            tactics.append("T1110 - Brute Force")
        
        if threat_indicators.get('privilege_escalation'):
            tactics.append("T1068 - Exploitation for Privilege Escalation")
        
        if threat_indicators.get('unusual_access'):
            tactics.append("T1078 - Valid Accounts")
        
        if threat_indicators.get('data_exfiltration'):
            tactics.append("T1041 - Exfiltration Over C2 Channel")
        
        if threat_indicators.get('suspicious_process'):
            tactics.append("T1059 - Command and Scripting Interpreter")
        
        return tactics


class NotificationService:
    """
    Service for sending notifications via multiple channels
    """
    
    def __init__(self):
        self.slack_webhook = settings.SLACK_WEBHOOK_URL
    
    async def send_alert_notification(
        self,
        alert_id: str,
        severity: str,
        title: str,
        description: str
    ) -> bool:
        """
        Send alert notification to configured channels
        """
        success = True
        
        # Send to Slack
        if self.slack_webhook:
            slack_success = await self._send_slack_notification(
                alert_id, severity, title, description
            )
            success = success and slack_success
        
        # Could add email, ServiceNow, etc. here
        
        return success
    
    async def _send_slack_notification(
        self,
        alert_id: str,
        severity: str,
        title: str,
        description: str
    ) -> bool:
        """Send notification to Slack"""
        if not self.slack_webhook:
            return False
        
        # Color coding based on severity
        color_map = {
            'critical': '#FF0000',
            'high': '#FF6600',
            'medium': '#FFCC00',
            'low': '#00FF00'
        }
        
        payload = {
            "attachments": [
                {
                    "color": color_map.get(severity, '#808080'),
                    "title": f"🚨 Security Alert: {title}",
                    "text": description,
                    "fields": [
                        {
                            "title": "Alert ID",
                            "value": alert_id,
                            "short": True
                        },
                        {
                            "title": "Severity",
                            "value": severity.upper(),
                            "short": True
                        }
                    ],
                    "footer": "CloudSentinelAI",
                    "ts": int(datetime.now().timestamp())
                }
            ]
        }
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(self.slack_webhook, json=payload, timeout=10) as response:
                    return response.status == 200
        except Exception as e:
            logger.error(f"Error sending Slack notification: {e}")
            return False
