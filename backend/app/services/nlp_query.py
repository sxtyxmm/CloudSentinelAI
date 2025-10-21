"""
Natural Language Query Service
Allows analysts to query threats using natural language
"""
import re
from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta
import structlog
from sqlalchemy import select, and_, or_
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.database import ThreatAlert, CloudLog

logger = structlog.get_logger()


class NaturalLanguageQueryService:
    """
    Service for processing natural language queries about threats
    """
    
    def __init__(self):
        self.severity_keywords = {
            'critical': ['critical', 'severe', 'urgent', 'emergency'],
            'high': ['high', 'serious', 'major', 'important'],
            'medium': ['medium', 'moderate'],
            'low': ['low', 'minor', 'small']
        }
        
        self.category_keywords = {
            'account_takeover': ['account takeover', 'compromised account', 'hijacked account'],
            'suspicious_login': ['suspicious login', 'unusual login', 'strange login'],
            'data_exfiltration': ['data exfiltration', 'data leak', 'data theft', 'data stolen'],
            'privilege_escalation': ['privilege escalation', 'elevated privileges', 'admin access'],
            'malicious_ip': ['malicious ip', 'bad ip', 'blacklisted ip', 'suspicious ip'],
            'insider_threat': ['insider threat', 'internal threat', 'employee threat']
        }
        
        self.status_keywords = {
            'open': ['open', 'active', 'unresolved', 'pending'],
            'investigating': ['investigating', 'in progress', 'under investigation'],
            'resolved': ['resolved', 'fixed', 'closed', 'completed'],
            'false_positive': ['false positive', 'false alarm', 'not a threat']
        }
    
    async def process_query(
        self,
        query: str,
        db: AsyncSession
    ) -> Dict[str, Any]:
        """
        Process a natural language query and return matching alerts
        
        Args:
            query: Natural language query (e.g., "Show critical threats from last 24 hours")
            db: Database session
            
        Returns:
            Dict with query results and interpretation
        """
        query_lower = query.lower()
        
        logger.info(f"Processing NL query: {query}")
        
        # Parse the query
        filters = self._parse_query(query_lower)
        
        # Build database query
        db_query = select(ThreatAlert)
        conditions = []
        
        # Apply severity filter
        if filters.get('severity'):
            conditions.append(ThreatAlert.severity.in_(filters['severity']))
        
        # Apply category filter
        if filters.get('category'):
            conditions.append(ThreatAlert.category.in_(filters['category']))
        
        # Apply status filter
        if filters.get('status'):
            conditions.append(ThreatAlert.status.in_(filters['status']))
        
        # Apply time filter
        if filters.get('time_range'):
            start_time, end_time = filters['time_range']
            if start_time:
                conditions.append(ThreatAlert.detected_at >= start_time)
            if end_time:
                conditions.append(ThreatAlert.detected_at <= end_time)
        
        # Apply geographic filter
        if filters.get('countries'):
            # This requires checking JSON field
            for country in filters['countries']:
                conditions.append(
                    ThreatAlert.geo_location['country'].astext == country
                )
        
        # Apply IP filter
        if filters.get('ip_addresses'):
            conditions.append(ThreatAlert.ip_address.in_(filters['ip_addresses']))
        
        # Apply user filter
        if filters.get('users'):
            conditions.append(ThreatAlert.user_id.in_(filters['users']))
        
        # Combine conditions
        if conditions:
            db_query = db_query.where(and_(*conditions))
        
        # Order by detection time (most recent first)
        db_query = db_query.order_by(ThreatAlert.detected_at.desc())
        
        # Apply limit
        limit = filters.get('limit', 100)
        db_query = db_query.limit(limit)
        
        # Execute query
        result = await db.execute(db_query)
        alerts = result.scalars().all()
        
        # Generate response
        return {
            'query': query,
            'interpretation': self._generate_interpretation(filters),
            'filters_applied': filters,
            'results_count': len(alerts),
            'alerts': [self._alert_to_dict(alert) for alert in alerts]
        }
    
    def _parse_query(self, query: str) -> Dict[str, Any]:
        """
        Parse natural language query into structured filters
        """
        filters = {}
        
        # Parse severity
        severity_list = []
        for severity, keywords in self.severity_keywords.items():
            if any(keyword in query for keyword in keywords):
                severity_list.append(severity)
        if severity_list:
            filters['severity'] = severity_list
        
        # Parse category
        category_list = []
        for category, keywords in self.category_keywords.items():
            if any(keyword in query for keyword in keywords):
                category_list.append(category)
        if category_list:
            filters['category'] = category_list
        
        # Parse status
        status_list = []
        for status, keywords in self.status_keywords.items():
            if any(keyword in query for keyword in keywords):
                status_list.append(status)
        if status_list:
            filters['status'] = status_list
        
        # Parse time range
        time_range = self._parse_time_range(query)
        if time_range:
            filters['time_range'] = time_range
        
        # Parse countries
        countries = self._parse_countries(query)
        if countries:
            filters['countries'] = countries
        
        # Parse IP addresses
        ip_addresses = self._parse_ip_addresses(query)
        if ip_addresses:
            filters['ip_addresses'] = ip_addresses
        
        # Parse limit
        limit = self._parse_limit(query)
        if limit:
            filters['limit'] = limit
        
        return filters
    
    def _parse_time_range(self, query: str) -> Optional[tuple]:
        """
        Parse time range from query
        """
        now = datetime.now()
        
        # Last X hours
        if 'last hour' in query or 'past hour' in query:
            return (now - timedelta(hours=1), now)
        elif match := re.search(r'last (\d+) hours?', query):
            hours = int(match.group(1))
            return (now - timedelta(hours=hours), now)
        
        # Last X days
        elif 'today' in query or 'last 24 hours' in query:
            return (now - timedelta(days=1), now)
        elif match := re.search(r'last (\d+) days?', query):
            days = int(match.group(1))
            return (now - timedelta(days=days), now)
        
        # Last week
        elif 'last week' in query or 'past week' in query:
            return (now - timedelta(weeks=1), now)
        
        # Last month
        elif 'last month' in query or 'past month' in query:
            return (now - timedelta(days=30), now)
        
        return None
    
    def _parse_countries(self, query: str) -> List[str]:
        """
        Parse country names from query
        """
        # Common country names and codes
        countries = []
        country_patterns = [
            r'\bfrom ([A-Z]{2})\b',  # Two-letter country codes
            r'\bin ([A-Za-z\s]+)\b',  # Country names after "in"
            r'\bfrom ([A-Za-z\s]+)\b',  # Country names after "from"
        ]
        
        common_countries = {
            'us': 'US', 'usa': 'US', 'united states': 'US',
            'uk': 'GB', 'britain': 'GB', 'united kingdom': 'GB',
            'china': 'CN', 'russia': 'RU', 'germany': 'DE',
            'france': 'FR', 'japan': 'JP', 'india': 'IN',
            'europe': 'EU', 'asia': 'AS'
        }
        
        for pattern in country_patterns:
            if matches := re.findall(pattern, query, re.IGNORECASE):
                for match in matches:
                    match_lower = match.lower().strip()
                    if match_lower in common_countries:
                        countries.append(common_countries[match_lower])
                    elif len(match) == 2:
                        countries.append(match.upper())
        
        return list(set(countries))
    
    def _parse_ip_addresses(self, query: str) -> List[str]:
        """
        Parse IP addresses from query
        """
        # IPv4 pattern
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        return re.findall(ip_pattern, query)
    
    def _parse_limit(self, query: str) -> Optional[int]:
        """
        Parse result limit from query
        """
        if match := re.search(r'(?:top|first|show) (\d+)', query):
            return int(match.group(1))
        elif 'all' in query:
            return 1000  # Max limit for "all"
        return None
    
    def _generate_interpretation(self, filters: Dict[str, Any]) -> str:
        """
        Generate human-readable interpretation of the query
        """
        parts = []
        
        if filters.get('severity'):
            parts.append(f"severity: {', '.join(filters['severity'])}")
        
        if filters.get('category'):
            parts.append(f"type: {', '.join(filters['category'])}")
        
        if filters.get('status'):
            parts.append(f"status: {', '.join(filters['status'])}")
        
        if filters.get('time_range'):
            start, end = filters['time_range']
            if start and end:
                parts.append(f"from {start.strftime('%Y-%m-%d %H:%M')} to {end.strftime('%Y-%m-%d %H:%M')}")
        
        if filters.get('countries'):
            parts.append(f"from countries: {', '.join(filters['countries'])}")
        
        if filters.get('ip_addresses'):
            parts.append(f"from IPs: {', '.join(filters['ip_addresses'])}")
        
        if not parts:
            return "Showing all alerts"
        
        return "Searching for alerts with " + ", ".join(parts)
    
    def _alert_to_dict(self, alert: ThreatAlert) -> Dict[str, Any]:
        """
        Convert alert to dictionary for response
        """
        return {
            'id': alert.id,
            'alert_id': alert.alert_id,
            'severity': alert.severity,
            'category': alert.category,
            'title': alert.title,
            'description': alert.description,
            'threat_score': alert.threat_score,
            'status': alert.status,
            'user_id': alert.user_id,
            'ip_address': alert.ip_address,
            'detected_at': alert.detected_at.isoformat() if alert.detected_at else None
        }


class QuerySuggestionService:
    """
    Service for providing query suggestions and examples
    """
    
    def get_example_queries(self) -> List[str]:
        """
        Return list of example natural language queries
        """
        return [
            "Show critical threats from last 24 hours",
            "Find suspicious logins from Russia",
            "List all open alerts with high severity",
            "Show data exfiltration attempts from last week",
            "Find threats from IP 192.168.1.1",
            "Show resolved critical alerts from last month",
            "List account takeover attempts from today",
            "Find all insider threats",
            "Show top 10 most recent threats",
            "List malicious IP alerts from Europe"
        ]
    
    def get_query_help(self) -> Dict[str, Any]:
        """
        Return help information for natural language queries
        """
        return {
            'description': 'Ask questions about threats in natural language',
            'examples': self.get_example_queries(),
            'supported_filters': {
                'severity': ['critical', 'high', 'medium', 'low'],
                'categories': [
                    'account takeover', 'suspicious login', 'data exfiltration',
                    'privilege escalation', 'malicious ip', 'insider threat'
                ],
                'status': ['open', 'investigating', 'resolved', 'false positive'],
                'time_ranges': [
                    'last hour', 'last 24 hours', 'today', 'last week',
                    'last month', 'last X days', 'last X hours'
                ],
                'geographic': ['from [country]', 'in [country]'],
                'ip_address': ['from IP [address]'],
                'limits': ['top X', 'first X', 'show X', 'all']
            },
            'tips': [
                'You can combine multiple filters in one query',
                'Use natural language - the system will interpret your intent',
                'Time ranges are relative to the current time',
                'Country names or 2-letter codes are supported'
            ]
        }
