# Advanced Features Guide

This document covers the advanced features implemented in CloudSentinelAI.

## Table of Contents

1. [Natural Language Querying](#natural-language-querying)
2. [Explainable AI](#explainable-ai)
3. [Graph-based Threat Analysis](#graph-based-threat-analysis)
4. [Predictive Threat Modeling](#predictive-threat-modeling)
5. [SIEM Integration](#siem-integration)

---

## Natural Language Querying

Query threats using natural language instead of complex filters.

### Overview

The Natural Language Query (NLQ) service allows security analysts to ask questions about threats in plain English. The system interprets the query and returns matching alerts.

### Examples

```
"Show critical threats from last 24 hours"
"Find suspicious logins from Russia"
"List all open alerts with high severity"
"Show data exfiltration attempts from last week"
"Find threats from IP 192.168.1.1"
```

### API Endpoints

#### Query Threats
```http
GET /api/v1/nlp/query?q=Show%20critical%20threats%20from%20last%2024%20hours
```

**Response:**
```json
{
  "query": "Show critical threats from last 24 hours",
  "interpretation": "Searching for alerts with severity: critical, from 2024-01-20 12:00 to 2024-01-21 12:00",
  "filters_applied": {
    "severity": ["critical"],
    "time_range": ["2024-01-20T12:00:00", "2024-01-21T12:00:00"]
  },
  "results_count": 15,
  "alerts": [...]
}
```

#### Get Example Queries
```http
GET /api/v1/nlp/examples
```

#### Get Query Help
```http
GET /api/v1/nlp/help
```

### Supported Filters

- **Severity**: critical, high, medium, low
- **Categories**: account takeover, suspicious login, data exfiltration, etc.
- **Status**: open, investigating, resolved, false positive
- **Time Ranges**: last hour, last 24 hours, today, last week, last month, last X days/hours
- **Geographic**: from [country], in [country]
- **IP Address**: from IP [address]
- **Limits**: top X, first X, show X, all

### Tips

- You can combine multiple filters in one query
- Use natural language - the system will interpret your intent
- Time ranges are relative to the current time
- Country names or 2-letter codes are supported

---

## Explainable AI

Understand why the AI made specific threat predictions.

### Overview

The Explainable AI service provides interpretability for ML model predictions, helping analysts understand why an alert was generated and which factors contributed to the threat score.

### Features

- **Alert Explanation**: Understand why a specific alert was generated
- **Feature Contributions**: See which features contributed most to the prediction
- **Global Model Explanation**: Understand how the model works overall
- **Threat Category Explanations**: Detailed information about threat types

### API Endpoints

#### Explain Alert
```http
GET /api/v1/explainability/alert/{alert_id}
```

**Response:**
```json
{
  "alert": {
    "id": 123,
    "severity": "critical",
    "threat_score": 0.92
  },
  "prediction_explanation": {
    "explanation": "This alert has a CRITICAL threat level.\nKey contributing factors:\n• Failed authentication attempts (strong indicator, +0.25)\n• Delete operations detected (strong indicator, +0.22)\n• Time of day (moderate indicator, +0.15)",
    "feature_contributions": {
      "is_failed_attempt": 0.25,
      "is_delete_event": 0.22,
      "hour_of_day": 0.15
    },
    "top_factors": [
      {
        "feature": "is_failed_attempt",
        "contribution": 0.25,
        "explanation": "Failed authentication attempts (strong indicator, +0.25)"
      }
    ],
    "interpretation": "Very high confidence - urgent investigation required"
  },
  "threat_type_explanation": {
    "description": "Unauthorized access to a user account",
    "indicators": [
      "Login from unusual geographic location",
      "Multiple failed login attempts followed by success"
    ],
    "recommended_actions": [
      "Immediately disable the compromised account",
      "Force password reset"
    ]
  }
}
```

#### Get Model Explanation
```http
GET /api/v1/explainability/model/global
```

#### Explain Threat Category
```http
GET /api/v1/explainability/threat-category/{category}
```

### Understanding Feature Contributions

Features are weighted based on their importance:
- **Strong indicators** (>0.1): Major factors in the decision
- **Moderate indicators** (0.05-0.1): Contributing factors
- **Minor indicators** (<0.05): Supporting evidence

---

## Graph-based Threat Analysis

Visualize entity relationships and detect lateral movement.

### Overview

The Graph Analysis service builds a network graph of threat relationships, showing connections between users, IPs, and resources. This helps identify attack patterns and lateral movement.

### Features

- **Lateral Movement Detection**: Identify attackers moving through your network
- **Attack Path Discovery**: Find paths attackers might take
- **Network Centrality Analysis**: Identify critical nodes
- **Graph Visualization**: Visual representation of threat relationships

### API Endpoints

#### Detect Lateral Movement
```http
GET /api/v1/graph/lateral-movement?hours=24
```

**Response:**
```json
{
  "time_window_hours": 24,
  "lateral_movements_detected": 3,
  "movements": [
    {
      "type": "rapid_resource_access",
      "user_id": "user@example.com",
      "resource_count": 5,
      "time_span_minutes": 15.5,
      "severity": "high",
      "description": "User accessed 5 resources in 15.5 minutes"
    }
  ]
}
```

#### Find Attack Paths
```http
GET /api/v1/graph/attack-paths?source=ip:192.168.1.1&target=resource:sensitive_data&max_length=5
```

#### Analyze Centrality
```http
GET /api/v1/graph/centrality?hours=24
```

**Response:**
```json
{
  "most_connected_nodes": [
    {
      "node": "user:admin@example.com",
      "centrality": 0.85,
      "type": "user",
      "alert_count": 12
    }
  ],
  "critical_intermediaries": [...],
  "network_stats": {
    "total_nodes": 45,
    "total_edges": 123,
    "density": 0.062
  }
}
```

#### Get Visualization Data
```http
GET /api/v1/graph/visualization?hours=24
```

### Use Cases

1. **Detect Insider Threats**: Identify users accessing unusual resources
2. **Find Compromised Accounts**: Spot accounts used as pivot points
3. **Trace Attack Chains**: Follow the path of an attacker
4. **Identify Critical Assets**: Find highly-connected resources

---

## Predictive Threat Modeling

Forecast future threats based on behavioral patterns.

### Overview

The Predictive Threat Modeling service analyzes historical data to predict future security incidents, identify high-risk users, and forecast threat trends.

### Features

- **User Risk Prediction**: Calculate risk scores for individual users
- **High-Risk User Identification**: Find users most likely to be involved in incidents
- **Threat Forecasting**: Predict future threat levels
- **Risk Factor Analysis**: Understand what drives risk scores

### API Endpoints

#### Predict User Risk
```http
GET /api/v1/predictive/user-risk/{user_id}?days=30
```

**Response:**
```json
{
  "user_id": "user@example.com",
  "risk_score": 0.75,
  "risk_level": "high",
  "prediction": {
    "predictions": [
      {
        "type": "elevated_risk",
        "probability": 0.65,
        "timeframe": "1-7 days",
        "description": "Increased risk of security incident"
      }
    ],
    "recommended_actions": [
      "Schedule security review within 24 hours",
      "Review recent user activity",
      "Monitor user sessions closely"
    ]
  },
  "risk_factors": {
    "alert_frequency": 0.85,
    "severity_trend": 0.42,
    "critical_alert_ratio": 0.30,
    "unresolved_ratio": 0.70
  },
  "historical_alert_count": 15
}
```

#### Get High-Risk Users
```http
GET /api/v1/predictive/high-risk-users?limit=10&days=30
```

#### Forecast Threats
```http
GET /api/v1/predictive/threat-forecast?forecast_days=7&lookback_days=30
```

**Response:**
```json
{
  "forecast_period_days": 7,
  "historical_period_days": 30,
  "forecast": [
    {
      "date": "2024-01-22",
      "predicted_alert_count": 12,
      "confidence": 0.70
    },
    {
      "date": "2024-01-23",
      "predicted_alert_count": 15,
      "confidence": 0.65
    }
  ],
  "trend": "increasing"
}
```

### Risk Factors

The system considers multiple factors when calculating risk:

1. **Alert Frequency**: How often alerts are generated for the user
2. **Severity Trend**: Whether threat severity is increasing over time
3. **Critical Alert Ratio**: Percentage of critical alerts
4. **Unresolved Ratio**: Percentage of unresolved alerts
5. **False Positive Rate**: Affects risk negatively (good indicator)

### Use Cases

1. **Proactive Security**: Identify users before they become threats
2. **Resource Allocation**: Focus security resources on high-risk users
3. **Trend Analysis**: Understand if threats are increasing or decreasing
4. **Capacity Planning**: Predict future security team workload

---

## SIEM Integration

Export alerts to external Security Information and Event Management (SIEM) systems.

### Overview

CloudSentinelAI can export threat alerts to popular SIEM platforms for centralized security monitoring and correlation with other security data.

### Supported SIEM Platforms

1. **Splunk** - HTTP Event Collector (HEC)
2. **Elastic SIEM** - Elasticsearch-based
3. **ArcSight** - CEF (Common Event Format)
4. **IBM QRadar** - LEEF (Log Event Extended Format)

### API Endpoints

#### Export to Splunk
```http
POST /api/v1/siem/export/splunk
Content-Type: application/json

{
  "url": "https://splunk.example.com:8088",
  "token": "your-hec-token",
  "alert_ids": [1, 2, 3, 4, 5]
}
```

**Response:**
```json
{
  "total": 5,
  "successful": 5,
  "failed": 0
}
```

#### Export to Elastic SIEM
```http
POST /api/v1/siem/export/elastic
Content-Type: application/json

{
  "index_name": "cloudsentinel-alerts",
  "alert_ids": [1, 2, 3]
}
```

#### Export in CEF Format
```http
POST /api/v1/siem/export/cef
Content-Type: application/json

{
  "alert_ids": [1, 2]
}
```

**Response:**
```json
{
  "format": "CEF",
  "total": 2,
  "events": [
    "CEF:0|CloudSentinelAI|ThreatDetection|1.0|account_takeover|Suspicious login|75|..."
  ]
}
```

#### Export in LEEF Format
```http
POST /api/v1/siem/export/leef
Content-Type: application/json

{
  "alert_ids": [1, 2]
}
```

#### Generic Sync Endpoint
```http
POST /api/v1/siem/sync
Content-Type: application/json

{
  "alert_ids": [1, 2, 3],
  "siem_type": "splunk",
  "config": {
    "url": "https://splunk.example.com:8088",
    "token": "your-token"
  }
}
```

#### Get Supported Formats
```http
GET /api/v1/siem/formats
```

### Configuration

#### Splunk HEC Setup

1. Enable HTTP Event Collector in Splunk
2. Create a new token
3. Use the token in the export request

```python
import requests

response = requests.post(
    "http://localhost:8000/api/v1/siem/export/splunk",
    json={
        "url": "https://splunk.example.com:8088",
        "token": "your-hec-token",
        "alert_ids": [1, 2, 3]
    },
    headers={"Authorization": "Bearer your-jwt-token"}
)
```

#### Elastic SIEM Setup

1. Configure Elasticsearch endpoint
2. Create index template (optional)
3. Specify index name in export request

```python
response = requests.post(
    "http://localhost:8000/api/v1/siem/export/elastic",
    json={
        "index_name": "cloudsentinel-alerts",
        "alert_ids": [1, 2, 3]
    },
    headers={"Authorization": "Bearer your-jwt-token"}
)
```

### Data Formats

#### Splunk HEC Format
```json
{
  "time": 1706099200,
  "host": "cloudsentinelai",
  "source": "threat_detection",
  "sourcetype": "security:alert",
  "event": {
    "alert_id": "alert_123",
    "severity": "critical",
    ...
  }
}
```

#### Elastic Common Schema (ECS)
```json
{
  "@timestamp": "2024-01-21T12:00:00Z",
  "event": {
    "kind": "alert",
    "category": ["threat"],
    "severity": 100
  },
  "threat": {
    "framework": "MITRE ATT&CK"
  },
  ...
}
```

#### CEF Format
```
CEF:0|CloudSentinelAI|ThreatDetection|1.0|account_takeover|Suspicious login|75|act=open src=192.168.1.1 suser=user@example.com
```

#### LEEF Format
```
LEEF:2.0|CloudSentinelAI|ThreatDetection|1.0|account_takeover|devTime=2024-01-21T12:00:00Z	severity=high	src=192.168.1.1
```

### Automation

You can automate SIEM exports using scheduled tasks or webhooks:

```python
# Example: Export all new critical alerts to Splunk every hour

from datetime import datetime, timedelta

async def export_critical_alerts_to_splunk():
    # Get critical alerts from last hour
    alerts = await get_alerts(
        severity="critical",
        start_date=datetime.now() - timedelta(hours=1)
    )
    
    alert_ids = [a.id for a in alerts]
    
    # Export to Splunk
    result = await export_to_splunk(alert_ids, config)
    
    return result
```

---

## Best Practices

### Natural Language Querying
- Start with simple queries and add complexity as needed
- Use time ranges to limit results
- Combine multiple filters for precise results

### Explainable AI
- Always check explanations for critical alerts
- Use explanations to improve model training
- Share explanations with non-technical stakeholders

### Graph Analysis
- Regularly check for lateral movement patterns
- Investigate high-centrality nodes
- Use graph visualization for incident response

### Predictive Modeling
- Monitor high-risk users proactively
- Use forecasts for resource planning
- Adjust risk thresholds based on your environment

### SIEM Integration
- Export alerts regularly to maintain consistency
- Use CEF/LEEF for multi-SIEM environments
- Automate exports for real-time synchronization
- Test integrations in development first

---

## Troubleshooting

### Natural Language Queries Not Working
- Check query syntax and examples
- Verify database connectivity
- Review query interpretation in response

### Explainability Service Errors
- Ensure alerts have associated features
- Check model is loaded
- Verify alert ID is correct

### Graph Analysis Empty Results
- Verify time window has data
- Check alert relationships exist
- Increase time window parameter

### Predictive Model Low Accuracy
- Increase historical data period
- Verify sufficient training data
- Check for data quality issues

### SIEM Export Failures
- Verify SIEM credentials
- Check network connectivity
- Review SIEM endpoint configuration
- Check alert data format compatibility

---

## API Reference Summary

### Natural Language
- `GET /api/v1/nlp/query` - Query with natural language
- `GET /api/v1/nlp/examples` - Get example queries
- `GET /api/v1/nlp/help` - Get query help

### Explainability
- `GET /api/v1/explainability/alert/{id}` - Explain alert
- `GET /api/v1/explainability/model/global` - Model explanation
- `GET /api/v1/explainability/threat-category/{category}` - Category explanation

### Graph Analysis
- `GET /api/v1/graph/lateral-movement` - Detect lateral movement
- `GET /api/v1/graph/attack-paths` - Find attack paths
- `GET /api/v1/graph/centrality` - Analyze centrality
- `GET /api/v1/graph/visualization` - Get visualization data

### Predictive
- `GET /api/v1/predictive/user-risk/{user_id}` - Predict user risk
- `GET /api/v1/predictive/high-risk-users` - Get high-risk users
- `GET /api/v1/predictive/threat-forecast` - Forecast threats

### SIEM Integration
- `POST /api/v1/siem/export/splunk` - Export to Splunk
- `POST /api/v1/siem/export/elastic` - Export to Elastic
- `POST /api/v1/siem/export/cef` - Export as CEF
- `POST /api/v1/siem/export/leef` - Export as LEEF
- `POST /api/v1/siem/sync` - Generic sync endpoint
- `GET /api/v1/siem/formats` - Get supported formats
