# CloudSentinelAI API Documentation

## Authentication

All API requests (except `/auth/login` and `/auth/register`) require authentication using JWT tokens.

### Login

```http
POST /api/v1/auth/login
Content-Type: application/x-www-form-urlencoded

username=admin&password=securepassword
```

**Response:**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "bearer"
}
```

### Using the Token

Include the token in the Authorization header:

```http
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

## Alerts API

### List Alerts

```http
GET /api/v1/alerts/?skip=0&limit=100&severity=critical&status=open
```

**Query Parameters:**
- `skip` (int): Number of records to skip
- `limit` (int): Maximum records to return
- `severity` (string): Filter by severity (critical, high, medium, low)
- `status` (string): Filter by status (open, investigating, resolved, false_positive)
- `category` (string): Filter by category
- `start_date` (datetime): Filter alerts after this date
- `end_date` (datetime): Filter alerts before this date

**Response:**
```json
[
  {
    "id": 1,
    "alert_id": "alert_1234567890",
    "severity": "critical",
    "category": "account_takeover",
    "source": "AWS",
    "title": "Suspicious login attempt",
    "description": "Multiple failed login attempts followed by successful login",
    "threat_score": 0.92,
    "confidence": 0.88,
    "status": "open",
    "user_id": "user@example.com",
    "ip_address": "192.168.1.1",
    "detected_at": "2024-01-01T12:00:00Z",
    "created_at": "2024-01-01T12:00:01Z"
  }
]
```

### Get Single Alert

```http
GET /api/v1/alerts/{alert_id}
```

### Update Alert

```http
PATCH /api/v1/alerts/{alert_id}
Content-Type: application/json

{
  "status": "investigating",
  "assigned_to": "analyst@example.com",
  "resolution_notes": "Investigating suspicious activity"
}
```

### Submit Feedback

```http
POST /api/v1/alerts/{alert_id}/feedback
Content-Type: application/json

{
  "is_true_positive": true,
  "feedback_notes": "Confirmed malicious activity"
}
```

## Threat Detection API

### Ingest AWS Logs

```http
POST /api/v1/threats/ingest/aws
Content-Type: application/json

[
  {
    "eventID": "event-123",
    "eventName": "ConsoleLogin",
    "sourceIPAddress": "192.168.1.1",
    "userIdentity": {
      "principalId": "user@example.com"
    },
    "eventTime": "2024-01-01T12:00:00Z",
    "resources": []
  }
]
```

### Ingest Azure Logs

```http
POST /api/v1/threats/ingest/azure
Content-Type: application/json

[
  {
    "operationId": "op-456",
    "operationName": "Microsoft.Compute/virtualMachines/write",
    "caller": "user@example.com",
    "eventTimestamp": "2024-01-01T12:00:00Z"
  }
]
```

### Analyze Single Log

```http
POST /api/v1/threats/analyze
Content-Type: application/json

{
  "log_id": "log_123",
  "source": "AWS",
  "service": "CloudTrail",
  "event_type": "ConsoleLogin",
  "user_id": "user@example.com",
  "ip_address": "192.168.1.1",
  "event_time": "2024-01-01T12:00:00Z"
}
```

### Check IP Reputation

```http
POST /api/v1/threats/check-ip/{ip_address}
```

**Response:**
```json
{
  "ip_address": "192.168.1.1",
  "is_malicious": false,
  "threat_score": 0.2,
  "sources": [
    {
      "source": "virustotal",
      "malicious_count": 0,
      "suspicious_count": 1,
      "total_engines": 89
    }
  ]
}
```

## Dashboard API

### Get Statistics

```http
GET /api/v1/dashboard/stats?start_date=2024-01-01&end_date=2024-01-31
```

**Response:**
```json
{
  "total_alerts": 1234,
  "critical_alerts": 45,
  "high_alerts": 123,
  "medium_alerts": 456,
  "low_alerts": 610,
  "open_alerts": 234,
  "resolved_alerts": 890,
  "false_positives": 110
}
```

### Get Threat Trends

```http
GET /api/v1/dashboard/trends?days=7
```

**Response:**
```json
[
  {
    "date": "2024-01-01",
    "count": 45,
    "severity": "critical"
  },
  {
    "date": "2024-01-01",
    "count": 123,
    "severity": "high"
  }
]
```

### Get Top Threats

```http
GET /api/v1/dashboard/top-threats?limit=10&days=30
```

**Response:**
```json
[
  {
    "category": "suspicious_login",
    "count": 345
  },
  {
    "category": "malicious_ip",
    "count": 234
  }
]
```

### Get Activity Heatmap

```http
GET /api/v1/dashboard/activity-heatmap?days=7
```

**Response:**
```json
{
  "heatmap": [
    [0, 2, 1, 0, 0, 0, 0, 3, 5, 8, 12, ...],
    [1, 0, 2, 1, 0, 0, 0, 2, 6, 9, 11, ...],
    ...
  ],
  "days": ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"],
  "hours": [0, 1, 2, ..., 23]
}
```

## ML Models API

### List Models

```http
GET /api/v1/models/
```

### Train New Model

```http
POST /api/v1/models/train?model_name=custom_detector
```

### Activate Model

```http
POST /api/v1/models/{model_id}/activate
```

### Get Model Performance

```http
GET /api/v1/models/performance/metrics?days=30
```

**Response:**
```json
{
  "model_name": "anomaly_detector",
  "metrics": {
    "precision": 0.92,
    "false_positive_rate": 0.035,
    "feedback_count": 456,
    "true_positives": 420,
    "false_positives": 36
  }
}
```

## Error Responses

All endpoints may return the following error responses:

### 400 Bad Request
```json
{
  "detail": "Invalid input data"
}
```

### 401 Unauthorized
```json
{
  "detail": "Could not validate credentials"
}
```

### 404 Not Found
```json
{
  "detail": "Resource not found"
}
```

### 500 Internal Server Error
```json
{
  "detail": "Internal server error"
}
```

## Rate Limiting

API requests are rate-limited to:
- 100 requests per minute for authenticated users
- 10 requests per minute for unauthenticated endpoints

## WebSocket Support (Coming Soon)

Real-time alert updates via WebSocket:

```javascript
const ws = new WebSocket('ws://localhost:8000/ws/alerts');
ws.onmessage = (event) => {
  const alert = JSON.parse(event.data);
  console.log('New alert:', alert);
};
```
