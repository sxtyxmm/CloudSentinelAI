# CloudSentinelAI Architecture

## System Overview

CloudSentinelAI is built as a microservices-based architecture with the following key components:

```
┌─────────────────────────────────────────────────────────────────┐
│                        Frontend Layer                            │
│                 (React + Next.js + TailwindCSS)                 │
└────────────────────────────┬────────────────────────────────────┘
                             │ HTTPS/REST API
┌────────────────────────────┴────────────────────────────────────┐
│                        Backend API Layer                         │
│                    (FastAPI + Python 3.11)                      │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐         │
│  │     Auth     │  │    Alerts    │  │   Threats    │         │
│  │   Endpoints  │  │  Endpoints   │  │  Endpoints   │         │
│  └──────────────┘  └──────────────┘  └──────────────┘         │
└────────────────────────────┬────────────────────────────────────┘
                             │
┌────────────────────────────┴────────────────────────────────────┐
│                      Services Layer                              │
│  ┌──────────────────┐  ┌──────────────────┐  ┌─────────────┐  │
│  │  Log Processor   │  │ Threat Intel     │  │  Response   │  │
│  │                  │  │ Service          │  │ Automation  │  │
│  └──────────────────┘  └──────────────────┘  └─────────────┘  │
└────────────────────────────┬────────────────────────────────────┘
                             │
┌────────────────────────────┴────────────────────────────────────┐
│                      ML/AI Engine Layer                          │
│  ┌──────────────────┐  ┌──────────────────┐  ┌─────────────┐  │
│  │ Anomaly Detector │  │  Threat Scorer   │  │   Feature   │  │
│  │ (Isolation Forest│  │                  │  │ Engineering │  │
│  │  Autoencoder)    │  │                  │  │             │  │
│  └──────────────────┘  └──────────────────┘  └─────────────┘  │
└────────────────────────────┬────────────────────────────────────┘
                             │
┌────────────────────────────┴────────────────────────────────────┐
│                      Data Layer                                  │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐         │
│  │  PostgreSQL  │  │    Redis     │  │Elasticsearch │         │
│  │  (Primary DB)│  │   (Cache)    │  │  (Search)    │         │
│  └──────────────┘  └──────────────┘  └──────────────┘         │
└──────────────────────────────────────────────────────────────────┘
```

## Component Details

### 1. Frontend Layer

**Technology:** React 18 + Next.js 14 + TailwindCSS

**Responsibilities:**
- User authentication and authorization
- Real-time dashboard visualization
- Alert management and investigation
- Analytics and reporting
- Analyst feedback submission

**Key Components:**
- `Dashboard.tsx` - Main dashboard with statistics and charts
- `AlertsList.tsx` - Alert listing and filtering
- `ThreatChart.tsx` - Trend visualization using Chart.js
- `ActivityHeatmap.tsx` - Time-based activity heatmap
- `StatsCards.tsx` - Statistics overview cards

**State Management:** React hooks (useState, useEffect)

### 2. Backend API Layer

**Technology:** FastAPI + Python 3.11

**Responsibilities:**
- RESTful API endpoints
- Request validation
- Authentication and authorization (JWT)
- Rate limiting
- Error handling
- API documentation (OpenAPI/Swagger)

**Key Modules:**
- `api/auth.py` - Authentication endpoints
- `api/alerts.py` - Alert management
- `api/threats.py` - Threat detection and log ingestion
- `api/dashboard.py` - Analytics and statistics
- `api/models.py` - ML model management

**Security:**
- JWT token-based authentication
- Role-based access control (RBAC)
- Input validation with Pydantic
- CORS middleware
- Rate limiting middleware

### 3. Services Layer

#### 3.1 Log Processor Service

**File:** `services/log_processor.py`

**Responsibilities:**
- Normalize logs from different cloud providers
- Extract features for ML model
- Coordinate with ML engine for anomaly detection
- Generate threat alerts
- Store processed logs in database

**Key Methods:**
- `process_log()` - Main processing pipeline
- `_categorize_threat()` - Threat categorization
- `_extract_threat_indicators()` - IOC extraction
- `_generate_alert_title()` - Alert generation

#### 3.2 Threat Intelligence Service

**File:** `services/threat_intelligence.py`

**Responsibilities:**
- Query external threat intelligence APIs
- IP reputation checking (VirusTotal, Shodan)
- MITRE ATT&CK mapping
- Threat enrichment

**External Integrations:**
- VirusTotal API v3
- Shodan API
- MITRE ATT&CK framework

#### 3.3 Notification Service

**File:** `services/threat_intelligence.py`

**Responsibilities:**
- Multi-channel alert notifications
- Slack webhook integration
- Email notifications
- ServiceNow incident creation

#### 3.4 Response Automation Service

**File:** `services/response_automation.py`

**Responsibilities:**
- Automated threat response actions
- Account disablement
- API key revocation
- IP address blocking
- Credential rotation
- Audit trail maintenance

### 4. ML/AI Engine Layer

#### 4.1 Anomaly Detector

**File:** `ml/anomaly_detector.py`

**Algorithms:**
- Isolation Forest (primary)
- One-Class SVM (alternative)
- Autoencoder (deep learning option)

**Features Extracted:**
- Temporal: hour_of_day, day_of_week, is_weekend
- Behavioral: login_frequency, access_patterns
- Geographic: country_hash, location_changes
- Event-based: event_type, success/failure rates

**Model Training:**
- Unsupervised learning
- Contamination rate: 10% (configurable)
- Periodic retraining based on new data

#### 4.2 Threat Scorer

**File:** `ml/anomaly_detector.py`

**Responsibilities:**
- Calculate comprehensive threat scores (0-1)
- Determine severity levels (critical/high/medium/low)
- Apply event-type multipliers
- Incorporate external intelligence

**Scoring Logic:**
```python
threat_score = base_anomaly_score * event_multiplier * external_intelligence_factor

Severity Mapping:
- >= 0.8: Critical
- >= 0.6: High
- >= 0.4: Medium
- <  0.4: Low
```

### 5. Data Layer

#### 5.1 PostgreSQL Database

**Purpose:** Primary data storage

**Tables:**
- `users` - User accounts and authentication
- `threat_alerts` - Security alerts and incidents
- `cloud_logs` - Processed cloud activity logs
- `automated_responses` - Response action records
- `analyst_feedback` - Feedback for model improvement
- `ml_models` - Model metadata and versioning

**Indexes:**
- Alert severity and status
- Log timestamps and sources
- User IDs and IP addresses

#### 5.2 Redis Cache

**Purpose:** Caching and session storage

**Use Cases:**
- API response caching
- Session management
- Rate limiting counters
- Real-time statistics

#### 5.3 Elasticsearch

**Purpose:** Log search and analytics

**Use Cases:**
- Full-text search on logs
- Log aggregation
- Time-series analytics
- Historical data queries

## Data Flow

### Alert Generation Pipeline

```
1. Log Ingestion
   ↓
2. Feature Extraction
   ↓
3. Anomaly Detection (ML Model)
   ↓
4. Threat Intelligence Enrichment
   ↓
5. Threat Scoring
   ↓
6. Alert Generation (if score > threshold)
   ↓
7. Notification Dispatch
   ↓
8. Automated Response (if applicable)
```

### Request Flow

```
1. Frontend → API Gateway
   ↓
2. Authentication Middleware (JWT Verification)
   ↓
3. Authorization (RBAC Check)
   ↓
4. Request Validation (Pydantic)
   ↓
5. Business Logic (Services Layer)
   ↓
6. Data Access (Database/Cache)
   ↓
7. Response Formation
   ↓
8. Frontend Display
```

## Scalability Considerations

### Horizontal Scaling

1. **Backend API**: Stateless design allows multiple instances
2. **Load Balancing**: Nginx/HAProxy for traffic distribution
3. **Database**: Read replicas for query distribution
4. **Cache**: Redis Cluster for distributed caching

### Vertical Scaling

1. **ML Processing**: GPU acceleration for deep learning models
2. **Database**: Increase resources for complex queries
3. **Elasticsearch**: Scale nodes for large log volumes

### Performance Optimizations

1. **Async Operations**: FastAPI async endpoints for I/O operations
2. **Batch Processing**: Process logs in batches for efficiency
3. **Connection Pooling**: Database connection reuse
4. **Caching Strategy**: Multi-level caching (Redis + in-memory)

## Security Architecture

### Authentication & Authorization

```
┌─────────────┐
│   User      │
└──────┬──────┘
       │ Login (username/password)
       ↓
┌─────────────────────────────┐
│  Authentication Service     │
│  - Verify credentials       │
│  - Generate JWT token       │
└──────────┬──────────────────┘
           │ JWT Token
           ↓
┌─────────────────────────────┐
│  Authorization Middleware   │
│  - Verify token signature   │
│  - Check token expiration   │
│  - Extract user role        │
└──────────┬──────────────────┘
           │ Authorized
           ↓
┌─────────────────────────────┐
│  Protected Resources        │
└─────────────────────────────┘
```

### Role-Based Access Control

**Roles:**
1. **Admin**: Full system access, user management, configuration
2. **Analyst**: View/manage alerts, provide feedback, investigations
3. **Viewer**: Read-only access to dashboard and alerts

**Permissions Matrix:**
| Resource | Admin | Analyst | Viewer |
|----------|-------|---------|--------|
| View Alerts | ✓ | ✓ | ✓ |
| Update Alerts | ✓ | ✓ | ✗ |
| Manage Users | ✓ | ✗ | ✗ |
| Train Models | ✓ | ✗ | ✗ |
| Configure System | ✓ | ✗ | ✗ |

## Monitoring & Observability

### Metrics

1. **Application Metrics**
   - Request rate and latency
   - Error rates
   - Active users

2. **Business Metrics**
   - Alerts generated per hour
   - Alert resolution time
   - False positive rate

3. **ML Metrics**
   - Model accuracy (precision, recall, F1)
   - Detection latency
   - Feature distribution

### Logging

**Structured Logging with structlog:**
```python
logger.info(
    "Alert generated",
    alert_id=alert.id,
    severity=alert.severity,
    category=alert.category,
    user_id=alert.user_id
)
```

**Log Levels:**
- DEBUG: Detailed troubleshooting information
- INFO: General operational information
- WARNING: Warning messages
- ERROR: Error events
- CRITICAL: Critical failures

### Health Checks

**Endpoints:**
- `/health` - Overall system health
- `/health/db` - Database connectivity
- `/health/redis` - Redis connectivity
- `/health/ml` - ML model status

## Deployment Architecture

### Docker Compose (Development)

```yaml
services:
  - postgres (Database)
  - redis (Cache)
  - elasticsearch (Search)
  - backend (FastAPI)
  - frontend (Next.js)
```

### Kubernetes (Production)

```
┌──────────────────────────────────────┐
│           Ingress Controller          │
└───────────┬──────────────────────────┘
            │
    ┌───────┴────────┐
    │                │
┌───▼───┐      ┌────▼───┐
│Backend│      │Frontend│
│ (3x)  │      │  (2x)  │
└───┬───┘      └────────┘
    │
    ├──────┬──────────┬────────┐
    │      │          │        │
┌───▼──┐ ┌─▼───┐ ┌───▼───┐ ┌──▼──┐
│Postgres│Redis│ │Elastic│ │Models│
└────────┘└─────┘ └───────┘ └─────┘
```

## Continuous Learning Pipeline

```
1. Alerts Generated
   ↓
2. Analyst Reviews
   ↓
3. Feedback Submitted (True/False Positive)
   ↓
4. Feedback Aggregation
   ↓
5. Model Retraining (Scheduled)
   ↓
6. Model Evaluation
   ↓
7. Model Deployment (if improved)
   ↓
8. Performance Monitoring
```

## Future Enhancements

1. **Graph-based Analysis**: Use Neo4j for entity relationships
2. **Natural Language Querying**: LLM integration for queries
3. **Explainable AI**: SHAP/LIME for model interpretability
4. **Predictive Analytics**: Forecast future threats
5. **SIEM Integration**: Splunk, Elastic SIEM connectors
6. **Mobile App**: React Native mobile application
