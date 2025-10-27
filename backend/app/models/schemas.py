"""
Pydantic schemas for request/response validation
"""
from pydantic import BaseModel, EmailStr, Field
from typing import Optional, List, Dict, Any
from datetime import datetime
from enum import Enum


# Enums
class SeverityLevel(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class AlertCategory(str, Enum):
    INSIDER_THREAT = "insider_threat"
    ACCOUNT_TAKEOVER = "account_takeover"
    DATA_EXFILTRATION = "data_exfiltration"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    SUSPICIOUS_LOGIN = "suspicious_login"
    MALICIOUS_IP = "malicious_ip"
    UNUSUAL_ACTIVITY = "unusual_activity"


class AlertStatus(str, Enum):
    OPEN = "open"
    INVESTIGATING = "investigating"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"


# User schemas
class UserBase(BaseModel):
    username: str
    email: EmailStr
    role: str = "analyst"


class UserCreate(UserBase):
    password: str


class UserResponse(UserBase):
    id: int
    is_active: bool
    created_at: datetime
    
    class Config:
        from_attributes = True


# Authentication schemas
class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    username: Optional[str] = None
    role: Optional[str] = None


# Alert schemas
class ThreatAlertBase(BaseModel):
    severity: SeverityLevel
    category: AlertCategory
    source: str
    title: str
    description: Optional[str] = None
    threat_score: float
    confidence: float
    user_id: Optional[str] = None
    ip_address: Optional[str] = None


class ThreatAlertCreate(ThreatAlertBase):
    alert_id: str
    indicators: Optional[Dict[str, Any]] = None
    affected_resources: Optional[List[str]] = None
    geo_location: Optional[Dict[str, Any]] = None
    mitre_tactics: Optional[List[str]] = None
    detected_at: datetime


class ThreatAlertUpdate(BaseModel):
    status: Optional[AlertStatus] = None
    assigned_to: Optional[str] = None
    resolution_notes: Optional[str] = None


class ThreatAlertResponse(ThreatAlertBase):
    id: int
    alert_id: str
    status: str
    indicators: Optional[Dict[str, Any]] = None
    affected_resources: Optional[List[str]] = None
    geo_location: Optional[Dict[str, Any]] = None
    mitre_tactics: Optional[List[str]] = None
    detected_at: datetime
    created_at: datetime
    updated_at: Optional[datetime] = None
    
    class Config:
        from_attributes = True


# Analyst Feedback schemas
class AnalystFeedbackCreate(BaseModel):
    alert_id: int
    is_true_positive: bool
    feedback_notes: Optional[str] = None


class AnalystFeedbackResponse(AnalystFeedbackCreate):
    id: int
    analyst_username: str
    created_at: datetime
    
    class Config:
        from_attributes = True


# Cloud Log schemas
class CloudLogCreate(BaseModel):
    log_id: str
    source: str
    service: str
    event_type: str
    event_name: str
    user_id: Optional[str] = None
    ip_address: Optional[str] = None
    raw_log: Dict[str, Any]
    event_time: datetime


class CloudLogResponse(CloudLogCreate):
    id: int
    anomaly_score: Optional[float] = None
    is_anomalous: bool
    ingested_at: datetime
    
    class Config:
        from_attributes = True


# Dashboard schemas
class DashboardStats(BaseModel):
    total_alerts: int
    critical_alerts: int
    high_alerts: int
    medium_alerts: int
    low_alerts: int
    open_alerts: int
    resolved_alerts: int
    false_positives: int
    avg_resolution_time: Optional[float] = None


class ThreatTrend(BaseModel):
    date: str
    count: int
    severity: str


class TopThreats(BaseModel):
    category: str
    count: int


# ML Model schemas
class MLModelMetrics(BaseModel):
    precision: float
    recall: float
    f1_score: float
    false_positive_rate: float


class MLModelResponse(BaseModel):
    id: int
    model_name: str
    model_type: str
    version: str
    is_active: bool
    metrics: MLModelMetrics
    trained_at: Optional[datetime] = None
    
    class Config:
        from_attributes = True


# Response action schemas
class AutomatedResponseCreate(BaseModel):
    alert_id: int
    action_type: str
    action_details: Optional[Dict[str, Any]] = None


class AutomatedResponseResponse(AutomatedResponseCreate):
    id: int
    action_status: str
    executed_at: datetime
    
    class Config:
        from_attributes = True
