"""
Database models for threats and alerts
"""
from sqlalchemy import Column, Integer, String, Float, DateTime, Text, Boolean, JSON, ForeignKey
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from datetime import datetime

from app.core.database import Base


class User(Base):
    """User model for authentication"""
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    email = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    role = Column(String, default="analyst")  # analyst, admin, viewer
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())


class ThreatAlert(Base):
    """Threat alert model"""
    __tablename__ = "threat_alerts"
    
    id = Column(Integer, primary_key=True, index=True)
    alert_id = Column(String, unique=True, index=True, nullable=False)
    severity = Column(String, index=True)  # critical, high, medium, low
    category = Column(String, index=True)  # insider_threat, account_takeover, data_exfiltration, etc.
    source = Column(String)  # AWS, Azure, GCP
    title = Column(String, nullable=False)
    description = Column(Text)
    
    # Threat details
    threat_score = Column(Float)
    confidence = Column(Float)
    indicators = Column(JSON)  # IOCs, patterns, behaviors
    affected_resources = Column(JSON)
    
    # User/Entity information
    user_id = Column(String)
    ip_address = Column(String)
    user_agent = Column(String)
    geo_location = Column(JSON)
    
    # Status and resolution
    status = Column(String, default="open")  # open, investigating, resolved, false_positive
    assigned_to = Column(String)
    resolution_notes = Column(Text)
    
    # External enrichment
    mitre_tactics = Column(JSON)
    external_references = Column(JSON)
    
    # Timestamps
    detected_at = Column(DateTime(timezone=True), nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    resolved_at = Column(DateTime(timezone=True))
    
    # Relationships
    responses = relationship("AutomatedResponse", back_populates="alert")
    feedbacks = relationship("AnalystFeedback", back_populates="alert")


class AutomatedResponse(Base):
    """Automated response actions taken"""
    __tablename__ = "automated_responses"
    
    id = Column(Integer, primary_key=True, index=True)
    alert_id = Column(Integer, ForeignKey("threat_alerts.id"))
    action_type = Column(String)  # disable_account, revoke_key, block_ip, etc.
    action_status = Column(String)  # pending, completed, failed
    action_details = Column(JSON)
    executed_at = Column(DateTime(timezone=True), server_default=func.now())
    
    alert = relationship("ThreatAlert", back_populates="responses")


class AnalystFeedback(Base):
    """Analyst feedback on alerts for model improvement"""
    __tablename__ = "analyst_feedback"
    
    id = Column(Integer, primary_key=True, index=True)
    alert_id = Column(Integer, ForeignKey("threat_alerts.id"))
    analyst_username = Column(String)
    is_true_positive = Column(Boolean)
    feedback_notes = Column(Text)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    
    alert = relationship("ThreatAlert", back_populates="feedbacks")


class CloudLog(Base):
    """Cloud activity logs"""
    __tablename__ = "cloud_logs"
    
    id = Column(Integer, primary_key=True, index=True)
    log_id = Column(String, unique=True, index=True)
    source = Column(String, index=True)  # AWS, Azure, GCP
    service = Column(String)  # CloudTrail, Monitor, etc.
    event_type = Column(String, index=True)
    event_name = Column(String)
    
    # User/Principal information
    user_id = Column(String, index=True)
    user_type = Column(String)
    ip_address = Column(String)
    user_agent = Column(String)
    
    # Event details
    raw_log = Column(JSON)
    processed_features = Column(JSON)
    
    # Geolocation
    country = Column(String)
    region = Column(String)
    city = Column(String)
    
    # Analysis
    anomaly_score = Column(Float)
    is_anomalous = Column(Boolean, default=False)
    
    # Timestamps
    event_time = Column(DateTime(timezone=True), index=True)
    ingested_at = Column(DateTime(timezone=True), server_default=func.now())


class MLModel(Base):
    """ML Model metadata and versioning"""
    __tablename__ = "ml_models"
    
    id = Column(Integer, primary_key=True, index=True)
    model_name = Column(String, unique=True, index=True)
    model_type = Column(String)  # isolation_forest, autoencoder, xgboost
    version = Column(String)
    
    # Performance metrics
    precision = Column(Float)
    recall = Column(Float)
    f1_score = Column(Float)
    false_positive_rate = Column(Float)
    
    # Model configuration
    hyperparameters = Column(JSON)
    features = Column(JSON)
    
    # Status
    is_active = Column(Boolean, default=False)
    training_data_size = Column(Integer)
    
    # Timestamps
    trained_at = Column(DateTime(timezone=True))
    deployed_at = Column(DateTime(timezone=True))
    created_at = Column(DateTime(timezone=True), server_default=func.now())
