from datetime import datetime
from sqlalchemy import Column, Integer, String, Float, Boolean, DateTime, Text, Index
from app.db.database import Base

class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    AlertId = Column(String(100), unique=True, index=True, nullable=False)
    IncidentId = Column(String(100), index=True, nullable=True)
    OrgId = Column(String(100), nullable=True, default="ORG-CORP-01")
    Timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    DetectorId = Column(String(100), nullable=True)
    AlertTitle = Column(String(255), nullable=False, index=True)
    Category = Column(String(100), nullable=False, index=True)
    MitreTechniques = Column(String(255), nullable=True)
    Severity = Column(String(50), default="Medium", index=True)
    IncidentGrade = Column(String(50), nullable=True, default="TruePositive", index=True) # Ground truth
    ActionGrouped = Column(String(50), nullable=True, default="Detected")
    DeviceId = Column(String(100), index=True, nullable=True)
    AccountUpn = Column(String(150), index=True, nullable=True)
    IpAddress = Column(String(100), index=True, nullable=True)
    Sha256 = Column(String(100), nullable=True)
    Url = Column(String(500), nullable=True)
    AnomalyScore = Column(Float, default=0.0)
    ClusterId = Column(String(100), index=True, nullable=True)
    RawPayload = Column(Text, nullable=True)

    __table_args__ = (
        Index("idx_alert_device_ts", "DeviceId", "Timestamp"),
        Index("idx_alert_account_ts", "AccountUpn", "Timestamp"),
    )

class Incident(Base):
    __tablename__ = "incidents"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    IncidentId = Column(String(100), unique=True, index=True, nullable=False)
    Title = Column(String(255), nullable=False)
    Summary = Column(Text, nullable=True)
    RiskScore = Column(Float, default=50.0, index=True)
    InitialSeverity = Column(String(50), default="Medium", index=True)
    PredictedGrade = Column(String(50), default="TruePositive", index=True)
    Confidence = Column(Float, default=0.85)
    AgentAction = Column(String(50), default="Request Review", index=True) # Escalate, Group, Suppress, Request Review
    Status = Column(String(50), default="New", index=True) # New, Investigating, Escalated, Suppressed, Resolved
    MitreTactics = Column(Text, nullable=True) # JSON list
    EntitySummary = Column(Text, nullable=True) # JSON dict of affected accounts, devices, ips
    RiskBreakdown = Column(Text, nullable=True) # JSON dict of risk factor contributions
    GraphDensity = Column(Float, default=0.0)
    AnomalyScore = Column(Float, default=0.0)
    AlertCount = Column(Integer, default=1)
    CreatedAt = Column(DateTime, default=datetime.utcnow, index=True)
    UpdatedAt = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class Evidence(Base):
    __tablename__ = "evidence"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    IncidentId = Column(String(100), index=True, nullable=False)
    EvidenceType = Column(String(100), nullable=False, index=True)
    Source = Column(String(100), nullable=False)
    Description = Column(Text, nullable=False)
    ConfidenceScore = Column(Float, default=0.9)
    IsMalicious = Column(Boolean, default=False, index=True)
    Timestamp = Column(DateTime, default=datetime.utcnow)

class AgentReasoningLog(Base):
    __tablename__ = "agent_reasoning_logs"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    IncidentId = Column(String(100), index=True, nullable=False)
    StepNumber = Column(Integer, nullable=False, index=True)
    StepName = Column(String(100), nullable=False)
    Observation = Column(Text, nullable=False)
    Thought = Column(Text, nullable=False)
    ActionTaken = Column(Text, nullable=False)
    Timestamp = Column(DateTime, default=datetime.utcnow)

class AnalystFeedback(Base):
    __tablename__ = "analyst_feedback"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    IncidentId = Column(String(100), index=True, nullable=False)
    OriginalAction = Column(String(50), nullable=True)
    FeedbackAction = Column(String(50), nullable=False)
    OriginalGrade = Column(String(50), nullable=True)
    NewGrade = Column(String(50), nullable=True)
    Comments = Column(Text, nullable=True)
    SubmittedAt = Column(DateTime, default=datetime.utcnow)

__all__ = ["Alert", "Incident", "Evidence", "AgentReasoningLog", "AnalystFeedback"]
