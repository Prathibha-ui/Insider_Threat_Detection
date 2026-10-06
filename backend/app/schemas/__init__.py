from typing import List, Dict, Any, Optional
from datetime import datetime
from pydantic import BaseModel, Field

class FeedbackRequest(BaseModel):
    incident_id: str
    action: str  # Escalate, Suppress, Group, Request Review
    new_grade: Optional[str] = None  # TruePositive, BenignPositive, FalsePositive
    comments: Optional[str] = None

class IngestionRequest(BaseModel):
    custom_filepath: Optional[str] = None

class UserAlertInput(BaseModel):
    title: str = Field(..., description="Alert Title / Threat Name")
    category: str = Field("Execution", description="MITRE Tactic / Category")
    severity: str = Field("High", description="Severity: Critical, High, Medium, Low, Informational")
    device_id: Optional[str] = Field("FIN-WS-101", description="Device ID / Hostname")
    account_upn: Optional[str] = Field("user@corp.local", description="User Account UPN")
    ip_address: Optional[str] = Field("185.220.101.42", description="Observed IP Address")
    sha256: Optional[str] = Field(None, description="SHA256 File Hash")
    url: Optional[str] = Field(None, description="Associated URL / Domain")
    mitre_techniques: Optional[str] = Field(None, description="MITRE ATT&CK Technique ID, e.g. T1059.001")
    action_grouped: Optional[str] = Field("Detected", description="Sensor Action: Detected, Blocked, Quarantined")
    mitigation: Optional[str] = Field(None, description="Suggested action / mitigation")
    source: Optional[str] = Field("EDR Sensor", description="Detection Source")

class BatchAlertInput(BaseModel):
    alerts: List[UserAlertInput]

class IngestResponse(BaseModel):
    status: str
    alert_ids: List[str]
    incident_id: Optional[str] = None
    message: str

class DemoAlertRequest(BaseModel):
    title: str = Field(..., description="Alert title")
    category: str = Field(..., description="Security category or tactic")
    severity: str = Field("High", description="Severity: Critical, High, Medium, Low, Informational")
    device_id: str = Field("DEV-WS-101", description="Target host or workstation")
    account_upn: str = Field("user@corp.local", description="User principal name")
    ip_address: str = Field("185.220.101.42", description="Observed IP address")
    mitigation: Optional[str] = Field("Review and isolate host", description="Suggested mitigation")
    source: str = Field("EDR Sensor", description="Detection telemetry source")

class FactorContribution(BaseModel):
    factor: str
    weight: float
    score: float
    description: str

class RiskBreakdownSchema(BaseModel):
    risk_score: float
    risk_level: str
    factors: List[FactorContribution]

class DemoAlertResponse(BaseModel):
    priority: str
    risk_score: float
    risk_level: str
    predicted_grade: str
    agent_action: str
    confidence: float
    summary: str
    reasons: List[str]
    mitre_techniques: List[Dict[str, str]]
    threat_intel: Dict[str, Any]
    risk_breakdown: RiskBreakdownSchema
    recommended_action: str

class HealthResponse(BaseModel):
    status: str
    app: str
    version: str
    database_connected: bool
    models_loaded: bool
    threat_intel_provider: str
    dataset_exists: bool

class AlertResponse(BaseModel):
    id: Optional[int] = None
    alert_id: Optional[str] = None
    title: Optional[str] = None
    category: Optional[str] = None
    alert_type: Optional[str] = None
    severity: Optional[str] = None
    timestamp: Optional[str] = None
    device_id: Optional[str] = None
    account_upn: Optional[str] = None
    ip_address: Optional[str] = None
    sha256: Optional[str] = None
    url: Optional[str] = None
    mitre: Optional[str] = None
    action: Optional[str] = None
    grade: Optional[str] = None
    incident_grade: Optional[str] = None
    anomaly_score: float = 0.0
    risk_score: Optional[float] = 0.0
    threat_level: Optional[str] = None
    reason: Optional[str] = None
    recommended_action: Optional[str] = None
    created_at: Optional[str] = None

class EvidenceResponse(BaseModel):
    id: int
    type: str
    source: str
    description: str
    confidence: float
    is_malicious: bool
    timestamp: Optional[str]

class ReasoningLogResponse(BaseModel):
    step: int
    name: str
    observation: str
    thought: str
    action: str
    timestamp: Optional[str]

class IncidentSummary(BaseModel):
    incident_id: str
    title: str
    summary: str
    risk_score: float
    severity: str
    predicted_grade: str
    confidence: float
    agent_action: str
    status: str
    alert_count: int
    mitre_tactics: List[str]
    entity_summary: Dict[str, Any]
    risk_breakdown: Optional[Dict[str, Any]] = None
    graph_density: float
    anomaly_score: float
    created_at: Optional[str]
    updated_at: Optional[str]

class IncidentsListResponse(BaseModel):
    incidents: List[IncidentSummary]
    total: int

class GraphNode(BaseModel):
    id: str
    label: str
    type: str
    severity: Optional[str] = "Medium"

class GraphEdge(BaseModel):
    source: str
    target: str
    relationship: str

class GraphData(BaseModel):
    incident_id: str
    density: float
    node_count: int
    edge_count: int
    nodes: List[GraphNode]
    edges: List[GraphEdge]

class TimelinePoint(BaseModel):
    alert_id: str
    timestamp: str
    full_time: str
    title: str
    category: str
    severity: str
    severity_value: int
    device: str
    user: str
    anomaly_score: float

class IncidentDetailResponse(BaseModel):
    incident: IncidentSummary
    alerts: List[AlertResponse]
    evidence: List[EvidenceResponse]
    reasoning_logs: List[ReasoningLogResponse]
    graph: GraphData
    timeline: List[TimelinePoint]

class MetricsResponse(BaseModel):
    model_config = {"protected_namespaces": ()}

    total_alerts: int
    total_incidents: int
    escalated_count: int
    suppressed_count: int
    compression_ratio: str
    noise_reduction_pct: float
    workload_reduction_pct: float
    tp_preservation_pct: float
    estimated_hours_saved: float
    evaluation_type: str = "Measured metrics from active pipeline"
    model_metrics: Optional[Dict[str, Any]] = None

class RawAlertItem(BaseModel):
    id: str
    title: str
    severity: str
    category: str
    entity: str
    timestamp: str
    is_noise: bool

class ComparisonResponse(BaseModel):
    raw_alerts: Dict[str, Any]
    socpilot_ai: Dict[str, Any]
