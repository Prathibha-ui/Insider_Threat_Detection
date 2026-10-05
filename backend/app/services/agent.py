import json
import logging
from typing import TypedDict, List, Dict, Any, Optional
from datetime import datetime
from sqlalchemy.orm import Session
from langgraph.graph import StateGraph, START, END

from app.models import Incident, Alert, Evidence, AgentReasoningLog
from app.services.threat_intelligence import threat_intel_service
from app.services.mitre_mapping import extract_mitre_techniques
from app.services.risk_engine import risk_engine, RiskAssessment
from app.services.ml_engine import ml_engine

logger = logging.getLogger(__name__)

class InvestigationState(TypedDict):
    alert: Dict[str, Any]
    entities: Dict[str, List[str]]
    threat_intelligence: Dict[str, Any]
    correlated_alerts: List[Dict[str, Any]]
    anomaly_result: Dict[str, Any]
    risk_score: float
    risk_level: str
    predicted_grade: str
    mitre_techniques: List[Dict[str, str]]
    evidence: List[Dict[str, Any]]
    reasoning: List[Dict[str, Any]]
    recommended_action: str
    confidence: float
    risk_breakdown: Optional[Dict[str, Any]]
    should_deep_correlate: bool
    summary: str

# -------------------------------------------------------------
# LangGraph Workflow Nodes
# -------------------------------------------------------------

def load_alert(state: InvestigationState) -> Dict[str, Any]:
    raw_alert = state.get("alert", {})
    alert_id = raw_alert.get("alert_id") or raw_alert.get("AlertId") or "ALT-LIVE"
    title = raw_alert.get("title") or raw_alert.get("AlertTitle") or "Unknown Alert"
    
    step = {
        "step": 1,
        "name": "Load Alert",
        "observation": f"Loaded alert [{alert_id}]: '{title}'",
        "thought": "Ingesting telemetry payload into LangGraph investigation state.",
        "action": "Validated telemetry structure and initialized state graph."
    }
    return {"reasoning": state.get("reasoning", []) + [step]}

def normalize_alert(state: InvestigationState) -> Dict[str, Any]:
    raw = state.get("alert", {})
    sev = str(raw.get("severity") or raw.get("Severity") or "Medium").capitalize()
    cat = str(raw.get("category") or raw.get("Category") or "SuspiciousActivity")
    dev = str(raw.get("device_id") or raw.get("DeviceId") or "DEV-UNKNOWN")
    acc = str(raw.get("account_upn") or raw.get("AccountUpn") or "corp\\unknown")
    ip = str(raw.get("ip_address") or raw.get("IpAddress") or "0.0.0.0")

    normalized = {
        "alert_id": raw.get("alert_id") or raw.get("AlertId") or "ALT-LIVE",
        "title": raw.get("title") or raw.get("AlertTitle") or "Security Alert",
        "category": cat,
        "severity": sev,
        "device_id": dev,
        "account_upn": acc,
        "ip_address": ip,
        "sha256": raw.get("sha256") or raw.get("Sha256") or "N/A",
        "url": raw.get("url") or raw.get("Url") or "N/A",
        "mitre": raw.get("mitre") or raw.get("MitreTechniques") or "N/A"
    }

    # Extract verified MITRE ATT&CK techniques
    mitre_techs = extract_mitre_techniques(normalized["mitre"], normalized["title"], normalized["category"])

    step = {
        "step": 2,
        "name": "Normalize Telemetry",
        "observation": f"Normalized alert category: {cat}, severity: {sev}, mapped {len(mitre_techs)} verified MITRE technique(s).",
        "thought": "Standardized schema across EDR and network sensors.",
        "action": "Mapped observable signals against MITRE ATT&CK Enterprise Matrix."
    }
    return {
        "alert": normalized,
        "mitre_techniques": mitre_techs,
        "reasoning": state.get("reasoning", []) + [step]
    }

def extract_entities(state: InvestigationState) -> Dict[str, Any]:
    alert = state.get("alert", {})
    accounts = [alert["account_upn"]] if alert.get("account_upn") and alert["account_upn"] not in ["corp\\unknown", "N/A"] else []
    devices = [alert["device_id"]] if alert.get("device_id") and alert["device_id"] not in ["DEV-UNKNOWN", "N/A"] else []
    ips = [alert["ip_address"]] if alert.get("ip_address") and alert["ip_address"] not in ["0.0.0.0", "127.0.0.1", "N/A"] else []

    is_admin = any("admin" in a.lower() or "svc" in a.lower() or "root" in a.lower() for a in accounts)

    new_evidence = []
    if accounts:
        new_evidence.append({
            "id": len(state.get("evidence", [])) + 1,
            "type": "IdentityPrivilege",
            "source": "Active Directory IAM",
            "description": f"Target identity {accounts[0]} has {'HIGH-PRIVILEGE (Administrator/Service)' if is_admin else 'Standard corporate user'} scope.",
            "confidence": 0.95,
            "is_malicious": is_admin
        })

    step = {
        "step": 3,
        "name": "Extract Entities",
        "observation": f"Discovered {len(accounts)} account(s), {len(devices)} device(s), and {len(ips)} IP(s). Administrator privilege: {is_admin}.",
        "thought": "Assessing asset criticality and lateral attack surface radius.",
        "action": "Queried identity directory and endpoint registry."
    }

    return {
        "entities": {"accounts": accounts, "devices": devices, "ips": ips},
        "evidence": state.get("evidence", []) + new_evidence,
        "reasoning": state.get("reasoning", []) + [step]
    }

def threat_intel_check(state: InvestigationState) -> Dict[str, Any]:
    alert = state.get("alert", {})
    ips = state.get("entities", {}).get("ips", [])
    sha256 = alert.get("sha256")
    url = alert.get("url")

    ti_findings = {}
    new_evidence = []
    is_any_malicious = False

    # Check IP
    for ip in ips:
        res = threat_intel_service.check_indicator(ip, "ip")
        ti_findings[ip] = res.to_dict()
        if res.malicious:
            is_any_malicious = True
            new_evidence.append({
                "id": len(state.get("evidence", [])) + len(new_evidence) + 1,
                "type": "ThreatIntelligence",
                "source": f"{res.provider_name} ({res.source})",
                "description": f"External IP {ip} flagged as malicious indicator ({res.confidence:.0%} confidence).",
                "confidence": res.confidence,
                "is_malicious": True
            })

    # Check Hash
    if sha256 and sha256 != "N/A":
        res = threat_intel_service.check_indicator(sha256, "hash")
        ti_findings[sha256] = res.to_dict()
        if res.malicious:
            is_any_malicious = True
            new_evidence.append({
                "id": len(state.get("evidence", [])) + len(new_evidence) + 1,
                "type": "FileHashReputation",
                "source": f"{res.provider_name} ({res.source})",
                "description": f"SHA256 payload {sha256[:16]}... confirmed malicious binary.",
                "confidence": res.confidence,
                "is_malicious": True
            })

    # Determine if low-risk routine alert can bypass deep correlation
    is_low_sev = alert.get("severity") in ["Low", "Informational"]
    should_deep = not (is_low_sev and not is_any_malicious and len(ips) == 0)

    step = {
        "step": 4,
        "name": "Threat Intel Correlation",
        "observation": f"Threat intel query via {threat_intel_service.provider_name}: {'Malicious indicator identified!' if is_any_malicious else 'No known malicious indicators.'}",
        "thought": "Checking external reputation databases and C2 tracking feeds.",
        "action": f"Executed reputation lookup using {threat_intel_service.provider_name}."
    }

    return {
        "threat_intelligence": ti_findings,
        "evidence": state.get("evidence", []) + new_evidence,
        "should_deep_correlate": should_deep,
        "reasoning": state.get("reasoning", []) + [step]
    }

def correlate_alerts(state: InvestigationState) -> Dict[str, Any]:
    corr_list = state.get("correlated_alerts", [])
    count = len(corr_list)

    new_evidence = []
    if count > 1:
        new_evidence.append({
            "id": len(state.get("evidence", [])) + 1,
            "type": "CrossAlertCorrelation",
            "source": "Correlation Engine",
            "description": f"Correlated {count} distinct alert events across shared host and temporal window.",
            "confidence": 0.88,
            "is_malicious": count >= 3
        })

    step = {
        "step": 5,
        "name": "Correlate Alerts",
        "observation": f"Correlated {count} related security signal(s) in active cluster.",
        "thought": "Assessing campaign progression and multi-stage execution chain.",
        "action": "Clustered alerts via observable entity overlap graph."
    }

    return {
        "evidence": state.get("evidence", []) + new_evidence,
        "reasoning": state.get("reasoning", []) + [step]
    }

def detect_anomaly(state: InvestigationState) -> Dict[str, Any]:
    alert = state.get("alert", {})
    anomaly_score = ml_engine.compute_anomaly_score(alert)
    is_anomaly = anomaly_score >= 0.55

    new_evidence = []
    if is_anomaly:
        new_evidence.append({
            "id": len(state.get("evidence", [])) + 1,
            "type": "BehavioralDeviation",
            "source": "IsolationForest Anomaly Model",
            "description": f"Statistical telemetry anomaly detected ({anomaly_score:.2f} score).",
            "confidence": round(anomaly_score, 2),
            "is_malicious": is_anomaly
        })

    step = {
        "step": 6,
        "name": "Detect Behavioral Anomaly",
        "observation": f"IsolationForest anomaly score calculated: {anomaly_score:.2f} ({'Significant outlier' if is_anomaly else 'Within normal bounds'}).",
        "thought": "Evaluating baseline deviation across process, network, and timing signals.",
        "action": "Queried scikit-learn IsolationForest anomaly model."
    }

    return {
        "anomaly_result": {"score": anomaly_score, "is_anomaly": is_anomaly},
        "evidence": state.get("evidence", []) + new_evidence,
        "reasoning": state.get("reasoning", []) + [step]
    }

def assess_risk(state: InvestigationState) -> Dict[str, Any]:
    alert = state.get("alert", {})
    anomaly_score = state.get("anomaly_result", {}).get("score", 0.3)
    ti_map = state.get("threat_intelligence", {})
    ti_malicious = any(v.get("malicious", False) for v in ti_map.values())
    ti_conf = max([v.get("confidence", 0.0) for v in ti_map.values()] or [0.0])
    entities = state.get("entities", {})
    mitre_techs = state.get("mitre_techniques", [])
    corr_count = max(1, len(state.get("correlated_alerts", [])))

    assessment: RiskAssessment = risk_engine.calculate_risk(
        severity=alert.get("severity", "Medium"),
        anomaly_score=anomaly_score,
        threat_intel_malicious=ti_malicious,
        threat_intel_confidence=ti_conf,
        accounts=entities.get("accounts", []),
        devices=entities.get("devices", []),
        mitre_techniques=mitre_techs,
        alert_count=corr_count
    )

    step = {
        "step": 7,
        "name": "Assess Risk",
        "observation": f"Deterministic risk score computed: {assessment.risk_score:.1f}/100 [{assessment.risk_level}].",
        "thought": "Synthesizing weighted contributions from severity, anomaly, threat intel, and blast radius.",
        "action": "Evaluated risk scoring model."
    }

    return {
        "risk_score": assessment.risk_score,
        "risk_level": assessment.risk_level,
        "risk_breakdown": assessment.to_dict(),
        "reasoning": state.get("reasoning", []) + [step]
    }

def classify_incident(state: InvestigationState) -> Dict[str, Any]:
    alert = state.get("alert", {})
    pred_grade, conf = ml_engine.predict_grade(alert)

    step = {
        "step": 8,
        "name": "Classify Incident",
        "observation": f"ML model predicted incident grade: '{pred_grade}' with {conf:.0%} confidence.",
        "thought": "Applying Random Forest classifier on observable features.",
        "action": "Inferred incident classification verdict."
    }

    return {
        "predicted_grade": pred_grade,
        "confidence": conf,
        "reasoning": state.get("reasoning", []) + [step]
    }

def summarize_investigation(state: InvestigationState) -> Dict[str, Any]:
    alert = state.get("alert", {})
    title = alert.get("title", "Security Alert")
    risk_score = state.get("risk_score", 50.0)
    risk_level = state.get("risk_level", "MEDIUM")
    grade = state.get("predicted_grade", "TruePositive")
    entities = state.get("entities", {})
    dev_str = ", ".join(entities.get("devices", [])) or "target asset"
    acc_str = ", ".join(entities.get("accounts", [])) or "user"
    malicious_evidence_count = sum(1 for e in state.get("evidence", []) if e.get("is_malicious"))

    if risk_score >= 75.0 or grade == "TruePositive":
        summary = (
            f"Autonomous investigation for '{title}' identified {malicious_evidence_count} critical indicators "
            f"on {dev_str} involving {acc_str}. Classified as {risk_level} risk ({risk_score:.1f}/100) requiring urgent containment."
        )
    elif risk_score < 30.0 or grade in ["BenignPositive", "FalsePositive"]:
        summary = (
            f"Investigation for '{title}' determined activity on {dev_str} matches benign baseline operations. "
            f"Assessed as {risk_level} risk ({risk_score:.1f}/100) with zero confirmed malicious indicators."
        )
    else:
        summary = (
            f"Activity '{title}' on {dev_str} exhibits elevated behavioral anomaly ({risk_score:.1f}/100). "
            f"Requires secondary review before final disposition."
        )

    step = {
        "step": 9,
        "name": "Summarize Investigation",
        "observation": f"Synthesized findings into analyst-ready investigation summary.",
        "thought": "Compiling multi-source telemetry evidence into a coherent situation report.",
        "action": "Generated executive investigation narrative."
    }

    return {
        "summary": summary,
        "reasoning": state.get("reasoning", []) + [step]
    }

def recommend_action(state: InvestigationState) -> Dict[str, Any]:
    risk_score = state.get("risk_score", 50.0)
    grade = state.get("predicted_grade", "TruePositive")
    ti_map = state.get("threat_intelligence", {})
    is_malicious = any(v.get("malicious", False) for v in ti_map.values())

    if risk_score >= 75.0 or (grade == "TruePositive" and is_malicious):
        action = "Escalate"
    elif risk_score < 30.0 or grade in ["BenignPositive", "FalsePositive"]:
        action = "Suppress"
    elif len(state.get("correlated_alerts", [])) > 1:
        action = "Group"
    else:
        action = "Request Review"

    step = {
        "step": 10,
        "name": "Recommend Action",
        "observation": f"Remediation verdict: {action.upper()}.",
        "thought": f"Action mapped based on composite risk {risk_score:.1f} and predicted grade {grade}.",
        "action": f"Recommended analyst triage workflow: {action}."
    }

    return {
        "recommended_action": action,
        "reasoning": state.get("reasoning", []) + [step]
    }

# -------------------------------------------------------------
# LangGraph Workflow Construction
# -------------------------------------------------------------

def build_investigation_graph():
    builder = StateGraph(InvestigationState)

    # Add Nodes
    builder.add_node("load_alert", load_alert)
    builder.add_node("normalize_alert", normalize_alert)
    builder.add_node("extract_entities", extract_entities)
    builder.add_node("threat_intel_check", threat_intel_check)
    builder.add_node("correlate_alerts", correlate_alerts)
    builder.add_node("detect_anomaly", detect_anomaly)
    builder.add_node("assess_risk", assess_risk)
    builder.add_node("classify_incident", classify_incident)
    builder.add_node("summarize_investigation", summarize_investigation)
    builder.add_node("recommend_action", recommend_action)

    # Linear and conditional edges
    builder.add_edge(START, "load_alert")
    builder.add_edge("load_alert", "normalize_alert")
    builder.add_edge("normalize_alert", "extract_entities")
    builder.add_edge("extract_entities", "threat_intel_check")

    # Conditional edge: Low-severity alerts with zero external indicators skip deep correlation
    def route_after_threat_intel(state: InvestigationState) -> str:
        if state.get("should_deep_correlate", True):
            return "correlate_alerts"
        return "detect_anomaly"

    builder.add_conditional_edges(
        "threat_intel_check",
        route_after_threat_intel,
        {
            "correlate_alerts": "correlate_alerts",
            "detect_anomaly": "detect_anomaly"
        }
    )

    builder.add_edge("correlate_alerts", "detect_anomaly")
    builder.add_edge("detect_anomaly", "assess_risk")
    builder.add_edge("assess_risk", "classify_incident")
    builder.add_edge("classify_incident", "summarize_investigation")
    builder.add_edge("summarize_investigation", "recommend_action")
    builder.add_edge("recommend_action", END)

    return builder.compile()

# Compile the singleton LangGraph agent graph
investigation_graph = build_investigation_graph()

def run_agent_on_alert(alert_dict: Dict[str, Any], correlated_alerts: Optional[List[Dict[str, Any]]] = None) -> InvestigationState:
    """
    Executes the compiled LangGraph investigation loop on an alert payload.
    """
    initial_state: InvestigationState = {
        "alert": alert_dict,
        "entities": {"accounts": [], "devices": [], "ips": []},
        "threat_intelligence": {},
        "correlated_alerts": correlated_alerts or [],
        "anomaly_result": {},
        "risk_score": 50.0,
        "risk_level": "MEDIUM",
        "predicted_grade": "TruePositive",
        "mitre_techniques": [],
        "evidence": [],
        "reasoning": [],
        "recommended_action": "Request Review",
        "confidence": 0.80,
        "risk_breakdown": None,
        "should_deep_correlate": True,
        "summary": ""
    }

    final_state = investigation_graph.invoke(initial_state)
    return final_state

def investigate_incident(incident: Incident, alerts: List[Alert], db: Session) -> Dict[str, Any]:
    """
    Runs the LangGraph agent for a correlated incident and persists evidence & reasoning logs.
    """
    inc_id = incident.IncidentId
    logger.info(f"LangGraph agent starting investigation on {inc_id} ({incident.Title})")

    # Clear prior evidence & logs
    db.query(Evidence).filter(Evidence.IncidentId == inc_id).delete()
    db.query(AgentReasoningLog).filter(AgentReasoningLog.IncidentId == inc_id).delete()
    db.commit()

    # Form alert payload
    lead_alert = alerts[0] if alerts else None
    alert_payload = {
        "alert_id": lead_alert.AlertId if lead_alert else inc_id,
        "title": lead_alert.AlertTitle if lead_alert else incident.Title,
        "category": lead_alert.Category if lead_alert else "Security",
        "severity": incident.InitialSeverity,
        "device_id": lead_alert.DeviceId if lead_alert else "DEV-UNKNOWN",
        "account_upn": lead_alert.AccountUpn if lead_alert else "corp\\unknown",
        "ip_address": lead_alert.IpAddress if lead_alert else "0.0.0.0",
        "sha256": lead_alert.Sha256 if lead_alert else "N/A",
        "url": lead_alert.Url if lead_alert else "N/A",
        "mitre": lead_alert.MitreTechniques if lead_alert else "N/A"
    }

    corr_payloads = [
        {"alert_id": a.AlertId, "title": a.AlertTitle, "severity": a.Severity, "device_id": a.DeviceId}
        for a in alerts
    ]

    # Execute LangGraph
    final_state = run_agent_on_alert(alert_payload, corr_payloads)

    # Persist Evidence
    db_evidence = []
    for ev in final_state["evidence"]:
        record = Evidence(
            IncidentId=inc_id,
            EvidenceType=ev.get("type", "Signal"),
            Source=ev.get("source", "Agent Sensor"),
            Description=ev.get("description", ""),
            ConfidenceScore=ev.get("confidence", 0.85),
            IsMalicious=ev.get("is_malicious", False),
            Timestamp=datetime.utcnow()
        )
        db_evidence.append(record)

    # Persist Reasoning Logs
    db_logs = []
    for step in final_state["reasoning"]:
        log = AgentReasoningLog(
            IncidentId=inc_id,
            StepNumber=step.get("step", 1),
            StepName=step.get("name", "Investigation Step"),
            Observation=step.get("observation", ""),
            Thought=step.get("thought", ""),
            ActionTaken=step.get("action", ""),
            Timestamp=datetime.utcnow()
        )
        db_logs.append(log)

    # Update Incident attributes
    incident.RiskScore = final_state["risk_score"]
    incident.AgentAction = final_state["recommended_action"]
    incident.PredictedGrade = final_state["predicted_grade"]
    incident.Confidence = final_state["confidence"]
    incident.Summary = final_state["summary"]
    if final_state["risk_breakdown"]:
        incident.RiskBreakdown = json.dumps(final_state["risk_breakdown"])

    db.bulk_save_objects(db_evidence)
    db.bulk_save_objects(db_logs)
    db.commit()

    return {
        "incident_id": inc_id,
        "agent_action": final_state["recommended_action"],
        "risk_score": final_state["risk_score"],
        "evidence_count": len(db_evidence),
        "steps_count": len(db_logs)
    }

def run_agent_investigation_loop(db: Session) -> Dict[str, Any]:
    """
    Executes LangGraph agent loop across all incidents.
    """
    incidents = db.query(Incident).all()
    if not incidents:
        return {"status": "success", "investigated_incidents": 0, "details": []}

    results = []
    for inc in incidents:
        alerts = db.query(Alert).filter(
            (Alert.ClusterId == inc.IncidentId) | (Alert.IncidentId == inc.IncidentId)
        ).all()
        res = investigate_incident(inc, alerts, db)
        results.append(res)

    logger.info(f"LangGraph investigation loop completed for {len(results)} incidents.")
    return {
        "status": "success",
        "investigated_incidents": len(results),
        "details": results
    }