from typing import Dict, Any, List, Optional
from dataclasses import dataclass

SEVERITY_SCORES: Dict[str, float] = {
    "Critical": 30.0,
    "High": 22.5,
    "Medium": 15.0,
    "Low": 7.5,
    "Informational": 2.0
}

@dataclass
class FactorScore:
    factor: str
    weight: float
    score: float
    description: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "factor": self.factor,
            "weight": self.weight,
            "score": round(self.score, 2),
            "description": self.description
        }

@dataclass
class RiskAssessment:
    risk_score: float
    risk_level: str
    action: str
    factors: List[FactorScore]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "risk_score": round(self.risk_score, 1),
            "risk_level": self.risk_level,
            "action": self.action,
            "factors": [f.to_dict() for f in self.factors]
        }

class RiskEngine:
    """
    Deterministic Security Risk Scoring Engine.
    
    Formula components (Total max: 100.0 points):
    1. Base Alert Severity: max 30.0 points
    2. Anomaly Outlier Score: max 20.0 points (anomaly_score * 20.0)
    3. Threat Intelligence Confidence: max 20.0 points (malicious_flag * confidence * 20.0)
    4. Blast Radius / Entity Criticality: max 15.0 points (privileged accounts, multi-host)
    5. MITRE ATT&CK Criticality: max 15.0 points (impact / credential dumping / lateral spread)
    
    Risk Thresholds:
    - CRITICAL: risk_score >= 75.0 -> Action: Escalate
    - HIGH:     50.0 <= risk_score < 75.0 -> Action: Escalate / Group
    - MEDIUM:   25.0 <= risk_score < 50.0 -> Action: Group / Request Review
    - LOW:      risk_score < 25.0 -> Action: Suppress
    """

    @staticmethod
    def calculate_risk(
        severity: str,
        anomaly_score: float,
        threat_intel_malicious: bool,
        threat_intel_confidence: float,
        accounts: List[str],
        devices: List[str],
        mitre_techniques: List[Dict[str, str]],
        alert_count: int = 1
    ) -> RiskAssessment:
        factors: List[FactorScore] = []

        # 1. Base Severity (0 - 30)
        clean_sev = severity.capitalize() if severity else "Medium"
        sev_points = SEVERITY_SCORES.get(clean_sev, 15.0)
        factors.append(FactorScore(
            factor="Base Severity",
            weight=0.30,
            score=sev_points,
            description=f"Initial signal severity is classified as {clean_sev} (+{sev_points:.1f} pts)."
        ))

        # 2. Anomaly Score (0 - 20)
        clamped_anomaly = max(0.0, min(1.0, float(anomaly_score)))
        anomaly_points = clamped_anomaly * 20.0
        factors.append(FactorScore(
            factor="Behavioral Anomaly",
            weight=0.20,
            score=anomaly_points,
            description=f"IsolationForest telemetry outlier score {clamped_anomaly:.2f} (+{anomaly_points:.1f} pts)."
        ))

        # 3. Threat Intelligence (0 - 20)
        if threat_intel_malicious:
            ti_points = max(5.0, min(20.0, float(threat_intel_confidence) * 20.0))
            ti_desc = f"Corroborated malicious indicator with {threat_intel_confidence:.0%} confidence (+{ti_points:.1f} pts)."
        else:
            ti_points = max(0.0, (1.0 - float(threat_intel_confidence)) * 2.0)
            ti_desc = f"No verified threat intelligence malicious reputation (+{ti_points:.1f} pts)."
        factors.append(FactorScore(
            factor="Threat Intelligence",
            weight=0.20,
            score=ti_points,
            description=ti_desc
        ))

        # 4. Blast Radius & Entity Criticality (0 - 15)
        entity_pts = 0.0
        # Privileged account check
        is_admin = any("admin" in a.lower() or "svc" in a.lower() or "root" in a.lower() for a in accounts)
        if is_admin:
            entity_pts += 8.0
        else:
            entity_pts += 2.0

        # Multi-device lateral spread
        if len(devices) > 1:
            entity_pts += min(7.0, len(devices) * 3.5)
        elif len(devices) == 1:
            entity_pts += 3.0
            
        entity_pts = min(15.0, entity_pts)
        factors.append(FactorScore(
            factor="Blast Radius",
            weight=0.15,
            score=entity_pts,
            description=f"{'High-privilege account context' if is_admin else 'Standard account'} across {len(devices)} device(s) (+{entity_pts:.1f} pts)."
        ))

        # 5. MITRE ATT&CK Criticality (0 - 15)
        mitre_pts = 0.0
        critical_tactics = {"Impact", "Credential Access", "Lateral Movement", "Privilege Escalation"}
        found_crit = False
        for tech in mitre_techniques:
            tactic = tech.get("tactic", "")
            if any(ct in tactic for ct in critical_tactics):
                found_crit = True
                mitre_pts += 6.0
            else:
                mitre_pts += 3.0
        if alert_count > 3:
            mitre_pts += 3.0
        mitre_pts = min(15.0, mitre_pts)
        factors.append(FactorScore(
            factor="MITRE Technique Risk",
            weight=0.15,
            score=mitre_pts,
            description=f"Maps to {len(mitre_techniques)} technique(s) with {'critical impact/access tactics' if found_crit else 'routine discovery/defense tactics'} (+{mitre_pts:.1f} pts)."
        ))

        # Sum total
        raw_score = sum(f.score for f in factors)
        final_score = float(max(5.0, min(99.5, round(raw_score, 1))))

        # Determine level & action
        if final_score >= 75.0:
            level = "CRITICAL"
            action = "Escalate"
        elif final_score >= 50.0:
            level = "HIGH"
            action = "Escalate" if is_admin or threat_intel_malicious else "Group"
        elif final_score >= 25.0:
            level = "MEDIUM"
            action = "Group" if len(devices) > 1 or alert_count > 1 else "Request Review"
        else:
            level = "LOW"
            action = "Suppress"

        return RiskAssessment(
            risk_score=final_score,
            risk_level=level,
            action=action,
            factors=factors
        )

risk_engine = RiskEngine()
