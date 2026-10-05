import json
import logging
from pathlib import Path
from typing import Dict, List, Any, Tuple, Optional
from datetime import datetime
import numpy as np
import pandas as pd
import joblib
from sqlalchemy.orm import Session

from app.config import settings
from app.models import Alert, Incident
from app.services.correlation import correlation_engine
from app.services.mitre_mapping import extract_mitre_techniques
from app.services.threat_intelligence import threat_intel_service
from app.services.risk_engine import risk_engine, RiskAssessment

logger = logging.getLogger(__name__)

class MLEngine:
    """
    ML Intelligence Engine for SOCPilot.
    Loads and runs verified scikit-learn models from trained_models/
    without ground-truth label or ID leakage.
    """

    def __init__(self, model_dir: Path = settings.MODEL_DIR):
        self.model_dir = model_dir
        self.grade_model = None
        self.anomaly_detector = None
        self.anomaly_scaler = None
        self.anomaly_features = []
        self.threat_severity_model = None
        self.metadata = {}
        self.is_loaded = False
        self._ensure_models_loaded()

    def _ensure_models_loaded(self):
        grade_path = self.model_dir / "grade_classifier.joblib"
        anomaly_path = self.model_dir / "anomaly_detector.joblib"
        metadata_path = self.model_dir / "metadata.json"

        if not (grade_path.exists() and anomaly_path.exists()):
            logger.info("Trained model files not found on disk. Initiating training...")
            from app.ml.train import train_and_evaluate
            train_and_evaluate(settings.DATASET_PATH, self.model_dir)

        try:
            self.grade_model = joblib.load(grade_path)
            anomaly_bundle = joblib.load(anomaly_path)
            self.anomaly_detector = anomaly_bundle["model"]
            self.anomaly_scaler = anomaly_bundle["scaler"]
            self.anomaly_features = anomaly_bundle["features"]

            sev_path = self.model_dir / "threat_severity_model.joblib"
            if sev_path.exists():
                self.threat_severity_model = joblib.load(sev_path)

            if metadata_path.exists():
                with open(metadata_path, "r", encoding="utf-8") as f:
                    self.metadata = json.load(f)

            self.is_loaded = True
            logger.info("ML Engine successfully loaded trained models and metadata.")
        except Exception as e:
            logger.error(f"Error loading trained models: {e}")
            self.is_loaded = False

    def alert_to_dataframe(self, alert_data: Any) -> pd.DataFrame:
        """Converts an Alert OR dict to a DataFrame with engineered observable features."""
        if hasattr(alert_data, "AlertTitle"):
            raw = {
                "AlertTitle": getattr(alert_data, "AlertTitle", "Security Alert"),
                "Category": getattr(alert_data, "Category", "SuspiciousActivity"),
                "Severity": getattr(alert_data, "Severity", "Medium"),
                "ActionGrouped": getattr(alert_data, "ActionGrouped", "Detected"),
                "DeviceId": getattr(alert_data, "DeviceId", "DEV-UNKNOWN"),
                "AccountUpn": getattr(alert_data, "AccountUpn", "corp\\unknown"),
                "IpAddress": getattr(alert_data, "IpAddress", "0.0.0.0"),
                "Sha256": getattr(alert_data, "Sha256", "N/A"),
                "Url": getattr(alert_data, "Url", "N/A"),
                "MitreTechniques": getattr(alert_data, "MitreTechniques", "N/A"),
                "Timestamp": getattr(alert_data, "Timestamp", datetime.utcnow())
            }
        elif isinstance(alert_data, dict):
            raw = {
                "AlertTitle": alert_data.get("title") or alert_data.get("AlertTitle") or "Security Alert",
                "Category": alert_data.get("category") or alert_data.get("Category") or "SuspiciousActivity",
                "Severity": alert_data.get("severity") or alert_data.get("Severity") or "Medium",
                "ActionGrouped": alert_data.get("action") or alert_data.get("ActionGrouped") or "Detected",
                "DeviceId": alert_data.get("device_id") or alert_data.get("DeviceId") or "DEV-UNKNOWN",
                "AccountUpn": alert_data.get("account_upn") or alert_data.get("AccountUpn") or "corp\\unknown",
                "IpAddress": alert_data.get("ip_address") or alert_data.get("IpAddress") or "0.0.0.0",
                "Sha256": alert_data.get("sha256") or alert_data.get("Sha256") or "N/A",
                "Url": alert_data.get("url") or alert_data.get("Url") or "N/A",
                "MitreTechniques": alert_data.get("mitre") or alert_data.get("MitreTechniques") or "N/A",
                "Timestamp": alert_data.get("timestamp") or alert_data.get("Timestamp") or datetime.utcnow()
            }
        else:
            raw = {}

        df = pd.DataFrame([raw])
        from app.ml.train import engineer_features
        return engineer_features(df)

    def predict_grade(self, alert_data: Any) -> Tuple[str, float]:
        """
        Predicts IncidentGrade (TruePositive / BenignPositive / FalsePositive) and model confidence.
        """
        if not self.is_loaded or self.grade_model is None:
            return "TruePositive", 0.70

        df = self.alert_to_dataframe(alert_data)
        try:
            pred = self.grade_model.predict(df)[0]
            probs = self.grade_model.predict_proba(df)[0]
            max_prob = float(np.max(probs))
            return str(pred), round(max_prob, 2)
        except Exception as e:
            logger.warning(f"Grade prediction error: {e}")
            return "TruePositive", 0.75

    def compute_anomaly_score(self, alert_data: Any) -> float:
        """
        Computes outlier score [0.0 - 1.0] where higher = more anomalous.
        """
        if not self.is_loaded or self.anomaly_detector is None:
            return 0.35

        df = self.alert_to_dataframe(alert_data)
        try:
            X_num = df[self.anomaly_features].values
            X_scaled = self.anomaly_scaler.transform(X_num)
            raw_dec = float(self.anomaly_detector.decision_function(X_scaled)[0])
            # Mapping: IsolationForest returns positive for inliers, negative for outliers
            # -0.2 (very anomalous) to +0.2 (very normal)
            norm = 1.0 - ((raw_dec + 0.25) / 0.50)
            return float(np.clip(round(norm, 3), 0.05, 0.95))
        except Exception as e:
            logger.warning(f"Anomaly scoring error: {e}")
            return 0.35

    def predict_severity(self, alert_data: Any) -> str:
        """Predicts likely alert severity."""
        if not self.is_loaded or self.threat_severity_model is None:
            return "High"
        df = self.alert_to_dataframe(alert_data)
        try:
            return str(self.threat_severity_model.predict(df)[0])
        except Exception:
            return "Medium"

    def execute_pipeline(self, db: Session) -> Dict[str, Any]:
        """
        Executes end-to-end processing across all stored alerts:
        1. Observable correlation clustering (no IncidentId leakage)
        2. ML anomaly scoring and grade inference
        3. Deterministic risk engine calculation
        4. Incident and graph persistence
        """
        alerts = db.query(Alert).all()
        if not alerts:
            return {"status": "error", "message": "No alerts found in database."}

        logger.info(f"Executing ML pipeline for {len(alerts)} alerts.")

        # 1. Correlate alerts using observable attributes
        clusters = correlation_engine.correlate_alerts(alerts)
        for a in alerts:
            a.ClusterId = clusters.get(a.AlertId, "INC-UNASSIGNED")
            a.AnomalyScore = self.compute_anomaly_score(a)
        db.commit()

        # Group alerts by assigned ClusterId
        cluster_groups: Dict[str, List[Alert]] = {}
        for a in alerts:
            cid = a.ClusterId or "INC-UNASSIGNED"
            if cid not in cluster_groups:
                cluster_groups[cid] = []
            cluster_groups[cid].append(a)

        # 2. Re-create Incident records
        db.query(Incident).delete()
        db.commit()

        created_incidents: List[Incident] = []

        for cid, group_alerts in cluster_groups.items():
            # Build attack graph topology
            graph_data = correlation_engine.build_correlation_graph(cid, group_alerts)
            density = graph_data["density"]
            avg_anomaly = sum(a.AnomalyScore for a in group_alerts) / len(group_alerts)

            # Extract entities
            accounts = list(set([a.AccountUpn for a in group_alerts if a.AccountUpn and a.AccountUpn not in ["corp\\unknown", "UNKNOWN", "N/A"]]))
            devices = list(set([a.DeviceId for a in group_alerts if a.DeviceId and a.DeviceId not in ["DEV-UNKNOWN", "N/A"]]))
            ips = list(set([a.IpAddress for a in group_alerts if a.IpAddress and a.IpAddress not in ["0.0.0.0", "127.0.0.1", "N/A"]]))

            # MITRE techniques extraction
            all_mitre: List[Dict[str, str]] = []
            for a in group_alerts:
                techs = extract_mitre_techniques(a.MitreTechniques, a.AlertTitle, a.Category)
                all_mitre.extend(techs)
            # Deduplicate by technique ID
            unique_mitre = {t["id"]: t for t in all_mitre}
            mitre_list = list(unique_mitre.values())

            # Threat Intel Check
            ti_malicious = False
            ti_max_conf = 0.0
            for ip in ips:
                ti_res = threat_intel_service.check_indicator(ip, "ip")
                if ti_res.malicious:
                    ti_malicious = True
                ti_max_conf = max(ti_max_conf, ti_res.confidence)
            for a in group_alerts:
                if a.Sha256 and a.Sha256 != "N/A":
                    ti_res = threat_intel_service.check_indicator(a.Sha256, "hash")
                    if ti_res.malicious:
                        ti_malicious = True
                    ti_max_conf = max(ti_max_conf, ti_res.confidence)

            # Max severity
            sev_rank = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Informational": 0}
            sorted_sevs = sorted([a.Severity for a in group_alerts], key=lambda s: sev_rank.get(s, 1), reverse=True)
            max_severity = sorted_sevs[0] if sorted_sevs else "Medium"

            # 3. Deterministic Risk Engine Assessment
            assessment: RiskAssessment = risk_engine.calculate_risk(
                severity=max_severity,
                anomaly_score=avg_anomaly,
                threat_intel_malicious=ti_malicious,
                threat_intel_confidence=ti_max_conf,
                accounts=accounts,
                devices=devices,
                mitre_techniques=mitre_list,
                alert_count=len(group_alerts)
            )

            # 4. Predict Incident Grade using ML model
            top_alert = group_alerts[0]
            pred_grade, model_conf = self.predict_grade(top_alert)

            # Synthesize title and summary
            categories = list(set([a.Category for a in group_alerts if a.Category]))
            primary_cat = categories[0] if categories else "Security"
            
            if any(a.Severity == "Critical" for a in group_alerts):
                title = f"Critical {primary_cat} Activity Cluster"
            elif any("Ransomware" in (a.AlertTitle or "") for a in group_alerts):
                title = "Multi-Stage Ransomware & Data Exfiltration"
            elif any("LSASS" in (a.AlertTitle or "") or "Mimikatz" in (a.AlertTitle or "") for a in group_alerts):
                title = "Credential Dumping & Lateral Movement"
            elif any("OAuth" in (a.AlertTitle or "") for a in group_alerts):
                title = "Cloud Identity Compromise & Token Exfiltration"
            elif any("Port Scan" in (a.AlertTitle or "") or "Nmap" in (a.AlertTitle or "") for a in group_alerts):
                title = "Routine IT Admin Vulnerability Scan"
            elif any("Failed" in (a.AlertTitle or "") for a in group_alerts):
                title = "Spike in Failed Domain Logon Attempts"
            else:
                title = f"{primary_cat} Investigation Cluster ({len(group_alerts)} alerts)"

            entity_summary = {
                "accounts": accounts,
                "devices": devices,
                "ips": ips,
                "total_alerts": len(group_alerts)
            }

            incident = Incident(
                IncidentId=cid,
                Title=title,
                Summary=f"Correlated {len(group_alerts)} alerts across {len(devices)} device(s) and {len(accounts)} user account(s).",
                RiskScore=assessment.risk_score,
                InitialSeverity=max_severity,
                PredictedGrade=pred_grade,
                Confidence=model_conf,
                AgentAction=assessment.action,
                Status="New",
                MitreTactics=json.dumps([t["id"] for t in mitre_list]),
                EntitySummary=json.dumps(entity_summary),
                RiskBreakdown=json.dumps(assessment.to_dict()),
                GraphDensity=density,
                AnomalyScore=round(avg_anomaly, 3),
                AlertCount=len(group_alerts),
                CreatedAt=min([a.Timestamp for a in group_alerts if a.Timestamp] or [datetime.utcnow()]),
                UpdatedAt=datetime.utcnow()
            )
            created_incidents.append(incident)

        db.bulk_save_objects(created_incidents)
        db.commit()

        logger.info(f"Pipeline complete. Created {len(created_incidents)} incidents from {len(alerts)} alerts.")
        return {
            "status": "success",
            "processed_alerts": len(alerts),
            "created_incidents": len(created_incidents)
        }

ml_engine = MLEngine()

def execute_ml_pipeline(db: Session) -> Dict[str, Any]:
    return ml_engine.execute_pipeline(db)