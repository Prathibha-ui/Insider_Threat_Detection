import os
import random
import logging
from pathlib import Path
from typing import Dict, Any, Optional
import pandas as pd
from datetime import datetime
from sqlalchemy.orm import Session

from app.models import Alert
from app.config import settings

logger = logging.getLogger(__name__)

GUIDE_COLUMNS = [
    "OrgId", "IncidentId", "AlertId", "Timestamp", "DetectorId",
    "AlertTitle", "Category", "MitreTechniques", "Severity",
    "IncidentGrade", "ActionGrouped", "DeviceId", "AccountUpn",
    "IpAddress", "Sha256", "Url"
]

def clean_and_impute_dataframe(df: pd.DataFrame) -> pd.DataFrame:
    """
    Cleans null values in dataframe according to column types.
    """
    df = df.copy()
    for col in df.columns:
        if df[col].dtype == "object" or pd.api.types.is_string_dtype(df[col]):
            df[col] = df[col].fillna("N/A")
        else:
            df[col] = df[col].fillna(0)
    return df

def ingest_guide_dataset(filepath: Optional[Path] = None, db: Optional[Session] = None) -> Dict[str, Any]:
    """
    Ingests the security telemetry dataset CSV into the alerts table.
    Initializes alerts with ClusterId="INC-UNASSIGNED" so correlation happens honestly.
    """
    if filepath:
        csv_path = Path(filepath)
        if not csv_path.exists():
            raise FileNotFoundError(f"Telemetry dataset not found at {csv_path}")
        df = pd.read_csv(csv_path)
    else:
        telemetry_dataset_path = settings.DATASET_PATH.parent / "GUIDE_Telemetry_Dataset.csv"
        paths_to_check = [telemetry_dataset_path, settings.DATASET_PATH]
        dfs = []
        for p in paths_to_check:
            if p.exists():
                dfs.append(pd.read_csv(p))
        if dfs:
            df = pd.concat(dfs, ignore_index=True).drop_duplicates(subset=["AlertId"])
            csv_path = telemetry_dataset_path if telemetry_dataset_path.exists() else settings.DATASET_PATH
        else:
            raise FileNotFoundError("No security telemetry dataset CSV found.")

    logger.info(f"Ingesting security telemetry dataset with {len(df)} records from {csv_path}")
    df = clean_and_impute_dataframe(df)

    if db is not None:
        db.query(Alert).delete()
        db.commit()

        alerts_to_insert = []
        for _, row in df.iterrows():
            ts = pd.to_datetime(row["Timestamp"]) if pd.notnull(row["Timestamp"]) else datetime.utcnow()
            dev_id = str(row.get("DeviceId", "DEV-UNKNOWN"))
            ip_addr = str(row.get("IpAddress", "0.0.0.0"))
            a_type = str(row.get("Category") or row.get("AlertTitle") or "SuspiciousActivity")
            sev = str(row.get("Severity", "Medium"))
            inc_grade = str(row.get("IncidentGrade", "TruePositive"))

            alert = Alert(
                # Explicit requested columns
                device_id=dev_id,
                ip_address=ip_addr,
                alert_type=a_type,
                severity=sev,
                timestamp=ts,
                incident_grade=inc_grade,
                risk_score=0.0,
                threat_level="Pending ML",
                reason="Telemetry record ingested; pending ML risk analysis.",
                recommended_action="Pending ML investigation verdict.",
                created_at=datetime.utcnow(),

                # Legacy attributes & GUIDE schema
                AlertId=str(row.get("AlertId", f"ALT-{random.randint(10000, 99999)}")),
                IncidentId=str(row.get("IncidentId", "INC-UNASSIGNED")),
                OrgId=str(row.get("OrgId", "ORG-CORP-01")),
                DetectorId=str(row.get("DetectorId", "DET-001")),
                AlertTitle=str(row.get("AlertTitle", "Generic Security Alert")),
                MitreTechniques=str(row.get("MitreTechniques", "N/A")),
                ActionGrouped=str(row.get("ActionGrouped", "Detected")),
                AccountUpn=str(row.get("AccountUpn", "corp\\unknown")),
                Sha256=str(row.get("Sha256", "N/A")),
                Url=str(row.get("Url", "N/A")),
                AnomalyScore=0.0,
                ClusterId="INC-UNASSIGNED"
            )
            alerts_to_insert.append(alert)

        db.bulk_save_objects(alerts_to_insert)
        db.commit()
        total_alerts = len(alerts_to_insert)
    else:
        total_alerts = len(df)

    ground_truth_incidents = len(df["IncidentId"].unique()) if "IncidentId" in df.columns else 0
    logger.info(f"Successfully ingested {total_alerts} telemetry alerts into database.")

    return {
        "status": "success",
        "total_alerts": total_alerts,
        "ground_truth_incidents": ground_truth_incidents,
        "dataset_path": str(csv_path)
    }