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
    Ingests the Microsoft GUIDE benchmark CSV dataset from backend/data/GUIDE_Train.csv.
    Initializes alerts with ClusterId="INC-UNASSIGNED" so correlation happens honestly.
    """
    csv_path = Path(filepath) if filepath else settings.DATASET_PATH

    if not csv_path.exists():
        raise FileNotFoundError(f"GUIDE benchmark dataset not found at {csv_path}")

    logger.info(f"Ingesting Microsoft GUIDE dataset from {csv_path}")
    df = pd.read_csv(csv_path)
    df = clean_and_impute_dataframe(df)

    if db is not None:
        db.query(Alert).delete()
        db.commit()

        alerts_to_insert = []
        for _, row in df.iterrows():
            ts = pd.to_datetime(row["Timestamp"]) if pd.notnull(row["Timestamp"]) else datetime.utcnow()
            alert = Alert(
                AlertId=str(row.get("AlertId", f"ALT-{random.randint(10000, 99999)}")),
                IncidentId=str(row.get("IncidentId", "INC-UNASSIGNED")), # Ground truth for evaluation only
                OrgId=str(row.get("OrgId", "ORG-CORP-01")),
                Timestamp=ts,
                DetectorId=str(row.get("DetectorId", "DET-001")),
                AlertTitle=str(row.get("AlertTitle", "Generic Security Alert")),
                Category=str(row.get("Category", "SuspiciousActivity")),
                MitreTechniques=str(row.get("MitreTechniques", "N/A")),
                Severity=str(row.get("Severity", "Medium")),
                IncidentGrade=str(row.get("IncidentGrade", "TruePositive")),
                ActionGrouped=str(row.get("ActionGrouped", "Detected")),
                DeviceId=str(row.get("DeviceId", "DEV-UNKNOWN")),
                AccountUpn=str(row.get("AccountUpn", "corp\\unknown")),
                IpAddress=str(row.get("IpAddress", "0.0.0.0")),
                Sha256=str(row.get("Sha256", "N/A")),
                Url=str(row.get("Url", "N/A")),
                AnomalyScore=0.0,
                ClusterId="INC-UNASSIGNED" # Strictly unassigned until CorrelationEngine runs!
            )
            alerts_to_insert.append(alert)

        db.bulk_save_objects(alerts_to_insert)
        db.commit()
        total_alerts = len(alerts_to_insert)
    else:
        total_alerts = len(df)

    ground_truth_incidents = len(df["IncidentId"].unique()) if "IncidentId" in df.columns else 0
    logger.info(f"Successfully ingested {total_alerts} alerts representing {ground_truth_incidents} ground-truth incidents.")

    return {
        "status": "success",
        "total_alerts": total_alerts,
        "ground_truth_incidents": ground_truth_incidents,
        "dataset_path": str(csv_path)
    }