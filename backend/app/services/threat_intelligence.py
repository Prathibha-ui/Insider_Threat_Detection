import json
import logging
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional, List
from pathlib import Path
import requests

from app.config import settings

logger = logging.getLogger(__name__)

class ThreatIntelResult:
    def __init__(
        self,
        indicator: str,
        indicator_type: str,
        malicious: bool,
        confidence: float,
        source: str,
        provider_name: str,
        details: Optional[Dict[str, Any]] = None
    ):
        self.indicator = indicator
        self.indicator_type = indicator_type
        self.malicious = malicious
        self.confidence = confidence
        self.source = source
        self.provider_name = provider_name
        self.details = details or {}

    def to_dict(self) -> Dict[str, Any]:
        return {
            "indicator": self.indicator,
            "type": self.indicator_type,
            "malicious": self.malicious,
            "confidence": round(self.confidence, 2),
            "source": self.source,
            "provider_name": self.provider_name,
            "details": self.details
        }

class ThreatIntelProvider(ABC):
    @abstractmethod
    def check_indicator(self, indicator: str, indicator_type: Optional[str] = None) -> ThreatIntelResult:
        pass

    @property
    @abstractmethod
    def provider_name(self) -> str:
        pass

class LocalThreatIntelProvider(ThreatIntelProvider):
    def __init__(self, data_path: Optional[Path] = None):
        self.data_path = data_path or settings.THREAT_INTEL_PATH
        self._cache: Dict[str, Dict[str, Any]] = {}
        self._load_local_data()

    def _load_local_data(self):
        if not self.data_path.exists():
            logger.warning(f"Threat intelligence file not found at {self.data_path}")
            return
        try:
            with open(self.data_path, "r", encoding="utf-8") as f:
                records = json.load(f)
                for item in records:
                    key = item.get("indicator", "").strip().lower()
                    if key:
                        self._cache[key] = item
            logger.info(f"Loaded {len(self._cache)} threat intelligence indicators from {self.data_path}")
        except Exception as e:
            logger.error(f"Failed to load local threat intelligence data: {e}")

    @property
    def provider_name(self) -> str:
        return "local threat intel dataset"

    def check_indicator(self, indicator: str, indicator_type: Optional[str] = None) -> ThreatIntelResult:
        clean_ind = (indicator or "").strip()
        key = clean_ind.lower()
        
        # Check local cache
        if key in self._cache:
            entry = self._cache[key]
            return ThreatIntelResult(
                indicator=clean_ind,
                indicator_type=entry.get("type", indicator_type or "unknown"),
                malicious=bool(entry.get("malicious", False)),
                confidence=float(entry.get("confidence", 0.5)),
                source=entry.get("source", "Local Feed"),
                provider_name=self.provider_name,
                details={"tags": entry.get("tags", []), "last_seen": entry.get("last_seen")}
            )
            
        # Private/internal IP detection
        if clean_ind.startswith("10.") or clean_ind.startswith("192.168.") or clean_ind in ["127.0.0.1", "0.0.0.0", "localhost"]:
            return ThreatIntelResult(
                indicator=clean_ind,
                indicator_type="ip",
                malicious=False,
                confidence=0.05,
                source="RFC 1918 Private IP Space",
                provider_name=self.provider_name,
                details={"classification": "Internal Non-Routable"}
            )

        # Default clean/unobserved indicator
        return ThreatIntelResult(
            indicator=clean_ind,
            indicator_type=indicator_type or "unknown",
            malicious=False,
            confidence=0.20,
            source="Local Baseline Sensor",
            provider_name=self.provider_name,
            details={"verdict": "Unobserved / No Malicious Record"}
        )

class VirusTotalProvider(ThreatIntelProvider):
    def __init__(self, api_key: str, fallback_provider: ThreatIntelProvider):
        self.api_key = api_key
        self.fallback = fallback_provider
        self.base_url = "https://www.virustotal.com/api/v3"

    @property
    def provider_name(self) -> str:
        return "VirusTotal API v3"

    def check_indicator(self, indicator: str, indicator_type: Optional[str] = None) -> ThreatIntelResult:
        clean_ind = (indicator or "").strip()
        if not clean_ind:
            return self.fallback.check_indicator(clean_ind, indicator_type)

        endpoint_map = {
            "ip": f"{self.base_url}/ip_addresses/{clean_ind}",
            "domain": f"{self.base_url}/domains/{clean_ind}",
            "hash": f"{self.base_url}/files/{clean_ind}"
        }

        url = endpoint_map.get(indicator_type or "ip")
        if not url:
            return self.fallback.check_indicator(clean_ind, indicator_type)

        headers = {"x-apikey": self.api_key}
        try:
            resp = requests.get(url, headers=headers, timeout=3.0)
            if resp.status_code == 200:
                data = resp.json().get("data", {}).get("attributes", {})
                stats = data.get("last_analysis_stats", {})
                malicious_votes = stats.get("malicious", 0)
                harmless_votes = stats.get("harmless", 0)
                total = malicious_votes + harmless_votes + stats.get("undetected", 0)
                
                is_mal = malicious_votes >= 2
                conf = min(0.99, max(0.10, (malicious_votes / max(total, 1)) * 1.5))
                return ThreatIntelResult(
                    indicator=clean_ind,
                    indicator_type=indicator_type or "unknown",
                    malicious=is_mal,
                    confidence=conf,
                    source="VirusTotal Live Telemetry",
                    provider_name=self.provider_name,
                    details={"stats": stats, "reputation": data.get("reputation", 0)}
                )
            elif resp.status_code == 429:
                logger.warning("VirusTotal API rate limit hit. Falling back to local provider.")
            else:
                logger.warning(f"VirusTotal query returned HTTP {resp.status_code}. Falling back.")
        except Exception as e:
            logger.warning(f"VirusTotal lookup error: {e}. Falling back to local provider.")

        # Fallback to local provider gracefully
        return self.fallback.check_indicator(clean_ind, indicator_type)

def get_threat_intel_service() -> ThreatIntelProvider:
    local_provider = LocalThreatIntelProvider()
    if settings.VIRUSTOTAL_API_KEY and settings.VIRUSTOTAL_API_KEY.strip():
        logger.info("Initializing VirusTotal threat intelligence provider with local fallback.")
        return VirusTotalProvider(settings.VIRUSTOTAL_API_KEY.strip(), local_provider)
    return local_provider

threat_intel_service = get_threat_intel_service()
