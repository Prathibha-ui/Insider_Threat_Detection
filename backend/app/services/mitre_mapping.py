import re
from typing import Dict, List, Any, Optional

# Verified MITRE ATT&CK Enterprise Techniques Catalog
MITRE_CATALOG: Dict[str, Dict[str, str]] = {
    "T1059": {"name": "Command and Scripting Interpreter", "tactic": "Execution"},
    "T1059.001": {"name": "PowerShell", "tactic": "Execution"},
    "T1059.007": {"name": "JavaScript", "tactic": "Execution"},
    "T1078": {"name": "Valid Accounts", "tactic": "Defense Evasion / Initial Access"},
    "T1078.004": {"name": "Cloud Accounts", "tactic": "Defense Evasion / Initial Access"},
    "T1003": {"name": "OS Credential Dumping", "tactic": "Credential Access"},
    "T1003.001": {"name": "LSASS Memory", "tactic": "Credential Access"},
    "T1110": {"name": "Brute Force", "tactic": "Credential Access"},
    "T1110.001": {"name": "Password Guessing / Spraying", "tactic": "Credential Access"},
    "T1486": {"name": "Data Encrypted for Impact", "tactic": "Impact"},
    "T1490": {"name": "Inhibit System Recovery", "tactic": "Impact"},
    "T1071": {"name": "Application Layer Protocol", "tactic": "Command and Control"},
    "T1071.001": {"name": "Web Protocols (HTTP/HTTPS)", "tactic": "Command and Control"},
    "T1046": {"name": "Network Service Discovery", "tactic": "Discovery"},
    "T1190": {"name": "Exploit Public-Facing Application", "tactic": "Initial Access"},
    "T1566": {"name": "Phishing", "tactic": "Initial Access"},
    "T1566.001": {"name": "Spearphishing Attachment", "tactic": "Initial Access"},
    "T1550": {"name": "Use Alternate Authentication Material", "tactic": "Lateral Movement"},
    "T1550.002": {"name": "Pass the Hash", "tactic": "Lateral Movement"},
    "T1021": {"name": "Remote Services", "tactic": "Lateral Movement"},
    "T1021.002": {"name": "SMB/Windows Admin Shares", "tactic": "Lateral Movement"},
    "T1021.006": {"name": "Windows Remote Management (WinRM)", "tactic": "Lateral Movement"},
    "T1484": {"name": "Domain Policy Modification", "tactic": "Defense Evasion / Persistence"},
    "T1484.001": {"name": "Group Policy Modification", "tactic": "Defense Evasion / Persistence"},
    "T1558": {"name": "Steal or Forge Kerberos Tickets", "tactic": "Privilege Escalation"},
    "T1558.001": {"name": "Golden Ticket", "tactic": "Privilege Escalation"},
    "T1621": {"name": "Multi-Factor Authentication Request Generation (MFA Fatigue)", "tactic": "Credential Access"},
    "T1528": {"name": "Steal Application Access Token", "tactic": "Credential Access"},
    "T1530": {"name": "Data from Cloud Storage Object", "tactic": "Collection / Exfiltration"},
    "T1574": {"name": "Hijack Execution Flow", "tactic": "Persistence / Privilege Escalation"},
    "T1574.002": {"name": "DLL Side-Loading", "tactic": "Defense Evasion / Persistence"},
    "T1053": {"name": "Scheduled Task/Job", "tactic": "Persistence / Privilege Escalation"},
    "T1053.005": {"name": "Scheduled Task", "tactic": "Persistence"},
    "T1560": {"name": "Archive Collected Data", "tactic": "Collection"},
    "T1560.001": {"name": "Archive via Utility", "tactic": "Collection"},
    "T1048": {"name": "Exfiltration Over Alternative Protocol", "tactic": "Exfiltration"},
    "T1048.003": {"name": "Exfiltration Over Unencrypted/Encrypted Non-C2 Protocol", "tactic": "Exfiltration"},
    "T1070": {"name": "Indicator Removal", "tactic": "Defense Evasion"},
    "T1070.001": {"name": "Clear Windows Event Logs", "tactic": "Defense Evasion"},
    "T1052": {"name": "Exfiltration Over Physical Medium", "tactic": "Exfiltration"},
    "T1052.001": {"name": "Exfiltration over USB", "tactic": "Exfiltration"}
}

# Heuristic category/title fallback mapping for raw strings
CATEGORY_TECHNIQUE_MAP: Dict[str, str] = {
    "ransomware": "T1486",
    "credentialaccess": "T1003",
    "mimikatz": "T1003.001",
    "initialaccess": "T1566.001",
    "commandandcontrol": "T1071.001",
    "lateralmovement": "T1021.002",
    "discovery": "T1046",
    "execution": "T1059.001",
    "webattack": "T1190",
    "cloudcompromise": "T1078.004",
    "supplychain": "T1574.002",
    "defenseevasion": "T1070.001"
}

def extract_mitre_techniques(raw_text: Optional[str], title: Optional[str] = None, category: Optional[str] = None) -> List[Dict[str, str]]:
    """
    Extracts verified MITRE ATT&CK techniques.
    Returns list of dicts with 'id', 'name', 'tactic'.
    Never outputs fabricated techniques.
    """
    results: Dict[str, Dict[str, str]] = {}

    # 1. Regex search for official MITRE IDs (e.g. T1059, T1059.001)
    if raw_text and raw_text != "N/A":
        matches = re.findall(r"T\d{4}(?:\.\d{3})?", raw_text)
        for tech_id in matches:
            if tech_id in MITRE_CATALOG:
                results[tech_id] = {
                    "id": tech_id,
                    "name": MITRE_CATALOG[tech_id]["name"],
                    "tactic": MITRE_CATALOG[tech_id]["tactic"]
                }
            else:
                # Check parent technique if sub-technique unknown
                parent_id = tech_id.split(".")[0]
                if parent_id in MITRE_CATALOG:
                    results[parent_id] = {
                        "id": parent_id,
                        "name": MITRE_CATALOG[parent_id]["name"],
                        "tactic": MITRE_CATALOG[parent_id]["tactic"]
                    }

    # 2. Category / Title fallback if no explicit MITRE ID in raw text
    if not results:
        check_str = f"{title or ''} {category or ''}".lower()
        for kw, tech_id in CATEGORY_TECHNIQUE_MAP.items():
            if kw in check_str and tech_id in MITRE_CATALOG:
                results[tech_id] = {
                    "id": tech_id,
                    "name": MITRE_CATALOG[tech_id]["name"],
                    "tactic": MITRE_CATALOG[tech_id]["tactic"]
                }
                break

    return list(results.values())
