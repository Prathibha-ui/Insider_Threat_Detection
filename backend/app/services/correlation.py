import logging
import networkx as nx
import numpy as np
from datetime import datetime
from typing import List, Dict, Any, Tuple, Optional
from collections import defaultdict

logger = logging.getLogger(__name__)

class CorrelationEngine:
    """
    Alert Correlation & Incident Clustering Engine.
    
    CRITICAL LEAKAGE RULE:
    IncidentId is NEVER used during correlation or clustering!
    Clusters are formed strictly from observable attributes:
    1. Shared identity / account (AccountUpn)
    2. Shared endpoint / device (DeviceId)
    3. Shared network indicator (IpAddress)
    4. Temporal proximity (within a 2-hour window)
    5. Common MITRE ATT&CK technique or attack category
    """

    @staticmethod
    def correlate_alerts(alerts: List[Any], time_window_hours: float = 2.0) -> Dict[str, str]:
        """
        Groups alerts into incident clusters using a connected-components graph on observable entities.
        Returns a mapping of AlertId -> ClusterId.
        """
        if not alerts:
            return {}

        G = nx.Graph()
        # Add every alert as a node
        for a in alerts:
            G.add_node(a.AlertId, alert=a)

        # Build entity inverted indices
        device_map = defaultdict(list)
        account_map = defaultdict(list)
        ip_map = defaultdict(list)

        for a in alerts:
            aid = a.AlertId
            dev = (a.DeviceId or "").strip()
            acc = (a.AccountUpn or "").strip()
            ip = (a.IpAddress or "").strip()

            if dev and dev not in ["DEV-UNKNOWN", "N/A"]:
                device_map[dev].append(a)
            if acc and acc not in ["corp\\unknown", "UNKNOWN", "N/A"]:
                account_map[acc].append(a)
            if ip and ip not in ["0.0.0.0", "127.0.0.1", "N/A"]:
                ip_map[ip].append(a)

        def time_diff_hours(t1: Optional[datetime], t2: Optional[datetime]) -> float:
            if not t1 or not t2:
                return 0.0
            return abs((t1 - t2).total_seconds()) / 3600.0

        # Connect alerts sharing the same DeviceId within time window
        for dev, dev_alerts in device_map.items():
            for i in range(len(dev_alerts)):
                for j in range(i + 1, len(dev_alerts)):
                    a1 = dev_alerts[i]
                    a2 = dev_alerts[j]
                    if time_diff_hours(a1.Timestamp, a2.Timestamp) <= time_window_hours:
                        G.add_edge(a1.AlertId, a2.AlertId, reason="SHARED_DEVICE")

        # Connect alerts sharing the same AccountUpn within time window
        for acc, acc_alerts in account_map.items():
            for i in range(len(acc_alerts)):
                for j in range(i + 1, len(acc_alerts)):
                    a1 = acc_alerts[i]
                    a2 = acc_alerts[j]
                    if time_diff_hours(a1.Timestamp, a2.Timestamp) <= time_window_hours:
                        G.add_edge(a1.AlertId, a2.AlertId, reason="SHARED_ACCOUNT")

        # Connect alerts sharing the same external/target IP
        for ip, ip_alerts in ip_map.items():
            # Only connect if not private network or if close in time
            is_external = not ip.startswith("10.") and not ip.startswith("192.168.")
            for i in range(len(ip_alerts)):
                for j in range(i + 1, len(ip_alerts)):
                    a1 = ip_alerts[i]
                    a2 = ip_alerts[j]
                    max_window = time_window_hours * 2 if is_external else time_window_hours
                    if time_diff_hours(a1.Timestamp, a2.Timestamp) <= max_window:
                        G.add_edge(a1.AlertId, a2.AlertId, reason="SHARED_IP")

        # Extract connected components as incident clusters
        clusters: Dict[str, str] = {}
        cluster_id_counter = 1001

        for component in nx.connected_components(G):
            assigned_cluster_id = f"INC-CORR-{cluster_id_counter}"
            cluster_id_counter += 1
            for alert_id in component:
                clusters[alert_id] = assigned_cluster_id

        return clusters

    @staticmethod
    def build_correlation_graph(incident_id: str, alerts: List[Any]) -> Dict[str, Any]:
        """
        Builds a NetworkX graph topology linking Alerts, Devices, Users, IPs, and MITRE techniques.
        """
        G = nx.Graph()

        for a in alerts:
            alert_node = f"Alert:{a.AlertId}"
            title_label = (a.AlertTitle or "Alert")[:24]
            G.add_node(alert_node, label=title_label, type="alert", severity=a.Severity)

            # Device node
            dev = (a.DeviceId or "").strip()
            if dev and dev not in ["DEV-UNKNOWN", "N/A"]:
                dev_node = f"Device:{dev}"
                G.add_node(dev_node, label=dev, type="device")
                G.add_edge(alert_node, dev_node, relationship="DETECTED_ON")

            # Account node
            acc = (a.AccountUpn or "").strip()
            if acc and acc not in ["corp\\unknown", "UNKNOWN", "N/A"]:
                user_label = acc.split("\\")[-1]
                acc_node = f"User:{acc}"
                G.add_node(acc_node, label=user_label, type="user")
                G.add_edge(alert_node, acc_node, relationship="ATTRIBUTED_TO")

            # IP node
            ip = (a.IpAddress or "").strip()
            if ip and ip not in ["0.0.0.0", "127.0.0.1", "N/A"]:
                ip_node = f"IP:{ip}"
                G.add_node(ip_node, label=ip, type="ip")
                G.add_edge(alert_node, ip_node, relationship="COMMUNICATES_WITH")

            # MITRE Technique node
            mitre_str = (a.MitreTechniques or "").strip()
            if mitre_str and mitre_str != "N/A":
                for tech in [t.strip() for t in mitre_str.split(",") if t.strip()]:
                    tech_node = f"MITRE:{tech}"
                    G.add_node(tech_node, label=tech, type="mitre")
                    G.add_edge(alert_node, tech_node, relationship="MAPS_TECHNIQUE")

        num_nodes = G.number_of_nodes()
        num_edges = G.number_of_edges()
        density = nx.density(G) if num_nodes > 1 else 0.0

        nodes_data = []
        for n, d in G.nodes(data=True):
            nodes_data.append({
                "id": n,
                "label": d.get("label", n),
                "type": d.get("type", "entity"),
                "severity": d.get("severity", "Medium")
            })

        edges_data = []
        for u, v, d in G.edges(data=True):
            edges_data.append({
                "source": u,
                "target": v,
                "relationship": d.get("relationship", "RELATED_TO")
            })

        return {
            "incident_id": incident_id,
            "density": round(float(density), 3),
            "node_count": num_nodes,
            "edge_count": num_edges,
            "nodes": nodes_data,
            "edges": edges_data
        }

correlation_engine = CorrelationEngine()
