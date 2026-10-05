export interface Alert {
  alert_id: string;
  title: string;
  category: string;
  severity: string;
  timestamp: string | null;
  device_id: string;
  account_upn: string;
  ip_address: string;
  sha256: string;
  url: string;
  mitre: string;
  action: string;
  grade: string;
  anomaly_score: number;
}

export interface EntitySummary {
  accounts?: string[];
  devices?: string[];
  ips?: string[];
  total_alerts?: number;
}

export interface Incident {
  incident_id: string;
  title: string;
  summary: string;
  risk_score: number;
  severity: string;
  predicted_grade: string;
  confidence: number;
  agent_action: 'Escalate' | 'Group' | 'Suppress' | 'Request Review';
  status: string;
  alert_count: number;
  mitre_tactics: string[];
  entity_summary: EntitySummary;
  graph_density: number;
  anomaly_score: number;
  created_at: string | null;
  updated_at: string | null;
}

export interface Evidence {
  id: number;
  type: string;
  source: string;
  description: string;
  confidence: number;
  is_malicious: boolean;
  timestamp: string | null;
}

export interface ReasoningLog {
  step: number;
  name: string;
  observation: string;
  thought: string;
  action: string;
  timestamp: string | null;
}

export interface GraphNode {
  id: string;
  label: string;
  type: 'alert' | 'user' | 'device' | 'ip' | 'mitre';
  severity?: string;
}

export interface GraphEdge {
  source: string;
  target: string;
  relationship: string;
}

export interface GraphData {
  incident_id: string;
  density: number;
  node_count: number;
  edge_count: number;
  nodes: GraphNode[];
  edges: GraphEdge[];
}

export interface TimelinePoint {
  alert_id: string;
  timestamp: string;
  full_time: string;
  title: string;
  category: string;
  severity: string;
  severity_value: number;
  device: string;
  user: string;
  anomaly_score: number;
}

export interface IncidentDetailResponse {
  incident: Incident;
  alerts: Alert[];
  evidence: Evidence[];
  reasoning_logs: ReasoningLog[];
  graph: GraphData;
  timeline: TimelinePoint[];
}

export interface Metrics {
  total_alerts: number;
  total_incidents: number;
  escalated_count: number;
  suppressed_count: number;
  compression_ratio: string;
  noise_reduction_pct: number;
  workload_reduction_pct: number;
  tp_preservation_pct: number;
  estimated_hours_saved: number;
}

export interface RawAlertItem {
  id: string;
  title: string;
  severity: string;
  category: string;
  entity: string;
  timestamp: string;
  is_noise: boolean;
}

export interface ComparisonData {
  raw_alerts: {
    total_items: number;
    sample_queue: RawAlertItem[];
    noise_ratio: string;
    analyst_fatigue: string;
  };
  socpilot_ai: {
    total_items: number;
    sample_queue: {
      id: string;
      title: string;
      risk_score: number;
      action: string;
      alert_count: number;
      predicted_grade: string;
      entities: string[];
    }[];
    noise_filtered: string;
    efficiency_gain: string;
  };
}