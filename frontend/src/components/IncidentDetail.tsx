import React, { useState } from 'react';
import {
  ShieldAlert,
  Clock,
  Network,
  ListFilter,
  BrainCircuit,
  CheckCircle2,
  AlertTriangle,
  Server,
  User,
  Globe,
  Tag,
  ThumbsUp,
  AlertOctagon,
  ShieldOff,
  Send,
  ExternalLink,
  ChevronRight
} from 'lucide-react';
import {
  ResponsiveContainer,
  AreaChart,
  Area,
  XAxis,
  YAxis,
  Tooltip,
  CartesianGrid
} from 'recharts';
import { IncidentDetailResponse, Alert, Evidence, ReasoningLog } from '../types';

interface Props {
  data: IncidentDetailResponse | null;
  loading: boolean;
  onFeedbackSubmit: (incidentId: string, action: string, newGrade?: string, comments?: string) => Promise<void>;
}

export const IncidentDetail: React.FC<Props> = ({ data, loading, onFeedbackSubmit }) => {
  const [activeTab, setActiveTab] = useState<'timeline' | 'graph' | 'alerts' | 'agent'>('timeline');
  const [feedbackComment, setFeedbackComment] = useState('');
  const [submittingAction, setSubmittingAction] = useState<string | null>(null);
  const [feedbackSuccess, setFeedbackSuccess] = useState(false);

  if (loading) {
    return (
      <div className="h-full bg-surface rounded-xl border border-border p-6 flex flex-col items-center justify-center animate-pulse text-slate-500">
        <BrainCircuit className="w-10 h-10 mb-3 text-blue-500 animate-spin" />
        <p className="text-sm font-mono">Loading Correlated Incident Telemetry...</p>
      </div>
    );
  }

  if (!data) {
    return (
      <div className="h-full bg-surface rounded-xl border border-border p-6 flex flex-col items-center justify-center text-slate-500 text-center">
        <div className="p-4 rounded-full bg-slate-900 border border-slate-800 text-slate-500 mb-3">
          <ShieldAlert className="w-10 h-10 text-slate-500" />
        </div>
        <h3 className="text-base font-semibold text-slate-300">Awaiting Alert Telemetry</h3>
        <p className="text-xs text-slate-500 max-w-md mt-1">
          Use the <strong>Security Alert Ingestion Console</strong> above or select a <strong>Threat Scenario Preset</strong> to ingest an alert and trigger real-time ML risk scoring, attack graph correlation, and the LangGraph reasoning loop.
        </p>
      </div>
    );
  }

  const { incident, alerts, evidence, reasoning_logs, graph, timeline } = data;

  const handleAction = async (action: string, grade?: string) => {
    setSubmittingAction(action);
    try {
      await onFeedbackSubmit(incident.incident_id, action, grade, feedbackComment);
      setFeedbackSuccess(true);
      setTimeout(() => setFeedbackSuccess(false), 3000);
      setFeedbackComment('');
    } finally {
      setSubmittingAction(null);
    }
  };

  const getRiskBadge = (score: number) => {
    if (score >= 80) {
      return (
        <span className="px-3 py-1 rounded-full text-xs font-mono font-bold bg-rose-500/20 text-rose-300 border border-rose-500/40 glow-red">
          RISK {score.toFixed(0)}/100 (CRITICAL)
        </span>
      );
    }
    if (score >= 60) {
      return (
        <span className="px-3 py-1 rounded-full text-xs font-mono font-bold bg-amber-500/20 text-amber-300 border border-amber-500/40">
          RISK {score.toFixed(0)}/100 (HIGH)
        </span>
      );
    }
    if (score >= 40) {
      return (
        <span className="px-3 py-1 rounded-full text-xs font-mono font-bold bg-blue-500/20 text-blue-300 border border-blue-500/40">
          RISK {score.toFixed(0)}/100 (MEDIUM)
        </span>
      );
    }
    return (
      <span className="px-3 py-1 rounded-full text-xs font-mono font-bold bg-emerald-500/20 text-emerald-300 border border-emerald-500/40">
        RISK {score.toFixed(0)}/100 (LOW)
      </span>
    );
  };

  const accounts = incident.entity_summary?.accounts || [];
  const devices = incident.entity_summary?.devices || [];
  const ips = incident.entity_summary?.ips || [];

  return (
    <div className="flex flex-col h-full bg-surface rounded-xl border border-border shadow-sm overflow-hidden">
      {/* Incident Header */}
      <div className="p-4 border-b border-border bg-slate-900/40 space-y-3">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div className="space-y-1">
            <div className="flex items-center gap-2 flex-wrap">
              <span className="font-mono text-sm font-bold text-blue-400 bg-blue-500/10 px-2 py-0.5 rounded border border-blue-500/20">
                {incident.incident_id}
              </span>
              <span className="text-xs font-semibold px-2 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700">
                Grade: {incident.predicted_grade}
              </span>
              <span className="text-xs font-semibold px-2 py-0.5 rounded bg-indigo-500/10 text-indigo-300 border border-indigo-500/20">
                Action: {incident.agent_action}
              </span>
            </div>
            <h2 className="text-lg font-bold text-slate-100">{incident.title}</h2>
            <p className="text-xs text-slate-400 max-w-2xl">{incident.summary}</p>
          </div>

          <div className="flex flex-col items-end gap-1.5">
            {getRiskBadge(incident.risk_score)}
            <span className="text-[11px] text-slate-400 font-mono">
              Confidence: {(incident.confidence * 100).toFixed(0)}%
            </span>
          </div>
        </div>

        {/* Entity Tags & MITRE Techniques */}
        <div className="flex flex-wrap items-center gap-2 pt-1 text-xs">
          {devices.map((d) => (
            <span key={d} className="flex items-center gap-1 px-2 py-0.5 rounded bg-slate-900 text-indigo-300 border border-slate-800">
              <Server className="w-3 h-3 text-indigo-400" /> {d}
            </span>
          ))}
          {accounts.map((a) => (
            <span key={a} className="flex items-center gap-1 px-2 py-0.5 rounded bg-slate-900 text-blue-300 border border-slate-800">
              <User className="w-3 h-3 text-blue-400" /> {a}
            </span>
          ))}
          {ips.map((ip) => (
            <span key={ip} className="flex items-center gap-1 px-2 py-0.5 rounded bg-slate-900 text-emerald-300 border border-slate-800">
              <Globe className="w-3 h-3 text-emerald-400" /> {ip}
            </span>
          ))}
          {incident.mitre_tactics.map((t) => (
            <span key={t} className="flex items-center gap-1 px-2 py-0.5 rounded bg-rose-500/10 text-rose-300 border border-rose-500/20 font-mono text-[11px]">
              <Tag className="w-2.5 h-2.5" /> {t}
            </span>
          ))}
        </div>
      </div>

      {/* Tabs Navigation */}
      <div className="flex items-center border-b border-border bg-slate-900/60 px-4 gap-2 text-xs">
        {[
          { id: 'timeline', label: 'Event Timeline', icon: Clock, count: timeline.length },
          { id: 'graph', label: 'Attack Graph', icon: Network, count: graph.nodes.length },
          { id: 'alerts', label: 'GUIDE Alerts', icon: ListFilter, count: alerts.length },
          { id: 'agent', label: 'Agent Reasoning & Evidence', icon: BrainCircuit, count: evidence.length }
        ].map((tab) => {
          const Icon = tab.icon;
          const isActive = activeTab === tab.id;
          return (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id as any)}
              className={`flex items-center gap-2 py-2.5 px-3 font-medium transition border-b-2 ${
                isActive
                  ? 'border-blue-500 text-blue-400 bg-slate-800/40'
                  : 'border-transparent text-slate-400 hover:text-slate-200 hover:bg-slate-800/20'
              }`}
            >
              <Icon className="w-3.5 h-3.5" />
              <span>{tab.label}</span>
              <span className="px-1.5 py-0.2 rounded-full text-[10px] bg-slate-800 text-slate-300 border border-slate-700">
                {tab.count}
              </span>
            </button>
          );
        })}
      </div>

      {/* Tab Content Area */}
      <div className="flex-1 overflow-y-auto p-4 space-y-4">
        {/* TAB 1: TIMELINE */}
        {activeTab === 'timeline' && (
          <div className="space-y-4">
            <div className="bg-slate-900/80 rounded-xl border border-border p-4">
              <h4 className="text-xs font-bold uppercase tracking-wider text-slate-300 mb-3 flex items-center gap-1.5">
                <Clock className="w-3.5 h-3.5 text-blue-400" /> Alert Sequence & Severity Curve
              </h4>
              <div className="h-48 w-full">
                <ResponsiveContainer width="100%" height="100%">
                  <AreaChart data={timeline} margin={{ top: 10, right: 20, left: -20, bottom: 0 }}>
                    <defs>
                      <linearGradient id="sevGrad" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="5%" stopColor="#3b82f6" stopOpacity={0.4} />
                        <stop offset="95%" stopColor="#3b82f6" stopOpacity={0.0} />
                      </linearGradient>
                    </defs>
                    <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                    <XAxis dataKey="timestamp" stroke="#64748b" fontSize={10} />
                    <YAxis domain={[0, 4]} ticks={[1, 2, 3, 4]} stroke="#64748b" fontSize={10} />
                    <Tooltip
                      contentStyle={{ backgroundColor: '#0f172a', borderColor: '#334155', borderRadius: '8px', fontSize: '11px' }}
                      formatter={(val: any) => [
                        val === 4 ? 'Critical' : val === 3 ? 'High' : val === 2 ? 'Medium' : 'Low',
                        'Severity'
                      ]}
                    />
                    <Area type="monotone" dataKey="severity_value" stroke="#3b82f6" strokeWidth={2} fillOpacity={1} fill="url(#sevGrad)" />
                  </AreaChart>
                </ResponsiveContainer>
              </div>
            </div>

            {/* Timeline Events List */}
            <div className="space-y-2">
              <h4 className="text-xs font-bold uppercase tracking-wider text-slate-400">Chronological Alert Sequence</h4>
              <div className="space-y-2">
                {timeline.map((item, idx) => (
                  <div key={item.alert_id} className="flex items-start gap-3 p-3 rounded-lg bg-slate-900/60 border border-border text-xs">
                    <div className="font-mono text-[11px] text-blue-400 whitespace-nowrap pt-0.5">
                      {item.timestamp}
                    </div>
                    <div className="w-2 h-2 rounded-full mt-1.5 bg-blue-500" />
                    <div className="flex-1 space-y-0.5">
                      <div className="flex items-center justify-between">
                        <span className="font-semibold text-slate-200">{item.title}</span>
                        <span className="font-mono text-[10px] text-slate-400">{item.alert_id}</span>
                      </div>
                      <div className="flex items-center gap-2 text-[11px] text-slate-400">
                        <span>Category: {item.category}</span>
                        <span>•</span>
                        <span>Host: {item.device}</span>
                        <span>•</span>
                        <span>User: {item.user}</span>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}

        {/* TAB 2: ATTACK GRAPH */}
        {activeTab === 'graph' && (
          <div className="space-y-3">
            <div className="flex items-center justify-between text-xs bg-slate-900/60 p-2.5 rounded-lg border border-border">
              <div className="flex items-center gap-4 text-slate-400">
                <span>Nodes: <strong className="text-slate-200">{graph.node_count}</strong></span>
                <span>Edges: <strong className="text-slate-200">{graph.edge_count}</strong></span>
                <span>Graph Density: <strong className="text-slate-200">{graph.density}</strong></span>
              </div>
              <div className="flex items-center gap-2 text-[10px]">
                <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-full bg-blue-400" /> Alert</span>
                <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-full bg-indigo-400" /> Host</span>
                <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-full bg-purple-400" /> User</span>
                <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-full bg-emerald-400" /> IP</span>
                <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-full bg-rose-400" /> MITRE</span>
              </div>
            </div>

            {/* Visual Graph Topology Canvas */}
            <div className="bg-slate-950/80 rounded-xl border border-border p-4 min-h-[300px] flex flex-col items-center justify-center relative overflow-hidden">
              <div className="grid grid-cols-2 sm:grid-cols-3 gap-3 w-full max-w-2xl">
                {graph.nodes.map((node) => {
                  let bgColor = 'bg-blue-500/10 text-blue-300 border-blue-500/30';
                  if (node.type === 'device') bgColor = 'bg-indigo-500/10 text-indigo-300 border-indigo-500/30';
                  if (node.type === 'user') bgColor = 'bg-purple-500/10 text-purple-300 border-purple-500/30';
                  if (node.type === 'ip') bgColor = 'bg-emerald-500/10 text-emerald-300 border-emerald-500/30';
                  if (node.type === 'mitre') bgColor = 'bg-rose-500/10 text-rose-300 border-rose-500/30';

                  return (
                    <div key={node.id} className={`p-2.5 rounded-lg border text-xs space-y-1 shadow-sm ${bgColor}`}>
                      <div className="flex items-center justify-between text-[10px] uppercase font-bold opacity-70">
                        <span>{node.type}</span>
                        {node.severity && <span>{node.severity}</span>}
                      </div>
                      <div className="font-semibold truncate">{node.label}</div>
                    </div>
                  );
                })}
              </div>
            </div>
          </div>
        )}

        {/* TAB 3: UNDERLYING ALERTS */}
        {activeTab === 'alerts' && (
          <div className="overflow-x-auto rounded-xl border border-border">
            <table className="w-full text-left text-xs">
              <thead className="bg-slate-900/80 text-slate-400 font-semibold border-b border-border">
                <tr>
                  <th className="p-2.5">Alert ID</th>
                  <th className="p-2.5">Title</th>
                  <th className="p-2.5">Category</th>
                  <th className="p-2.5">Severity</th>
                  <th className="p-2.5">Host / User</th>
                  <th className="p-2.5">MITRE</th>
                  <th className="p-2.5">Anomaly</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border/60 text-slate-300">
                {alerts.map((a) => (
                  <tr key={a.alert_id} className="hover:bg-slate-800/30 transition">
                    <td className="p-2.5 font-mono text-blue-400">{a.alert_id}</td>
                    <td className="p-2.5 font-medium text-slate-100">{a.title}</td>
                    <td className="p-2.5 text-slate-400">{a.category}</td>
                    <td className="p-2.5">
                      <span className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${
                        a.severity === 'Critical' ? 'bg-rose-500/20 text-rose-400' :
                        a.severity === 'High' ? 'bg-amber-500/20 text-amber-400' :
                        a.severity === 'Medium' ? 'bg-blue-500/20 text-blue-400' : 'bg-emerald-500/20 text-emerald-400'
                      }`}>
                        {a.severity}
                      </span>
                    </td>
                    <td className="p-2.5 text-slate-400">
                      <div>{a.device_id}</div>
                      <div className="text-[10px] text-slate-500">{a.account_upn}</div>
                    </td>
                    <td className="p-2.5 font-mono text-[11px] text-rose-300">{a.mitre}</td>
                    <td className="p-2.5 font-mono">{(a.anomaly_score * 100).toFixed(0)}%</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {/* TAB 4: AGENT REASONING & EVIDENCE */}
        {activeTab === 'agent' && (
          <div className="space-y-4">
            {/* Evidence Cards */}
            <div>
              <h4 className="text-xs font-bold uppercase tracking-wider text-slate-300 mb-2 flex items-center gap-1.5">
                <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" /> Gathered Contextual Evidence ({evidence.length})
              </h4>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5">
                {evidence.map((ev) => (
                  <div
                    key={ev.id}
                    className={`p-3 rounded-lg border text-xs space-y-1.5 ${
                      ev.is_malicious
                        ? 'bg-rose-950/20 border-rose-500/40 text-rose-200'
                        : 'bg-slate-900/60 border-border text-slate-300'
                    }`}
                  >
                    <div className="flex items-center justify-between text-[10px]">
                      <span className="font-semibold text-slate-400 uppercase">{ev.type}</span>
                      <span className="font-mono text-emerald-400 font-bold">{(ev.confidence * 100).toFixed(0)}% Conf</span>
                    </div>
                    <p className="font-medium">{ev.description}</p>
                    <div className="text-[10px] text-slate-500">Source: {ev.source}</div>
                  </div>
                ))}
              </div>
            </div>

            {/* Step-by-Step Reasoning Trace */}
            <div>
              <h4 className="text-xs font-bold uppercase tracking-wider text-slate-300 mb-2 flex items-center gap-1.5">
                <BrainCircuit className="w-3.5 h-3.5 text-blue-400" /> Autonomous Agent Investigation Trace
              </h4>
              <div className="space-y-2">
                {reasoning_logs.map((log) => (
                  <div key={log.step} className="p-3 rounded-lg bg-slate-900/70 border border-border text-xs space-y-1.5">
                    <div className="flex items-center gap-2">
                      <span className="w-5 h-5 rounded-full bg-blue-500/20 text-blue-400 font-mono font-bold flex items-center justify-center text-[10px] border border-blue-500/30">
                        {log.step}
                      </span>
                      <span className="font-bold text-slate-200">{log.name}</span>
                    </div>
                    <p className="text-slate-400 pl-7 text-[11px]"><strong className="text-slate-300">Observation:</strong> {log.observation}</p>
                    <p className="text-blue-300 pl-7 text-[11px]"><strong className="text-blue-400">Thought:</strong> {log.thought}</p>
                    <p className="text-emerald-300 pl-7 text-[11px]"><strong className="text-emerald-400">Action:</strong> {log.action}</p>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Analyst Decision & Feedback Action Bar */}
      <div className="p-3 border-t border-border bg-slate-900/90 space-y-2">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div className="flex items-center gap-2">
            <button
              disabled={submittingAction !== null}
              onClick={() => handleAction('Escalate', 'TruePositive')}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-rose-600 hover:bg-rose-500 text-white text-xs font-semibold shadow-md shadow-rose-600/20 transition"
            >
              <AlertOctagon className="w-3.5 h-3.5" /> Escalate to Tier 3
            </button>

            <button
              disabled={submittingAction !== null}
              onClick={() => handleAction('Suppress', 'FalsePositive')}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-semibold border border-slate-700 transition"
            >
              <ShieldOff className="w-3.5 h-3.5" /> Suppress Noise
            </button>

            <button
              disabled={submittingAction !== null}
              onClick={() => handleAction(incident.agent_action)}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-blue-600 hover:bg-blue-500 text-white text-xs font-semibold shadow-md shadow-blue-600/20 transition"
            >
              <ThumbsUp className="w-3.5 h-3.5" /> Approve Agent ({incident.agent_action})
            </button>
          </div>

          {feedbackSuccess && (
            <span className="text-xs font-semibold text-emerald-400 flex items-center gap-1 animate-pulse">
              <CheckCircle2 className="w-3.5 h-3.5" /> Feedback Saved & Queue Updated
            </span>
          )}
        </div>
      </div>
    </div>
  );
};