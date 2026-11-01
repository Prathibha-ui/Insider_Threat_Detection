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
  ChevronRight,
  Usb,
  HardDriveDownload,
  KeyRound,
  Laptop
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
        <h3 className="text-base font-semibold text-slate-300">Select an Alert from the List</h3>
        <p className="text-xs text-slate-500 max-w-md mt-1">
          Click on any security alert in the <strong>Alert List</strong> to inspect its <strong>Device details</strong>, <strong>Risk score</strong>, <strong>Reason for generating alert</strong>, and <strong>Alert timing</strong>.
        </p>
      </div>
    );
  }

  const { incident, alerts, evidence, reasoning_logs, graph, timeline } = data;
  const primaryAlert = alerts[0];

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
    if (score >= 70.0) {
      return (
        <span className="px-3 py-1 rounded-full text-xs font-mono font-bold bg-rose-500/20 text-rose-300 border border-rose-500/40 glow-red flex items-center gap-1.5">
          <span className="w-2 h-2 rounded-full bg-rose-400 animate-pulse" />
          RISK {score.toFixed(1)}/100 (HIGH RISK - RED)
        </span>
      );
    }
    if (score >= 40.0) {
      return (
        <span className="px-3 py-1 rounded-full text-xs font-mono font-bold bg-amber-500/20 text-amber-300 border border-amber-500/40 flex items-center gap-1.5">
          <span className="w-2 h-2 rounded-full bg-amber-400" />
          RISK {score.toFixed(1)}/100 (MEDIUM RISK - ORANGE)
        </span>
      );
    }
    return (
      <span className="px-3 py-1 rounded-full text-xs font-mono font-bold bg-yellow-500/20 text-yellow-300 border border-yellow-500/40 flex items-center gap-1.5">
        <span className="w-2 h-2 rounded-full bg-yellow-400" />
        RISK {score.toFixed(1)}/100 (LOW RISK - YELLOW)
      </span>
    );
  };

  const formatTimingFull = (isoString?: string | null) => {
    if (!isoString) return 'Real-time telemetry event';
    try {
      const d = new Date(isoString);
      return d.toLocaleString('en-US', {
        weekday: 'short',
        year: 'numeric',
        month: 'short',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit',
        timeZoneName: 'short'
      });
    } catch {
      return isoString;
    }
  };

  const formatRelative = (isoString?: string | null) => {
    if (!isoString) return 'Just now';
    try {
      const d = new Date(isoString);
      const diffMs = Date.now() - d.getTime();
      const mins = Math.floor(diffMs / 60000);
      if (mins < 1) return 'Just now';
      if (mins < 60) return `${mins}m ago`;
      const hours = Math.floor(mins / 60);
      if (hours < 24) return `${hours}h ago`;
      return `${Math.floor(hours / 24)}d ago`;
    } catch {
      return 'Recent';
    }
  };

  const accounts = incident.entity_summary?.accounts || [];
  const devices = incident.entity_summary?.devices || [];
  const ips = incident.entity_summary?.ips || [];

  return (
    <div className="flex flex-col h-full bg-surface rounded-xl border border-border shadow-sm overflow-hidden">
      {/* Top Header */}
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
          </div>

          <div className="flex flex-col items-end gap-1.5">
            {getRiskBadge(incident.risk_score)}
            <span className="text-[11px] text-slate-400 font-mono">
              Confidence: {(incident.confidence * 100).toFixed(0)}%
            </span>
          </div>
        </div>

        {/* FEATURE 2 SPOTLIGHT CARD: Exactly what user requested */}
        <div className="bg-slate-950/80 rounded-xl border border-blue-500/30 p-3.5 space-y-2.5 shadow-md">
          <div className="flex items-center justify-between pb-2 border-b border-border/60">
            <span className="text-[11px] font-bold uppercase tracking-wider text-blue-400 flex items-center gap-1.5">
              <ShieldAlert className="w-4 h-4 text-blue-400" />
              Feature 2: Alert Details (On Clicking an Alert)
            </span>
            <span className="text-[10px] font-mono text-slate-400">
              Correlated Threat Intelligence
            </span>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3 text-xs">
            {/* 1. Device details */}
            <div className="bg-slate-900/80 rounded-lg p-2.5 border border-border/80 space-y-1">
              <span className="text-[10px] uppercase font-bold text-slate-400 flex items-center gap-1">
                <Server className="w-3 h-3 text-indigo-400" /> 1. Device Details
              </span>
              <div className="font-mono font-bold text-slate-100 text-sm">
                {devices[0] || primaryAlert?.device_id || 'DEV-FIN-01'}
              </div>
              <div className="text-[11px] text-slate-300">
                IP: <span className="font-mono text-emerald-400">{ips[0] || primaryAlert?.ip_address || '10.10.15.42'}</span>
              </div>
              <div className="text-[11px] text-slate-400">
                Target User: <span className="font-mono text-purple-300">{accounts[0] || primaryAlert?.account_upn || 'corp\\user'}</span>
              </div>
            </div>

            {/* 2. Risk score */}
            <div className="bg-slate-900/80 rounded-lg p-2.5 border border-border/80 space-y-1">
              <span className="text-[10px] uppercase font-bold text-slate-400 flex items-center gap-1">
                <AlertTriangle className="w-3 h-3 text-amber-400" /> 2. Risk Score
              </span>
              <div className="flex items-baseline gap-2">
                <span className="text-xl font-black font-mono text-slate-100">
                  {incident.risk_score.toFixed(1)}
                </span>
                <span className="text-[10px] text-slate-400">/ 100</span>
              </div>
              <div className="text-[11px] font-semibold">
                {incident.risk_score >= 70 ? (
                  <span className="text-rose-400">🔴 High Risk Tier (&gt;70)</span>
                ) : incident.risk_score >= 40 ? (
                  <span className="text-amber-400">🟠 Medium Risk Tier (40-70)</span>
                ) : (
                  <span className="text-yellow-400">🟡 Low Risk Tier (&lt;40)</span>
                )}
              </div>
              <div className="text-[10px] text-slate-500 font-mono">
                Anomaly Outlier: {(incident.anomaly_score * 100).toFixed(0)}%
              </div>
            </div>

            {/* 3. Reason for generating alert */}
            <div className="bg-slate-900/80 rounded-lg p-2.5 border border-border/80 space-y-1">
              <span className="text-[10px] uppercase font-bold text-slate-400 flex items-center gap-1">
                <Tag className="w-3 h-3 text-rose-400" /> 3. Reason for Generating Alert
              </span>
              <p className="text-[11px] text-slate-200 line-clamp-3 leading-relaxed">
                {primaryAlert?.reason || incident.summary || 'Triggered by behavioral anomaly threshold deviation, off-hours timing, and MITRE ATT&CK technique mapping.'}
              </p>
            </div>

            {/* 4. Alert timing */}
            <div className="bg-slate-900/80 rounded-lg p-2.5 border border-border/80 space-y-1">
              <span className="text-[10px] uppercase font-bold text-slate-400 flex items-center gap-1">
                <Clock className="w-3 h-3 text-blue-400" /> 4. Alert Timing (Date &amp; Time)
              </span>
              <div className="font-mono text-[11px] font-semibold text-slate-100">
                {formatTimingFull(primaryAlert?.timestamp || incident.created_at)}
              </div>
              <div className="text-[11px] text-slate-400">
                Relative: <span className="text-blue-300 font-medium">{formatRelative(primaryAlert?.timestamp || incident.created_at)}</span>
              </div>
              <div className="text-[10px] text-slate-500 font-mono">
                Initial Severity: <span className="text-slate-300">{incident.severity}</span>
              </div>
            </div>
          </div>
        </div>

        {/* MITRE Tags & Entity Pills */}
        <div className="flex flex-wrap items-center gap-1.5 pt-1 text-xs">
          {devices.map((d) => (
            <span key={d} className="flex items-center gap-1 px-2 py-0.5 rounded bg-slate-900 text-indigo-300 border border-slate-800 text-[11px]">
              <Server className="w-3 h-3 text-indigo-400" /> {d}
            </span>
          ))}
          {accounts.map((a) => (
            <span key={a} className="flex items-center gap-1 px-2 py-0.5 rounded bg-slate-900 text-purple-300 border border-slate-800 text-[11px]">
              <User className="w-3 h-3 text-purple-400" /> {a}
            </span>
          ))}
          {ips.map((ip) => (
            <span key={ip} className="flex items-center gap-1 px-2 py-0.5 rounded bg-slate-900 text-emerald-300 border border-slate-800 text-[11px]">
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
          { id: 'alerts', label: 'Security Alerts', icon: ListFilter, count: alerts.length },
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
              <div className="h-44 w-full">
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
              <h4 className="text-xs font-bold uppercase tracking-wider text-slate-400">
                Chronological Alert Sequence
              </h4>
              <div className="space-y-2">
                {timeline.map((item) => (
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

            <div className="bg-slate-950/80 rounded-xl border border-border p-4 min-h-[260px] flex flex-col items-center justify-center relative overflow-hidden">
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
                  <th className="p-2.5">Title &amp; Reason</th>
                  <th className="p-2.5">Severity</th>
                  <th className="p-2.5">Device &amp; IP</th>
                  <th className="p-2.5">User Account</th>
                  <th className="p-2.5">Timing</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border/60 text-slate-300">
                {alerts.map((a) => (
                  <tr key={a.alert_id} className="hover:bg-slate-800/30 transition">
                    <td className="p-2.5 font-mono text-blue-400">{a.alert_id}</td>
                    <td className="p-2.5">
                      <div className="font-medium text-slate-100">{a.title}</div>
                      {a.reason && (
                        <div className="text-[10px] text-amber-300/90 mt-0.5 line-clamp-2 italic">
                          "{a.reason}"
                        </div>
                      )}
                    </td>
                    <td className="p-2.5">
                      <span className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${
                        a.severity === 'Critical' ? 'bg-rose-500/20 text-rose-400' :
                        a.severity === 'High' ? 'bg-amber-500/20 text-amber-400' :
                        a.severity === 'Medium' ? 'bg-blue-500/20 text-blue-400' : 'bg-yellow-500/20 text-yellow-400'
                      }`}>
                        {a.severity}
                      </span>
                    </td>
                    <td className="p-2.5 text-slate-400 font-mono text-[11px]">
                      <div>{a.device_id}</div>
                      <div className="text-[10px] text-slate-500">{a.ip_address}</div>
                    </td>
                    <td className="p-2.5 font-mono text-[11px] text-purple-300">
                      {a.account_upn}
                    </td>
                    <td className="p-2.5 font-mono text-[10px] text-slate-400 whitespace-nowrap">
                      {formatTimingFull(a.timestamp)}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {/* TAB 4: AGENT REASONING & EVIDENCE */}
        {activeTab === 'agent' && (
          <div className="space-y-4">
            {/* Reasoning Trace */}
            <div className="space-y-2">
              <h4 className="text-xs font-bold uppercase tracking-wider text-slate-400">
                LangGraph Autonomous Agent Investigation Trace
              </h4>
              <div className="space-y-2">
                {reasoning_logs.map((step) => (
                  <div key={step.step} className="p-3 rounded-lg bg-slate-900/60 border border-border text-xs space-y-1.5">
                    <div className="flex items-center justify-between">
                      <span className="font-bold text-blue-400 font-mono">
                        Step {step.step}: {step.name}
                      </span>
                    </div>
                    <div className="text-slate-300">
                      <strong className="text-slate-400">Observation:</strong> {step.observation}
                    </div>
                    <div className="text-slate-400 italic">
                      <strong className="text-slate-500">Thought:</strong> {step.thought}
                    </div>
                    <div className="text-slate-300">
                      <strong className="text-slate-400">Action:</strong> {step.action}
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* Extracted Evidence */}
            <div className="space-y-2">
              <h4 className="text-xs font-bold uppercase tracking-wider text-slate-400">
                Discovered Evidence &amp; IOC Indicators
              </h4>
              <div className="space-y-2">
                {evidence.map((ev) => (
                  <div key={ev.id} className="p-2.5 rounded-lg bg-slate-900/40 border border-border text-xs flex items-center justify-between">
                    <div>
                      <span className="font-semibold text-slate-200">[{ev.type}]</span> {ev.description}
                    </div>
                    <span className="text-[10px] font-mono text-emerald-400">
                      {(ev.confidence * 100).toFixed(0)}% Conf
                    </span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Analyst Feedback Footer */}
      <div className="p-3.5 border-t border-border bg-slate-900/80 flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-2 flex-1 max-w-lg">
          <input
            type="text"
            placeholder="Analyst note or override comments..."
            value={feedbackComment}
            onChange={(e) => setFeedbackComment(e.target.value)}
            className="w-full bg-slate-950 border border-border rounded-lg px-3 py-1.5 text-xs text-slate-100 placeholder-slate-500 focus:outline-none focus:border-blue-500"
          />
        </div>

        <div className="flex items-center gap-2">
          {feedbackSuccess && (
            <span className="text-xs text-emerald-400 font-bold flex items-center gap-1 animate-pulse">
              <CheckCircle2 className="w-3.5 h-3.5" /> Verdict Recorded
            </span>
          )}
          <button
            onClick={() => handleAction('Escalate', 'TruePositive')}
            disabled={submittingAction !== null}
            className="px-3 py-1.5 rounded-lg bg-rose-600 hover:bg-rose-500 text-white font-bold text-xs shadow-sm transition disabled:opacity-50"
          >
            Escalate (High Risk)
          </button>
          <button
            onClick={() => handleAction('Suppress', 'FalsePositive')}
            disabled={submittingAction !== null}
            className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 font-medium text-xs border border-slate-700 transition disabled:opacity-50"
          >
            Suppress (Benign/Noise)
          </button>
        </div>
      </div>
    </div>
  );
};
