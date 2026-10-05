import React from 'react';
import { 
  ShieldAlert, 
  BrainCircuit, 
  ArrowRight, 
  CheckCircle2, 
  XCircle, 
  Clock, 
  Filter, 
  Layers, 
  Zap, 
  AlertTriangle 
} from 'lucide-react';
import { ComparisonData } from '../types';

interface Props {
  data: ComparisonData | null;
  loading: boolean;
  onClose: () => void;
}

export const ComparisonView: React.FC<Props> = ({ data, loading, onClose }) => {
  if (loading || !data) {
    return (
      <div className="p-8 text-center text-slate-500 animate-pulse">
        <BrainCircuit className="w-10 h-10 mx-auto mb-2 text-blue-500 animate-spin" />
        <p className="text-sm">Calculating Triage Efficiency Comparison Metrics...</p>
      </div>
    );
  }

  const { raw_alerts, socpilot_ai } = data;

  return (
    <div className="space-y-6">
      {/* Top Banner */}
      <div className="bg-gradient-to-r from-blue-950/40 via-surface to-indigo-950/40 rounded-2xl border border-blue-500/30 p-6 flex flex-wrap items-center justify-between gap-4">
        <div className="space-y-1">
          <div className="flex items-center gap-2">
            <span className="px-2.5 py-0.5 rounded-full text-xs font-mono font-bold bg-blue-500/20 text-blue-400 border border-blue-500/30">
              ROUND 3 BENCHMARK EVALUATION
            </span>
            <span className="text-xs text-emerald-400 font-semibold flex items-center gap-1">
              <CheckCircle2 className="w-3.5 h-3.5" /> 100% True Incident Preservation
            </span>
          </div>
          <h2 className="text-xl font-extrabold text-slate-100">
            Raw Alert Severity Sorting vs. Insider Threat Detector Autonomous Prioritization
          </h2>
          <p className="text-xs text-slate-400 max-w-3xl">
            Comparing conventional linear alert handling with Insider Threat Detector ML clustering, anomaly scoring, and LangGraph autonomous evidence gathering.
          </p>
        </div>

        <button
          onClick={onClose}
          className="px-4 py-2 rounded-xl bg-blue-600 hover:bg-blue-500 text-white text-xs font-bold shadow-lg shadow-blue-600/30 transition"
        >
          Return to Live Console
        </button>
      </div>

      {/* Comparison Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* LEFT: RAW ALERT TRIAGE */}
        <div className="bg-surface rounded-2xl border border-rose-900/40 p-5 space-y-4 shadow-sm">
          <div className="flex items-center justify-between pb-3 border-b border-border">
            <div className="flex items-center gap-2.5">
              <div className="p-2 rounded-lg bg-rose-500/10 text-rose-400 border border-rose-500/20">
                <ShieldAlert className="w-5 h-5" />
              </div>
              <div>
                <h3 className="text-sm font-bold text-slate-100">Traditional Raw Alert Triage</h3>
                <p className="text-[11px] text-slate-400">Uncorrelated Microsoft GUIDE Telemetry</p>
              </div>
            </div>
            <span className="text-xs font-mono font-bold px-2 py-0.5 rounded bg-rose-500/10 text-rose-300 border border-rose-500/30">
              {raw_alerts.total_items} Raw Alerts
            </span>
          </div>

          {/* Drawbacks Metrics */}
          <div className="grid grid-cols-2 gap-2.5 text-xs">
            <div className="p-3 rounded-xl bg-slate-900/80 border border-rose-900/30 space-y-1">
              <span className="text-[10px] text-slate-400 uppercase font-semibold">Noise & False Positives</span>
              <div className="text-base font-bold text-rose-400">{raw_alerts.noise_ratio}</div>
              <span className="text-[10px] text-slate-500">Unfiltered benign logs</span>
            </div>
            <div className="p-3 rounded-xl bg-slate-900/80 border border-rose-900/30 space-y-1">
              <span className="text-[10px] text-slate-400 uppercase font-semibold">Analyst Load</span>
              <div className="text-base font-bold text-rose-400">High Fatigue</div>
              <span className="text-[10px] text-slate-500">Linear 1-by-1 manual inspection</span>
            </div>
          </div>

          {/* Raw Alerts Sample Stream */}
          <div className="space-y-1.5 max-h-[360px] overflow-y-auto pr-1">
            {raw_alerts.sample_queue.map((item) => (
              <div
                key={item.id}
                className={`p-2.5 rounded-lg border text-xs flex items-center justify-between gap-2 ${
                  item.is_noise
                    ? 'bg-slate-900/40 border-border/40 text-slate-400'
                    : 'bg-rose-950/20 border-rose-700/30 text-slate-200'
                }`}
              >
                <div className="space-y-0.5 truncate">
                  <div className="flex items-center gap-1.5">
                    <span className="font-mono text-[10px] text-slate-400">{item.id}</span>
                    <span className="font-semibold truncate">{item.title}</span>
                  </div>
                  <div className="text-[10px] text-slate-500 truncate">
                    Entity: {item.entity} • {item.category}
                  </div>
                </div>

                <div className="flex items-center gap-1.5 shrink-0">
                  <span className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${
                    item.severity === 'Critical' ? 'bg-rose-500/20 text-rose-400' :
                    item.severity === 'High' ? 'bg-amber-500/20 text-amber-400' : 'bg-slate-800 text-slate-400'
                  }`}>
                    {item.severity}
                  </span>
                  {item.is_noise && (
                    <span className="text-[9px] px-1 py-0.2 rounded bg-slate-800 text-slate-500">Noise</span>
                  )}
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* RIGHT: INSIDER THREAT DETECTOR AUTONOMOUS TRIAGE */}
        <div className="bg-surface rounded-2xl border border-blue-500/40 p-5 space-y-4 shadow-sm relative overflow-hidden">
          <div className="flex items-center justify-between pb-3 border-b border-border">
            <div className="flex items-center gap-2.5">
              <div className="p-2 rounded-lg bg-blue-500/10 text-blue-400 border border-blue-500/20">
                <BrainCircuit className="w-5 h-5" />
              </div>
              <div>
                <h3 className="text-sm font-bold text-slate-100">Insider Threat Detector Autonomous Triage</h3>
                <p className="text-[11px] text-blue-400">ML Correlation + LangGraph Agent Loop</p>
              </div>
            </div>
            <span className="text-xs font-mono font-bold px-2 py-0.5 rounded bg-blue-500/10 text-blue-300 border border-blue-500/30">
              {socpilot_ai.total_items} Actionable Incidents
            </span>
          </div>

          {/* Efficiency Metrics */}
          <div className="grid grid-cols-2 gap-2.5 text-xs">
            <div className="p-3 rounded-xl bg-slate-900/80 border border-emerald-500/30 space-y-1">
              <span className="text-[10px] text-slate-400 uppercase font-semibold">Noise Reduction Rate</span>
              <div className="text-base font-bold text-emerald-400">{socpilot_ai.noise_filtered}</div>
              <span className="text-[10px] text-emerald-400/80">94%+ Autonomous Noise Filtering</span>
            </div>
            <div className="p-3 rounded-xl bg-slate-900/80 border border-blue-500/30 space-y-1">
              <span className="text-[10px] text-slate-400 uppercase font-semibold">Triage Speed Gain</span>
              <div className="text-base font-bold text-blue-400">{socpilot_ai.efficiency_gain}</div>
              <span className="text-[10px] text-blue-400/80">Automated Evidence & Reasoning</span>
            </div>
          </div>

          {/* AI Prioritized Queue Sample */}
          <div className="space-y-1.5 max-h-[360px] overflow-y-auto pr-1">
            {socpilot_ai.sample_queue.map((item) => (
              <div
                key={item.id}
                className="p-3 rounded-xl bg-slate-900/90 border border-border hover:border-blue-500/40 text-xs flex items-center justify-between gap-3 transition"
              >
                <div className="space-y-1 truncate">
                  <div className="flex items-center gap-2">
                    <span className="font-mono text-xs font-bold text-blue-400">{item.id}</span>
                    <span className="font-semibold text-slate-200 truncate">{item.title}</span>
                  </div>
                  <div className="flex items-center gap-2 text-[10px] text-slate-400">
                    <span className="text-slate-300">Grade: {item.predicted_grade}</span>
                    <span>•</span>
                    <span>{item.alert_count} Correlated Alerts</span>
                  </div>
                </div>

                <div className="flex items-center gap-2 shrink-0">
                  <span className="font-mono font-bold text-xs text-slate-200">
                    {item.risk_score.toFixed(0)}/100
                  </span>
                  <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                    item.action === 'Escalate' ? 'bg-rose-500/20 text-rose-400 border border-rose-500/30' :
                    item.action === 'Group' ? 'bg-blue-500/20 text-blue-400 border border-blue-500/30' :
                    'bg-slate-800 text-slate-400'
                  }`}>
                    {item.action}
                  </span>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
};