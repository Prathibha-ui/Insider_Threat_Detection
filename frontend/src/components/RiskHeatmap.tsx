import React, { useState } from 'react';
import { Flame, ShieldAlert, Laptop, AlertOctagon, AlertTriangle, ShieldCheck, X, Filter } from 'lucide-react';
import { Incident } from '../types';

interface Props {
  incidents: Incident[];
  selectedFilter: string | null;
  onSelectFilter: (filter: string | null) => void;
}

export const RiskHeatmap: React.FC<Props> = ({ incidents, selectedFilter, onSelectFilter }) => {
  const [viewType, setViewType] = useState<'threats' | 'devices'>('threats');

  // Red – High Risk (> 70)
  const highRiskIncidents = incidents.filter((i) => i.risk_score >= 70.0);
  // Orange – Medium Risk (40 - 70)
  const mediumRiskIncidents = incidents.filter((i) => i.risk_score >= 40.0 && i.risk_score < 70.0);
  // Yellow – Low Risk (< 40)
  const lowRiskIncidents = incidents.filter((i) => i.risk_score < 40.0);

  // Group devices by highest risk score
  const deviceRiskMap: Record<string, { maxRisk: number; incidents: Incident[] }> = {};
  incidents.forEach((inc) => {
    const devs = inc.entity_summary?.devices || [];
    devs.forEach((d) => {
      if (!deviceRiskMap[d]) {
        deviceRiskMap[d] = { maxRisk: inc.risk_score, incidents: [inc] };
      } else {
        deviceRiskMap[d].maxRisk = Math.max(deviceRiskMap[d].maxRisk, inc.risk_score);
        deviceRiskMap[d].incidents.push(inc);
      }
    });
  });

  const highRiskDevices = Object.entries(deviceRiskMap).filter(([_, v]) => v.maxRisk >= 70.0);
  const medRiskDevices = Object.entries(deviceRiskMap).filter(([_, v]) => v.maxRisk >= 40.0 && v.maxRisk < 70.0);
  const lowRiskDevices = Object.entries(deviceRiskMap).filter(([_, v]) => v.maxRisk < 40.0);

  return (
    <div className="bg-surface rounded-xl border border-border p-4 shadow-sm space-y-3">
      {/* Header Bar */}
      <div className="flex flex-wrap items-center justify-between gap-3 pb-3 border-b border-border/80">
        <div className="flex items-center gap-2.5">
          <div className="p-2 rounded-lg bg-rose-500/10 text-rose-400 border border-rose-500/20">
            <Flame className="w-4 h-4" />
          </div>
          <div>
            <h3 className="text-xs font-bold uppercase tracking-wider text-slate-100 flex items-center gap-2">
              5. Security Risk Heatmap (High • Medium • Low)
            </h3>
            <p className="text-[11px] text-slate-400">
              Interactive visualization displaying threats and endpoint devices arranged by risk severity level
            </p>
          </div>
        </div>

        {/* View Switcher: Threats vs Devices */}
        <div className="flex items-center gap-2">
          <div className="flex items-center bg-slate-950/80 rounded-lg p-0.5 border border-border text-xs">
            <button
              onClick={() => setViewType('threats')}
              className={`px-3 py-1 rounded text-xs font-semibold transition flex items-center gap-1.5 ${
                viewType === 'threats'
                  ? 'bg-blue-600 text-white shadow-sm'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              <ShieldAlert className="w-3.5 h-3.5" /> Threat Incidents ({incidents.length})
            </button>
            <button
              onClick={() => setViewType('devices')}
              className={`px-3 py-1 rounded text-xs font-semibold transition flex items-center gap-1.5 ${
                viewType === 'devices'
                  ? 'bg-blue-600 text-white shadow-sm'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              <Laptop className="w-3.5 h-3.5" /> Endpoint Devices ({Object.keys(deviceRiskMap).length})
            </button>
          </div>

          {selectedFilter && (
            <button
              onClick={() => onSelectFilter(null)}
              className="flex items-center gap-1 text-[11px] px-2 py-1 rounded bg-slate-800 text-slate-300 hover:text-white border border-slate-700 transition"
              title="Reset Filter"
            >
              <X className="w-3 h-3" /> Clear Filter
            </button>
          )}
        </div>
      </div>

      {/* 3 Color-Coded Risk Heatmap Cards: Red, Orange, Yellow */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-3.5">
        {/* 1. RED - High Risk */}
        <div
          onClick={() => onSelectFilter(selectedFilter === 'HighRisk' ? null : 'HighRisk')}
          className={`cursor-pointer rounded-xl p-4 border transition-all duration-200 ${
            selectedFilter === 'HighRisk'
              ? 'bg-rose-950/90 border-rose-400 ring-2 ring-rose-400 shadow-lg shadow-rose-950/50'
              : 'bg-gradient-to-b from-rose-950/40 to-slate-900/60 border-rose-500/30 hover:border-rose-400 hover:bg-rose-950/50'
          }`}
        >
          <div className="flex items-center justify-between mb-2">
            <div className="flex items-center gap-2">
              <span className="w-3 h-3 rounded-full bg-rose-500 shadow-sm shadow-rose-500/50 animate-pulse" />
              <span className="text-xs font-extrabold uppercase tracking-wide text-rose-300">
                Red – High Risk (Score &gt; 70)
              </span>
            </div>
            <span className="text-[10px] font-bold px-2 py-0.5 rounded-full bg-rose-500/20 text-rose-300 border border-rose-500/40">
              CRITICAL
            </span>
          </div>

          <div className="flex items-baseline gap-2 my-2">
            <span className="text-3xl font-black font-mono text-rose-200">
              {viewType === 'threats' ? highRiskIncidents.length : highRiskDevices.length}
            </span>
            <span className="text-xs text-rose-300/80">
              {viewType === 'threats' ? 'Critical threats detected' : 'Compromised devices'}
            </span>
          </div>

          <div className="mt-3 pt-2.5 border-t border-rose-900/50 text-[11px] text-slate-300 space-y-1">
            <div className="font-semibold text-rose-400 text-[10px] uppercase tracking-wider">
              {viewType === 'threats' ? 'Top High-Risk Alerts:' : 'Top High-Risk Devices:'}
            </div>
            {viewType === 'threats' ? (
              <div className="space-y-1">
                {highRiskIncidents.slice(0, 3).map((inc) => (
                  <div key={inc.incident_id} className="truncate flex items-center justify-between text-[11px]">
                    <span className="truncate text-slate-200">{inc.title}</span>
                    <span className="font-mono text-rose-400 font-bold ml-2 shrink-0">{inc.risk_score.toFixed(0)}</span>
                  </div>
                ))}
              </div>
            ) : (
              <div className="space-y-1">
                {highRiskDevices.slice(0, 3).map(([d, v]) => (
                  <div key={d} className="truncate flex items-center justify-between text-[11px]">
                    <span className="truncate font-mono text-slate-200">{d}</span>
                    <span className="font-mono text-rose-400 font-bold ml-2 shrink-0">Risk {v.maxRisk.toFixed(0)}</span>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>

        {/* 2. ORANGE - Medium Risk */}
        <div
          onClick={() => onSelectFilter(selectedFilter === 'MediumRisk' ? null : 'MediumRisk')}
          className={`cursor-pointer rounded-xl p-4 border transition-all duration-200 ${
            selectedFilter === 'MediumRisk'
              ? 'bg-amber-950/90 border-amber-400 ring-2 ring-amber-400 shadow-lg shadow-amber-950/50'
              : 'bg-gradient-to-b from-amber-950/30 to-slate-900/60 border-amber-500/30 hover:border-amber-400 hover:bg-amber-950/40'
          }`}
        >
          <div className="flex items-center justify-between mb-2">
            <div className="flex items-center gap-2">
              <span className="w-3 h-3 rounded-full bg-amber-500 shadow-sm shadow-amber-500/50" />
              <span className="text-xs font-extrabold uppercase tracking-wide text-amber-300">
                Orange – Medium Risk (Score 40 - 70)
              </span>
            </div>
            <span className="text-[10px] font-bold px-2 py-0.5 rounded-full bg-amber-500/20 text-amber-300 border border-amber-500/40">
              ELEVATED
            </span>
          </div>

          <div className="flex items-baseline gap-2 my-2">
            <span className="text-3xl font-black font-mono text-amber-200">
              {viewType === 'threats' ? mediumRiskIncidents.length : medRiskDevices.length}
            </span>
            <span className="text-xs text-amber-300/80">
              {viewType === 'threats' ? 'Medium-risk threats' : 'Monitored devices'}
            </span>
          </div>

          <div className="mt-3 pt-2.5 border-t border-amber-900/50 text-[11px] text-slate-300 space-y-1">
            <div className="font-semibold text-amber-400 text-[10px] uppercase tracking-wider">
              {viewType === 'threats' ? 'Sample Medium Threats:' : 'Sample Devices:'}
            </div>
            {viewType === 'threats' ? (
              <div className="space-y-1">
                {mediumRiskIncidents.slice(0, 3).map((inc) => (
                  <div key={inc.incident_id} className="truncate flex items-center justify-between text-[11px]">
                    <span className="truncate text-slate-200">{inc.title}</span>
                    <span className="font-mono text-amber-400 font-bold ml-2 shrink-0">{inc.risk_score.toFixed(0)}</span>
                  </div>
                ))}
              </div>
            ) : (
              <div className="space-y-1">
                {medRiskDevices.slice(0, 3).map(([d, v]) => (
                  <div key={d} className="truncate flex items-center justify-between text-[11px]">
                    <span className="truncate font-mono text-slate-200">{d}</span>
                    <span className="font-mono text-amber-400 font-bold ml-2 shrink-0">Risk {v.maxRisk.toFixed(0)}</span>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>

        {/* 3. YELLOW - Low Risk */}
        <div
          onClick={() => onSelectFilter(selectedFilter === 'LowRisk' ? null : 'LowRisk')}
          className={`cursor-pointer rounded-xl p-4 border transition-all duration-200 ${
            selectedFilter === 'LowRisk'
              ? 'bg-yellow-950/90 border-yellow-400 ring-2 ring-yellow-400 shadow-lg shadow-yellow-950/50'
              : 'bg-gradient-to-b from-yellow-950/20 to-slate-900/60 border-yellow-500/30 hover:border-yellow-400 hover:bg-yellow-950/30'
          }`}
        >
          <div className="flex items-center justify-between mb-2">
            <div className="flex items-center gap-2">
              <span className="w-3 h-3 rounded-full bg-yellow-400 shadow-sm shadow-yellow-400/50" />
              <span className="text-xs font-extrabold uppercase tracking-wide text-yellow-300">
                Yellow – Low Risk (Score &lt; 40)
              </span>
            </div>
            <span className="text-[10px] font-bold px-2 py-0.5 rounded-full bg-yellow-500/20 text-yellow-300 border border-yellow-500/40">
              ROUTINE / NOISE
            </span>
          </div>

          <div className="flex items-baseline gap-2 my-2">
            <span className="text-3xl font-black font-mono text-yellow-200">
              {viewType === 'threats' ? lowRiskIncidents.length : lowRiskDevices.length}
            </span>
            <span className="text-xs text-yellow-300/80">
              {viewType === 'threats' ? 'Low risk & benign signals' : 'Baseline normal devices'}
            </span>
          </div>

          <div className="mt-3 pt-2.5 border-t border-yellow-900/50 text-[11px] text-slate-300 space-y-1">
            <div className="font-semibold text-yellow-400 text-[10px] uppercase tracking-wider">
              {viewType === 'threats' ? 'Auto-Suppressed Noise:' : 'Baseline Devices:'}
            </div>
            {viewType === 'threats' ? (
              <div className="space-y-1">
                {lowRiskIncidents.slice(0, 3).map((inc) => (
                  <div key={inc.incident_id} className="truncate flex items-center justify-between text-[11px]">
                    <span className="truncate text-slate-200">{inc.title}</span>
                    <span className="font-mono text-yellow-400 font-bold ml-2 shrink-0">{inc.risk_score.toFixed(0)}</span>
                  </div>
                ))}
              </div>
            ) : (
              <div className="space-y-1">
                {lowRiskDevices.slice(0, 3).map(([d, v]) => (
                  <div key={d} className="truncate flex items-center justify-between text-[11px]">
                    <span className="truncate font-mono text-slate-200">{d}</span>
                    <span className="font-mono text-yellow-400 font-bold ml-2 shrink-0">Risk {v.maxRisk.toFixed(0)}</span>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
