import React from 'react';
import { Flame, ShieldAlert, Sparkles, X } from 'lucide-react';
import { Incident } from '../types';

interface Props {
  incidents: Incident[];
  selectedFilter: string | null;
  onSelectFilter: (filter: string | null) => void;
}

export const RiskHeatmap: React.FC<Props> = ({ incidents, selectedFilter, onSelectFilter }) => {
  // Severity levels (rows)
  const severities = ['Critical', 'High', 'Medium', 'Low'];
  // Impact levels (columns)
  const impactLevels = [
    { key: 'Multi-Host', label: 'Multi-Host / Core' },
    { key: 'Single-Host', label: 'Single Host' },
    { key: 'Perimeter-Noise', label: 'Perimeter / Noise' }
  ];

  // Helper to categorize incident blast radius
  const getImpactCategory = (inc: Incident) => {
    const devices = inc.entity_summary?.devices || [];
    const accounts = inc.entity_summary?.accounts || [];
    if (devices.length > 1 || accounts.length > 2) return 'Multi-Host';
    if (devices.length === 1 || accounts.length === 1) return 'Single-Host';
    return 'Perimeter-Noise';
  };

  // Build matrix counts
  const matrix: Record<string, Record<string, Incident[]>> = {};
  severities.forEach((sev) => {
    matrix[sev] = {};
    impactLevels.forEach((imp) => {
      matrix[sev][imp.key] = [];
    });
  });

  incidents.forEach((inc) => {
    const sev = inc.severity || 'Medium';
    const imp = getImpactCategory(inc);
    if (matrix[sev] && matrix[sev][imp]) {
      matrix[sev][imp].push(inc);
    }
  });

  // Severity stats
  const criticalCount = incidents.filter(i => i.severity === 'Critical').length;
  const highCount = incidents.filter(i => i.severity === 'High').length;
  const medCount = incidents.filter(i => i.severity === 'Medium').length;
  const lowCount = incidents.filter(i => i.severity === 'Low').length;

  const getCellColor = (sev: string, count: number, isSelected: boolean) => {
    if (count === 0) return 'bg-slate-900/40 text-slate-600 border-slate-800/60 hover:bg-slate-800/40';
    
    if (sev === 'Critical') {
      return isSelected 
        ? 'bg-rose-500 text-white border-rose-400 ring-2 ring-rose-400 shadow-lg shadow-rose-500/30'
        : 'bg-rose-950/60 text-rose-300 border-rose-700/50 hover:bg-rose-900/80 hover:border-rose-500';
    }
    if (sev === 'High') {
      return isSelected
        ? 'bg-amber-500 text-slate-950 border-amber-400 ring-2 ring-amber-400 shadow-lg shadow-amber-500/30'
        : 'bg-amber-950/50 text-amber-300 border-amber-700/40 hover:bg-amber-900/70 hover:border-amber-500';
    }
    if (sev === 'Medium') {
      return isSelected
        ? 'bg-blue-600 text-white border-blue-400 ring-2 ring-blue-400 shadow-lg shadow-blue-500/30'
        : 'bg-blue-950/40 text-blue-300 border-blue-800/40 hover:bg-blue-900/60 hover:border-blue-500';
    }
    return isSelected
      ? 'bg-emerald-600 text-white border-emerald-400 ring-2 ring-emerald-400'
      : 'bg-emerald-950/30 text-emerald-300 border-emerald-800/30 hover:bg-emerald-900/50 hover:border-emerald-500';
  };

  return (
    <div className="bg-surface rounded-xl border border-border p-4 shadow-sm">
      {/* Header */}
      <div className="flex items-center justify-between pb-3 border-b border-border/80">
        <div className="flex items-center gap-2">
          <div className="p-1.5 rounded-lg bg-rose-500/10 text-rose-400 border border-rose-500/20">
            <Flame className="w-4 h-4" />
          </div>
          <div>
            <h3 className="text-xs font-bold uppercase tracking-wider text-slate-200">
              Risk Heat Map (Threat vs Impact)
            </h3>
            <p className="text-[11px] text-slate-400">Click any matrix cell to filter priority queue</p>
          </div>
        </div>

        {/* Quick Severity Badges */}
        <div className="flex items-center gap-1.5">
          <span className="text-[10px] px-2 py-0.5 rounded font-mono font-medium bg-rose-500/10 text-rose-400 border border-rose-500/30">
            {criticalCount} Critical
          </span>
          <span className="text-[10px] px-2 py-0.5 rounded font-mono font-medium bg-amber-500/10 text-amber-400 border border-amber-500/30">
            {highCount} High
          </span>
          <span className="text-[10px] px-2 py-0.5 rounded font-mono font-medium bg-blue-500/10 text-blue-400 border border-blue-500/30">
            {medCount} Med
          </span>
          <span className="text-[10px] px-2 py-0.5 rounded font-mono font-medium bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
            {lowCount} Low
          </span>

          {selectedFilter && (
            <button
              onClick={() => onSelectFilter(null)}
              className="ml-2 flex items-center gap-1 text-[11px] px-2 py-0.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 transition"
              title="Clear Heat Map Filter"
            >
              <X className="w-3 h-3" /> Clear Filter
            </button>
          )}
        </div>
      </div>

      {/* 2D Heat Grid */}
      <div className="mt-3 grid grid-cols-[80px_repeat(3,1fr)] gap-2 items-center text-xs">
        {/* Column Headers */}
        <div className="text-[10px] uppercase tracking-wider text-slate-500 font-semibold">Severity</div>
        {impactLevels.map((imp) => (
          <div key={imp.key} className="text-center text-[10px] uppercase tracking-wider text-slate-400 font-medium truncate">
            {imp.label}
          </div>
        ))}

        {/* Rows */}
        {severities.map((sev) => (
          <React.Fragment key={sev}>
            <div className="flex items-center gap-1.5 font-medium text-slate-300 text-[11px]">
              <span
                className={`w-2 h-2 rounded-full ${
                  sev === 'Critical'
                    ? 'bg-rose-500 ring-2 ring-rose-500/30'
                    : sev === 'High'
                    ? 'bg-amber-500'
                    : sev === 'Medium'
                    ? 'bg-blue-500'
                    : 'bg-emerald-500'
                }`}
              />
              {sev}
            </div>

            {impactLevels.map((imp) => {
              const cellKey = `${sev}:${imp.key}`;
              const count = matrix[sev][imp.key].length;
              const isSelected = selectedFilter === cellKey;

              return (
                <button
                  key={imp.key}
                  disabled={count === 0}
                  onClick={() => onSelectFilter(isSelected ? null : cellKey)}
                  className={`h-9 rounded-lg border flex items-center justify-between px-3 transition-all duration-150 ${getCellColor(
                    sev,
                    count,
                    isSelected
                  )} ${count === 0 ? 'cursor-default' : 'cursor-pointer'}`}
                >
                  <span className="text-[11px] font-medium opacity-80">{imp.key}</span>
                  <span className="font-mono font-bold text-xs">{count}</span>
                </button>
              );
            })}
          </React.Fragment>
        ))}
      </div>
    </div>
  );
};