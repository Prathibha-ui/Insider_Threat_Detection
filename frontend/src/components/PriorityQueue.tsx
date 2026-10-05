import React, { useState } from 'react';
import { 
  AlertOctagon, 
  GitMerge, 
  ShieldOff, 
  Eye, 
  Search, 
  Layers, 
  Server, 
  User, 
  ChevronRight,
  TrendingUp,
  ArrowUpDown
} from 'lucide-react';
import { Incident } from '../types';

interface Props {
  incidents: Incident[];
  selectedIncidentId: string | null;
  onSelectIncident: (id: string) => void;
  heatmapFilter: string | null;
}

export const PriorityQueue: React.FC<Props> = ({
  incidents,
  selectedIncidentId,
  onSelectIncident,
  heatmapFilter
}) => {
  const [searchQuery, setSearchQuery] = useState('');
  const [actionFilter, setActionFilter] = useState<string>('All');
  const [sortBy, setSortBy] = useState<'risk' | 'alerts' | 'recent'>('risk');

  // Filter incidents based on heat map, action filter, and search text
  const filteredIncidents = incidents.filter((inc) => {
    // Heatmap filter check: format "Severity:Impact"
    if (heatmapFilter) {
      const [sev, imp] = heatmapFilter.split(':');
      if (inc.severity !== sev) return false;
      const devices = inc.entity_summary?.devices || [];
      const accounts = inc.entity_summary?.accounts || [];
      let incImp = 'Perimeter-Noise';
      if (devices.length > 1 || accounts.length > 2) incImp = 'Multi-Host';
      else if (devices.length === 1 || accounts.length === 1) incImp = 'Single-Host';
      if (incImp !== imp) return false;
    }

    // Action filter
    if (actionFilter !== 'All' && inc.agent_action !== actionFilter) {
      return false;
    }

    // Search query
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      const matchId = inc.incident_id.toLowerCase().includes(q);
      const matchTitle = inc.title.toLowerCase().includes(q);
      const matchAccounts = (inc.entity_summary?.accounts || []).some(a => a.toLowerCase().includes(q));
      const matchDevices = (inc.entity_summary?.devices || []).some(d => d.toLowerCase().includes(q));
      if (!matchId && !matchTitle && !matchAccounts && !matchDevices) return false;
    }

    return true;
  });

  // Sort incidents
  const sortedIncidents = [...filteredIncidents].sort((a, b) => {
    if (sortBy === 'risk') return b.risk_score - a.risk_score;
    if (sortBy === 'alerts') return b.alert_count - a.alert_count;
    if (sortBy === 'recent') {
      const timeA = a.created_at ? new Date(a.created_at).getTime() : 0;
      const timeB = b.created_at ? new Date(b.created_at).getTime() : 0;
      return timeB - timeA;
    }
    return 0;
  });

  const getActionBadge = (action: string) => {
    switch (action) {
      case 'Escalate':
        return (
          <span className="flex items-center gap-1 text-[10px] font-bold px-2 py-0.5 rounded-full bg-rose-500/15 text-rose-400 border border-rose-500/30">
            <AlertOctagon className="w-3 h-3" /> ESCALATE
          </span>
        );
      case 'Group':
        return (
          <span className="flex items-center gap-1 text-[10px] font-bold px-2 py-0.5 rounded-full bg-blue-500/15 text-blue-400 border border-blue-500/30">
            <GitMerge className="w-3 h-3" /> GROUP
          </span>
        );
      case 'Suppress':
        return (
          <span className="flex items-center gap-1 text-[10px] font-bold px-2 py-0.5 rounded-full bg-slate-700/40 text-slate-400 border border-slate-700">
            <ShieldOff className="w-3 h-3" /> SUPPRESSED
          </span>
        );
      default:
        return (
          <span className="flex items-center gap-1 text-[10px] font-bold px-2 py-0.5 rounded-full bg-amber-500/15 text-amber-400 border border-amber-500/30">
            <Eye className="w-3 h-3" /> REVIEW
          </span>
        );
    }
  };

  const getRiskBarColor = (score: number) => {
    if (score >= 80) return 'bg-rose-500 shadow-sm shadow-rose-500/50';
    if (score >= 60) return 'bg-amber-500 shadow-sm shadow-amber-500/50';
    if (score >= 40) return 'bg-blue-500';
    return 'bg-emerald-500';
  };

  return (
    <div className="flex flex-col h-full bg-surface rounded-xl border border-border shadow-sm overflow-hidden">
      {/* Header & Controls */}
      <div className="p-3.5 border-b border-border space-y-2.5">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <TrendingUp className="w-4 h-4 text-blue-400" />
            <h2 className="text-xs font-bold uppercase tracking-wider text-slate-200">
              Analyst Priority Queue ({sortedIncidents.length})
            </h2>
          </div>

          {/* Sort Selector */}
          <div className="flex items-center gap-1 text-[11px] text-slate-400">
            <ArrowUpDown className="w-3 h-3" />
            <select
              value={sortBy}
              onChange={(e) => setSortBy(e.target.value as any)}
              className="bg-slate-900 border border-border rounded px-1.5 py-0.5 text-slate-300 focus:outline-none focus:border-blue-500 text-[11px]"
            >
              <option value="risk">Risk Score</option>
              <option value="alerts">Alert Count</option>
              <option value="recent">Recent</option>
            </select>
          </div>
        </div>

        {/* Search */}
        <div className="relative">
          <Search className="w-3.5 h-3.5 absolute left-2.5 top-2.5 text-slate-500" />
          <input
            type="text"
            placeholder="Search by ID, title, host, user..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full pl-8 pr-3 py-1.5 bg-slate-900/90 border border-border rounded-lg text-xs text-slate-200 placeholder:text-slate-500 focus:outline-none focus:border-blue-500 transition"
          />
        </div>

        {/* Filter Tabs */}
        <div className="flex items-center gap-1 overflow-x-auto pb-1 text-xs">
          {['All', 'Escalate', 'Group', 'Request Review', 'Suppress'].map((f) => (
            <button
              key={f}
              onClick={() => setActionFilter(f)}
              className={`px-2.5 py-1 rounded-md text-[11px] font-medium transition whitespace-nowrap ${
                actionFilter === f
                  ? 'bg-blue-600 text-white shadow-sm shadow-blue-500/30'
                  : 'bg-slate-900 text-slate-400 hover:text-slate-200 hover:bg-slate-800'
              }`}
            >
              {f}
            </button>
          ))}
        </div>
      </div>

      {/* Incident List */}
      <div className="flex-1 overflow-y-auto divide-y divide-border/60 p-1.5 space-y-1">
        {sortedIncidents.length === 0 ? (
          <div className="text-center py-12 text-slate-500 text-xs">
            No incidents match your current search or filter.
          </div>
        ) : (
          sortedIncidents.map((inc) => {
            const isSelected = selectedIncidentId === inc.incident_id;
            const accounts = inc.entity_summary?.accounts || [];
            const devices = inc.entity_summary?.devices || [];

            return (
              <div
                key={inc.incident_id}
                onClick={() => onSelectIncident(inc.incident_id)}
                className={`p-3 rounded-lg cursor-pointer transition-all duration-150 relative border ${
                  isSelected
                    ? 'bg-slate-800/90 border-blue-500/80 shadow-md shadow-blue-500/10 ring-1 ring-blue-500/50'
                    : 'bg-surface hover:bg-slate-800/40 border-transparent hover:border-border'
                }`}
              >
                {/* Top bar: ID, Alert Count, Action Badge */}
                <div className="flex items-center justify-between gap-2">
                  <div className="flex items-center gap-1.5">
                    <span className="font-mono text-xs font-bold text-slate-200">
                      {inc.incident_id}
                    </span>
                    <span className="flex items-center gap-0.5 text-[10px] font-mono px-1.5 py-0.5 rounded bg-slate-900 text-slate-400 border border-slate-800">
                      <Layers className="w-2.5 h-2.5" /> {inc.alert_count} alerts
                    </span>
                  </div>
                  {getActionBadge(inc.agent_action)}
                </div>

                {/* Title */}
                <h4 className="mt-1.5 text-xs font-semibold text-slate-100 line-clamp-1">
                  {inc.title}
                </h4>

                {/* Risk Score Meter */}
                <div className="mt-2 flex items-center gap-2">
                  <span className="text-[11px] font-mono font-bold text-slate-300 w-9">
                    {inc.risk_score.toFixed(0)}
                    <span className="text-[9px] text-slate-500">/100</span>
                  </span>
                  <div className="flex-1 h-1.5 bg-slate-900 rounded-full overflow-hidden">
                    <div
                      className={`h-full rounded-full transition-all duration-300 ${getRiskBarColor(inc.risk_score)}`}
                      style={{ width: `${Math.min(100, Math.max(5, inc.risk_score))}%` }}
                    />
                  </div>
                  <span className="text-[10px] uppercase font-bold text-slate-400">
                    {inc.severity}
                  </span>
                </div>

                {/* Affected Entities */}
                <div className="mt-2.5 flex items-center gap-2 text-[10px] text-slate-400 overflow-hidden truncate">
                  {devices.length > 0 && (
                    <span className="flex items-center gap-1 truncate bg-slate-900/60 px-1.5 py-0.5 rounded border border-slate-800/60">
                      <Server className="w-2.5 h-2.5 text-indigo-400" />
                      {devices[0]} {devices.length > 1 ? `+${devices.length - 1}` : ''}
                    </span>
                  )}
                  {accounts.length > 0 && (
                    <span className="flex items-center gap-1 truncate bg-slate-900/60 px-1.5 py-0.5 rounded border border-slate-800/60">
                      <User className="w-2.5 h-2.5 text-blue-400" />
                      {accounts[0].split('\\').pop()}
                    </span>
                  )}
                </div>
              </div>
            );
          })
        )}
      </div>
    </div>
  );
};