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
  TrendingDown,
  Clock,
  Usb,
  HardDriveDownload,
  KeyRound,
  ShieldAlert,
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
  const [tierFilter, setTierFilter] = useState<'All' | 'HighRisk' | 'MediumRisk' | 'LowRisk'>('All');
  const [actionFilter, setActionFilter] = useState<string>('All');

  // Filter alerts / incidents
  const filteredIncidents = incidents.filter((inc) => {
    // 1. Heatmap Filter (from Risk Heatmap click)
    const activeTier = heatmapFilter || (tierFilter !== 'All' ? tierFilter : null);
    if (activeTier === 'HighRisk' && inc.risk_score < 70.0) return false;
    if (activeTier === 'MediumRisk' && (inc.risk_score < 40.0 || inc.risk_score >= 70.0)) return false;
    if (activeTier === 'LowRisk' && inc.risk_score >= 40.0) return false;

    // 2. Action filter
    if (actionFilter !== 'All' && inc.agent_action !== actionFilter) {
      return false;
    }

    // 3. Search query
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

  // Always arrange from HIGHEST to LOWEST risk score as specified
  const sortedIncidents = [...filteredIncidents].sort((a, b) => b.risk_score - a.risk_score);

  const getRiskPill = (score: number) => {
    if (score >= 70.0) {
      return (
        <span className="flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-mono font-bold bg-rose-500/20 text-rose-300 border border-rose-500/40">
          <span className="w-1.5 h-1.5 rounded-full bg-rose-400 animate-pulse" />
          {score.toFixed(1)} HIGH
        </span>
      );
    }
    if (score >= 40.0) {
      return (
        <span className="flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-mono font-bold bg-amber-500/20 text-amber-300 border border-amber-500/40">
          <span className="w-1.5 h-1.5 rounded-full bg-amber-400" />
          {score.toFixed(1)} MED
        </span>
      );
    }
    return (
      <span className="flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-mono font-bold bg-yellow-500/20 text-yellow-300 border border-yellow-500/40">
        <span className="w-1.5 h-1.5 rounded-full bg-yellow-400" />
        {score.toFixed(1)} LOW
      </span>
    );
  };

  const getThreatIcon = (title: string) => {
    const t = title.toLowerCase();
    if (t.includes('usb') || t.includes('removable')) {
      return <Usb className="w-4 h-4 text-rose-400" />;
    }
    if (t.includes('bulk') || t.includes('transfer') || t.includes('exfiltration')) {
      return <HardDriveDownload className="w-4 h-4 text-rose-400" />;
    }
    if (t.includes('login') || t.includes('logon') || t.includes('credential') || t.includes('off-hours')) {
      return <KeyRound className="w-4 h-4 text-amber-400" />;
    }
    return <ShieldAlert className="w-4 h-4 text-blue-400" />;
  };

  const formatTiming = (isoString: string | null) => {
    if (!isoString) return 'Just now';
    try {
      const d = new Date(isoString);
      return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) + ' ' + d.toLocaleDateString([], { month: 'short', day: 'numeric' });
    } catch {
      return 'Recent';
    }
  };

  return (
    <div className="bg-surface rounded-xl border border-border h-full flex flex-col overflow-hidden shadow-sm">
      {/* Header Bar */}
      <div className="p-3.5 border-b border-border/80 space-y-2.5 bg-slate-900/60">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <TrendingDown className="w-4 h-4 text-rose-400" />
            <h2 className="text-xs font-extrabold uppercase tracking-wider text-slate-100">
              6. Security Alert List (Ranked Highest &rarr; Lowest Risk)
            </h2>
          </div>
          <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-blue-500/15 text-blue-300 border border-blue-500/30">
            {sortedIncidents.length} of {incidents.length} Alerts
          </span>
        </div>

        {/* Search Input */}
        <div className="relative">
          <Search className="w-3.5 h-3.5 absolute left-2.5 top-1/2 -translate-y-1/2 text-slate-400" />
          <input
            type="text"
            placeholder="Search by threat title, device, or user..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full bg-slate-950 border border-border rounded-lg pl-8 pr-3 py-1.5 text-xs text-slate-100 placeholder-slate-500 focus:outline-none focus:border-blue-500"
          />
        </div>

        {/* Risk Level Tiers & Filters */}
        <div className="flex flex-wrap items-center justify-between gap-1.5 text-[11px]">
          <div className="flex items-center gap-1 bg-slate-950/80 rounded-lg p-0.5 border border-border">
            <button
              onClick={() => setTierFilter('All')}
              className={`px-2 py-0.5 rounded font-medium transition ${
                tierFilter === 'All' && !heatmapFilter ? 'bg-blue-600 text-white' : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              All
            </button>
            <button
              onClick={() => setTierFilter('HighRisk')}
              className={`px-2 py-0.5 rounded font-medium transition ${
                (tierFilter === 'HighRisk' || heatmapFilter === 'HighRisk') ? 'bg-rose-600 text-white font-bold' : 'text-rose-400 hover:text-rose-200'
              }`}
            >
              🔴 High Risk (&gt;70)
            </button>
            <button
              onClick={() => setTierFilter('MediumRisk')}
              className={`px-2 py-0.5 rounded font-medium transition ${
                (tierFilter === 'MediumRisk' || heatmapFilter === 'MediumRisk') ? 'bg-amber-600 text-white font-bold' : 'text-amber-400 hover:text-amber-200'
              }`}
            >
              🟠 Med (40-70)
            </button>
            <button
              onClick={() => setTierFilter('LowRisk')}
              className={`px-2 py-0.5 rounded font-medium transition ${
                (tierFilter === 'LowRisk' || heatmapFilter === 'LowRisk') ? 'bg-yellow-600 text-white font-bold' : 'text-yellow-400 hover:text-yellow-200'
              }`}
            >
              🟡 Low (&lt;40)
            </button>
          </div>

          <span className="text-[10px] text-slate-400 italic">
            Top threats investigated first
          </span>
        </div>
      </div>

      {/* Ranked Alerts List Body */}
      <div className="flex-1 overflow-y-auto divide-y divide-border/60">
        {sortedIncidents.length === 0 ? (
          <div className="py-12 text-center text-slate-500 text-xs">
            No alerts match the active risk filter.
          </div>
        ) : (
          sortedIncidents.map((inc) => {
            const isSelected = inc.incident_id === selectedIncidentId;
            const devices = inc.entity_summary?.devices || [];
            const accounts = inc.entity_summary?.accounts || [];

            return (
              <div
                key={inc.incident_id}
                onClick={() => onSelectIncident(inc.incident_id)}
                className={`p-3 cursor-pointer transition-all duration-150 flex items-start gap-3 relative ${
                  isSelected
                    ? 'bg-blue-950/40 border-l-4 border-l-blue-500'
                    : 'hover:bg-slate-800/30'
                }`}
              >
                {/* Threat Icon */}
                <div className="mt-0.5 p-1.5 rounded-lg bg-slate-900 border border-border shrink-0">
                  {getThreatIcon(inc.title)}
                </div>

                {/* Main Content */}
                <div className="flex-1 min-w-0 space-y-1">
                  <div className="flex items-center justify-between gap-2">
                    <span className="font-semibold text-xs text-slate-100 truncate">
                      {inc.title}
                    </span>
                    {getRiskPill(inc.risk_score)}
                  </div>

                  {/* Device and User Details */}
                  <div className="flex flex-wrap items-center gap-2 text-[11px] text-slate-400">
                    <span className="flex items-center gap-1 font-mono text-slate-300">
                      <Server className="w-3 h-3 text-blue-400" />
                      {devices[0] || 'DEV-FLEET'}
                    </span>
                    <span>•</span>
                    <span className="flex items-center gap-1 font-mono text-slate-400 truncate max-w-[120px]">
                      <User className="w-3 h-3 text-purple-400" />
                      {accounts[0] || 'system'}
                    </span>
                    <span>•</span>
                    <span className="flex items-center gap-1 text-[10px] text-slate-500">
                      <Clock className="w-3 h-3" />
                      {formatTiming(inc.created_at)}
                    </span>
                  </div>

                  {/* Incident Summary snippet */}
                  <p className="text-[11px] text-slate-400 line-clamp-1">
                    {inc.summary || 'Correlated security threat under autonomous investigation.'}
                  </p>
                </div>

                <ChevronRight className={`w-4 h-4 shrink-0 mt-2 transition ${isSelected ? 'text-blue-400' : 'text-slate-600'}`} />
              </div>
            );
          })
        )}
      </div>
    </div>
  );
};
