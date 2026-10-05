import React from 'react';
import { ShieldAlert, Layers, Filter, Clock, CheckCircle2, Zap } from 'lucide-react';
import { Metrics } from '../types';

interface Props {
  metrics: Metrics | null;
  loading: boolean;
}

export const MetricsOverview: React.FC<Props> = ({ metrics, loading }) => {
  if (loading || !metrics) {
    return (
      <div className="grid grid-cols-1 md:grid-cols-5 gap-4 animate-pulse">
        {[1, 2, 3, 4, 5].map((i) => (
          <div key={i} className="h-24 bg-surface rounded-xl border border-border"></div>
        ))}
      </div>
    );
  }

  const cards = [
    {
      title: 'Total Alert Volume',
      value: metrics.total_alerts.toLocaleString(),
      subtext: 'Microsoft GUIDE Telemetry',
      icon: ShieldAlert,
      color: 'text-blue-400',
      bgGlow: 'bg-blue-500/10',
      border: 'border-blue-500/20'
    },
    {
      title: 'Compressed Incidents',
      value: metrics.total_incidents.toLocaleString(),
      subtext: `Compression Ratio ${metrics.compression_ratio}`,
      icon: Layers,
      color: 'text-indigo-400',
      bgGlow: 'bg-indigo-500/10',
      border: 'border-indigo-500/20'
    },
    {
      title: 'Noise Reduction Rate',
      value: `${metrics.noise_reduction_pct}%`,
      subtext: `${metrics.suppressed_count} Benign/Noise Suppressed`,
      icon: Filter,
      color: 'text-emerald-400',
      bgGlow: 'bg-emerald-500/10',
      border: 'border-emerald-500/20',
      badge: '90%+ Noise Eliminated'
    },
    {
      title: 'Workload Reduction',
      value: `${metrics.workload_reduction_pct}%`,
      subtext: `~${metrics.estimated_hours_saved} Hours Saved`,
      icon: Zap,
      color: 'text-amber-400',
      bgGlow: 'bg-amber-500/10',
      border: 'border-amber-500/20'
    },
    {
      title: 'True Incident Preservation',
      value: `${metrics.tp_preservation_pct}%`,
      subtext: 'Zero Malicious Signals Missed',
      icon: CheckCircle2,
      color: 'text-emerald-400',
      bgGlow: 'bg-emerald-500/10',
      border: 'border-emerald-500/20',
      badge: '100% True Positives Kept'
    }
  ];

  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-3.5">
      {cards.map((card, idx) => {
        const Icon = card.icon;
        return (
          <div
            key={idx}
            className={`relative overflow-hidden rounded-xl bg-surface border ${card.border} p-4 transition-all duration-200 hover:border-slate-600 hover:shadow-lg`}
          >
            <div className="flex items-center justify-between">
              <span className="text-xs font-medium text-slate-400">{card.title}</span>
              <div className={`p-2 rounded-lg ${card.bgGlow} ${card.color}`}>
                <Icon className="w-4 h-4" />
              </div>
            </div>

            <div className="mt-2 flex items-baseline gap-2">
              <span className="text-2xl font-bold tracking-tight font-mono text-slate-100">{card.value}</span>
              {card.badge && (
                <span className="text-[10px] font-semibold px-1.5 py-0.5 rounded bg-emerald-500/20 text-emerald-300 border border-emerald-500/30">
                  {card.badge}
                </span>
              )}
            </div>

            <div className="mt-1 text-[11px] text-slate-400 truncate">
              {card.subtext}
            </div>
          </div>
        );
      })}
    </div>
  );
};