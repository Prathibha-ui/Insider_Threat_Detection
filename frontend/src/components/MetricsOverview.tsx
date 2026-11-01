import React from 'react';
import { Server, Activity, AlertTriangle, Flame, ShieldCheck, ArrowRight } from 'lucide-react';
import { Metrics } from '../types';

interface Props {
  metrics: Metrics | null;
  loading: boolean;
  onOpenDeviceManager?: () => void;
}

export const MetricsOverview: React.FC<Props> = ({ metrics, loading, onOpenDeviceManager }) => {
  if (loading || !metrics) {
    return (
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-3.5 animate-pulse">
        {[1, 2, 3, 4, 5].map((i) => (
          <div key={i} className="h-28 bg-surface rounded-xl border border-border"></div>
        ))}
      </div>
    );
  }

  const cards = [
    {
      id: 'total_endpoints',
      title: '1. Total Endpoints',
      value: (metrics.total_endpoints ?? 0).toLocaleString(),
      subtext: 'Registered devices in system',
      icon: Server,
      color: 'text-blue-400',
      bgGlow: 'bg-blue-500/10',
      border: 'border-blue-500/30',
      badge: 'Endpoint Fleet',
      badgeColor: 'bg-blue-500/15 text-blue-300 border-blue-500/30',
      clickable: true
    },
    {
      id: 'online_endpoints',
      title: '2. Online Endpoints',
      value: `${metrics.online_endpoints ?? 0}`,
      subtext: 'Reporting active telemetry data',
      icon: Activity,
      color: 'text-emerald-400',
      bgGlow: 'bg-emerald-500/10',
      border: 'border-emerald-500/30',
      badge: `${Math.round(((metrics.online_endpoints ?? 0) / Math.max(metrics.total_endpoints ?? 1, 1)) * 100)}% Online`,
      badgeColor: 'bg-emerald-500/15 text-emerald-300 border-emerald-500/30',
      clickable: true
    },
    {
      id: 'high_risk_devices',
      title: '3. High-Risk Devices',
      value: `${metrics.high_risk_devices ?? 0}`,
      subtext: 'Devices having risk score > 70',
      icon: AlertTriangle,
      color: 'text-rose-400',
      bgGlow: 'bg-rose-500/10',
      border: (metrics.high_risk_devices ?? 0) > 0 ? 'border-rose-500/50 shadow-rose-500/5' : 'border-slate-800',
      badge: (metrics.high_risk_devices ?? 0) > 0 ? 'Requires Isolation' : 'Safe Fleet',
      badgeColor: (metrics.high_risk_devices ?? 0) > 0 ? 'bg-rose-500/20 text-rose-300 border-rose-500/40 animate-pulse' : 'bg-slate-800 text-slate-400 border-slate-700',
      clickable: true
    },
    {
      id: 'active_incidents',
      title: '4. Active Incidents',
      value: (metrics.active_incidents ?? 0).toLocaleString(),
      subtext: 'Active threats detected in system',
      icon: Flame,
      color: 'text-amber-400',
      bgGlow: 'bg-amber-500/10',
      border: 'border-amber-500/30',
      badge: `${metrics.escalated_count ?? 0} Escalated`,
      badgeColor: 'bg-amber-500/15 text-amber-300 border-amber-500/30'
    },
    {
      id: 'noise_reduction',
      title: 'Autonomous Noise Filter',
      value: `${metrics.noise_reduction_pct ?? 0}%`,
      subtext: `${metrics.suppressed_count ?? 0} Benign alerts suppressed`,
      icon: ShieldCheck,
      color: 'text-indigo-400',
      bgGlow: 'bg-indigo-500/10',
      border: 'border-indigo-500/30',
      badge: 'Zero Analyst Fatigue',
      badgeColor: 'bg-indigo-500/15 text-indigo-300 border-indigo-500/30'
    }
  ];

  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-3.5">
      {cards.map((card) => {
        const Icon = card.icon;
        return (
          <div
            key={card.id}
            onClick={card.clickable && onOpenDeviceManager ? onOpenDeviceManager : undefined}
            className={`relative overflow-hidden rounded-xl bg-surface border ${card.border} p-4 transition-all duration-200 hover:border-slate-600 hover:shadow-lg ${
              card.clickable ? 'cursor-pointer group' : ''
            }`}
          >
            <div className="flex items-center justify-between">
              <span className="text-xs font-semibold uppercase tracking-wider text-slate-300">
                {card.title}
              </span>
              <div className={`p-2 rounded-lg ${card.bgGlow} ${card.color}`}>
                <Icon className="w-4 h-4" />
              </div>
            </div>

            <div className="mt-2 flex items-baseline gap-2">
              <span className="text-2xl font-black tracking-tight font-mono text-slate-100">
                {card.value}
              </span>
              {card.badge && (
                <span className={`text-[10px] font-bold px-2 py-0.5 rounded-full border ${card.badgeColor}`}>
                  {card.badge}
                </span>
              )}
            </div>

            <div className="mt-1 flex items-center justify-between text-[11px] text-slate-400">
              <span className="truncate">{card.subtext}</span>
              {card.clickable && (
                <ArrowRight className="w-3 h-3 text-slate-500 group-hover:text-blue-400 transition transform group-hover:translate-x-0.5" />
              )}
            </div>
          </div>
        );
      })}
    </div>
  );
};
