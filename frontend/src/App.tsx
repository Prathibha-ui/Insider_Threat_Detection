import React, { useState, useEffect } from 'react';
import { 
  ShieldAlert, 
  BrainCircuit, 
  Server,
  Sparkles
} from 'lucide-react';

import { MetricsOverview } from './components/MetricsOverview';
import { RiskHeatmap } from './components/RiskHeatmap';
import { PriorityQueue } from './components/PriorityQueue';
import { IncidentDetail } from './components/IncidentDetail';
import { EndpointDeviceModal } from './components/EndpointDeviceModal';
import { Incident, Metrics, IncidentDetailResponse } from './types';

const API_BASE = 'http://127.0.0.1:8000';

export function App() {
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [metrics, setMetrics] = useState<Metrics | null>(null);
  const [selectedIncidentId, setSelectedIncidentId] = useState<string | null>(null);
  const [incidentDetail, setIncidentDetail] = useState<IncidentDetailResponse | null>(null);
  const [heatmapFilter, setHeatmapFilter] = useState<string | null>(null);
  const [isDeviceModalOpen, setIsDeviceModalOpen] = useState<boolean>(false);
  const [demoBanner, setDemoBanner] = useState<string | null>(null);

  const [loading, setLoading] = useState<boolean>(true);
  const [loadingDetail, setLoadingDetail] = useState<boolean>(false);
  const [actionLoading, setActionLoading] = useState<string | null>(null);

  // Fetch all core data
  const fetchData = async () => {
    try {
      setLoading(true);
      const [incRes, metRes] = await Promise.all([
        fetch(`${API_BASE}/api/incidents`),
        fetch(`${API_BASE}/api/metrics`)
      ]);
      const incJson = await incRes.json();
      const metJson = await metRes.json();

      const incs = incJson.incidents || [];
      setIncidents(incs);
      setMetrics(metJson);

      // Auto-select first incident if current selected doesn't exist
      if (incs.length > 0) {
        setSelectedIncidentId((prev) => {
          if (prev && incs.some((i: Incident) => i.incident_id === prev)) {
            return prev;
          }
          return incs[0].incident_id;
        });
      } else {
        setSelectedIncidentId(null);
        setIncidentDetail(null);
      }
    } catch (err) {
      console.error('Failed to load SOCPilot data:', err);
    } finally {
      setLoading(false);
    }
  };

  // Fetch incident detail
  const fetchIncidentDetail = async (id: string) => {
    try {
      setLoadingDetail(true);
      const res = await fetch(`${API_BASE}/api/incidents/${id}`);
      if (res.ok) {
        const json = await res.json();
        setIncidentDetail(json);
      }
    } catch (err) {
      console.error(`Failed to fetch incident ${id}:`, err);
    } finally {
      setLoadingDetail(false);
    }
  };

  useEffect(() => {
    fetchData();
  }, []);

  useEffect(() => {
    if (selectedIncidentId) {
      fetchIncidentDetail(selectedIncidentId);
    } else {
      setIncidentDetail(null);
    }
  }, [selectedIncidentId]);

  // Actions

  const handleRunAgent = async () => {
    setActionLoading('agent');
    try {
      await fetch(`${API_BASE}/api/run-agent`, { method: 'POST' });
      await fetchData();
      if (selectedIncidentId) await fetchIncidentDetail(selectedIncidentId);
    } finally {
      setActionLoading(null);
    }
  };

  const handleRunDemo = async () => {
    setActionLoading('demo');
    try {
      const res = await fetch(`${API_BASE}/api/run-random-demo`, { method: 'POST' });
      if (res.ok) {
        const data = await res.json();
        await fetchData();
        if (data.incident_id) {
          setSelectedIncidentId(data.incident_id);
          await fetchIncidentDetail(data.incident_id);
        }
        setDemoBanner(data.message || `Demo executed on ${data.device_id}: ${data.threat_title}`);
        setTimeout(() => setDemoBanner(null), 9000);
      }
    } catch (err) {
      console.error('Failed to run demo:', err);
    } finally {
      setActionLoading(null);
    }
  };


  const handleFeedbackSubmit = async (
    incidentId: string,
    action: string,
    newGrade?: string,
    comments?: string
  ) => {
    try {
      await fetch(`${API_BASE}/api/feedback`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          incident_id: incidentId,
          action,
          new_grade: newGrade,
          comments
        })
      });
      await fetchData();
      await fetchIncidentDetail(incidentId);
    } catch (err) {
      console.error('Failed to submit analyst feedback:', err);
    }
  };

  return (
    <div className="min-h-screen bg-[#090d16] text-slate-100 flex flex-col selection:bg-blue-500/30">
      {/* Top Cyber Navigation Bar */}
      <header className="border-b border-border/80 bg-surface/90 backdrop-blur sticky top-0 z-50 px-4 py-3">
        <div className="max-w-[1720px] mx-auto flex flex-wrap items-center justify-between gap-3">
          {/* Logo & Subtitle */}
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-xl bg-blue-600/20 text-blue-400 border border-blue-500/30 shadow-lg shadow-blue-500/10">
              <ShieldAlert className="w-6 h-6 text-blue-400" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h1 className="text-base font-extrabold tracking-tight bg-gradient-to-r from-blue-400 via-indigo-200 to-slate-100 bg-clip-text text-transparent">
                  Insider Threat Detector
                </h1>
                <span className="text-[10px] font-mono font-bold px-2 py-0.5 rounded-full bg-emerald-500/15 text-emerald-400 border border-emerald-500/30 flex items-center gap-1.5">
                  <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" /> AGENT ACTIVE
                </span>
              </div>
              <p className="text-[11px] text-slate-400">
                Autonomous Security Alert Investigation Agent • Microsoft GUIDE Benchmark
              </p>
            </div>
          </div>

          {/* Quick Action Controls */}
          <div className="flex items-center gap-2 flex-wrap">
                        {/* Feature 1: Manage Endpoint Devices Button */}
            <button
              onClick={() => setIsDeviceModalOpen(true)}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-indigo-950/60 hover:bg-indigo-900/80 text-indigo-200 text-xs font-semibold border border-indigo-700/50 shadow-sm transition"
              title="Register and Manage Endpoint Devices"
            >
              <Server className="w-3.5 h-3.5 text-indigo-400" />
              Manage Endpoints ({metrics?.total_endpoints ?? 0})
            </button>

            {/* Pipeline / Agent Run Buttons */}

            <button
              disabled={actionLoading !== null}
              onClick={handleRunAgent}
              className="flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg bg-blue-600 hover:bg-blue-500 text-white text-xs font-bold shadow-md shadow-blue-600/20 transition"
              title="Run LangGraph Autonomous Investigation Loop"
            >
              <BrainCircuit className={`w-3.5 h-3.5 ${actionLoading === 'agent' ? 'animate-spin' : ''}`} />
              Execute Agent
            </button>

            {/* Run Demo Button */}
            <button
              disabled={actionLoading !== null}
              onClick={handleRunDemo}
              className="flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg bg-gradient-to-r from-purple-600 to-indigo-600 hover:from-purple-500 hover:to-indigo-500 text-white text-xs font-bold shadow-lg shadow-purple-900/30 transition border border-purple-400/30"
              title="Select a random device, simulate an insider threat, and produce all outputs"
            >
              <Sparkles className={`w-3.5 h-3.5 ${actionLoading === 'demo' ? 'animate-spin' : ''}`} />
              Run Demo
            </button>

          </div>
        </div>
      </header>

      {/* Main Content Body */}
      <main className="flex-1 max-w-[1720px] w-full mx-auto p-4 space-y-4">
        {/* Run Demo Notification Banner */}
        {demoBanner && (
          <div className="bg-gradient-to-r from-purple-950/80 via-indigo-950/80 to-slate-900 border border-purple-500/40 rounded-xl p-3 flex items-center justify-between text-xs text-purple-200 shadow-lg shadow-purple-950/40">
            <div className="flex items-center gap-2.5">
              <span className="p-1.5 rounded-lg bg-purple-600/30 text-purple-300 border border-purple-400/40">
                <Sparkles className="w-4 h-4 text-purple-300" />
              </span>
              <div>
                <span className="font-bold text-white uppercase tracking-wider text-[11px] mr-2">Demo Triggered:</span>
                <span>{demoBanner}</span>
              </div>
            </div>
            <button 
              onClick={() => setDemoBanner(null)} 
              className="text-purple-400 hover:text-white px-2 py-0.5 text-xs font-semibold rounded bg-purple-900/40 transition"
            >
              Dismiss
            </button>
          </div>
        )}

        {/* Executive Metrics Overview Bar */}
        <MetricsOverview metrics={metrics} loading={loading} onOpenDeviceManager={() => setIsDeviceModalOpen(true)} />

        <div className="space-y-4">

            {/* Small Risk Heat Map (Specifically requested!) */}
            <RiskHeatmap
              incidents={incidents}
              selectedFilter={heatmapFilter}
              onSelectFilter={setHeatmapFilter}
            />

            {/* Split Grid: Priority Queue (Left) & Incident Deep Dive (Right) */}
            <div className="grid grid-cols-1 lg:grid-cols-12 gap-4 h-[calc(100vh-310px)] min-h-[580px]">
              {/* Left Column: Priority Queue (4 cols / ~33%) */}
              <div className="lg:col-span-5 xl:col-span-4 h-full">
                <PriorityQueue
                  incidents={incidents}
                  selectedIncidentId={selectedIncidentId}
                  onSelectIncident={setSelectedIncidentId}
                  heatmapFilter={heatmapFilter}
                />
              </div>

              {/* Right Column: Incident Investigation Detail (8 cols / ~66%) */}
              <div className="lg:col-span-7 xl:col-span-8 h-full">
                <IncidentDetail
                  data={incidentDetail}
                  loading={loadingDetail}
                  onFeedbackSubmit={handleFeedbackSubmit}
                />
              </div>
            </div>
          </div>
      </main>
      {/* Feature 1: Register & Manage Endpoint Devices Modal */}
      <EndpointDeviceModal
        isOpen={isDeviceModalOpen}
        onClose={() => setIsDeviceModalOpen(false)}
        onDeviceUpdated={fetchData}
      />
    </div>
  );
}

export default App;