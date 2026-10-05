import React, { useState, useEffect } from 'react';
import { 
  ShieldAlert, 
  BrainCircuit, 
  RefreshCw, 
  Play, 
  Database, 
  SlidersHorizontal, 
  Sparkles,
  Layers,
  Columns
} from 'lucide-react';

import { MetricsOverview } from './components/MetricsOverview';
import { RiskHeatmap } from './components/RiskHeatmap';
import { PriorityQueue } from './components/PriorityQueue';
import { IncidentDetail } from './components/IncidentDetail';
import { ComparisonView } from './components/ComparisonView';
import { DemoAlertPanel, DemoAlertInput, DemoAlertResult } from './components/DemoAlertPanel';
import { Incident, Metrics, IncidentDetailResponse, ComparisonData } from './types';

const API_BASE = 'http://127.0.0.1:8000';

export function App() {
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [metrics, setMetrics] = useState<Metrics | null>(null);
  const [selectedIncidentId, setSelectedIncidentId] = useState<string | null>(null);
  const [incidentDetail, setIncidentDetail] = useState<IncidentDetailResponse | null>(null);
  const [heatmapFilter, setHeatmapFilter] = useState<string | null>(null);
  const [viewMode, setViewMode] = useState<'console' | 'comparison'>('console');
  const [comparisonData, setComparisonData] = useState<ComparisonData | null>(null);

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

      setIncidents(incJson.incidents || []);
      setMetrics(metJson);

      // Auto-select first critical/high incident if none selected
      if (incJson.incidents && incJson.incidents.length > 0) {
        const topInc = incJson.incidents[0];
        setSelectedIncidentId((prev) => prev || topInc.incident_id);
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

  // Fetch comparison data
  const fetchComparison = async () => {
    try {
      const res = await fetch(`${API_BASE}/api/comparison`);
      if (res.ok) {
        const json = await res.json();
        setComparisonData(json);
      }
    } catch (err) {
      console.error('Failed to fetch comparison:', err);
    }
  };

  useEffect(() => {
    fetchData();
  }, []);

  useEffect(() => {
    if (selectedIncidentId) {
      fetchIncidentDetail(selectedIncidentId);
    }
  }, [selectedIncidentId]);

  useEffect(() => {
    if (viewMode === 'comparison') {
      fetchComparison();
    }
  }, [viewMode]);

  // Actions
  const handleRunPipeline = async () => {
    setActionLoading('pipeline');
    try {
      await fetch(`${API_BASE}/api/process-pipeline`, { method: 'POST' });
      await fetchData();
      if (selectedIncidentId) await fetchIncidentDetail(selectedIncidentId);
    } finally {
      setActionLoading(null);
    }
  };

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

  const handleReloadDataset = async () => {
    setActionLoading('dataset');
    try {
      await fetch(`${API_BASE}/api/load-guide-dataset`, { method: 'POST' });
      await fetch(`${API_BASE}/api/process-pipeline`, { method: 'POST' });
      await fetch(`${API_BASE}/api/run-agent`, { method: 'POST' });
      await fetchData();
      if (selectedIncidentId) await fetchIncidentDetail(selectedIncidentId);
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

  const handleRunDemoAlert = async (payload: DemoAlertInput): Promise<DemoAlertResult | null> => {
    try {
      const res = await fetch(`${API_BASE}/api/demo-live-alert`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });

      if (!res.ok) {
        console.error('Live demo request failed');
        return null;
      }

      const json = await res.json();
      return json;
    } catch (err) {
      console.error('Error running live demo:', err);
      return null;
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
            {/* View Switcher */}
            <div className="flex items-center bg-slate-900 rounded-lg p-1 border border-border text-xs mr-2">
              <button
                onClick={() => setViewMode('console')}
                className={`flex items-center gap-1.5 px-3 py-1 rounded-md transition font-medium ${
                  viewMode === 'console'
                    ? 'bg-blue-600 text-white shadow-sm'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                <Layers className="w-3.5 h-3.5" /> Threat Console
              </button>
              <button
                onClick={() => setViewMode('comparison')}
                className={`flex items-center gap-1.5 px-3 py-1 rounded-md transition font-medium ${
                  viewMode === 'comparison'
                    ? 'bg-blue-600 text-white shadow-sm'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                <Columns className="w-3.5 h-3.5" /> Triage Comparison
              </button>
            </div>

            {/* Pipeline / Agent Run Buttons */}
            <button
              disabled={actionLoading !== null}
              onClick={handleRunPipeline}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-semibold border border-slate-700 transition"
              title="Re-run 6-Model ML Pipeline"
            >
              <SlidersHorizontal className={`w-3.5 h-3.5 ${actionLoading === 'pipeline' ? 'animate-spin text-blue-400' : ''}`} />
              Run ML Pipeline
            </button>

            <button
              disabled={actionLoading !== null}
              onClick={handleRunAgent}
              className="flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg bg-blue-600 hover:bg-blue-500 text-white text-xs font-bold shadow-md shadow-blue-600/20 transition"
              title="Run LangGraph Autonomous Investigation Loop"
            >
              <BrainCircuit className={`w-3.5 h-3.5 ${actionLoading === 'agent' ? 'animate-spin' : ''}`} />
              Execute Agent
            </button>

            <button
              disabled={actionLoading !== null}
              onClick={handleReloadDataset}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 text-slate-300 text-xs font-medium border border-border transition"
              title="Reload Microsoft GUIDE Benchmark"
            >
              <RefreshCw className={`w-3 h-3 ${actionLoading === 'dataset' ? 'animate-spin' : ''}`} />
              Reload GUIDE
            </button>
          </div>
        </div>
      </header>

      {/* Main Content Body */}
      <main className="flex-1 max-w-[1720px] w-full mx-auto p-4 space-y-4">
        {/* Executive Metrics Overview Bar */}
        <MetricsOverview metrics={metrics} loading={loading} />

        {viewMode === 'comparison' ? (
          <ComparisonView
            data={comparisonData}
            loading={loading}
            onClose={() => setViewMode('console')}
          />
        ) : (
          <div className="space-y-4">
            <DemoAlertPanel onRunDemo={handleRunDemoAlert} />

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
        )}
      </main>
    </div>
  );
}

export default App;