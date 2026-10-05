import React, { useState } from 'react';
import { AlertTriangle, BrainCircuit, ShieldCheck, ShieldAlert, Sparkles } from 'lucide-react';

export interface DemoAlertInput {
  title: string;
  category: string;
  severity: 'Critical' | 'High' | 'Medium' | 'Low' | 'Informational';
  device_id: string;
  account_upn: string;
  ip_address: string;
  mitigation: string;
  source: string;
}

export interface DemoAlertResult {
  priority: string;
  risk_score: number;
  predicted_grade: string;
  agent_action: string;
  summary: string;
  reasons: string[];
  confidence: number;
}

interface Props {
  onRunDemo: (payload: DemoAlertInput) => Promise<DemoAlertResult | null>;
}

const emptyForm: DemoAlertInput = {
  title: '0',
  category: '0',
  severity: 'Low',
  device_id: '0',
  account_upn: '0',
  ip_address: '0',
  mitigation: '0',
  source: '0'
};

const sampleForm: DemoAlertInput = {
  title: 'Suspicious PowerShell Execution on Finance Workstation',
  category: 'Execution',
  severity: 'High',
  device_id: 'FIN-WS-204',
  account_upn: 'j.smith@contoso.com',
  ip_address: '185.220.101.42',
  mitigation: 'Isolate host and review script execution',
  source: 'EDR Alert'
};

export const DemoAlertPanel: React.FC<Props> = ({ onRunDemo }) => {
  const [form, setForm] = useState<DemoAlertInput>(emptyForm);
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<DemoAlertResult | null>(null);

  const updateField = (field: keyof DemoAlertInput, value: string) => {
    setForm((prev) => ({ ...prev, [field]: value }));
  };

  const handleSubmit = async (event: React.FormEvent) => {
    event.preventDefault();
    setLoading(true);
    try {
      const response = await onRunDemo(form);
      setResult(response);
    } finally {
      setLoading(false);
    }
  };

  const getPriorityStyles = (priority: string) => {
    switch (priority) {
      case 'Critical':
        return 'bg-rose-500/15 text-rose-300 border border-rose-500/30';
      case 'High':
        return 'bg-amber-500/15 text-amber-300 border border-amber-500/30';
      case 'Medium':
        return 'bg-blue-500/15 text-blue-300 border border-blue-500/30';
      default:
        return 'bg-emerald-500/15 text-emerald-300 border border-emerald-500/30';
    }
  };

  return (
    <div className="grid grid-cols-1 xl:grid-cols-[1.1fr_0.9fr] gap-4">
      <form onSubmit={handleSubmit} className="bg-surface rounded-xl border border-border p-4">
        <div className="flex items-center justify-between mb-4">
          <div>
            <p className="text-[10px] uppercase tracking-[0.2em] text-slate-400">Live Demo</p>
            <h3 className="text-lg font-bold text-slate-100">Simulate a security alert</h3>
          </div>
          <div className="flex items-center gap-2 rounded-lg bg-blue-500/10 px-2 py-1 text-blue-300 text-[10px] font-semibold border border-blue-500/20">
            <BrainCircuit className="w-3.5 h-3.5" /> Agent alive
          </div>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
          <label className="text-xs text-slate-300">
            Alert title
            <input
              className="mt-1 w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100 outline-none focus:border-blue-500"
              value={form.title}
              onChange={(e) => updateField('title', e.target.value)}
            />
          </label>

          <label className="text-xs text-slate-300">
            Category
            <input
              className="mt-1 w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100 outline-none focus:border-blue-500"
              value={form.category}
              onChange={(e) => updateField('category', e.target.value)}
            />
          </label>

          <label className="text-xs text-slate-300">
            Severity
            <select
              value={form.severity}
              onChange={(e) => updateField('severity', e.target.value)}
              className="mt-1 w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100 outline-none focus:border-blue-500"
            >
              <option>Critical</option>
              <option>High</option>
              <option>Medium</option>
              <option>Low</option>
              <option>Informational</option>
            </select>
          </label>

          <label className="text-xs text-slate-300">
            Device
            <input
              className="mt-1 w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100 outline-none focus:border-blue-500"
              value={form.device_id}
              onChange={(e) => updateField('device_id', e.target.value)}
            />
          </label>

          <label className="text-xs text-slate-300">
            User / Account
            <input
              className="mt-1 w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100 outline-none focus:border-blue-500"
              value={form.account_upn}
              onChange={(e) => updateField('account_upn', e.target.value)}
            />
          </label>

          <label className="text-xs text-slate-300">
            IP Address
            <input
              className="mt-1 w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100 outline-none focus:border-blue-500"
              value={form.ip_address}
              onChange={(e) => updateField('ip_address', e.target.value)}
            />
          </label>

          <label className="text-xs text-slate-300 md:col-span-2">
            Suggested action / mitigation
            <input
              className="mt-1 w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100 outline-none focus:border-blue-500"
              value={form.mitigation}
              onChange={(e) => updateField('mitigation', e.target.value)}
            />
          </label>

          <label className="text-xs text-slate-300 md:col-span-2">
            Detection source
            <input
              className="mt-1 w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100 outline-none focus:border-blue-500"
              value={form.source}
              onChange={(e) => updateField('source', e.target.value)}
            />
          </label>
        </div>

        <div className="mt-4 flex items-center justify-between gap-3">
          <button
            type="submit"
            disabled={loading}
            className="inline-flex items-center gap-2 rounded-lg bg-blue-600 px-4 py-2 text-sm font-semibold text-white hover:bg-blue-500 disabled:cursor-not-allowed disabled:opacity-60"
          >
            <Sparkles className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
            {loading ? 'Analyzing...' : 'Run live investigation'}
          </button>

          <button
            type="button"
            onClick={() => { setForm(sampleForm); setResult(null); }}
            className="text-xs text-slate-400 hover:text-slate-200"
          >
            Load sample
          </button>
          <button
            type="button"
            onClick={() => { setForm(emptyForm); setResult(null); }}
            className="text-xs text-rose-400 hover:text-rose-200"
          >
            Clear
          </button>
        </div>
      </form>

      <div className="bg-surface rounded-xl border border-border p-4 min-h-[260px]">
        <div className="flex items-center justify-between">
          <div>
            <p className="text-[10px] uppercase tracking-[0.2em] text-slate-400">Result</p>
            <h3 className="text-lg font-bold text-slate-100">Agent verdict</h3>
          </div>
          {result ? (
            <span className={`rounded-full px-2 py-1 text-[10px] font-bold ${getPriorityStyles(result.priority)}`}>
              {result.priority}
            </span>
          ) : (
            <span className="rounded-full border border-slate-700 bg-slate-900 px-2 py-1 text-[10px] text-slate-400">
              Waiting
            </span>
          )}
        </div>

        {result ? (
          <div className="mt-4 space-y-3">
            <div className="flex items-center gap-2 text-sm text-slate-300">
              <ShieldAlert className="w-4 h-4 text-blue-400" />
              Risk Score: <span className="font-bold text-white">{result.risk_score.toFixed(1)}/100</span>
            </div>

            <div className="flex items-center gap-2 text-sm text-slate-300">
              <ShieldCheck className="w-4 h-4 text-emerald-400" />
              Predicted Grade: <span className="font-bold text-white">{result.predicted_grade}</span>
            </div>

            <div className="flex items-center gap-2 text-sm text-slate-300">
              <AlertTriangle className="w-4 h-4 text-amber-400" />
              Agent Action: <span className="font-bold text-white">{result.agent_action}</span>
            </div>

            <div className="rounded-lg border border-slate-700 bg-slate-950 p-3 text-xs text-slate-300">
              <p className="font-semibold text-slate-200 mb-2">Summary</p>
              <p>{result.summary}</p>
            </div>

            <div className="rounded-lg border border-slate-700 bg-slate-950 p-3 text-xs text-slate-300">
              <p className="font-semibold text-slate-200 mb-2">Agent reasoning</p>
              <ul className="list-disc space-y-1 pl-4">
                {result.reasons.map((reason) => (
                  <li key={reason}>{reason}</li>
                ))}
              </ul>
            </div>
          </div>
        ) : (
          <div className="mt-8 flex h-[180px] items-center justify-center rounded-xl border border-dashed border-slate-700 bg-slate-950 text-center text-xs text-slate-500">
            Fill in the alert details and run the live investigation to see the agent decision.
          </div>
        )}
      </div>
    </div>
  );
};
