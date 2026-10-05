import React, { useState } from 'react';
import {
  ShieldAlert,
  BrainCircuit,
  Sparkles,
  PlusCircle,
  FileCode,
  CheckCircle2,
  Trash2,
  Zap,
  ChevronDown,
  ChevronUp,
  Server,
  User,
  Globe,
  Tag,
  AlertTriangle,
  RotateCcw
} from 'lucide-react';

export interface AlertInputData {
  title: string;
  category: string;
  severity: 'Critical' | 'High' | 'Medium' | 'Low' | 'Informational';
  device_id: string;
  account_upn: string;
  ip_address: string;
  sha256?: string;
  url?: string;
  mitre_techniques?: string;
  action_grouped?: string;
  mitigation?: string;
  source?: string;
}

interface Props {
  onIngestAlert: (payload: AlertInputData) => Promise<{ success: boolean; incident_id?: string | null; message?: string }>;
  onIngestBatch: (alerts: AlertInputData[]) => Promise<{ success: boolean; message?: string }>;
  onClearAllData: () => Promise<void>;
  loading: boolean;
  totalIncidents: number;
}

const emptyForm: AlertInputData = {
  title: '',
  category: 'Execution',
  severity: 'High',
  device_id: '',
  account_upn: '',
  ip_address: '',
  sha256: '',
  mitre_techniques: '',
  action_grouped: 'Detected',
  mitigation: '',
  source: 'EDR Sensor'
};

const PRESET_SCENARIOS: { label: string; icon: string; data: AlertInputData }[] = [
  {
    label: 'Insider Data Exfiltration',
    icon: '🚨',
    data: {
      title: 'Bulk Database Dump & Cloud Storage Exfiltration',
      category: 'Exfiltration',
      severity: 'Critical',
      device_id: 'FIN-SRV-01',
      account_upn: 'corp\\finance_lead',
      ip_address: '185.220.101.5',
      sha256: '4a5e1e53ab392576b2512a87a6c986966838a0f900b991c2cbcfcb80f5a9e334',
      mitre_techniques: 'T1567.002, T1048',
      action_grouped: 'Detected',
      mitigation: 'Revoke cloud sync tokens and isolate finance host',
      source: 'DLP & Network Monitor'
    }
  },
  {
    label: 'Credential Dumping (LSASS)',
    icon: '🔑',
    data: {
      title: 'LSASS Memory Injection & Mimikatz Access',
      category: 'Credential Access',
      severity: 'Critical',
      device_id: 'DC-AUTH-01',
      account_upn: 'svc_backup_admin',
      ip_address: '10.10.40.12',
      sha256: 'c72b220311ef314a428612140bb9d30cc2f01f8d95133abdd07843f50ab0bc90',
      mitre_techniques: 'T1003.001',
      action_grouped: 'Blocked',
      mitigation: 'Rotate domain admin credentials and isolate domain controller',
      source: 'EDR Behavioral Sensor'
    }
  },
  {
    label: 'Obfuscated PowerShell',
    icon: '⚡',
    data: {
      title: 'Suspicious Encoded PowerShell Download Cradle',
      category: 'Execution',
      severity: 'High',
      device_id: 'HR-WS-109',
      account_upn: 'hr.recruiter@corp.local',
      ip_address: '194.26.29.112',
      sha256: '7b502c3a1f48c8609ae212cdfb639dee39673f5e',
      mitre_techniques: 'T1059.001, T1027',
      action_grouped: 'Quarantined',
      mitigation: 'Terminate PowerShell process tree and inspect user inbox',
      source: 'Endpoint Defense'
    }
  },
  {
    label: 'Ransomware Shadow Deletion',
    icon: '🔒',
    data: {
      title: 'Volume Shadow Copy Deletion via vssadmin',
      category: 'Impact',
      severity: 'Critical',
      device_id: 'SQL-PROD-02',
      account_upn: 'db_admin',
      ip_address: '192.168.1.50',
      mitre_techniques: 'T1490',
      action_grouped: 'Blocked',
      mitigation: 'Emergency network isolation and snapshot restore verification',
      source: 'Host Integrity Sensor'
    }
  },
  {
    label: 'Benign IT Maintenance',
    icon: '🟢',
    data: {
      title: 'Scheduled System Backup and Log Archive',
      category: 'System Maintenance',
      severity: 'Low',
      device_id: 'IT-DESK-04',
      account_upn: 'it_support@corp.local',
      ip_address: '10.0.0.15',
      mitre_techniques: 'N/A',
      action_grouped: 'Detected',
      mitigation: 'Routine audit confirmation',
      source: 'Syslog Agent'
    }
  }
];

export const AlertIngestConsole: React.FC<Props> = ({
  onIngestAlert,
  onIngestBatch,
  onClearAllData,
  loading,
  totalIncidents
}) => {
  const [isExpanded, setIsExpanded] = useState<boolean>(true);
  const [inputMode, setInputMode] = useState<'form' | 'json'>('form');
  const [form, setForm] = useState<AlertInputData>(emptyForm);
  const [jsonText, setJsonText] = useState<string>('');
  const [jsonError, setJsonError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState<boolean>(false);
  const [feedbackBanner, setFeedbackBanner] = useState<{ type: 'success' | 'error'; text: string } | null>(null);
  const [showClearConfirm, setShowClearConfirm] = useState<boolean>(false);

  const updateField = (field: keyof AlertInputData, value: string) => {
    setForm((prev) => ({ ...prev, [field]: value }));
  };

  const handleApplyPreset = (preset: AlertInputData) => {
    setForm(preset);
    setFeedbackBanner(null);
  };

  const handleFormSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!form.title.trim()) {
      setFeedbackBanner({ type: 'error', text: 'Alert title is required.' });
      return;
    }

    setSubmitting(true);
    setFeedbackBanner(null);
    try {
      const res = await onIngestAlert({
        ...form,
        device_id: form.device_id.trim() || 'DEV-HOST-01',
        account_upn: form.account_upn.trim() || 'user@corp.local',
        ip_address: form.ip_address.trim() || '127.0.0.1'
      });

      if (res.success) {
        setFeedbackBanner({
          type: 'success',
          text: res.message || 'Telemetry ingested! AI Autonomous Investigation complete.'
        });
        setForm(emptyForm);
      } else {
        setFeedbackBanner({ type: 'error', text: res.message || 'Failed to ingest alert.' });
      }
    } catch (err: any) {
      setFeedbackBanner({ type: 'error', text: err?.message || 'Error ingesting alert.' });
    } finally {
      setSubmitting(false);
    }
  };

  const handleJsonSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setJsonError(null);
    setFeedbackBanner(null);

    try {
      const parsed = JSON.parse(jsonText);
      setSubmitting(true);

      if (Array.isArray(parsed)) {
        const res = await onIngestBatch(parsed);
        if (res.success) {
          setFeedbackBanner({ type: 'success', text: `Successfully ingested batch of ${parsed.length} alerts.` });
          setJsonText('');
        } else {
          setFeedbackBanner({ type: 'error', text: res.message || 'Failed to ingest batch.' });
        }
      } else if (typeof parsed === 'object' && parsed !== null) {
        const res = await onIngestAlert(parsed);
        if (res.success) {
          setFeedbackBanner({ type: 'success', text: 'Alert telemetry ingested and analyzed successfully.' });
          setJsonText('');
        } else {
          setFeedbackBanner({ type: 'error', text: res.message || 'Failed to ingest alert.' });
        }
      } else {
        setJsonError('JSON must be an alert object or an array of alert objects.');
      }
    } catch (err: any) {
      setJsonError(`Invalid JSON format: ${err.message}`);
    } finally {
      setSubmitting(false);
    }
  };

  const handleClearData = async () => {
    setShowClearConfirm(false);
    setSubmitting(true);
    try {
      await onClearAllData();
      setFeedbackBanner({ type: 'success', text: 'All incident data and telemetry have been cleared.' });
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="bg-surface rounded-xl border border-border shadow-lg overflow-hidden transition-all duration-300">
      {/* Header Bar */}
      <div className="p-4 border-b border-border/80 flex flex-wrap items-center justify-between gap-3 bg-gradient-to-r from-slate-900/90 via-slate-900/50 to-slate-900/90">
        <div className="flex items-center gap-3">
          <div className="p-2 rounded-xl bg-blue-500/10 text-blue-400 border border-blue-500/20 shadow-sm">
            <PlusCircle className="w-5 h-5" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h2 className="text-sm font-bold tracking-tight text-slate-100">
                Security Alert Ingestion & Investigation Console
              </h2>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-blue-500/15 text-blue-300 border border-blue-500/30">
                LIVE INPUT MODE
              </span>
            </div>
            <p className="text-xs text-slate-400">
              Input custom security telemetry, insider threats, or EDR logs to trigger real-time AI triage & graph correlation
            </p>
          </div>
        </div>

        {/* Action Buttons */}
        <div className="flex items-center gap-2">
          {/* Mode Switcher */}
          <div className="flex items-center bg-slate-950/80 rounded-lg p-1 border border-border text-xs">
            <button
              type="button"
              onClick={() => setInputMode('form')}
              className={`px-3 py-1 rounded font-medium transition text-xs ${
                inputMode === 'form' ? 'bg-blue-600 text-white shadow-sm' : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              Interactive Form
            </button>
            <button
              type="button"
              onClick={() => {
                setInputMode('json');
                if (!jsonText) {
                  setJsonText(JSON.stringify(PRESET_SCENARIOS[0].data, null, 2));
                }
              }}
              className={`px-3 py-1 rounded font-medium transition text-xs flex items-center gap-1.5 ${
                inputMode === 'json' ? 'bg-blue-600 text-white shadow-sm' : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              <FileCode className="w-3.5 h-3.5" /> JSON Ingest
            </button>
          </div>

          {/* Clear All Data Button */}
          {totalIncidents > 0 && (
            <button
              type="button"
              onClick={() => setShowClearConfirm(true)}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-rose-950/40 hover:bg-rose-900/60 text-rose-300 border border-rose-800/40 text-xs font-semibold transition"
              title="Clear all active incidents and reset to clean state"
            >
              <Trash2 className="w-3.5 h-3.5" />
              Reset All Data
            </button>
          )}

          {/* Expand / Collapse Toggle */}
          <button
            type="button"
            onClick={() => setIsExpanded(!isExpanded)}
            className="p-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 text-slate-400 hover:text-slate-200 border border-border transition"
            title={isExpanded ? 'Collapse Input Panel' : 'Expand Input Panel'}
          >
            {isExpanded ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
          </button>
        </div>
      </div>

      {/* Confirmation Modal for Clearing Data */}
      {showClearConfirm && (
        <div className="p-4 bg-rose-950/60 border-b border-rose-800/60 flex items-center justify-between gap-4 animate-in fade-in duration-200">
          <div className="flex items-center gap-2 text-xs text-rose-200">
            <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0" />
            <span>
              Are you sure you want to clear all <strong>{totalIncidents}</strong> active incidents, evidence traces, and reasoning logs? This will reset the workspace to zero.
            </span>
          </div>
          <div className="flex items-center gap-2 shrink-0">
            <button
              onClick={handleClearData}
              className="px-3 py-1 rounded bg-rose-600 hover:bg-rose-500 text-white font-bold text-xs shadow-sm transition"
            >
              Yes, Clear Everything
            </button>
            <button
              onClick={() => setShowClearConfirm(false)}
              className="px-3 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs transition"
            >
              Cancel
            </button>
          </div>
        </div>
      )}

      {/* Notification Banner */}
      {feedbackBanner && (
        <div
          className={`p-3 text-xs flex items-center justify-between border-b ${
            feedbackBanner.type === 'success'
              ? 'bg-emerald-950/60 text-emerald-200 border-emerald-800/50'
              : 'bg-rose-950/60 text-rose-200 border-rose-800/50'
          }`}
        >
          <div className="flex items-center gap-2">
            {feedbackBanner.type === 'success' ? (
              <CheckCircle2 className="w-4 h-4 text-emerald-400" />
            ) : (
              <AlertTriangle className="w-4 h-4 text-rose-400" />
            )}
            <span>{feedbackBanner.text}</span>
          </div>
          <button
            onClick={() => setFeedbackBanner(null)}
            className="text-slate-400 hover:text-slate-200 text-xs px-2 py-0.5"
          >
            ✕
          </button>
        </div>
      )}

      {isExpanded && (
        <div className="p-4 space-y-4">
          {/* Preset Quick Scenarios */}
          <div>
            <div className="flex items-center justify-between mb-2">
              <span className="text-[11px] uppercase tracking-wider font-semibold text-slate-400 flex items-center gap-1.5">
                <Zap className="w-3.5 h-3.5 text-amber-400" />
                Quick Threat Scenario Presets (Click to autofill):
              </span>
              <button
                type="button"
                onClick={() => setForm(emptyForm)}
                className="text-[11px] text-slate-400 hover:text-slate-200 flex items-center gap-1 transition"
              >
                <RotateCcw className="w-3 h-3" /> Blank Form
              </button>
            </div>

            <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-2">
              {PRESET_SCENARIOS.map((preset, idx) => (
                <button
                  key={idx}
                  type="button"
                  onClick={() => handleApplyPreset(preset.data)}
                  className="flex items-center gap-2 p-2 rounded-lg bg-slate-900/90 hover:bg-slate-800 border border-slate-800 hover:border-blue-500/50 text-left transition group shadow-sm"
                >
                  <span className="text-base">{preset.icon}</span>
                  <div className="overflow-hidden">
                    <div className="text-[11px] font-semibold text-slate-200 group-hover:text-blue-300 truncate">
                      {preset.label}
                    </div>
                    <div className="text-[9px] text-slate-500 font-mono truncate">
                      {preset.data.severity} • {preset.data.category}
                    </div>
                  </div>
                </button>
              ))}
            </div>
          </div>

          {inputMode === 'form' ? (
            /* Interactive Form Mode */
            <form onSubmit={handleFormSubmit} className="space-y-4">
              <div className="grid grid-cols-1 md:grid-cols-3 lg:grid-cols-4 gap-3">
                {/* Alert Title */}
                <div className="md:col-span-2 lg:col-span-2">
                  <label className="block text-[11px] font-semibold text-slate-300 mb-1">
                    Alert Title / Incident Name <span className="text-rose-400">*</span>
                  </label>
                  <input
                    type="text"
                    required
                    placeholder="e.g. Unauthorized Cloud Storage Data Transfer"
                    value={form.title}
                    onChange={(e) => updateField('title', e.target.value)}
                    className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-xs text-slate-100 placeholder:text-slate-600 outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500 transition font-medium"
                  />
                </div>

                {/* Category */}
                <div>
                  <label className="block text-[11px] font-semibold text-slate-300 mb-1">
                    Category / MITRE Tactic
                  </label>
                  <input
                    type="text"
                    placeholder="e.g. Exfiltration, Execution, Credential Access"
                    value={form.category}
                    onChange={(e) => updateField('category', e.target.value)}
                    className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-xs text-slate-100 placeholder:text-slate-600 outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500 transition"
                  />
                </div>

                {/* Severity */}
                <div>
                  <label className="block text-[11px] font-semibold text-slate-300 mb-1">
                    Severity
                  </label>
                  <select
                    value={form.severity}
                    onChange={(e) => updateField('severity', e.target.value as any)}
                    className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-xs text-slate-100 outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500 transition"
                  >
                    <option value="Critical">Critical (High Risk)</option>
                    <option value="High">High</option>
                    <option value="Medium">Medium</option>
                    <option value="Low">Low</option>
                    <option value="Informational">Informational</option>
                  </select>
                </div>

                {/* Device / Host */}
                <div>
                  <label className="block text-[11px] font-semibold text-slate-300 mb-1">
                    Device / Hostname
                  </label>
                  <div className="relative">
                    <Server className="w-3.5 h-3.5 absolute left-2.5 top-2.5 text-slate-500" />
                    <input
                      type="text"
                      placeholder="e.g. FIN-WS-204"
                      value={form.device_id}
                      onChange={(e) => updateField('device_id', e.target.value)}
                      className="w-full pl-8 pr-3 py-2 rounded-lg border border-slate-700 bg-slate-950 text-xs text-slate-100 placeholder:text-slate-600 outline-none focus:border-blue-500 transition font-mono"
                    />
                  </div>
                </div>

                {/* User / Account */}
                <div>
                  <label className="block text-[11px] font-semibold text-slate-300 mb-1">
                    User Account / UPN
                  </label>
                  <div className="relative">
                    <User className="w-3.5 h-3.5 absolute left-2.5 top-2.5 text-slate-500" />
                    <input
                      type="text"
                      placeholder="e.g. j.smith@contoso.com"
                      value={form.account_upn}
                      onChange={(e) => updateField('account_upn', e.target.value)}
                      className="w-full pl-8 pr-3 py-2 rounded-lg border border-slate-700 bg-slate-950 text-xs text-slate-100 placeholder:text-slate-600 outline-none focus:border-blue-500 transition font-mono"
                    />
                  </div>
                </div>

                {/* IP Address */}
                <div>
                  <label className="block text-[11px] font-semibold text-slate-300 mb-1">
                    IP Address
                  </label>
                  <div className="relative">
                    <Globe className="w-3.5 h-3.5 absolute left-2.5 top-2.5 text-slate-500" />
                    <input
                      type="text"
                      placeholder="e.g. 185.220.101.42"
                      value={form.ip_address}
                      onChange={(e) => updateField('ip_address', e.target.value)}
                      className="w-full pl-8 pr-3 py-2 rounded-lg border border-slate-700 bg-slate-950 text-xs text-slate-100 placeholder:text-slate-600 outline-none focus:border-blue-500 transition font-mono"
                    />
                  </div>
                </div>

                {/* MITRE Technique */}
                <div>
                  <label className="block text-[11px] font-semibold text-slate-300 mb-1">
                    MITRE ATT&CK ID
                  </label>
                  <div className="relative">
                    <Tag className="w-3.5 h-3.5 absolute left-2.5 top-2.5 text-slate-500" />
                    <input
                      type="text"
                      placeholder="e.g. T1059.001, T1567"
                      value={form.mitre_techniques || ''}
                      onChange={(e) => updateField('mitre_techniques', e.target.value)}
                      className="w-full pl-8 pr-3 py-2 rounded-lg border border-slate-700 bg-slate-950 text-xs text-slate-100 placeholder:text-slate-600 outline-none focus:border-blue-500 transition font-mono"
                    />
                  </div>
                </div>

                {/* SHA256 Hash */}
                <div className="md:col-span-2">
                  <label className="block text-[11px] font-semibold text-slate-300 mb-1">
                    Payload / File SHA256 Hash (Optional)
                  </label>
                  <input
                    type="text"
                    placeholder="e.g. 4a5e1e53ab392576b2512a87a6c986966838a0f900b991c2cbcfcb80f5a9e334"
                    value={form.sha256 || ''}
                    onChange={(e) => updateField('sha256', e.target.value)}
                    className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-xs text-slate-100 placeholder:text-slate-600 outline-none focus:border-blue-500 transition font-mono text-[11px]"
                  />
                </div>

                {/* Mitigation / Suggested Action */}
                <div className="md:col-span-2">
                  <label className="block text-[11px] font-semibold text-slate-300 mb-1">
                    Suggested Remediation / Action
                  </label>
                  <input
                    type="text"
                    placeholder="e.g. Revoke cloud credentials and isolate compromised endpoint"
                    value={form.mitigation || ''}
                    onChange={(e) => updateField('mitigation', e.target.value)}
                    className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-xs text-slate-100 placeholder:text-slate-600 outline-none focus:border-blue-500 transition"
                  />
                </div>
              </div>

              {/* Submit Row */}
              <div className="flex flex-wrap items-center justify-between gap-3 pt-2 border-t border-slate-800">
                <div className="text-[11px] text-slate-400 flex items-center gap-1.5">
                  <BrainCircuit className="w-4 h-4 text-blue-400" />
                  Submitting will automatically run entity correlation, ML anomaly detection, and LangGraph autonomous reasoning.
                </div>

                <div className="flex items-center gap-2">
                  <button
                    type="button"
                    onClick={() => setForm(emptyForm)}
                    className="px-3 py-2 rounded-lg bg-slate-900 hover:bg-slate-800 text-slate-400 hover:text-slate-200 border border-slate-800 text-xs font-medium transition"
                  >
                    Clear Form
                  </button>

                  <button
                    type="submit"
                    disabled={submitting || loading}
                    className="flex items-center gap-2 px-5 py-2 rounded-lg bg-blue-600 hover:bg-blue-500 disabled:bg-blue-800 text-white text-xs font-bold shadow-lg shadow-blue-600/30 transition cursor-pointer"
                  >
                    <Sparkles className={`w-4 h-4 ${submitting ? 'animate-spin' : ''}`} />
                    {submitting ? 'Running Autonomous AI Investigation...' : 'Submit Alert & Investigate'}
                  </button>
                </div>
              </div>
            </form>
          ) : (
            /* JSON Ingest Mode */
            <form onSubmit={handleJsonSubmit} className="space-y-3">
              <div className="flex items-center justify-between">
                <label className="text-xs font-semibold text-slate-300">
                  Paste Raw JSON (Single Alert object or Array of Alerts)
                </label>
                <button
                  type="button"
                  onClick={() => setJsonText(JSON.stringify(PRESET_SCENARIOS.map(s => s.data), null, 2))}
                  className="text-xs text-blue-400 hover:text-blue-300"
                >
                  Load Multi-Alert Batch Sample
                </button>
              </div>

              <textarea
                rows={8}
                value={jsonText}
                onChange={(e) => setJsonText(e.target.value)}
                placeholder={'[{\n  "title": "Suspicious Process Injection",\n  "category": "Defense Evasion",\n  "severity": "High",\n  "device_id": "FIN-WS-101",\n  "account_upn": "user@corp.local",\n  "ip_address": "185.220.101.42"\n}]'}
                className="w-full font-mono text-xs rounded-lg border border-slate-700 bg-slate-950 p-3 text-slate-100 placeholder:text-slate-600 outline-none focus:border-blue-500 transition"
              />

              {jsonError && (
                <p className="text-xs text-rose-400 flex items-center gap-1">
                  <AlertTriangle className="w-3.5 h-3.5" /> {jsonError}
                </p>
              )}

              <div className="flex justify-end gap-2">
                <button
                  type="button"
                  onClick={() => setJsonText('')}
                  className="px-3 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 text-slate-400 hover:text-slate-200 border border-slate-800 text-xs transition"
                >
                  Clear
                </button>
                <button
                  type="submit"
                  disabled={submitting || !jsonText.trim()}
                  className="flex items-center gap-2 px-5 py-2 rounded-lg bg-blue-600 hover:bg-blue-500 disabled:bg-blue-800 text-white text-xs font-bold shadow-lg shadow-blue-600/30 transition"
                >
                  <Sparkles className={`w-4 h-4 ${submitting ? 'animate-spin' : ''}`} />
                  {submitting ? 'Processing Telemetry...' : 'Ingest JSON Telemetry'}
                </button>
              </div>
            </form>
          )}
        </div>
      )}
    </div>
  );
};
