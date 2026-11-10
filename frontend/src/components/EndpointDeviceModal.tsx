import React, { useState, useEffect } from 'react';
import {
  Server,
  PlusCircle,
  X,
  Trash2,
  ShieldAlert,
  Activity,
  CheckCircle2,
  AlertTriangle,
  Search,
  Filter,
  Lock,
  RefreshCw,
  Laptop
} from 'lucide-react';
import { EndpointDevice } from '../types';

interface Props {
  isOpen: boolean;
  onClose: () => void;
  onDeviceUpdated?: () => void;
}

const API_BASE = import.meta.env.VITE_API_BASE ?? '';

export const EndpointDeviceModal: React.FC<Props> = ({ isOpen, onClose, onDeviceUpdated }) => {
  const [devices, setDevices] = useState<EndpointDevice[]>([]);
  const [loading, setLoading] = useState(false);
  const [search, setSearch] = useState('');
  const [statusFilter, setStatusFilter] = useState<string>('All');
  const [showAddForm, setShowAddForm] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [notification, setNotification] = useState<{ type: 'success' | 'error'; text: string } | null>(null);

  // Form state
  const [newDeviceId, setNewDeviceId] = useState('');
  const [newHostname, setNewHostname] = useState('');
  const [newIpAddress, setNewIpAddress] = useState('');
  const [newOs, setNewOs] = useState('Windows 11 Enterprise');
  const [newDepartment, setNewDepartment] = useState('Engineering');
  const [newStatus, setNewStatus] = useState<'Online' | 'Offline'>('Online');

  const fetchDevices = async () => {
    try {
      setLoading(true);
      const res = await fetch(`${API_BASE}/api/devices`);
      if (res.ok) {
        const data = await res.json();
        setDevices(data);
      }
    } catch (err) {
      console.error('Failed to load devices:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (isOpen) {
      fetchDevices();
      setNotification(null);
    }
  }, [isOpen]);

  if (!isOpen) return null;

  const handleRegisterDevice = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newDeviceId.trim()) {
      setNotification({ type: 'error', text: 'Device ID is required.' });
      return;
    }

    setSubmitting(true);
    setNotification(null);
    try {
      const res = await fetch(`${API_BASE}/api/devices`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          device_id: newDeviceId.trim().toUpperCase(),
          hostname: newHostname.trim() || `${newDeviceId.trim().toLowerCase()}.corp.local`,
          ip_address: newIpAddress.trim() || '10.10.1.100',
          os: newOs,
          department: newDepartment,
          status: newStatus
        })
      });

      if (!res.ok) {
        const err = await res.json();
        throw new Error(err.detail || 'Failed to register device');
      }

      setNotification({ type: 'success', text: `Device ${newDeviceId.toUpperCase()} successfully registered!` });
      setNewDeviceId('');
      setNewHostname('');
      setNewIpAddress('');
      setShowAddForm(false);
      await fetchDevices();
      if (onDeviceUpdated) onDeviceUpdated();
    } catch (err: any) {
      setNotification({ type: 'error', text: err.message || 'Error registering device' });
    } finally {
      setSubmitting(false);
    }
  };

  const handleDeleteDevice = async (deviceId: string) => {
    if (!window.confirm(`Are you sure you want to remove device ${deviceId} from management?`)) return;
    try {
      const res = await fetch(`${API_BASE}/api/devices/${deviceId}`, { method: 'DELETE' });
      if (res.ok) {
        setNotification({ type: 'success', text: `Device ${deviceId} removed.` });
        await fetchDevices();
        if (onDeviceUpdated) onDeviceUpdated();
      }
    } catch (err) {
      console.error('Error removing device:', err);
    }
  };

  const handleToggleStatus = async (deviceId: string, currentStatus: string) => {
    const nextStatus = currentStatus === 'Online' ? 'Isolated' : currentStatus === 'Isolated' ? 'Offline' : 'Online';
    try {
      const res = await fetch(`${API_BASE}/api/devices/${deviceId}/status`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ status: nextStatus })
      });
      if (res.ok) {
        await fetchDevices();
        if (onDeviceUpdated) onDeviceUpdated();
      }
    } catch (err) {
      console.error('Failed to update status:', err);
    }
  };

  const filteredDevices = devices.filter((d) => {
    if (statusFilter !== 'All' && d.status !== statusFilter) return false;
    if (search.trim()) {
      const q = search.toLowerCase();
      return (
        d.device_id.toLowerCase().includes(q) ||
        (d.hostname && d.hostname.toLowerCase().includes(q)) ||
        (d.ip_address && d.ip_address.includes(q)) ||
        d.department.toLowerCase().includes(q)
      );
    }
    return true;
  });

  const getRiskBadge = (score: number) => {
    if (score >= 70) {
      return (
        <span className="px-2 py-0.5 rounded-full text-[10px] font-mono font-bold bg-rose-500/20 text-rose-300 border border-rose-500/40">
          RISK {score.toFixed(1)} (HIGH)
        </span>
      );
    }
    if (score >= 40) {
      return (
        <span className="px-2 py-0.5 rounded-full text-[10px] font-mono font-bold bg-amber-500/20 text-amber-300 border border-amber-500/40">
          RISK {score.toFixed(1)} (MED)
        </span>
      );
    }
    return (
      <span className="px-2 py-0.5 rounded-full text-[10px] font-mono font-bold bg-yellow-500/20 text-yellow-300 border border-yellow-500/40">
        RISK {score.toFixed(1)} (LOW)
      </span>
    );
  };

  return (
    <div className="fixed inset-0 z-50 bg-slate-950/80 backdrop-blur-sm flex items-center justify-center p-4 animate-in fade-in duration-200">
      <div className="bg-surface rounded-2xl border border-border shadow-2xl w-full max-w-5xl max-h-[90vh] flex flex-col overflow-hidden">
        {/* Modal Header */}
        <div className="p-4 border-b border-border/80 flex items-center justify-between bg-gradient-to-r from-slate-900/90 via-slate-900/50 to-slate-900/90">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-xl bg-blue-500/10 text-blue-400 border border-blue-500/20">
              <Server className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h2 className="text-sm font-bold text-slate-100">
                  Feature 1: Register & Manage Endpoint Devices
                </h2>
                <span className="text-[10px] font-mono font-semibold px-2 py-0.5 rounded-full bg-blue-500/15 text-blue-300 border border-blue-500/30">
                  {devices.length} Total Devices
                </span>
              </div>
              <p className="text-xs text-slate-400">
                Manage all registered workstations, servers, and domain controllers connected to the telemetry pipeline.
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={() => setShowAddForm(!showAddForm)}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-blue-600 hover:bg-blue-500 text-white text-xs font-semibold shadow-sm transition"
            >
              <PlusCircle className="w-3.5 h-3.5" />
              {showAddForm ? 'Cancel Registration' : 'Register New Endpoint'}
            </button>
            <button
              onClick={onClose}
              className="p-1.5 rounded-lg text-slate-400 hover:text-slate-100 hover:bg-slate-800 transition"
            >
              <X className="w-5 h-5" />
            </button>
          </div>
        </div>

        {/* Notification Banner */}
        {notification && (
          <div
            className={`p-3 text-xs flex items-center justify-between border-b ${
              notification.type === 'success'
                ? 'bg-emerald-950/60 text-emerald-200 border-emerald-800/50'
                : 'bg-rose-950/60 text-rose-200 border-rose-800/50'
            }`}
          >
            <div className="flex items-center gap-2">
              {notification.type === 'success' ? (
                <CheckCircle2 className="w-4 h-4 text-emerald-400" />
              ) : (
                <AlertTriangle className="w-4 h-4 text-rose-400" />
              )}
              <span>{notification.text}</span>
            </div>
            <button onClick={() => setNotification(null)} className="text-slate-400 hover:text-slate-200 text-xs">
              ✕
            </button>
          </div>
        )}

        {/* Add Device Form Drawer */}
        {showAddForm && (
          <form
            onSubmit={handleRegisterDevice}
            className="p-4 bg-slate-900/90 border-b border-border space-y-3 animate-in slide-in-from-top duration-200"
          >
            <div className="flex items-center justify-between">
              <h3 className="text-xs font-bold uppercase tracking-wider text-blue-400 flex items-center gap-1.5">
                <Laptop className="w-3.5 h-3.5" /> Administrator Endpoint Registration Form
              </h3>
              <span className="text-[11px] text-slate-400">Add workstation or server to active telemetry fleet</span>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-3">
              <div>
                <label className="text-[11px] font-medium text-slate-300 block mb-1">
                  Device ID / Asset Tag *
                </label>
                <input
                  type="text"
                  placeholder="e.g. WS-FIN-09, SRV-DB-02"
                  value={newDeviceId}
                  onChange={(e) => setNewDeviceId(e.target.value)}
                  className="w-full bg-slate-950 border border-border rounded-lg px-2.5 py-1.5 text-xs text-slate-100 placeholder-slate-500 focus:outline-none focus:border-blue-500"
                  required
                />
              </div>

              <div>
                <label className="text-[11px] font-medium text-slate-300 block mb-1">
                  Hostname (FQDN)
                </label>
                <input
                  type="text"
                  placeholder="e.g. ws-fin-09.corp.local"
                  value={newHostname}
                  onChange={(e) => setNewHostname(e.target.value)}
                  className="w-full bg-slate-950 border border-border rounded-lg px-2.5 py-1.5 text-xs text-slate-100 placeholder-slate-500 focus:outline-none focus:border-blue-500"
                />
              </div>

              <div>
                <label className="text-[11px] font-medium text-slate-300 block mb-1">
                  Assigned IP Address
                </label>
                <input
                  type="text"
                  placeholder="e.g. 10.10.15.55"
                  value={newIpAddress}
                  onChange={(e) => setNewIpAddress(e.target.value)}
                  className="w-full bg-slate-950 border border-border rounded-lg px-2.5 py-1.5 text-xs text-slate-100 placeholder-slate-500 focus:outline-none focus:border-blue-500"
                />
              </div>

              <div>
                <label className="text-[11px] font-medium text-slate-300 block mb-1">
                  Operating System
                </label>
                <select
                  value={newOs}
                  onChange={(e) => setNewOs(e.target.value)}
                  className="w-full bg-slate-950 border border-border rounded-lg px-2.5 py-1.5 text-xs text-slate-100 focus:outline-none focus:border-blue-500"
                >
                  <option value="Windows 11 Enterprise">Windows 11 Enterprise</option>
                  <option value="Windows 10 Pro">Windows 10 Pro</option>
                  <option value="Windows Server 2022">Windows Server 2022</option>
                  <option value="Ubuntu 22.04 LTS">Ubuntu 22.04 LTS</option>
                  <option value="Red Hat Enterprise Linux 9">Red Hat Enterprise Linux 9</option>
                  <option value="macOS Sonoma">macOS Sonoma</option>
                </select>
              </div>

              <div>
                <label className="text-[11px] font-medium text-slate-300 block mb-1">
                  Department / Organizational Unit
                </label>
                <select
                  value={newDepartment}
                  onChange={(e) => setNewDepartment(e.target.value)}
                  className="w-full bg-slate-950 border border-border rounded-lg px-2.5 py-1.5 text-xs text-slate-100 focus:outline-none focus:border-blue-500"
                >
                  <option value="Finance">Finance</option>
                  <option value="Engineering">Engineering</option>
                  <option value="Human Resources">Human Resources</option>
                  <option value="Domain Controller / IAM">Domain Controller / IAM</option>
                  <option value="Infrastructure / Production">Infrastructure / Production</option>
                  <option value="Executive Management">Executive Management</option>
                  <option value="Marketing & Sales">Marketing & Sales</option>
                  <option value="Legal & Compliance">Legal & Compliance</option>
                </select>
              </div>

              <div>
                <label className="text-[11px] font-medium text-slate-300 block mb-1">
                  Initial Telemetry Status
                </label>
                <select
                  value={newStatus}
                  onChange={(e) => setNewStatus(e.target.value as any)}
                  className="w-full bg-slate-950 border border-border rounded-lg px-2.5 py-1.5 text-xs text-slate-100 focus:outline-none focus:border-blue-500"
                >
                  <option value="Online">Online (Reporting Telemetry)</option>
                  <option value="Offline">Offline</option>
                </select>
              </div>
            </div>

            <div className="flex justify-end gap-2 pt-2">
              <button
                type="button"
                onClick={() => setShowAddForm(false)}
                className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs transition"
              >
                Cancel
              </button>
              <button
                type="submit"
                disabled={submitting}
                className="px-4 py-1.5 rounded-lg bg-blue-600 hover:bg-blue-500 text-white font-bold text-xs shadow-md transition disabled:opacity-50"
              >
                {submitting ? 'Registering...' : 'Register Endpoint Device'}
              </button>
            </div>
          </form>
        )}

        {/* Filter & Search Bar */}
        <div className="p-3 border-b border-border flex flex-wrap items-center justify-between gap-3 bg-slate-950/40">
          <div className="flex items-center gap-2 flex-1 max-w-md">
            <div className="relative w-full">
              <Search className="w-3.5 h-3.5 absolute left-2.5 top-1/2 -translate-y-1/2 text-slate-400" />
              <input
                type="text"
                placeholder="Search by Device ID, Hostname, IP, or Department..."
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                className="w-full bg-slate-900 border border-border rounded-lg pl-8 pr-3 py-1.5 text-xs text-slate-100 placeholder-slate-500 focus:outline-none focus:border-blue-500"
              />
            </div>
          </div>

          <div className="flex items-center gap-2">
            <span className="text-xs text-slate-400 flex items-center gap-1">
              <Filter className="w-3 h-3" /> Status:
            </span>
            <div className="flex items-center bg-slate-900 rounded-lg p-0.5 border border-border text-xs">
              {(['All', 'Online', 'Offline', 'Isolated'] as const).map((s) => (
                <button
                  key={s}
                  onClick={() => setStatusFilter(s)}
                  className={`px-2.5 py-1 rounded text-[11px] font-medium transition ${
                    statusFilter === s ? 'bg-blue-600 text-white shadow-sm' : 'text-slate-400 hover:text-slate-200'
                  }`}
                >
                  {s}
                </button>
              ))}
            </div>

            <button
              onClick={fetchDevices}
              className="p-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 text-slate-400 hover:text-slate-200 border border-border transition"
              title="Refresh Devices List"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
            </button>
          </div>
        </div>

        {/* Devices Table */}
        <div className="flex-1 overflow-y-auto p-4">
          {loading && devices.length === 0 ? (
            <div className="py-12 text-center text-slate-500 font-mono text-xs">
              Loading registered endpoint fleet...
            </div>
          ) : filteredDevices.length === 0 ? (
            <div className="py-12 text-center text-slate-500 text-xs">
              No endpoint devices match the active filter criteria.
            </div>
          ) : (
            <div className="overflow-x-auto rounded-xl border border-border">
              <table className="w-full text-left text-xs">
                <thead className="bg-slate-900/90 text-slate-400 font-semibold border-b border-border">
                  <tr>
                    <th className="p-3">Device ID</th>
                    <th className="p-3">Hostname & IP</th>
                    <th className="p-3">Department</th>
                    <th className="p-3">Operating System</th>
                    <th className="p-3">Status</th>
                    <th className="p-3">Risk Score</th>
                    <th className="p-3">Alerts</th>
                    <th className="p-3 text-right">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border/60 text-slate-300">
                  {filteredDevices.map((d) => (
                    <tr key={d.device_id} className="hover:bg-slate-800/30 transition">
                      <td className="p-3 font-mono font-bold text-slate-100 flex items-center gap-2">
                        <Server className="w-3.5 h-3.5 text-blue-400 shrink-0" />
                        <span>{d.device_id}</span>
                      </td>

                      <td className="p-3">
                        <div className="font-medium text-slate-200">{d.hostname}</div>
                        <div className="font-mono text-[10px] text-slate-400">{d.ip_address}</div>
                      </td>

                      <td className="p-3">
                        <span className="px-2 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700 text-[11px]">
                          {d.department}
                        </span>
                      </td>

                      <td className="p-3 text-slate-300 text-[11px]">{d.os}</td>

                      <td className="p-3">
                        <button
                          onClick={() => handleToggleStatus(d.device_id, d.status)}
                          title="Click to toggle status (Online -> Isolated -> Offline)"
                          className={`flex items-center gap-1.5 px-2 py-0.5 rounded-full text-[10px] font-bold border transition ${
                            d.status === 'Online'
                              ? 'bg-emerald-500/15 text-emerald-400 border-emerald-500/30 hover:bg-emerald-500/25'
                              : d.status === 'Isolated'
                              ? 'bg-rose-500/20 text-rose-300 border-rose-500/40 hover:bg-rose-500/30'
                              : 'bg-slate-800 text-slate-400 border-slate-700 hover:bg-slate-700'
                          }`}
                        >
                          <span
                            className={`w-1.5 h-1.5 rounded-full ${
                              d.status === 'Online'
                                ? 'bg-emerald-400 animate-pulse'
                                : d.status === 'Isolated'
                                ? 'bg-rose-400'
                                : 'bg-slate-500'
                            }`}
                          />
                          {d.status.toUpperCase()}
                        </button>
                      </td>

                      <td className="p-3">{getRiskBadge(d.risk_score)}</td>

                      <td className="p-3 font-mono text-[11px] text-slate-400">
                        {d.alert_count ?? 0}
                      </td>

                      <td className="p-3 text-right">
                        <button
                          onClick={() => handleDeleteDevice(d.device_id)}
                          className="p-1 rounded text-slate-500 hover:text-rose-400 hover:bg-rose-950/40 transition"
                          title="Remove device"
                        >
                          <Trash2 className="w-3.5 h-3.5" />
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>

        {/* Modal Footer */}
        <div className="p-3 border-t border-border bg-slate-950/80 flex items-center justify-between text-xs text-slate-400">
          <div>
            Showing <strong>{filteredDevices.length}</strong> of <strong>{devices.length}</strong> registered devices
          </div>
          <button
            onClick={onClose}
            className="px-4 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-semibold transition"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
};
