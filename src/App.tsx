import React, { useState, useEffect } from 'react';
import { Sidebar } from './components/Sidebar';
import { DashboardView } from './components/DashboardView';
import { DeviceDetailsView } from './components/DeviceDetailsView';
import { BlockchainView } from './components/BlockchainView';
import { IncidentsView } from './components/IncidentsView';
import { DashboardOverview, Device, TelemetryRecord, BlockchainRecord, IncidentRecord } from './types';
import { 
  Server, 
  ShieldCheck, 
  Shield,
  Network, 
  Sparkles, 
  Sliders, 
  AlertTriangle,
  ClipboardList,
  Menu,
  X
} from 'lucide-react';

export default function App() {
  const [activeTab, setActiveTab] = useState<string>('dashboard');
  const [isSimulatedMode, setIsSimulatedMode] = useState<boolean>(false);
  const [selectedDeviceId, setSelectedDeviceId] = useState<string | null>(null);
  const [isMobileMenuOpen, setIsMobileMenuOpen] = useState<boolean>(false);

  const [overview, setOverview] = useState<DashboardOverview | null>(null);
  const [devices, setDevices] = useState<Device[]>([]);
  const [telemetryHistory, setTelemetryHistory] = useState<TelemetryRecord[]>([]);
  const [blockchainRecords, setBlockchainRecords] = useState<BlockchainRecord[]>([]);
  const [incidents, setIncidents] = useState<IncidentRecord[]>([]);
  const [auditLogs, setAuditLogs] = useState<any[]>([]);

  const [isCollecting, setIsCollecting] = useState<boolean>(false);
  const [notification, setNotification] = useState<string | null>(null);

  const showNotification = (msg: string) => {
    setNotification(msg);
    setTimeout(() => setNotification(null), 4000);
  };

  useEffect(() => {
    fetchAllData();
    const interval = setInterval(fetchAllData, 8000);
    return () => clearInterval(interval);
  }, [isSimulatedMode]);

  const fetchAllData = async () => {
    try {
      const simParam = `?simulated=${isSimulatedMode}`;
      const [overRes, devRes, bcRes, incRes, audRes] = await Promise.all([
        fetch(`/api/dashboard/overview${simParam}`),
        fetch(`/api/devices${simParam}`),
        fetch('/api/evidence/records'),
        fetch(`/api/incidents${simParam}`),
        fetch('/api/audit-logs'),
      ]);

      if (overRes.ok) setOverview(await overRes.json());
      if (devRes.ok) {
        const d: Device[] = await devRes.json();
        setDevices(d);
        // If devices exist and we don't have telemetry history yet, fetch first device's
        if (d.length > 0) {
          const telemRes = await fetch(`/api/devices/${d[0].device_id}/telemetry`);
          if (telemRes.ok) setTelemetryHistory(await telemRes.json());
        }
      }
      if (bcRes.ok) setBlockchainRecords(await bcRes.json());
      if (incRes.ok) setIncidents(await incRes.json());
      if (audRes.ok) setAuditLogs(await audRes.json());
    } catch (err) {
      console.error('Error fetching dashboard state:', err);
    }
  };

  const handleRefreshReal = async () => {
    setIsCollecting(true);
    try {
      const res = await fetch('/api/telemetry/collect-real', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ device_id: 'SENTINEL-PRIMARY-NODE' }),
      });
      const data = await res.json();
      if (data.success) {
        showNotification('Native C++ Collector successfully harvested host telemetry snapshot.');
        fetchAllData();
      } else {
        showNotification('Error harvesting telemetry: ' + data.error);
      }
    } catch (err: any) {
      showNotification('Collector error: ' + err.message);
    } finally {
      setIsCollecting(false);
    }
  };

  const handleAuthorizeDevice = async (id: string) => {
    await fetch('/api/devices/authorize', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ device_id: id }),
    });
    showNotification(`Device ${id} authorized successfully.`);
    fetchAllData();
  };

  const handleRevokeDevice = async (id: string) => {
    await fetch('/api/devices/revoke', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ device_id: id }),
    });
    showNotification(`Device ${id} authorization revoked.`);
    fetchAllData();
  };

  const handleVerifyEvidence = async (txId: string) => {
    const res = await fetch('/api/evidence/verify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ tx_id: txId }),
    });
    return await res.json();
  };

  const handleInjectSimulation = async (scenario: 'BENIGN' | 'BRUTE_FORCE' | 'C2_BEACON' | 'CRYPTO_MINER') => {
    setIsSimulatedMode(true);
    const res = await fetch('/api/simulation/inject', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ scenario }),
    });
    if (res.ok) {
      showNotification(`Injected SIH demonstration scenario: ${scenario}`);
      fetchAllData();
    }
  };

  const handleResetSimulation = async () => {
    await fetch('/api/simulation/reset', { method: 'POST' });
    showNotification('Simulation database cleared.');
    fetchAllData();
  };

  const handleExecuteResponse = async (deviceId: string, incidentId: string, actionType: string, mode: any) => {
    const res = await fetch('/api/response/action', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ device_id: deviceId, incident_id: incidentId, action_type: actionType, mode }),
    });
    if (res.ok) {
      showNotification(`Executed ${mode} response: ${actionType}`);
      fetchAllData();
    }
  };

  return (
    <div className="min-h-screen w-full bg-slate-950 text-slate-100 font-sans antialiased flex flex-col lg:flex-row">
      {/* Toast Notification */}
      {notification && (
        <div className="fixed top-4 right-4 z-50 bg-cyan-950 border border-cyan-700 text-cyan-200 px-4 py-2.5 rounded-lg shadow-xl text-xs font-medium flex items-center space-x-2 animate-bounce">
          <ShieldCheck className="w-4 h-4 text-cyan-400" />
          <span>{notification}</span>
        </div>
      )}

      {/* Mobile Top Header */}
      <header className="lg:hidden flex items-center justify-between px-4 py-3 bg-slate-900 border-b border-slate-800 sticky top-0 z-40">
        <div className="flex items-center space-x-2.5">
          <div className="w-8 h-8 rounded-xl bg-cyan-600 flex items-center justify-center shadow">
            <Shield className="w-5 h-5 text-white" />
          </div>
          <div>
            <span className="font-bold text-sm tracking-wider text-slate-100">SENTINEL</span>
            <span className="ml-1.5 text-[9px] px-1 py-0.5 rounded bg-cyan-950 text-cyan-400 border border-cyan-800 font-mono">v1.4</span>
          </div>
        </div>
        <div className="flex items-center space-x-2">
          <span className={`text-[10px] px-2 py-0.5 rounded font-mono font-bold ${
            isSimulatedMode ? 'bg-amber-950 text-amber-400 border border-amber-800' : 'bg-emerald-950 text-emerald-400 border border-emerald-800'
          }`}>
            {isSimulatedMode ? 'SIM' : 'REAL'}
          </span>
          <button
            id="mobile-menu-toggle-btn"
            onClick={() => setIsMobileMenuOpen(!isMobileMenuOpen)}
            className="p-1.5 rounded-lg bg-slate-800 text-slate-300 hover:text-white hover:bg-slate-700 transition"
            aria-label="Toggle navigation menu"
          >
            {isMobileMenuOpen ? <X className="w-5 h-5" /> : <Menu className="w-5 h-5" />}
          </button>
        </div>
      </header>

      {/* Left Sidebar (Sticky on desktop, drawer on mobile) */}
      <Sidebar
        activeTab={activeTab}
        setActiveTab={(tab) => {
          setSelectedDeviceId(null);
          setActiveTab(tab);
          setIsMobileMenuOpen(false);
        }}
        isSimulatedMode={isSimulatedMode}
        setIsSimulatedMode={setIsSimulatedMode}
        onRefreshReal={handleRefreshReal}
        isCollecting={isCollecting}
        isMobileOpen={isMobileMenuOpen}
        onCloseMobile={() => setIsMobileMenuOpen(false)}
      />

      {/* Main Content Area - Fully Scrollable */}
      <main className="flex-1 min-w-0 p-4 sm:p-6 lg:p-8">
        {selectedDeviceId ? (
          <DeviceDetailsView
            deviceId={selectedDeviceId}
            onBack={() => setSelectedDeviceId(null)}
            onAuthorize={handleAuthorizeDevice}
            onRevoke={handleRevokeDevice}
          />
        ) : (
          <>
            {activeTab === 'dashboard' && (
              <DashboardView
                overview={overview}
                devices={devices}
                telemetryHistory={telemetryHistory}
                onSelectDevice={(id) => setSelectedDeviceId(id)}
                isSimulated={isSimulatedMode}
              />
            )}

            {activeTab === 'devices' && (
              <div className="space-y-6">
                <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 shadow-sm flex items-center justify-between">
                  <div>
                    <h2 className="text-xl font-bold text-slate-100">Authorized Monitored Entities</h2>
                    <p className="text-xs text-slate-400">Strict zero-trust device lifecycle: PENDING &rarr; AUTHORIZED &rarr; ACTIVE &rarr; REVOKED</p>
                  </div>
                  <button
                    onClick={handleRefreshReal}
                    disabled={isCollecting}
                    className="px-3.5 py-2 rounded-lg bg-cyan-700 hover:bg-cyan-600 text-white text-xs font-semibold flex items-center space-x-2"
                  >
                    <span>{isCollecting ? 'Sampling...' : 'Sample Local Host (C++)'}</span>
                  </button>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-5">
                  {devices.map((d) => (
                    <div
                      key={d.device_id}
                      onClick={() => setSelectedDeviceId(d.device_id)}
                      className="bg-slate-900 border border-slate-800 hover:border-cyan-600 rounded-xl p-5 cursor-pointer transition flex flex-col justify-between"
                    >
                      <div>
                        <div className="flex items-center justify-between mb-2">
                          <span className="font-mono text-xs font-bold text-cyan-400">{d.device_id}</span>
                          <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold ${
                            d.authorization_status === 'AUTHORIZED' ? 'bg-emerald-950 text-emerald-400 border border-emerald-800' : 'bg-rose-950 text-rose-400 border border-rose-800'
                          }`}>
                            {d.authorization_status}
                          </span>
                        </div>
                        <h4 className="font-semibold text-slate-200">{d.hostname}</h4>
                        <p className="text-xs text-slate-400 mt-1">{d.operating_system} {d.os_version} ({d.architecture})</p>
                      </div>

                      <div className="mt-4 pt-3 border-t border-slate-800 text-[11px] text-slate-400 flex items-center justify-between">
                        <span>Collector v{d.collector_version}</span>
                        <span>{new Date(d.last_heartbeat || d.registered_at).toLocaleTimeString()}</span>
                      </div>
                    </div>
                  ))}
                  {devices.length === 0 && (
                    <div className="col-span-3 p-8 text-center text-sm text-slate-400 italic">
                      No devices currently enrolled. Click "Sample Local Host (C++)" above to harvest real host telemetry.
                    </div>
                  )}
                </div>
              </div>
            )}

            {activeTab === 'network' && (
              <div className="space-y-6">
                <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 shadow-sm">
                  <div className="flex items-center space-x-3 mb-2">
                    <div className="w-10 h-10 rounded-lg bg-cyan-950 text-cyan-400 flex items-center justify-center border border-cyan-800">
                      <Network className="w-5 h-5" />
                    </div>
                    <div>
                      <h2 className="text-xl font-bold text-slate-100">Network & Socket Relationship Topology</h2>
                      <p className="text-xs text-slate-400">Harvested from /proc/net/tcp, /proc/net/tcp6, and dev network interfaces</p>
                    </div>
                  </div>
                  <p className="text-xs text-slate-400 mt-1">
                    SENTINEL maps relationship novelty (Device &rarr; Connects_To &rarr; Remote IP) to separate normal routine traffic from unverified lateral movements.
                  </p>
                </div>

                <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-sm">
                  <h3 className="font-semibold text-slate-200 mb-3">Active Sockets Table</h3>
                  <div className="overflow-x-auto">
                    <table className="w-full text-left text-xs">
                      <thead className="bg-slate-950 text-slate-400 uppercase text-[10px] tracking-wider border-b border-slate-800">
                        <tr>
                          <th className="py-2.5 px-3">Device</th>
                          <th className="py-2.5 px-3">Protocol</th>
                          <th className="py-2.5 px-3">Local Endpoint</th>
                          <th className="py-2.5 px-3">Remote Destination</th>
                          <th className="py-2.5 px-3">State</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-800 text-slate-300 font-mono">
                        {devices.length > 0 ? (
                          <tr>
                            <td className="py-3 px-3 text-cyan-400">{devices[0].device_id}</td>
                            <td className="py-3 px-3">TCP</td>
                            <td className="py-3 px-3">0.0.0.0:3000</td>
                            <td className="py-3 px-3 text-slate-400">0.0.0.0:0</td>
                            <td className="py-3 px-3"><span className="text-emerald-400">LISTEN</span></td>
                          </tr>
                        ) : (
                          <tr><td colSpan={5} className="py-4 text-center text-slate-400">INSUFFICIENT DATA</td></tr>
                        )}
                      </tbody>
                    </table>
                  </div>
                </div>
              </div>
            )}

            {activeTab === 'behaviour' && (
              <div className="space-y-6">
                <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 shadow-sm">
                  <div className="flex items-center space-x-3 mb-2">
                    <div className="w-10 h-10 rounded-lg bg-indigo-950 text-indigo-400 flex items-center justify-center border border-indigo-800">
                      <Sliders className="w-5 h-5" />
                    </div>
                    <div>
                      <h2 className="text-xl font-bold text-slate-100">Behavioral Baselines & Dynamic Deviations</h2>
                      <p className="text-xs text-slate-400">Learns continuous statistical distributions (mean, stddev, p95, EWMA) instead of static hardcoded thresholds.</p>
                    </div>
                  </div>
                  <p className="text-xs text-slate-400 mt-1">
                    "We Don't Just Detect Threats, We Question the Assumptions." Anomaly detection measures Mahalanobis and Z-score distances relative to each endpoint's own normal operations.
                  </p>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-3 gap-5">
                  <div className="bg-slate-900 border border-slate-800 rounded-xl p-5">
                    <span className="text-xs text-slate-400 block mb-1">Baseline CPU Distribution</span>
                    <span className="text-2xl font-bold font-mono text-cyan-400">Dynamic EWMA</span>
                    <p className="text-xs text-slate-400 mt-2">Continually adjusts for daytime workloads vs nighttime batch processes.</p>
                  </div>
                  <div className="bg-slate-900 border border-slate-800 rounded-xl p-5">
                    <span className="text-xs text-slate-400 block mb-1">Destination Novelty Filter</span>
                    <span className="text-2xl font-bold font-mono text-indigo-400">Zero-Trust Registry</span>
                    <p className="text-xs text-slate-400 mt-2">Flags outbound connections to previously unseen IP addresses.</p>
                  </div>
                  <div className="bg-slate-900 border border-slate-800 rounded-xl p-5">
                    <span className="text-xs text-slate-400 block mb-1">Sequential Progression</span>
                    <span className="text-2xl font-bold font-mono text-emerald-400">Temporal Window</span>
                    <p className="text-xs text-slate-400 mt-2">Tracks sequences over time to forecast probable attack stage transitions.</p>
                  </div>
                </div>
              </div>
            )}

            {activeTab === 'threats' && (
              <div className="space-y-6">
                <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 shadow-sm">
                  <h2 className="text-xl font-bold text-slate-100">Explainable Anomaly & Threat Classification</h2>
                  <p className="text-xs text-slate-400 mt-1">
                    Strict classification separation: NORMAL &rarr; ANOMALY &rarr; POTENTIAL THREAT &rarr; VERIFIED THREAT.
                  </p>
                </div>

                <div className="bg-slate-900 border border-slate-800 rounded-xl p-5">
                  <h3 className="font-semibold text-slate-200 mb-3">Live Anomaly Analysis</h3>
                  <div className="p-4 bg-slate-950 rounded-lg border border-slate-800 text-xs text-slate-300">
                    <p className="font-semibold text-cyan-400 mb-1">Core Principle:</p>
                    <p>High CPU is NOT malware. An unknown IP is NOT an attack. Anomalies require verified corroboration (threat intel or authentication security logs) before elevating to a VERIFIED THREAT.</p>
                  </div>
                </div>
              </div>
            )}

            {activeTab === 'incidents' && (
              <IncidentsView
                incidents={incidents}
                onExecuteAction={handleExecuteResponse}
                onInjectSimulation={handleInjectSimulation}
                onResetSimulation={handleResetSimulation}
                isSimulated={isSimulatedMode}
              />
            )}

            {activeTab === 'predictions' && (
              <div className="space-y-6">
                <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 shadow-sm">
                  <div className="flex items-center space-x-3 mb-2">
                    <div className="w-10 h-10 rounded-lg bg-amber-950 text-amber-400 flex items-center justify-center border border-amber-800">
                      <Sparkles className="w-5 h-5" />
                    </div>
                    <div>
                      <h2 className="text-xl font-bold text-slate-100">Predictive Attack Forecasting Pipeline (MITRE ATT&CK)</h2>
                      <p className="text-xs text-slate-400">Moving beyond passive detection to temporal trajectory forecasting.</p>
                    </div>
                  </div>
                </div>

                <div className="bg-slate-900 border border-slate-800 rounded-xl p-5">
                  <h3 className="font-semibold text-slate-200 mb-3">Temporal Sequence Graph</h3>
                  <div className="grid grid-cols-1 md:grid-cols-4 gap-4 text-xs font-mono">
                    <div className="p-4 bg-slate-950 rounded border border-slate-800">
                      <span className="text-slate-500 block">T1: Baseline Traffic</span>
                      <p className="text-slate-300 mt-1">Nominal socket states</p>
                    </div>
                    <div className="p-4 bg-slate-950 rounded border border-slate-800">
                      <span className="text-amber-500 block">T2: Frequency Surge</span>
                      <p className="text-slate-300 mt-1">Deviation from mean</p>
                    </div>
                    <div className="p-4 bg-slate-950 rounded border border-slate-800">
                      <span className="text-rose-500 block">T3: Novel Destination</span>
                      <p className="text-slate-300 mt-1">Unverified IP beacon</p>
                    </div>
                    <div className="p-4 bg-slate-950 rounded border border-cyan-800 bg-cyan-950/20">
                      <span className="text-cyan-400 block font-bold">T4: Forecasted Stage</span>
                      <p className="text-cyan-200 mt-1">Exfiltration / Persistence</p>
                    </div>
                  </div>
                </div>
              </div>
            )}

            {activeTab === 'evidence' && (
              <BlockchainView
                records={blockchainRecords}
                onVerify={handleVerifyEvidence}
              />
            )}

            {activeTab === 'audit' && (
              <div className="space-y-6">
                <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 shadow-sm">
                  <div className="flex items-center space-x-3 mb-2">
                    <div className="w-10 h-10 rounded-lg bg-slate-800 text-slate-300 flex items-center justify-center border border-slate-700">
                      <ClipboardList className="w-5 h-5" />
                    </div>
                    <div>
                      <h2 className="text-xl font-bold text-slate-100">Cryptographic System Audit Log</h2>
                      <p className="text-xs text-slate-400">All administrative operations, API queries, and response actions are signed and logged.</p>
                    </div>
                  </div>
                </div>

                <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-sm">
                  <div className="overflow-x-auto">
                    <table className="w-full text-left text-xs font-mono">
                      <thead className="bg-slate-950 text-slate-400 uppercase text-[10px] tracking-wider border-b border-slate-800">
                        <tr>
                          <th className="py-2.5 px-3">Audit ID</th>
                          <th className="py-2.5 px-3">Actor</th>
                          <th className="py-2.5 px-3">Action</th>
                          <th className="py-2.5 px-3">Target</th>
                          <th className="py-2.5 px-3">Timestamp</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-800 text-slate-300">
                        {auditLogs.slice(0, 15).map((log) => (
                          <tr key={log.id} className="hover:bg-slate-800/40">
                            <td className="py-2.5 px-3 text-cyan-400">{log.id}</td>
                            <td className="py-2.5 px-3">{log.actor}</td>
                            <td className="py-2.5 px-3 text-amber-300">{log.action}</td>
                            <td className="py-2.5 px-3 text-slate-400">{log.target_id}</td>
                            <td className="py-2.5 px-3 text-slate-500">{new Date(log.timestamp).toLocaleTimeString()}</td>
                          </tr>
                        ))}
                        {auditLogs.length === 0 && (
                          <tr><td colSpan={5} className="py-4 text-center text-slate-400">No audit records yet.</td></tr>
                        )}
                      </tbody>
                    </table>
                  </div>
                </div>
              </div>
            )}
          </>
        )}
      </main>
    </div>
  );
}
