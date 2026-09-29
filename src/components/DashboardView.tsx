import React from 'react';
import { 
  Server, 
  ShieldAlert, 
  AlertTriangle, 
  HeartPulse, 
  TrendingUp, 
  ArrowUpRight, 
  Cpu, 
  HardDrive,
  Activity
} from 'lucide-react';
import { DashboardOverview, Device, TelemetryRecord } from '../types';
import { ResponsiveContainer, AreaChart, Area, XAxis, YAxis, Tooltip, CartesianGrid } from 'recharts';

interface DashboardViewProps {
  overview: DashboardOverview | null;
  devices: Device[];
  telemetryHistory: TelemetryRecord[];
  onSelectDevice: (deviceId: string) => void;
  isSimulated: boolean;
}

export const DashboardView: React.FC<DashboardViewProps> = ({
  overview,
  devices,
  telemetryHistory,
  onSelectDevice,
  isSimulated
}) => {
  const chartData = telemetryHistory.map((t, idx) => ({
    time: new Date(t.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }),
    cpu: t.cpu_percent,
    memory: t.memory_percent,
    connections: t.active_connections_count
  })).reverse();

  return (
    <div className="space-y-6">
      {/* Top Banner if in Simulation Mode */}
      {isSimulated && (
        <div className="bg-amber-950/70 border border-amber-800 text-amber-200 px-4 py-2.5 rounded-lg flex items-center justify-between text-sm">
          <div className="flex items-center space-x-2">
            <AlertTriangle className="w-4 h-4 text-amber-400" />
            <span className="font-semibold">SIMULATION MODE ACTIVE:</span>
            <span>All displayed entities and telemetric events are generated in an isolated sandbox.</span>
          </div>
          <span className="text-xs uppercase tracking-wider font-mono bg-amber-900/60 px-2 py-0.5 rounded border border-amber-700">Sandbox</span>
        </div>
      )}

      {/* KPI Metrics Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-5">
        {/* Total Authorized Devices */}
        <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-5 shadow-sm">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-slate-400 uppercase tracking-wider">Authorized Devices</span>
            <div className="w-8 h-8 rounded-lg bg-blue-950 text-blue-400 flex items-center justify-center border border-blue-900">
              <Server className="w-4 h-4" />
            </div>
          </div>
          <div className="mt-4 flex items-baseline justify-between">
            <span className="text-3xl font-bold font-mono text-slate-100">
              {overview ? overview.total_devices : '0'}
            </span>
            <span className="text-xs text-emerald-400 font-medium">100% Verified</span>
          </div>
          <p className="mt-1 text-xs text-slate-400">All registered via C++ Collector Agent</p>
        </div>

        {/* Active Threats */}
        <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-5 shadow-sm">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-slate-400 uppercase tracking-wider">Active Threats</span>
            <div className="w-8 h-8 rounded-lg bg-rose-950 text-rose-400 flex items-center justify-center border border-rose-900">
              <ShieldAlert className="w-4 h-4" />
            </div>
          </div>
          <div className="mt-4 flex items-baseline justify-between">
            <span className={`text-3xl font-bold font-mono ${overview && overview.active_threats > 0 ? 'text-rose-400' : 'text-slate-100'}`}>
              {overview ? overview.active_threats : '0'}
            </span>
            <span className="text-xs text-slate-400">Validated signals</span>
          </div>
          <p className="mt-1 text-xs text-slate-400">Anomaly ≠ Threat (Strict MITRE Mapping)</p>
        </div>

        {/* Open Incidents */}
        <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-5 shadow-sm">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-slate-400 uppercase tracking-wider">Open Incidents</span>
            <div className="w-8 h-8 rounded-lg bg-amber-950 text-amber-400 flex items-center justify-center border border-amber-900">
              <AlertTriangle className="w-4 h-4" />
            </div>
          </div>
          <div className="mt-4 flex items-baseline justify-between">
            <span className="text-3xl font-bold font-mono text-slate-100">
              {overview ? overview.open_incidents : '0'}
            </span>
            <span className="text-xs text-amber-400 font-medium">Needs Attention</span>
          </div>
          <p className="mt-1 text-xs text-slate-400">Chain-of-custody sealed on-chain</p>
        </div>

        {/* Cyber Health Score */}
        <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-5 shadow-sm">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-slate-400 uppercase tracking-wider">Cyber Health Score</span>
            <div className="w-8 h-8 rounded-lg bg-emerald-950 text-emerald-400 flex items-center justify-center border border-emerald-900">
              <HeartPulse className="w-4 h-4" />
            </div>
          </div>
          <div className="mt-4 flex items-baseline justify-between">
            <span className="text-3xl font-bold font-mono text-emerald-400">
              {overview && overview.cyber_health_score !== null ? `${overview.cyber_health_score}/100` : 'INSUFFICIENT DATA'}
            </span>
            <span className="text-xs text-emerald-400 font-medium">Posture</span>
          </div>
          <p className="mt-1 text-xs text-slate-400">Calculated from dynamic telemetry deviations</p>
        </div>
      </div>

      {/* Main Charts & Overview Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Telemetry Resource Timeline */}
        <div className="lg:col-span-2 bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-sm">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h3 className="font-semibold text-slate-200">Real-Time Host Telemetry Timeline</h3>
              <p className="text-xs text-slate-400">Direct procfs & sysinfo kernel telemetry streaming via C++20</p>
            </div>
            <div className="flex items-center space-x-3 text-xs">
              <span className="flex items-center text-cyan-400">
                <span className="w-2.5 h-2.5 rounded-full bg-cyan-400 mr-1.5"></span> CPU %
              </span>
              <span className="flex items-center text-indigo-400">
                <span className="w-2.5 h-2.5 rounded-full bg-indigo-400 mr-1.5"></span> Memory %
              </span>
            </div>
          </div>

          {chartData.length > 0 ? (
            <div className="h-64 w-full">
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={chartData}>
                  <defs>
                    <linearGradient id="cpuGradient" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#06b6d4" stopOpacity={0.4}/>
                      <stop offset="95%" stopColor="#06b6d4" stopOpacity={0.0}/>
                    </linearGradient>
                    <linearGradient id="memGradient" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#6366f1" stopOpacity={0.4}/>
                      <stop offset="95%" stopColor="#6366f1" stopOpacity={0.0}/>
                    </linearGradient>
                  </defs>
                  <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
                  <XAxis dataKey="time" stroke="#64748b" tick={{ fontSize: 11 }} />
                  <YAxis domain={[0, 100]} stroke="#64748b" tick={{ fontSize: 11 }} />
                  <Tooltip 
                    contentStyle={{ backgroundColor: '#0f172a', borderColor: '#334155', borderRadius: '8px' }}
                    labelStyle={{ color: '#94a3b8' }}
                  />
                  <Area type="monotone" dataKey="cpu" stroke="#06b6d4" strokeWidth={2} fillOpacity={1} fill="url(#cpuGradient)" name="CPU %" />
                  <Area type="monotone" dataKey="memory" stroke="#6366f1" strokeWidth={2} fillOpacity={1} fill="url(#memGradient)" name="Memory %" />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          ) : (
            <div className="h-64 flex items-center justify-center text-slate-400 text-sm italic">
              INSUFFICIENT DATA (Awaiting C++ collector samples)
            </div>
          )}
        </div>

        {/* Top Risk Entities */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-sm flex flex-col justify-between">
          <div>
            <h3 className="font-semibold text-slate-200 mb-1">High-Risk Monitored Entities</h3>
            <p className="text-xs text-slate-400 mb-4">Ranked by explainable multi-factor risk engine</p>

            <div className="space-y-3">
              {devices.slice(0, 4).map((d) => (
                <div 
                  key={d.device_id}
                  onClick={() => onSelectDevice(d.device_id)}
                  className="p-3 rounded-lg bg-slate-950 border border-slate-800 hover:border-cyan-700/60 cursor-pointer transition flex items-center justify-between"
                >
                  <div className="min-w-0">
                    <p className="font-mono text-sm font-semibold text-slate-200 truncate">{d.hostname || d.device_id}</p>
                    <p className="text-[11px] text-slate-400">{d.operating_system} {d.os_version} ({d.architecture})</p>
                  </div>
                  <div className="text-right ml-3 flex-shrink-0">
                    <span className={`inline-block px-2 py-0.5 rounded text-xs font-mono font-bold ${
                      d.authorization_status === 'AUTHORIZED' ? 'bg-emerald-950 text-emerald-400 border border-emerald-800' : 'bg-rose-950 text-rose-400 border border-rose-800'
                    }`}>
                      {d.authorization_status}
                    </span>
                  </div>
                </div>
              ))}
              {devices.length === 0 && (
                <div className="p-4 text-center text-sm text-slate-400 italic">
                  No devices registered. Click "Harvest Native C++" to initialize primary node.
                </div>
              )}
            </div>
          </div>

          <div className="mt-4 pt-3 border-t border-slate-800 text-[11px] text-slate-400 flex items-center justify-between">
            <span>Traceable Source</span>
            <span className="font-mono text-cyan-400">/proc/stat + sysinfo</span>
          </div>
        </div>
      </div>

      {/* Recent Alerts Feed */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-sm">
        <h3 className="font-semibold text-slate-200 mb-1">Recent Anomaly & Security Decisions</h3>
        <p className="text-xs text-slate-400 mb-4">Every alert is traceable with baseline deviation and evidence proof</p>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-slate-950 text-slate-400 uppercase text-[10px] tracking-wider border-b border-slate-800">
              <tr>
                <th className="py-2.5 px-3">Device Target</th>
                <th className="py-2.5 px-3">Classification</th>
                <th className="py-2.5 px-3">Risk Score</th>
                <th className="py-2.5 px-3">Explainable Root Causes</th>
                <th className="py-2.5 px-3">Response Recommendation</th>
                <th className="py-2.5 px-3">Time</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800 text-slate-300">
              {overview?.recent_alerts?.slice(0, 5).map((a) => {
                let reasons: string[] = [];
                try {
                  reasons = JSON.parse(a.key_reasons);
                } catch {
                  reasons = [a.key_reasons];
                }
                return (
                  <tr key={a.id} className="hover:bg-slate-800/40 transition">
                    <td className="py-3 px-3 font-mono font-medium text-cyan-400">{a.device_id}</td>
                    <td className="py-3 px-3">
                      <span className={`px-2 py-0.5 rounded text-[11px] font-semibold ${
                        a.classification === 'VERIFIED THREAT' ? 'bg-rose-950 text-rose-300 border border-rose-800' :
                        a.classification === 'POTENTIAL THREAT' ? 'bg-amber-950 text-amber-300 border border-amber-800' :
                        'bg-slate-800 text-slate-300'
                      }`}>
                        {a.classification}
                      </span>
                    </td>
                    <td className="py-3 px-3 font-mono font-bold">
                      <span className={a.risk_score >= 60 ? 'text-rose-400' : a.risk_score >= 30 ? 'text-amber-400' : 'text-emerald-400'}>
                        {a.risk_score.toFixed(1)} / 100
                      </span>
                    </td>
                    <td className="py-3 px-3 max-w-md">
                      <ul className="list-disc list-inside space-y-0.5 text-slate-300">
                        {reasons.slice(0, 2).map((r, i) => (
                          <li key={i} className="truncate">{r}</li>
                        ))}
                      </ul>
                    </td>
                    <td className="py-3 px-3">
                      <span className="font-mono text-[11px] px-2 py-0.5 rounded bg-slate-950 border border-slate-700 text-slate-300">
                        {a.recommended_response}
                      </span>
                    </td>
                    <td className="py-3 px-3 text-slate-400 font-mono">
                      {new Date(a.timestamp).toLocaleTimeString()}
                    </td>
                  </tr>
                );
              })}
              {(!overview?.recent_alerts || overview.recent_alerts.length === 0) && (
                <tr>
                  <td colSpan={6} className="py-6 text-center text-slate-400 italic">
                    No anomalous events recorded yet. System monitoring nominal baseline.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
