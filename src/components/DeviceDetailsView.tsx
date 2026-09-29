import React, { useState, useEffect } from 'react';
import { 
  Server, 
  Cpu, 
  HardDrive, 
  Network, 
  ShieldAlert, 
  Activity, 
  CheckCircle, 
  AlertTriangle, 
  Clock, 
  ArrowLeft,
  Key,
  ShieldCheck,
  Terminal,
  Radio
} from 'lucide-react';
import { Device, TelemetryRecord, NetworkConnectionRecord, ProcessRecord, BehaviourBaseline, AnomalyRecord, PredictionRecord, RiskRecord } from '../types';

interface DeviceDetailsViewProps {
  deviceId: string;
  onBack: () => void;
  onAuthorize: (id: string) => void;
  onRevoke: (id: string) => void;
}

export const DeviceDetailsView: React.FC<DeviceDetailsViewProps> = ({
  deviceId,
  onBack,
  onAuthorize,
  onRevoke
}) => {
  const [device, setDevice] = useState<Device | null>(null);
  const [telemetry, setTelemetry] = useState<TelemetryRecord[]>([]);
  const [connections, setConnections] = useState<NetworkConnectionRecord[]>([]);
  const [processes, setProcesses] = useState<ProcessRecord[]>([]);
  const [baseline, setBaseline] = useState<BehaviourBaseline | null>(null);
  const [anomalies, setAnomalies] = useState<AnomalyRecord[]>([]);
  const [predictions, setPredictions] = useState<PredictionRecord[]>([]);
  const [risk, setRisk] = useState<RiskRecord | null>(null);
  const [loading, setLoading] = useState<boolean>(true);

  useEffect(() => {
    fetchDeviceData();
  }, [deviceId]);

  const fetchDeviceData = async () => {
    setLoading(true);
    try {
      const [devRes, telemRes, netRes, procRes, baseRes, anomRes, predRes, riskRes] = await Promise.all([
        fetch(`/api/devices/${deviceId}`),
        fetch(`/api/devices/${deviceId}/telemetry`),
        fetch(`/api/devices/${deviceId}/network`),
        fetch(`/api/devices/${deviceId}/processes`),
        fetch(`/api/devices/${deviceId}/baseline`),
        fetch(`/api/devices/${deviceId}/anomalies`),
        fetch(`/api/devices/${deviceId}/predictions`),
        fetch(`/api/devices/${deviceId}/risk`),
      ]);

      if (devRes.ok) setDevice(await devRes.json());
      if (telemRes.ok) setTelemetry(await telemRes.json());
      if (netRes.ok) setConnections(await netRes.json());
      if (procRes.ok) setProcesses(await procRes.json());
      if (baseRes.ok) {
        const b = await baseRes.json();
        setBaseline(b.status === 'INSUFFICIENT DATA' ? null : b);
      }
      if (anomRes.ok) setAnomalies(await anomRes.json());
      if (predRes.ok) setPredictions(await predRes.json());
      if (riskRes.ok) {
        const r = await riskRes.json();
        setRisk(r.status === 'INSUFFICIENT DATA' ? null : r);
      }
    } catch (err) {
      console.error('Failed to load device details:', err);
    } finally {
      setLoading(false);
    }
  };

  const latestTelemetry = telemetry.length > 0 ? telemetry[0] : null;

  return (
    <div className="space-y-6">
      {/* Back button and header */}
      <div className="flex items-center justify-between">
        <button
          onClick={onBack}
          className="flex items-center space-x-2 text-xs font-semibold text-slate-400 hover:text-slate-200 transition"
        >
          <ArrowLeft className="w-4 h-4" />
          <span>Back to Overview</span>
        </button>

        <div className="flex items-center space-x-3">
          {device?.authorization_status !== 'AUTHORIZED' ? (
            <button
              onClick={() => onAuthorize(deviceId)}
              className="px-3 py-1.5 rounded bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-semibold flex items-center space-x-1.5 transition"
            >
              <ShieldCheck className="w-3.5 h-3.5" />
              <span>Authorize Device</span>
            </button>
          ) : (
            <button
              onClick={() => onRevoke(deviceId)}
              className="px-3 py-1.5 rounded bg-rose-600 hover:bg-rose-500 text-white text-xs font-semibold flex items-center space-x-1.5 transition"
            >
              <AlertTriangle className="w-3.5 h-3.5" />
              <span>Revoke Credentials</span>
            </button>
          )}
        </div>
      </div>

      {/* Device Overview Banner */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 shadow-sm">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
          <div>
            <div className="flex items-center space-x-3">
              <h2 className="text-xl font-bold font-mono text-slate-100">{device?.hostname || deviceId}</h2>
              <span className={`px-2 py-0.5 rounded text-xs font-mono font-bold ${
                device?.authorization_status === 'AUTHORIZED' ? 'bg-emerald-950 text-emerald-400 border border-emerald-800' : 'bg-rose-950 text-rose-400 border border-rose-800'
              }`}>
                {device?.authorization_status || 'UNKNOWN'}
              </span>
              <span className="text-xs text-slate-400 font-mono">ID: {deviceId}</span>
            </div>
            <p className="mt-1 text-xs text-slate-400">
              {device?.operating_system} {device?.os_version} | Architecture: {device?.architecture} | Collector: {device?.collector_version}
            </p>
          </div>

          <div className="flex items-center space-x-6 text-xs">
            <div className="text-right">
              <span className="text-slate-400 block">Current Risk</span>
              <span className={`font-mono text-lg font-bold ${
                risk && risk.risk_score >= 60 ? 'text-rose-400' : risk && risk.risk_score >= 30 ? 'text-amber-400' : 'text-emerald-400'
              }`}>
                {risk ? `${risk.risk_score.toFixed(1)} / 100` : 'INSUFFICIENT DATA'}
              </span>
            </div>
            <div className="text-right">
              <span className="text-slate-400 block">Classification</span>
              <span className="font-mono text-sm font-semibold text-slate-200">
                {risk ? risk.classification : 'INSUFFICIENT DATA'}
              </span>
            </div>
          </div>
        </div>
      </div>

      {/* Real Hardware Telemetry Gauges */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        {/* CPU */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-4">
          <div className="flex items-center justify-between text-xs text-slate-400">
            <span>CPU Utilization</span>
            <Cpu className="w-4 h-4 text-cyan-400" />
          </div>
          <div className="mt-2 flex items-baseline justify-between">
            <span className="text-2xl font-bold font-mono text-slate-100">
              {latestTelemetry ? `${latestTelemetry.cpu_percent.toFixed(1)}%` : 'INSUFFICIENT DATA'}
            </span>
            <span className="text-[11px] text-slate-400">
              Baseline: {baseline ? `${baseline.cpu_mean.toFixed(1)}%` : 'N/A'}
            </span>
          </div>
          <div className="mt-2 w-full bg-slate-800 rounded-full h-1.5 overflow-hidden">
            <div 
              className="bg-cyan-500 h-1.5 rounded-full transition-all duration-500" 
              style={{ width: `${Math.min(100, latestTelemetry ? latestTelemetry.cpu_percent : 0)}%` }}
            />
          </div>
        </div>

        {/* RAM */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-4">
          <div className="flex items-center justify-between text-xs text-slate-400">
            <span>Memory Utilization</span>
            <Activity className="w-4 h-4 text-indigo-400" />
          </div>
          <div className="mt-2 flex items-baseline justify-between">
            <span className="text-2xl font-bold font-mono text-slate-100">
              {latestTelemetry ? `${latestTelemetry.memory_percent.toFixed(1)}%` : 'INSUFFICIENT DATA'}
            </span>
            <span className="text-[11px] text-slate-400">
              Used: {latestTelemetry ? `${(latestTelemetry.memory_used_bytes / (1024 * 1024)).toFixed(0)} MB` : 'N/A'}
            </span>
          </div>
          <div className="mt-2 w-full bg-slate-800 rounded-full h-1.5 overflow-hidden">
            <div 
              className="bg-indigo-500 h-1.5 rounded-full transition-all duration-500" 
              style={{ width: `${Math.min(100, latestTelemetry ? latestTelemetry.memory_percent : 0)}%` }}
            />
          </div>
        </div>

        {/* Disk */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-4">
          <div className="flex items-center justify-between text-xs text-slate-400">
            <span>Root Storage Space</span>
            <HardDrive className="w-4 h-4 text-emerald-400" />
          </div>
          <div className="mt-2 flex items-baseline justify-between">
            <span className="text-2xl font-bold font-mono text-slate-100">
              {latestTelemetry ? `${latestTelemetry.disk_percent.toFixed(1)}%` : 'INSUFFICIENT DATA'}
            </span>
            <span className="text-[11px] text-slate-400">
              Capacity: {device ? `${(device.total_disk_bytes / (1024 * 1024 * 1024)).toFixed(0)} GB` : 'N/A'}
            </span>
          </div>
          <div className="mt-2 w-full bg-slate-800 rounded-full h-1.5 overflow-hidden">
            <div 
              className="bg-emerald-500 h-1.5 rounded-full transition-all duration-500" 
              style={{ width: `${Math.min(100, latestTelemetry ? latestTelemetry.disk_percent : 0)}%` }}
            />
          </div>
        </div>

        {/* Network Connections */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-4">
          <div className="flex items-center justify-between text-xs text-slate-400">
            <span>Active Sockets</span>
            <Network className="w-4 h-4 text-amber-400" />
          </div>
          <div className="mt-2 flex items-baseline justify-between">
            <span className="text-2xl font-bold font-mono text-slate-100">
              {latestTelemetry ? latestTelemetry.active_connections_count : '0'}
            </span>
            <span className="text-[11px] text-slate-400">
              Tx: {latestTelemetry ? `${(latestTelemetry.network_bytes_sent / 1024).toFixed(0)} KB` : '0'}
            </span>
          </div>
          <p className="mt-2 text-[11px] text-slate-400 truncate">Procfs /proc/net socket mapping</p>
        </div>
      </div>

      {/* Explainable AI Risk & Forecasting Panel */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Risk Explanation */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5">
          <h3 className="font-semibold text-slate-200 mb-1">Explainable AI Risk Breakdown</h3>
          <p className="text-xs text-slate-400 mb-4">No black-box decisions. Mathematical baseline deviations & causal weights:</p>

          {risk ? (
            <div className="space-y-3">
              <div className="p-3 rounded-lg bg-slate-950 border border-slate-800">
                <span className="text-xs font-semibold text-slate-300 block mb-1">Primary Causal Factors:</span>
                <ul className="space-y-1 text-xs text-slate-300">
                  {JSON.parse(risk.key_reasons || '[]').map((r: string, idx: number) => (
                    <li key={idx} className="flex items-start space-x-2">
                      <span className="text-cyan-400 font-bold">•</span>
                      <span>{r}</span>
                    </li>
                  ))}
                </ul>
              </div>

              <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 text-xs">
                <span className="text-slate-400 block mb-1">Cryptographic Evidence Hash:</span>
                <p className="font-mono text-[11px] text-emerald-400 break-all">{latestTelemetry?.evidence_hash || 'PENDING_HASH'}</p>
              </div>

              <div className="flex items-center justify-between text-xs pt-2">
                <span className="text-slate-400">Recommended Response:</span>
                <span className="font-mono font-bold text-amber-400 px-2 py-0.5 rounded bg-amber-950/60 border border-amber-800">
                  {risk.recommended_response}
                </span>
              </div>
            </div>
          ) : (
            <div className="p-6 text-center text-sm text-slate-400 italic">
              INSUFFICIENT DATA (Requires continuous collector sampling)
            </div>
          )}
        </div>

        {/* Temporal Attack Stage Forecasting */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5">
          <h3 className="font-semibold text-slate-200 mb-1">Temporal Attack Forecasting (MITRE ATT&CK)</h3>
          <p className="text-xs text-slate-400 mb-4">Predictive sequence model projecting probable progression steps:</p>

          {predictions.length > 0 ? (
            <div className="space-y-3">
              <div className="grid grid-cols-2 gap-3 text-xs">
                <div className="p-3 rounded bg-slate-950 border border-slate-800">
                  <span className="text-slate-400 block mb-1">Current MITRE Stage</span>
                  <span className="font-semibold text-cyan-300 font-mono">{predictions[0].current_stage}</span>
                </div>
                <div className="p-3 rounded bg-slate-950 border border-slate-800">
                  <span className="text-slate-400 block mb-1">Forecasted Next Stage</span>
                  <span className="font-semibold text-amber-400 font-mono">{predictions[0].predicted_next_stage}</span>
                </div>
              </div>

              <div className="p-3 rounded bg-slate-950 border border-slate-800 text-xs">
                <span className="text-slate-400 block mb-1">Forecasting Hypothesis:</span>
                <p className="text-slate-200">{predictions[0].forecast_hypothesis}</p>
              </div>

              <div className="flex items-center justify-between text-xs pt-1">
                <span className="text-slate-400">Model Confidence:</span>
                <span className="font-mono text-cyan-400">{(predictions[0].confidence * 100).toFixed(0)}%</span>
              </div>
            </div>
          ) : (
            <div className="p-6 text-center text-sm text-slate-400 italic">
              INSUFFICIENT DATA (Temporal pipeline analyzing initial windows)
            </div>
          )}
        </div>
      </div>

      {/* Active Processes Table */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-sm">
        <h3 className="font-semibold text-slate-200 mb-1">Real Harvested Host Processes (/proc)</h3>
        <p className="text-xs text-slate-400 mb-4">Direct execution audit from native OS process descriptors</p>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-slate-950 text-slate-400 uppercase text-[10px] tracking-wider border-b border-slate-800">
              <tr>
                <th className="py-2 px-3">PID</th>
                <th className="py-2 px-3">Name</th>
                <th className="py-2 px-3">Executable Path</th>
                <th className="py-2 px-3">Memory (RSS)</th>
                <th className="py-2 px-3">Threads</th>
                <th className="py-2 px-3">Command Line</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800 text-slate-300 font-mono">
              {processes.slice(0, 10).map((p) => (
                <tr key={p.id || p.pid} className="hover:bg-slate-800/40">
                  <td className="py-2 px-3 text-cyan-400">{p.pid}</td>
                  <td className="py-2 px-3 font-semibold text-slate-200">{p.name}</td>
                  <td className="py-2 px-3 text-slate-400 truncate max-w-xs">{p.exe_path || 'kernel_thread'}</td>
                  <td className="py-2 px-3">{(p.memory_rss_bytes / (1024 * 1024)).toFixed(1)} MB</td>
                  <td className="py-2 px-3">{p.thread_count}</td>
                  <td className="py-2 px-3 text-slate-400 truncate max-w-md">{p.cmdline || p.name}</td>
                </tr>
              ))}
              {processes.length === 0 && (
                <tr>
                  <td colSpan={6} className="py-4 text-center text-slate-400 italic">
                    INSUFFICIENT DATA
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
