import React, { useState } from 'react';
import { 
  AlertTriangle, 
  ShieldAlert, 
  CheckCircle, 
  XCircle, 
  Play, 
  RefreshCw, 
  Lock, 
  FileCheck,
  Radio,
  Sliders,
  Sparkles
} from 'lucide-react';
import { IncidentRecord } from '../types';

interface IncidentsViewProps {
  incidents: IncidentRecord[];
  onExecuteAction: (deviceId: string, incidentId: string, actionType: string, mode: 'RECOMMENDATION' | 'SIMULATION' | 'EXECUTED') => void;
  onInjectSimulation: (scenario: 'BENIGN' | 'BRUTE_FORCE' | 'C2_BEACON' | 'CRYPTO_MINER') => void;
  onResetSimulation: () => void;
  isSimulated: boolean;
}

export const IncidentsView: React.FC<IncidentsViewProps> = ({
  incidents,
  onExecuteAction,
  onInjectSimulation,
  onResetSimulation,
  isSimulated
}) => {
  const [selectedIncident, setSelectedIncident] = useState<IncidentRecord | null>(null);
  const [responseMode, setResponseMode] = useState<'RECOMMENDATION' | 'SIMULATION'>('RECOMMENDATION');

  return (
    <div className="space-y-6">
      {/* Simulation Scenario Injection Toolbar */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-sm">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div>
            <div className="flex items-center space-x-2">
              <Sparkles className="w-5 h-5 text-amber-400" />
              <h3 className="font-semibold text-slate-100">SIH Reproducible Attack Scenarios (Sandbox Pipeline)</h3>
            </div>
            <p className="text-xs text-slate-400 mt-1">
              Inject controlled behavioural deviations into the isolated simulation pipeline to observe live anomaly detection, MITRE forecasting, and blockchain sealing.
            </p>
          </div>

          <div className="flex flex-wrap gap-2">
            <button
              onClick={() => onInjectSimulation('BRUTE_FORCE')}
              className="px-3 py-1.5 rounded bg-amber-900/60 hover:bg-amber-800/80 border border-amber-700 text-amber-200 text-xs font-semibold flex items-center space-x-1.5 transition"
            >
              <span>Auth Spray Attack</span>
            </button>
            <button
              onClick={() => onInjectSimulation('C2_BEACON')}
              className="px-3 py-1.5 rounded bg-rose-900/60 hover:bg-rose-800/80 border border-rose-700 text-rose-200 text-xs font-semibold flex items-center space-x-1.5 transition"
            >
              <span>C2 Beaconing Pattern</span>
            </button>
            <button
              onClick={() => onInjectSimulation('CRYPTO_MINER')}
              className="px-3 py-1.5 rounded bg-purple-900/60 hover:bg-purple-800/80 border border-purple-700 text-purple-200 text-xs font-semibold flex items-center space-x-1.5 transition"
            >
              <span>Compute Hijack (Miner)</span>
            </button>
            <button
              onClick={() => onInjectSimulation('BENIGN')}
              className="px-3 py-1.5 rounded bg-emerald-900/60 hover:bg-emerald-800/80 border border-emerald-700 text-emerald-200 text-xs font-semibold flex items-center space-x-1.5 transition"
            >
              <span>Benign Endpoint</span>
            </button>
            <button
              onClick={onResetSimulation}
              className="px-3 py-1.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-semibold flex items-center space-x-1.5 transition"
            >
              <RefreshCw className="w-3.5 h-3.5" />
              <span>Reset Sandbox</span>
            </button>
          </div>
        </div>
      </div>

      {/* Incidents Table & Response Panel */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Incidents List */}
        <div className="lg:col-span-2 bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-sm">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h3 className="font-semibold text-slate-200">Security Incidents & Breaches</h3>
              <p className="text-xs text-slate-400">Strictly generated from verified multi-factor risk scores (Score &ge; 60)</p>
            </div>
            <span className="text-xs font-mono font-bold text-slate-400">{incidents.length} Records</span>
          </div>

          <div className="space-y-3">
            {incidents.map((inc) => (
              <div
                key={inc.id}
                onClick={() => setSelectedIncident(inc)}
                className={`p-4 rounded-lg border cursor-pointer transition ${
                  selectedIncident?.id === inc.id 
                    ? 'bg-slate-800/90 border-cyan-500 shadow-md' 
                    : 'bg-slate-950 border-slate-800 hover:border-slate-700'
                }`}
              >
                <div className="flex items-center justify-between">
                  <div className="flex items-center space-x-3">
                    <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold ${
                      inc.severity === 'CRITICAL' ? 'bg-rose-950 text-rose-300 border border-rose-800' : 'bg-amber-950 text-amber-300 border border-amber-800'
                    }`}>
                      {inc.severity}
                    </span>
                    <span className="font-mono text-xs font-bold text-cyan-400">{inc.id}</span>
                    <span className="text-xs font-semibold text-slate-200 truncate">{inc.title}</span>
                  </div>
                  <span className={`text-[11px] font-mono px-2 py-0.5 rounded ${
                    inc.status === 'OPEN' ? 'bg-rose-900/40 text-rose-300' :
                    inc.status === 'CONTAINED' ? 'bg-blue-900/40 text-blue-300' :
                    'bg-emerald-900/40 text-emerald-300'
                  }`}>
                    {inc.status}
                  </span>
                </div>

                <p className="text-xs text-slate-400 mt-2 line-clamp-2">{inc.explanation}</p>

                <div className="mt-3 pt-2 border-t border-slate-800 flex items-center justify-between text-[11px] text-slate-400">
                  <span className="font-mono">Target: {inc.device_id}</span>
                  <span>{new Date(inc.created_at).toLocaleTimeString()}</span>
                </div>
              </div>
            ))}

            {incidents.length === 0 && (
              <div className="p-8 text-center text-sm text-slate-400 italic">
                No active security incidents detected. System telemetry remains within nominal thresholds.
              </div>
            )}
          </div>
        </div>

        {/* Selected Incident Actions & Details */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-sm flex flex-col justify-between">
          <div>
            <h3 className="font-semibold text-slate-200 mb-1">Controlled Response Orchestrator</h3>
            <p className="text-xs text-slate-400 mb-4">Adhering to strict safety guidelines (Default: Recommendation / Simulation)</p>

            {selectedIncident ? (
              <div className="space-y-4">
                <div className="p-3 bg-slate-950 rounded-lg border border-slate-800 text-xs">
                  <span className="text-slate-400 block mb-1">Target Entity</span>
                  <p className="font-mono font-bold text-cyan-400">{selectedIncident.device_id}</p>
                  <p className="text-slate-400 mt-1">Severity: <span className="text-rose-400 font-bold">{selectedIncident.severity}</span></p>
                </div>

                <div className="p-3 bg-slate-950 rounded-lg border border-slate-800 text-xs">
                  <span className="text-slate-400 block mb-1">Forensic Evidence & Root Cause:</span>
                  <p className="text-slate-200">{selectedIncident.explanation}</p>
                </div>

                {/* Response Action Execution Buttons */}
                <div className="space-y-2">
                  <span className="text-xs font-semibold text-slate-300 block">Available Response Actions:</span>
                  
                  <button
                    onClick={() => onExecuteAction(selectedIncident.device_id, selectedIncident.id, 'PRESERVE_EVIDENCE', responseMode)}
                    className="w-full py-2 px-3 rounded bg-indigo-700 hover:bg-indigo-600 text-white text-xs font-semibold flex items-center justify-center space-x-2 transition"
                  >
                    <FileCheck className="w-3.5 h-3.5" />
                    <span>Preserve Socket & Memory State</span>
                  </button>

                  <button
                    onClick={() => onExecuteAction(selectedIncident.device_id, selectedIncident.id, 'ISOLATE_NETWORK', responseMode)}
                    className="w-full py-2 px-3 rounded bg-amber-700 hover:bg-amber-600 text-white text-xs font-semibold flex items-center justify-center space-x-2 transition"
                  >
                    <Lock className="w-3.5 h-3.5" />
                    <span>Apply Network Quarantine (Simulated)</span>
                  </button>

                  <button
                    onClick={() => onExecuteAction(selectedIncident.device_id, selectedIncident.id, 'CHALLENGE_AUTH', responseMode)}
                    className="w-full py-2 px-3 rounded bg-cyan-700 hover:bg-cyan-600 text-white text-xs font-semibold flex items-center justify-center space-x-2 transition"
                  >
                    <CheckCircle className="w-3.5 h-3.5" />
                    <span>Force Re-Authentication & Token Revocation</span>
                  </button>
                </div>
              </div>
            ) : (
              <div className="p-8 text-center text-sm text-slate-400 italic">
                Select an incident from the list to review evidence and orchestrate containment responses.
              </div>
            )}
          </div>

          <div className="mt-4 pt-3 border-t border-slate-800 text-[11px] text-slate-400 flex items-center justify-between">
            <span>Safety Mode</span>
            <span className="font-mono text-emerald-400 font-semibold">NON-DESTRUCTIVE</span>
          </div>
        </div>
      </div>
    </div>
  );
};
