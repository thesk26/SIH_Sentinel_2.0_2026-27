import React, { useState } from 'react';
import { Link2, ShieldCheck, AlertTriangle, FileCode, CheckCircle2, Copy } from 'lucide-react';
import { BlockchainRecord } from '../types';

interface BlockchainViewProps {
  records: BlockchainRecord[];
  onVerify: (txId: string) => Promise<{ status: 'VALID' | 'TAMPERED' | 'NOT_FOUND'; details: string; record?: BlockchainRecord }>;
}

export const BlockchainView: React.FC<BlockchainViewProps> = ({ records, onVerify }) => {
  const [selectedTx, setSelectedTx] = useState<string>('');
  const [verificationResult, setVerificationResult] = useState<{ status: string; details: string; record?: BlockchainRecord } | null>(null);
  const [verifying, setVerifying] = useState<boolean>(false);

  const handleVerify = async (txId: string) => {
    setSelectedTx(txId);
    setVerifying(true);
    try {
      const res = await onVerify(txId);
      setVerificationResult(res);
    } finally {
      setVerifying(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header Banner */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 shadow-sm">
        <div className="flex items-center space-x-3 mb-2">
          <div className="w-10 h-10 rounded-lg bg-emerald-950 text-emerald-400 flex items-center justify-center border border-emerald-900">
            <Link2 className="w-5 h-5" />
          </div>
          <div>
            <h2 className="text-xl font-bold text-slate-100">Immutable Blockchain Evidence Ledger</h2>
            <p className="text-xs text-slate-400">Cryptographically verifiable chain-of-custody for incidents, forensic evidence, and AI security decisions.</p>
          </div>
        </div>
        <p className="text-xs text-slate-400 mt-2">
          Raw telemetry is never placed on-chain. Each high-risk event or incident is canonically serialized, hashed with SHA-256, and linked with Merkle tree proofs.
        </p>
      </div>

      {/* Verification Tool Box */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-sm">
        <h3 className="font-semibold text-slate-200 mb-2">Cryptographic Evidence Verification Engine</h3>
        <p className="text-xs text-slate-400 mb-4">Validate cryptographic proof against block hash, Merkle root, and HMAC digital signatures.</p>

        <div className="flex gap-3">
          <input
            type="text"
            placeholder="Enter Blockchain Transaction ID (0x...)"
            value={selectedTx}
            onChange={(e) => setSelectedTx(e.target.value)}
            className="flex-1 bg-slate-950 border border-slate-700 rounded-lg px-3.5 py-2 text-xs font-mono text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500"
          />
          <button
            onClick={() => handleVerify(selectedTx)}
            disabled={!selectedTx || verifying}
            className="px-4 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-semibold flex items-center space-x-2 transition disabled:opacity-50"
          >
            <ShieldCheck className="w-4 h-4" />
            <span>{verifying ? 'Verifying Proof...' : 'Verify Cryptographic Proof'}</span>
          </button>
        </div>

        {/* Verification Result Dialog */}
        {verificationResult && (
          <div className={`mt-4 p-4 rounded-lg border text-xs ${
            verificationResult.status === 'VALID' ? 'bg-emerald-950/60 border-emerald-800 text-emerald-200' :
            verificationResult.status === 'TAMPERED' ? 'bg-rose-950/60 border-rose-800 text-rose-200' :
            'bg-slate-950 border-slate-800 text-slate-300'
          }`}>
            <div className="flex items-center space-x-2 font-bold mb-1.5">
              {verificationResult.status === 'VALID' ? (
                <CheckCircle2 className="w-4 h-4 text-emerald-400" />
              ) : (
                <AlertTriangle className="w-4 h-4 text-rose-400" />
              )}
              <span className="font-mono uppercase tracking-wider">RESULT: {verificationResult.status}</span>
            </div>
            <p className="mb-2">{verificationResult.details}</p>
            {verificationResult.record && (
              <div className="p-3 bg-slate-950/80 rounded border border-slate-800/80 font-mono text-[11px] space-y-1 text-slate-300">
                <p><span className="text-slate-500">Block Index:</span> {verificationResult.record.block_index}</p>
                <p><span className="text-slate-500">Evidence SHA-256:</span> {verificationResult.record.evidence_hash}</p>
                <p><span className="text-slate-500">Merkle Root:</span> {verificationResult.record.merkle_root}</p>
                <p><span className="text-slate-500">Digital Signature:</span> {verificationResult.record.signature.substring(0, 32)}...</p>
              </div>
            )}
          </div>
        )}
      </div>

      {/* Ledger Block History Table */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-sm">
        <h3 className="font-semibold text-slate-200 mb-1">Immutable Block Registry</h3>
        <p className="text-xs text-slate-400 mb-4">Consecutive forensic blocks anchored with verifiable SHA-256 pointers</p>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-slate-950 text-slate-400 uppercase text-[10px] tracking-wider border-b border-slate-800">
              <tr>
                <th className="py-2.5 px-3">Block #</th>
                <th className="py-2.5 px-3">Transaction ID</th>
                <th className="py-2.5 px-3">Device Target</th>
                <th className="py-2.5 px-3">Incident Ref</th>
                <th className="py-2.5 px-3">Evidence Hash (SHA-256)</th>
                <th className="py-2.5 px-3">Timestamp</th>
                <th className="py-2.5 px-3">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800 text-slate-300 font-mono">
              {records.map((r) => (
                <tr key={r.tx_id} className="hover:bg-slate-800/40">
                  <td className="py-3 px-3 font-bold text-cyan-400">#{r.block_index}</td>
                  <td className="py-3 px-3 text-slate-300 truncate max-w-xs">{r.tx_id.substring(0, 18)}...</td>
                  <td className="py-3 px-3 text-slate-200">{r.device_id}</td>
                  <td className="py-3 px-3 text-amber-400 font-medium">{r.incident_id || 'AUTO_EVIDENCE'}</td>
                  <td className="py-3 px-3 text-emerald-400 truncate max-w-xs">{r.evidence_hash.substring(0, 24)}...</td>
                  <td className="py-3 px-3 text-slate-400">{new Date(r.timestamp).toLocaleTimeString()}</td>
                  <td className="py-3 px-3">
                    <button
                      onClick={() => handleVerify(r.tx_id)}
                      className="px-2.5 py-1 rounded bg-slate-800 hover:bg-cyan-700 text-white text-[11px] font-sans font-medium transition"
                    >
                      Verify
                    </button>
                  </td>
                </tr>
              ))}
              {records.length === 0 && (
                <tr>
                  <td colSpan={7} className="py-6 text-center text-slate-400 italic font-sans">
                    No blockchain forensic evidence blocks anchored yet. Trigger an anomaly or incident to create a cryptographic block.
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
