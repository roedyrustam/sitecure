import React, { useState } from 'react';
import { Cpu, Play, ShieldAlert, FileText, CheckCircle2, Clock, AlertCircle } from 'lucide-react';
import axios from 'axios';
import ScanLiveFeed from './ScanLiveFeed';

export default function ScannerControl({ targets, scans, onScanStarted }) {
  const [selectedTargetId, setSelectedTargetId] = useState('');
  const [scanType, setScanType] = useState('full');
  const [activeScanId, setActiveScanId] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const handleStartScan = async (e) => {
    e.preventDefault();
    if (!selectedTargetId) {
      setError('Pilih target asset terlebih dahulu.');
      return;
    }

    try {
      setLoading(true);
      setError('');
      const res = await axios.post('/api/v1/scans/', {
        target_id: parseInt(selectedTargetId),
        scan_type: scanType
      });
      setActiveScanId(res.data.id);
      onScanStarted(res.data);
    } catch (err) {
      setError(err.response?.data?.detail || 'Gagal memulai scan job.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Scan Trigger Panel */}
      <div className="glass-panel rounded-2xl p-6 border border-slate-800">
        <h2 className="text-lg font-bold text-white mb-2 flex items-center space-x-2">
          <Cpu className="w-5 h-5 text-cyan-400" />
          <span>Launch Vulnerability Scan</span>
        </h2>
        <p className="text-xs text-slate-400 mb-6">
          Pilih target asset internal dan jenis modul pemindaian yang ingin dijalankan.
        </p>

        {error && (
          <div className="mb-4 p-3 rounded-xl bg-red-950/80 border border-red-800 text-red-300 text-xs flex items-center space-x-2">
            <AlertCircle className="w-4 h-4 text-red-400 shrink-0" />
            <span>{error}</span>
          </div>
        )}

        <form onSubmit={handleStartScan} className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <div>
            <label className="block text-xs font-semibold text-slate-300 mb-1.5">Target Asset</label>
            <select
              value={selectedTargetId}
              onChange={(e) => setSelectedTargetId(e.target.value)}
              className="w-full px-3.5 py-2.5 rounded-xl bg-slate-900 border border-slate-700 text-slate-100 text-xs focus:outline-none focus:border-cyan-500 transition"
            >
              <option value="">-- Pilih Target Asset --</option>
              {targets.map((t) => (
                <option key={t.id} value={t.id}>
                  {t.name} ({t.target_url})
                </option>
              ))}
            </select>
          </div>

          <div>
            <label className="block text-xs font-semibold text-slate-300 mb-1.5">Scan Module Mode</label>
            <select
              value={scanType}
              onChange={(e) => setScanType(e.target.value)}
              className="w-full px-3.5 py-2.5 rounded-xl bg-slate-900 border border-slate-700 text-slate-100 text-xs focus:outline-none focus:border-cyan-500 transition"
            >
              <option value="full">Full Audit (DAST + SAST + Ports Audit)</option>
              <option value="dast">DAST Only (Web HTTP Fuzzing & Headers)</option>
              <option value="sast">SAST Only (Source Code & Secrets Scan)</option>
              <option value="ports">Port Scan Only (Open TCP Services)</option>
            </select>
          </div>

          <div className="flex items-end">
            <button
              type="submit"
              disabled={loading || !selectedTargetId}
              className="w-full py-2.5 rounded-xl bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-slate-950 font-bold text-xs shadow-md shadow-cyan-500/20 flex items-center justify-center space-x-2 transition disabled:opacity-50"
            >
              <Play className="w-4 h-4 fill-slate-950" />
              <span>{loading ? 'Starting Scan...' : 'Start Scan Job'}</span>
            </button>
          </div>
        </form>
      </div>

      {/* Live SSE Streaming Terminal Feed */}
      {activeScanId && (
        <ScanLiveFeed scanId={activeScanId} onClose={() => setActiveScanId(null)} />
      )}

      {/* Scan History Table */}
      <div className="glass-panel rounded-2xl p-6">
        <h3 className="text-md font-bold text-white mb-4">Scan Jobs History ({scans.length})</h3>

        {scans.length === 0 ? (
          <div className="text-center py-12 text-slate-500 text-xs">
            Belum ada riwayat scan job. Pilih target asset di atas untuk memulai.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs text-slate-300">
              <thead className="bg-slate-900/80 text-slate-400 uppercase text-[11px] font-bold border-b border-slate-800">
                <tr>
                  <th className="py-3 px-4">Scan ID</th>
                  <th className="py-3 px-4">Target Asset</th>
                  <th className="py-3 px-4">Scan Type</th>
                  <th className="py-3 px-4">Status</th>
                  <th className="py-3 px-4">Progress</th>
                  <th className="py-3 px-4">Findings</th>
                  <th className="py-3 px-4">Started At</th>
                  <th className="py-3 px-4">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {scans.map((scan) => (
                  <tr key={scan.id} className="hover:bg-slate-900/40 transition">
                    <td className="py-3.5 px-4 font-mono font-bold text-cyan-400">#{scan.id}</td>
                    <td className="py-3.5 px-4 font-semibold text-white">
                      {targets.find(t => t.id === scan.target_id)?.name || `Target #${scan.target_id}`}
                    </td>
                    <td className="py-3.5 px-4 uppercase font-mono text-[11px]">{scan.scan_type}</td>
                    <td className="py-3.5 px-4">
                      <span className={`px-2 py-0.5 rounded-full text-[10px] font-bold uppercase ${
                        scan.status === 'completed' ? 'bg-emerald-950 text-emerald-400 border border-emerald-800' :
                        scan.status === 'running' ? 'bg-cyan-950 text-cyan-400 border border-cyan-800 animate-pulse' :
                        'bg-slate-800 text-slate-400'
                      }`}>
                        {scan.status}
                      </span>
                    </td>
                    <td className="py-3.5 px-4 font-mono">{scan.progress_pct}%</td>
                    <td className="py-3.5 px-4 font-bold text-amber-400">{scan.total_findings} Vulnerabilities</td>
                    <td className="py-3.5 px-4 text-slate-500">{new Date(scan.started_at).toLocaleTimeString()}</td>
                    <td className="py-3.5 px-4">
                      <button
                        onClick={() => setActiveScanId(scan.id)}
                        className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-cyan-400 text-[11px] font-medium border border-slate-700"
                      >
                        View Logs
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
