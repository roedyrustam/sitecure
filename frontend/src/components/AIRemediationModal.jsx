import React, { useState, useEffect } from 'react';
import { Sparkles, X, Check, Copy, Code, ShieldCheck, RefreshCw, AlertTriangle } from 'lucide-react';
import axios from 'axios';

export default function AIRemediationModal({ vulnerability, onClose, refreshData }) {
  const [patch, setPatch] = useState(null);
  const [loading, setLoading] = useState(true);
  const [copied, setCopied] = useState(false);
  const [rescanLoading, setRescanLoading] = useState(false);
  const [rescanStatus, setRescanStatus] = useState(null);

  useEffect(() => {
    if (!vulnerability) return;

    const fetchPatch = async () => {
      try {
        setLoading(true);
        const res = await axios.post('/api/v1/vulnerabilities/generate-patch', {
          vulnerability_id: vulnerability.id
        });
        setPatch(res.data);
      } catch (err) {
        console.error('Failed to generate patch', err);
      } finally {
        setLoading(false);
      }
    };

    fetchPatch();
  }, [vulnerability]);

  const handleCopyCode = (codeText) => {
    navigator.clipboard.writeText(codeText);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleRescanVerify = async () => {
    try {
      setRescanLoading(true);
      setRescanStatus(null);
      const res = await axios.post(`/api/v1/scans/rescan-vulnerability/${vulnerability.id}`);
      setRescanStatus(res.data);
      refreshData();
    } catch (err) {
      alert('Rescan error');
    } finally {
      setRescanLoading(false);
    }
  };

  if (!vulnerability) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-md">
      <div className="glass-panel w-full max-w-4xl max-h-[90vh] rounded-3xl border border-indigo-500/30 flex flex-col overflow-hidden shadow-2xl">
        {/* Header */}
        <div className="p-6 border-b border-slate-800 flex items-start justify-between bg-gradient-to-r from-slate-900 via-slate-900 to-indigo-950/40">
          <div className="flex items-center space-x-3">
            <div className="p-3 rounded-2xl bg-indigo-600/20 text-indigo-400 border border-indigo-500/40 shadow-lg glow-cyan">
              <Sparkles className="w-6 h-6" />
            </div>
            <div>
              <div className="flex items-center space-x-2">
                <span className="text-xs font-bold uppercase px-2 py-0.5 rounded bg-indigo-950 text-indigo-300 border border-indigo-800">
                  AI Remediation Assistant
                </span>
                <span className="text-xs font-mono text-cyan-400">{vulnerability.cwe_id}</span>
              </div>
              <h2 className="text-lg font-bold text-white mt-1">{vulnerability.title}</h2>
              <p className="text-xs text-slate-400 font-mono mt-0.5">Target: {vulnerability.affected_endpoint}</p>
            </div>
          </div>

          <button
            onClick={onClose}
            className="p-2 rounded-xl text-slate-400 hover:text-white hover:bg-slate-800 transition"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Modal Body */}
        <div className="p-6 overflow-y-auto space-y-6 flex-1 text-xs">
          {loading ? (
            <div className="flex flex-col items-center justify-center py-16 space-y-4">
              <div className="w-12 h-12 rounded-full border-4 border-indigo-500/30 border-t-indigo-400 animate-spin"></div>
              <p className="text-sm font-semibold text-indigo-300 animate-pulse">
                AI Gemini sedang menganalisis kerentanan & menyusun Patch Perbaikan Kode...
              </p>
            </div>
          ) : patch ? (
            <>
              {/* AI Explanation Box */}
              <div className="p-4 rounded-2xl bg-indigo-950/40 border border-indigo-800/60 text-slate-200 leading-relaxed">
                <h4 className="font-bold text-indigo-300 mb-1 flex items-center space-x-2">
                  <ShieldCheck className="w-4 h-4 text-indigo-400" />
                  <span>Rasional & Panduan Penambalan AI:</span>
                </h4>
                <p className="text-slate-300 text-xs mt-1">{patch.ai_explanation}</p>
              </div>

              {/* Diff Text / Snippet Comparison */}
              <div className="space-y-4">
                <div className="flex items-center justify-between">
                  <h4 className="font-bold text-white flex items-center space-x-2">
                    <Code className="w-4 h-4 text-cyan-400" />
                    <span>Code Patch Recommendation (Diff View)</span>
                  </h4>

                  {patch.patched_code && (
                    <button
                      onClick={() => handleCopyCode(patch.patched_code)}
                      className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-semibold border border-slate-700 flex items-center space-x-1.5 transition"
                    >
                      {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                      <span>{copied ? 'Copied to Clipboard!' : 'Copy Patched Code'}</span>
                    </button>
                  )}
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  {/* Unsafe Code */}
                  <div className="space-y-1">
                    <div className="text-[11px] font-bold text-red-400 uppercase tracking-wider flex items-center space-x-1">
                      <span className="w-2 h-2 rounded-full bg-red-500"></span>
                      <span>Kode Lama (Rentan)</span>
                    </div>
                    <pre className="p-4 rounded-xl bg-slate-950 border border-red-900/50 text-red-300 font-mono text-[11px] overflow-x-auto whitespace-pre-wrap">
                      {patch.original_code}
                    </pre>
                  </div>

                  {/* Patched Code */}
                  <div className="space-y-1">
                    <div className="text-[11px] font-bold text-emerald-400 uppercase tracking-wider flex items-center space-x-1">
                      <span className="w-2 h-2 rounded-full bg-emerald-500"></span>
                      <span>Kode Baru (Tertambal / Safe)</span>
                    </div>
                    <pre className="p-4 rounded-xl bg-slate-950 border border-emerald-900/50 text-emerald-300 font-mono text-[11px] overflow-x-auto whitespace-pre-wrap">
                      {patch.patched_code}
                    </pre>
                  </div>
                </div>
              </div>

              {/* Rescan Status Banner */}
              {rescanStatus && (
                <div className={`p-4 rounded-xl border flex items-center justify-between ${
                  rescanStatus.status === 'remediated'
                    ? 'bg-emerald-950/80 text-emerald-300 border-emerald-800'
                    : 'bg-amber-950/80 text-amber-300 border-amber-800'
                }`}>
                  <div className="flex items-center space-x-2">
                    {rescanStatus.status === 'remediated' ? <ShieldCheck className="w-5 h-5 text-emerald-400" /> : <AlertTriangle className="w-5 h-5 text-amber-400" />}
                    <span className="font-semibold">{rescanStatus.message}</span>
                  </div>
                </div>
              )}
            </>
          ) : (
            <div className="text-center py-8 text-slate-400">Gagal memuat rekomendasi AI.</div>
          )}
        </div>

        {/* Footer */}
        <div className="p-4 border-t border-slate-800 bg-slate-900/80 flex items-center justify-between">
          <button
            onClick={onClose}
            className="px-4 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-semibold"
          >
            Tutup
          </button>

          <button
            onClick={handleRescanVerify}
            disabled={rescanLoading}
            className="px-5 py-2.5 rounded-xl bg-gradient-to-r from-emerald-500 to-teal-600 hover:from-emerald-400 hover:to-teal-500 text-slate-950 font-bold text-xs shadow-md shadow-emerald-500/20 flex items-center space-x-2 transition disabled:opacity-50"
          >
            <RefreshCw className={`w-4 h-4 ${rescanLoading ? 'animate-spin' : ''}`} />
            <span>{rescanLoading ? 'Verifying...' : 'Verify Fix (Rescan)'}</span>
          </button>
        </div>
      </div>
    </div>
  );
}
