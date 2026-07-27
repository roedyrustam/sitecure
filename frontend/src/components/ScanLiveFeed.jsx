import React, { useEffect, useState, useRef } from 'react';
import { Terminal, Shield, CheckCircle, AlertOctagon } from 'lucide-react';

export default function ScanLiveFeed({ scanId, onClose }) {
  const [logs, setLogs] = useState([]);
  const [progress, setProgress] = useState(0);
  const [status, setStatus] = useState('Initializing scan engine...');
  const bottomRef = useRef(null);

  useEffect(() => {
    if (!scanId) return;

    const eventSource = new EventSource(`/api/v1/scans/${scanId}/stream`);

    eventSource.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);
        setLogs((prev) => [...prev, data]);
        if (data.progress !== undefined) setProgress(data.progress);
        if (data.message) setStatus(data.message);
      } catch (err) {
        console.error("SSE parse error", err);
      }
    };

    eventSource.onerror = () => {
      eventSource.close();
    };

    return () => {
      eventSource.close();
    };
  }, [scanId]);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [logs]);

  return (
    <div className="glass-panel rounded-2xl p-5 border border-cyan-500/30 space-y-4">
      {/* Header bar */}
      <div className="flex items-center justify-between">
        <div className="flex items-center space-x-3">
          <div className="p-2 rounded-lg bg-cyan-950 text-cyan-400 border border-cyan-800">
            <Terminal className="w-5 h-5 animate-pulse" />
          </div>
          <div>
            <h3 className="text-sm font-bold text-white flex items-center space-x-2">
              <span>Live Scanning Feed Terminal</span>
              <span className="text-xs text-cyan-400 font-mono">Scan #{scanId}</span>
            </h3>
            <p className="text-xs text-slate-400 font-mono">{status}</p>
          </div>
        </div>

        <button
          onClick={onClose}
          className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-semibold"
        >
          Hide Terminal
        </button>
      </div>

      {/* Progress Bar */}
      <div>
        <div className="flex justify-between text-xs font-semibold text-slate-400 mb-1">
          <span>Execution Progress</span>
          <span className="text-cyan-400 font-mono">{progress}%</span>
        </div>
        <div className="w-full bg-slate-900 rounded-full h-2.5 overflow-hidden border border-slate-800">
          <div
            className="bg-gradient-to-r from-cyan-500 via-blue-500 to-indigo-500 h-2.5 rounded-full transition-all duration-300 shadow-md shadow-cyan-500/30"
            style={{ width: `${progress}%` }}
          ></div>
        </div>
      </div>

      {/* Terminal Output Box */}
      <div className="bg-slate-950/90 rounded-xl p-4 font-mono text-xs text-slate-300 border border-slate-800 h-64 overflow-y-auto space-y-1">
        {logs.length === 0 ? (
          <div className="text-slate-600 italic">Waiting for scan engine logs stream...</div>
        ) : (
          logs.map((log, index) => (
            <div key={index} className="flex items-start space-x-2 hover:bg-slate-900/50 p-1 rounded">
              <span className="text-slate-500 shrink-0">[{log.time}]</span>
              <span className="text-cyan-400 shrink-0">›</span>
              <span className="text-slate-200">{log.message}</span>
            </div>
          ))
        )}
        <div ref={bottomRef} />
      </div>
    </div>
  );
}
