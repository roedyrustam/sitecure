import React, { useState, useEffect } from 'react';
import { Search, Command, ShieldAlert, Globe, X } from 'lucide-react';

export default function CommandPalette({ isOpen, onClose, vulnerabilities, targets, onSelectVuln, onSelectTarget }) {
  const [query, setQuery] = useState('');

  useEffect(() => {
    const handleKeyDown = (e) => {
      if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
        e.preventDefault();
        if (isOpen) onClose();
        else {
          setQuery('');
        }
      }
      if (e.key === 'Escape' && isOpen) {
        onClose();
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [isOpen, onClose]);

  if (!isOpen) return null;

  const filteredVulns = vulnerabilities.filter(v => 
    v.title.toLowerCase().includes(query.toLowerCase()) ||
    v.affected_endpoint.toLowerCase().includes(query.toLowerCase())
  ).slice(0, 5);

  const filteredTargets = targets.filter(t => 
    t.name.toLowerCase().includes(query.toLowerCase()) ||
    t.target_url.toLowerCase().includes(query.toLowerCase())
  ).slice(0, 3);

  return (
    <div className="fixed inset-0 z-50 flex items-start justify-center pt-20 bg-slate-950/80 backdrop-blur-md p-4 animate-in fade-in">
      <div className="bg-slate-900 border border-slate-700/80 rounded-2xl w-full max-w-2xl shadow-2xl overflow-hidden">
        
        {/* Input Bar */}
        <div className="p-4 border-b border-slate-800 flex items-center gap-3">
          <Search className="w-5 h-5 text-cyan-400 shrink-0" />
          <input
            type="text"
            placeholder="Ketik untuk mencari vulnerability, endpoint, atau target asset... (ESC untuk keluar)"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            autoFocus
            className="w-full bg-transparent text-sm text-slate-100 placeholder-slate-500 focus:outline-none"
          />
          <button onClick={onClose} className="p-1 text-slate-500 hover:text-slate-300 rounded">
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Results List */}
        <div className="p-4 max-h-[60vh] overflow-y-auto space-y-4 text-xs">
          
          {/* Target Assets */}
          {filteredTargets.length > 0 && (
            <div>
              <div className="text-[10px] uppercase font-bold text-slate-400 mb-2 tracking-wider">Target Assets</div>
              <div className="space-y-1">
                {filteredTargets.map((t) => (
                  <div
                    key={t.id}
                    onClick={() => { onSelectTarget(t); onClose(); }}
                    className="p-2.5 rounded-xl bg-slate-950/60 hover:bg-slate-800/80 cursor-pointer flex justify-between items-center transition border border-slate-800/60"
                  >
                    <div className="flex items-center gap-2">
                      <Globe className="w-4 h-4 text-cyan-400" />
                      <span className="font-semibold text-slate-200">{t.name}</span>
                    </div>
                    <span className="font-mono text-slate-400">{t.target_url}</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Vulnerabilities */}
          {filteredVulns.length > 0 && (
            <div>
              <div className="text-[10px] uppercase font-bold text-slate-400 mb-2 tracking-wider">Vulnerabilities Found</div>
              <div className="space-y-1">
                {filteredVulns.map((v) => (
                  <div
                    key={v.id}
                    onClick={() => { onSelectVuln(v); onClose(); }}
                    className="p-2.5 rounded-xl bg-slate-950/60 hover:bg-slate-800/80 cursor-pointer flex justify-between items-center transition border border-slate-800/60"
                  >
                    <div className="flex items-center gap-2">
                      <ShieldAlert className="w-4 h-4 text-rose-400" />
                      <span className="font-semibold text-slate-200">{v.title}</span>
                    </div>
                    <span className="font-mono text-slate-400">{v.affected_endpoint}</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {filteredTargets.length === 0 && filteredVulns.length === 0 && (
            <div className="py-8 text-center text-slate-500 italic">
              Tidak ada hasil yang cocok dengan pencarian "{query}".
            </div>
          )}

        </div>

        {/* Footer */}
        <div className="p-3 border-t border-slate-800/80 bg-slate-950/60 text-[11px] text-slate-400 flex justify-between items-center px-4">
          <span className="flex items-center gap-1.5">
            <Command className="w-3.5 h-3.5 text-cyan-400" />
            <span>Pintasan Global SiteCure Quick Inspector</span>
          </span>
          <span className="font-mono bg-slate-800 px-2 py-0.5 rounded text-[10px]">Ctrl + K</span>
        </div>

      </div>
    </div>
  );
}
