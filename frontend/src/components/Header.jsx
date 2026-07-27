import React from 'react';
import { ShieldAlert, Cpu, Activity, Database, Sparkles } from 'lucide-react';

export default function Header({ activeTab, setActiveTab, targetCount, activeScansCount, onOpenCommandPalette }) {

  return (
    <header className="sticky top-0 z-40 glass-panel border-b border-slate-800 px-6 py-3.5 mb-6">
      <div className="max-w-7xl mx-auto flex flex-col md:flex-row items-center justify-between gap-4">
        {/* Brand & Logo */}
        <div className="flex items-center space-x-3 cursor-pointer" onClick={() => setActiveTab('dashboard')}>
          <div className="p-2.5 rounded-xl bg-gradient-to-tr from-cyan-600 via-blue-600 to-indigo-600 shadow-lg glow-cyan flex items-center justify-center">
            <ShieldAlert className="w-6 h-6 text-white" />
          </div>
          <div>
            <div className="flex items-center space-x-2">
              <h1 className="text-xl font-extrabold tracking-tight bg-gradient-to-r from-white via-cyan-200 to-cyan-400 bg-clip-text text-transparent">
                SiteCure
              </h1>
              <span className="px-2 py-0.5 text-[10px] font-bold rounded-full bg-cyan-950 text-cyan-400 border border-cyan-800/60 uppercase tracking-widest">
                v1.0 DAST+SAST
              </span>
            </div>
            <p className="text-xs text-slate-400 font-medium">Internal Web Vulnerability Scanner & Remediation</p>
          </div>
        </div>

        {/* Navigation Tabs */}
        <nav className="flex items-center space-x-1 bg-slate-900/80 p-1.5 rounded-xl border border-slate-800">
          <button
            onClick={() => setActiveTab('dashboard')}
            className={`px-4 py-2 rounded-lg text-xs font-semibold transition-all duration-200 flex items-center space-x-2 ${
              activeTab === 'dashboard'
                ? 'bg-cyan-500 text-slate-950 shadow-md shadow-cyan-500/20'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'
            }`}
          >
            <Activity className="w-4 h-4" />
            <span>Dashboard</span>
          </button>

          <button
            onClick={() => setActiveTab('targets')}
            className={`px-4 py-2 rounded-lg text-xs font-semibold transition-all duration-200 flex items-center space-x-2 ${
              activeTab === 'targets'
                ? 'bg-cyan-500 text-slate-950 shadow-md shadow-cyan-500/20'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'
            }`}
          >
            <Database className="w-4 h-4" />
            <span>Target Assets</span>
            {targetCount > 0 && (
              <span className="ml-1 px-1.5 py-0.2 rounded-full text-[10px] bg-slate-950 text-cyan-300 font-bold">
                {targetCount}
              </span>
            )}
          </button>

          <button
            onClick={() => setActiveTab('scanner')}
            className={`px-4 py-2 rounded-lg text-xs font-semibold transition-all duration-200 flex items-center space-x-2 ${
              activeTab === 'scanner'
                ? 'bg-cyan-500 text-slate-950 shadow-md shadow-cyan-500/20'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'
            }`}
          >
            <Cpu className="w-4 h-4" />
            <span>Scan Control</span>
            {activeScansCount > 0 && (
              <span className="ml-1 px-1.5 py-0.2 rounded-full text-[10px] bg-amber-400 text-slate-950 font-bold animate-pulse">
                {activeScansCount} Active
              </span>
            )}
          </button>
        </nav>

        {/* Live Status & Command Palette trigger */}
        <div className="flex items-center space-x-3">
          <button
            onClick={onOpenCommandPalette}
            className="hidden sm:flex items-center gap-2 px-3 py-1.5 rounded-xl bg-slate-900 border border-slate-800 text-xs text-slate-400 hover:text-slate-200 hover:border-slate-700 transition"
          >
            <span>Search</span>
            <span className="font-mono text-[10px] bg-slate-800 px-1.5 py-0.5 rounded text-cyan-400">Ctrl K</span>
          </button>

          <div className="flex items-center space-x-2 px-3 py-1.5 rounded-full bg-emerald-950/60 border border-emerald-800/60 text-emerald-400 text-xs font-medium">
            <span className="w-2 h-2 rounded-full bg-emerald-400 animate-ping"></span>
            <span>Engine Ready</span>
          </div>

          <div className="flex items-center space-x-1.5 px-3 py-1.5 rounded-full bg-indigo-950/60 border border-indigo-800/60 text-indigo-300 text-xs font-medium">
            <Sparkles className="w-3.5 h-3.5 text-indigo-400" />
            <span>AI Patch Active</span>
          </div>
        </div>
      </div>
    </header>
  );
}

