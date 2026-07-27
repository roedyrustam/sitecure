import React, { useState } from 'react';
import { 
  ShieldAlert, ShieldCheck, AlertTriangle, Bug, FileSpreadsheet, 
  Sparkles, CheckCircle2, RefreshCw, ExternalLink, ArrowRight, Play, BarChart3, PieChart as PieIcon
} from 'lucide-react';
import { ResponsiveContainer, PieChart, Pie, Cell, Tooltip, BarChart, Bar, XAxis, YAxis, CartesianGrid } from 'recharts';
import VulnerabilityMatrix from './VulnerabilityMatrix';
import AttackChainGraph from './AttackChainGraph';
import ComplianceScorecard from './ComplianceScorecard';


export default function Dashboard({ 
  targets, scans, vulnerabilities, onLaunchScan, onOpenPatchModal, onOpenVirtualPatchModal, onExportReport, refreshData 
}) {
  const [dashboardView, setDashboardView] = useState('matrix');

  const totalVulnerabilities = vulnerabilities.length;
  const criticalCount = vulnerabilities.filter(v => v.severity === 'CRITICAL').length;
  const highCount = vulnerabilities.filter(v => v.severity === 'HIGH').length;
  const mediumCount = vulnerabilities.filter(v => v.severity === 'MEDIUM').length;
  const lowCount = vulnerabilities.filter(v => v.severity === 'LOW').length;
  const remediatedCount = vulnerabilities.filter(v => v.is_remediated).length;

  const fixPercentage = totalVulnerabilities > 0 
    ? Math.round((remediatedCount / totalVulnerabilities) * 100) 
    : 100;

  // Calculate Security Health Score (0-100)
  let healthScore = 100 - (criticalCount * 25 + highCount * 15 + mediumCount * 5 + lowCount * 2);
  healthScore = Math.max(0, Math.min(100, healthScore));

  const pieData = [
    { name: 'Critical', value: criticalCount, color: '#ef4444' },
    { name: 'High', value: highCount, color: '#f59e0b' },
    { name: 'Medium', value: mediumCount, color: '#eab308' },
    { name: 'Low', value: lowCount, color: '#3b82f6' },
  ].filter(d => d.value > 0);

  const dastCount = vulnerabilities.filter(v => v.vulnerability_type === 'DAST').length;
  const sastCount = vulnerabilities.filter(v => v.vulnerability_type === 'SAST').length;
  const portCount = vulnerabilities.filter(v => v.vulnerability_type === 'PORT').length;

  const categoryBarData = [
    { category: 'DAST Web', count: dastCount },
    { category: 'SAST Code', count: sastCount },
    { category: 'Ports Service', count: portCount }
  ];

  return (
    <div className="space-y-6">
      {/* Top Metric Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-5 gap-4">
        {/* Security Health Score */}
        <div className="glass-card rounded-2xl p-5 relative overflow-hidden group">
          <div className="flex justify-between items-start">
            <div>
              <p className="text-xs font-semibold uppercase tracking-wider text-slate-400">Security Score</p>
              <h3 className={`text-3xl font-extrabold mt-1 ${
                healthScore > 80 ? 'text-emerald-400' : healthScore > 50 ? 'text-yellow-400' : 'text-red-500'
              }`}>
                {healthScore}/100
              </h3>
              <p className="text-[11px] text-slate-400 mt-1">
                {healthScore > 80 ? 'Sistem Aman' : healthScore > 50 ? 'Butuh Perhatian' : 'Kondisi Kritis!'}
              </p>
            </div>
            <div className={`p-3 rounded-xl border ${
              healthScore > 80 ? 'bg-emerald-950/80 text-emerald-400 border-emerald-800' : 'bg-red-950/80 text-red-400 border-red-800'
            }`}>
              <ShieldCheck className="w-5 h-5" />
            </div>
          </div>
        </div>

        {/* Total Target Assets */}
        <div className="glass-card rounded-2xl p-5 relative overflow-hidden group">
          <div className="flex justify-between items-start">
            <div>
              <p className="text-xs font-semibold uppercase tracking-wider text-slate-400">Target Assets</p>
              <h3 className="text-3xl font-extrabold text-white mt-1">{targets.length}</h3>
              <p className="text-[11px] text-slate-400 mt-1">Website & IP Internal/Prod</p>
            </div>
            <div className="p-3 rounded-xl bg-slate-800/80 text-cyan-400 border border-slate-700">
              <Bug className="w-5 h-5" />
            </div>
          </div>
        </div>

        {/* Critical Severity */}
        <div className="glass-card rounded-2xl p-5 relative overflow-hidden group border-red-900/40 glow-red">
          <div className="flex justify-between items-start">
            <div>
              <p className="text-xs font-semibold uppercase tracking-wider text-red-400">Critical Threats</p>
              <h3 className="text-3xl font-extrabold text-red-500 mt-1">{criticalCount}</h3>
              <p className="text-[11px] text-slate-400 mt-1">Tindakan Segera</p>
            </div>
            <div className="p-3 rounded-xl bg-red-950/80 text-red-400 border border-red-800/80">
              <ShieldAlert className="w-5 h-5 animate-pulse" />
            </div>
          </div>
        </div>

        {/* High Severity */}
        <div className="glass-card rounded-2xl p-5 relative overflow-hidden group border-amber-900/40 glow-amber">
          <div className="flex justify-between items-start">
            <div>
              <p className="text-xs font-semibold uppercase tracking-wider text-amber-400">High Risk</p>
              <h3 className="text-3xl font-extrabold text-amber-500 mt-1">{highCount}</h3>
              <p className="text-[11px] text-slate-400 mt-1">Prioritas Tinggi</p>
            </div>
            <div className="p-3 rounded-xl bg-amber-950/80 text-amber-400 border border-amber-800/80">
              <AlertTriangle className="w-5 h-5" />
            </div>
          </div>
        </div>

        {/* Remediation Fix Rate */}
        <div className="glass-card rounded-2xl p-5 relative overflow-hidden group">
          <div className="flex justify-between items-start">
            <div>
              <p className="text-xs font-semibold uppercase tracking-wider text-emerald-400">Fix Rate</p>
              <h3 className="text-3xl font-extrabold text-emerald-400 mt-1">{fixPercentage}%</h3>
              <p className="text-[11px] text-slate-400 mt-1">{remediatedCount} of {totalVulnerabilities} Penambalan</p>
            </div>
            <div className="p-3 rounded-xl bg-emerald-950/80 text-emerald-400 border border-emerald-800/80">
              <ShieldCheck className="w-5 h-5" />
            </div>
          </div>
        </div>
      </div>

      {/* Recharts Analytics Section */}
      {totalVulnerabilities > 0 && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          {/* Pie Chart: Severity Distribution */}
          <div className="glass-panel rounded-2xl p-5 border border-slate-800">
            <h3 className="text-xs font-bold uppercase tracking-wider text-slate-300 mb-4 flex items-center space-x-2">
              <PieIcon className="w-4 h-4 text-cyan-400" />
              <span>Vulnerability Severity Breakdown</span>
            </h3>
            <div className="h-48">
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={pieData}
                    cx="50%"
                    cy="50%"
                    innerRadius={45}
                    outerRadius={75}
                    paddingAngle={5}
                    dataKey="value"
                  >
                    {pieData.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={entry.color} />
                    ))}
                  </Pie>
                  <Tooltip 
                    contentStyle={{ backgroundColor: '#0f172a', borderColor: '#334155', borderRadius: '12px', fontSize: '12px' }} 
                  />
                </PieChart>
              </ResponsiveContainer>
            </div>
          </div>

          {/* Bar Chart: Vulnerability Types */}
          <div className="glass-panel rounded-2xl p-5 border border-slate-800">
            <h3 className="text-xs font-bold uppercase tracking-wider text-slate-300 mb-4 flex items-center space-x-2">
              <BarChart3 className="w-4 h-4 text-cyan-400" />
              <span>Threats Vector by Scanner Module</span>
            </h3>
            <div className="h-48">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={categoryBarData}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                  <XAxis dataKey="category" stroke="#94a3b8" fontSize={11} />
                  <YAxis stroke="#94a3b8" fontSize={11} />
                  <Tooltip 
                    contentStyle={{ backgroundColor: '#0f172a', borderColor: '#334155', borderRadius: '12px', fontSize: '12px' }} 
                  />
                  <Bar dataKey="count" fill="#06b6d4" radius={[6, 6, 0, 0]} />
                </BarChart>
              </ResponsiveContainer>
            </div>
          </div>
        </div>
      )}

      {/* Main Content Section Header with View Selector */}
      <div className="glass-panel rounded-2xl p-6">
        <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-4 mb-6">
          <div>
            <h2 className="text-lg font-bold text-white flex items-center space-x-2">
              <span>Security Dashboard & Matrix</span>
              <span className="px-2.5 py-0.5 rounded-full text-xs bg-slate-800 text-cyan-400 border border-slate-700 font-mono">
                {totalVulnerabilities} Total
              </span>
            </h2>
            <p className="text-xs text-slate-400 mt-1">
              Antarmuka analisis kerentanan terintegrasi, visualisasi rantai serangan, dan shield WAF instan.
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            {/* View Mode Switcher */}
            <div className="flex bg-slate-900/80 p-1 rounded-xl border border-slate-800">
              <button
                onClick={() => setDashboardView('matrix')}
                className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition ${
                  dashboardView === 'matrix' ? 'bg-cyan-500 text-slate-950 shadow' : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                Vulnerability Matrix
              </button>
              <button
                onClick={() => setDashboardView('attack-chain')}
                className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition ${
                  dashboardView === 'attack-chain' ? 'bg-cyan-500 text-slate-950 shadow' : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                Attack Chain Graph
              </button>
              <button
                onClick={() => setDashboardView('compliance')}
                className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition ${
                  dashboardView === 'compliance' ? 'bg-cyan-500 text-slate-950 shadow' : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                Compliance Scorecard
              </button>
            </div>

            <button
              onClick={refreshData}
              className="p-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 transition"
              title="Refresh Data"
            >
              <RefreshCw className="w-4 h-4" />
            </button>

            {scans.length > 0 && (
              <>
                <a
                  href={`http://localhost:8000/api/v1/scans/${scans[0].id}/regression-suite`}
                  target="_blank"
                  rel="noreferrer"
                  className="px-3.5 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-semibold border border-slate-700 flex items-center space-x-1.5 transition"
                  title="Download Automated Pytest Security Regression Suite"
                >
                  <Sparkles className="w-3.5 h-3.5 text-cyan-400" />
                  <span>Regression Suite</span>
                </a>

                <button
                  onClick={() => onExportReport(scans[0].id)}
                  className="px-4 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-semibold border border-slate-700 flex items-center space-x-2 transition"
                >
                  <FileSpreadsheet className="w-4 h-4 text-emerald-400" />
                  <span>Export Report (PDF)</span>
                </button>
              </>
            )}
          </div>
        </div>

        {/* View Switch Content */}
        {dashboardView === 'matrix' ? (
          <VulnerabilityMatrix 
            vulnerabilities={vulnerabilities}
            onOpenPatchModal={onOpenPatchModal}
            onOpenVirtualPatchModal={onOpenVirtualPatchModal}
            refreshData={refreshData}
          />
        ) : dashboardView === 'attack-chain' ? (
          <AttackChainGraph scanId={scans.length > 0 ? scans[0].id : null} />
        ) : (
          <ComplianceScorecard scanId={scans.length > 0 ? scans[0].id : null} />
        )}

      </div>
    </div>
  );
}

