import React from 'react';
import { FileSpreadsheet, FileCode, Download, ShieldCheck, FileText } from 'lucide-react';
import axios from 'axios';

export default function ReportExporter({ scanId }) {
  const handleDownloadPDF = () => {
    window.open(`/api/v1/reports/pdf/${scanId}`, '_blank');
  };

  const handleDownloadCSV = () => {
    window.open(`/api/v1/reports/csv/${scanId}`, '_blank');
  };

  const handleDownloadJSON = async () => {
    try {
      const res = await axios.get(`/api/v1/reports/json/${scanId}`);
      const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(res.data, null, 2));
      const downloadAnchor = document.createElement('a');
      downloadAnchor.setAttribute("href", dataStr);
      downloadAnchor.setAttribute("download", `sitecure_audit_scan_${scanId}.json`);
      document.body.appendChild(downloadAnchor);
      downloadAnchor.click();
      downloadAnchor.remove();
    } catch (err) {
      alert('Gagal mengunduh laporan JSON.');
    }
  };

  return (
    <div className="glass-card rounded-2xl p-5 border border-emerald-500/30 space-y-4">
      <div className="flex items-center space-x-3">
        <div className="p-2.5 rounded-xl bg-emerald-950 text-emerald-400 border border-emerald-800">
          <ShieldCheck className="w-5 h-5" />
        </div>
        <div>
          <h3 className="text-sm font-bold text-white">Executive Audit Report Generator</h3>
          <p className="text-xs text-slate-400">Unduh hasil pemindaian & audit kerentanan resmi untuk Scan #{scanId}</p>
        </div>
      </div>

      <div className="flex flex-wrap items-center gap-3 pt-2">
        <button
          onClick={handleDownloadPDF}
          className="px-4 py-2.5 rounded-xl bg-gradient-to-r from-emerald-500 to-teal-600 hover:from-emerald-400 hover:to-teal-500 text-slate-950 font-bold text-xs shadow-md shadow-emerald-500/20 flex items-center space-x-2 transition"
        >
          <FileSpreadsheet className="w-4 h-4" />
          <span>Download PDF Report</span>
        </button>

        <button
          onClick={handleDownloadCSV}
          className="px-4 py-2.5 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-200 font-bold text-xs border border-slate-700 flex items-center space-x-2 transition"
        >
          <FileText className="w-4 h-4 text-emerald-400" />
          <span>Download CSV Format</span>
        </button>

        <button
          onClick={handleDownloadJSON}
          className="px-4 py-2.5 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-200 font-bold text-xs border border-slate-700 flex items-center space-x-2 transition"
        >
          <FileCode className="w-4 h-4 text-cyan-400" />
          <span>Export JSON Audit Format</span>
        </button>
      </div>
    </div>
  );
}
