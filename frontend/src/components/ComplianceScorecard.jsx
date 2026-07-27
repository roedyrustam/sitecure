import React, { useEffect, useState } from 'react';
import { ShieldCheck, ShieldAlert, Award, FileText, CheckCircle2, AlertOctagon } from 'lucide-react';
import axios from 'axios';

export default function ComplianceScorecard({ scanId }) {
  const [loading, setLoading] = useState(false);
  const [compliance, setCompliance] = useState(null);

  useEffect(() => {
    if (scanId) {
      fetchCompliance();
    }
  }, [scanId]);

  const fetchCompliance = async () => {
    setLoading(true);
    try {
      const res = await axios.get(`http://localhost:8000/api/v1/scans/${scanId}/compliance-report`);
      setCompliance(res.data);
    } catch (err) {
      console.error('Failed to fetch compliance report:', err);
    } finally {
      setLoading(false);
    }
  };

  if (loading) {
    return (
      <div className="py-12 text-center text-slate-400 flex flex-col items-center gap-2">
        <div className="w-8 h-8 border-2 border-emerald-500 border-t-transparent rounded-full animate-spin"></div>
        Mengkalkulasi Kepatuhan Standar Keamanan Enterprise (PCI-DSS & ISO 27001)...
      </div>
    );
  }

  if (!compliance) return null;

  const { summary, standards } = compliance;

  return (
    <div className="space-y-6">
      
      {/* Overview Metric Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        
        {/* PCI-DSS Score Card */}
        <div className={`p-5 rounded-2xl border ${
          summary.pci_dss_compliance_status.includes('COMPLIANT') 
            ? 'bg-emerald-950/40 border-emerald-800/80' 
            : 'bg-rose-950/40 border-rose-800/80'
        }`}>
          <div className="flex justify-between items-start">
            <div>
              <span className="text-xs font-bold uppercase tracking-wider text-slate-400">Payment Card Industry</span>
              <h3 className="text-xl font-extrabold text-slate-100 mt-1">PCI-DSS v4.0 (Req 6)</h3>
              <div className="flex items-center gap-2 mt-2">
                <span className={`text-2xl font-black ${
                  summary.pci_dss_compliance_status.includes('COMPLIANT') ? 'text-emerald-400' : 'text-rose-400'
                }`}>
                  {summary.pci_dss_score}
                </span>
                <span className={`text-xs font-bold px-2.5 py-0.5 rounded-full ${
                  summary.pci_dss_compliance_status.includes('COMPLIANT')
                    ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/30'
                    : 'bg-rose-500/20 text-rose-300 border border-rose-500/30'
                }`}>
                  {summary.pci_dss_compliance_status}
                </span>
              </div>
            </div>
            <Award className={`w-8 h-8 ${
              summary.pci_dss_compliance_status.includes('COMPLIANT') ? 'text-emerald-400' : 'text-rose-400'
            }`} />
          </div>
          <p className="text-xs text-slate-400 mt-3">
            {standards.pci_dss_violations_count} Pelanggaran regulasi keamanan perangkat lunak terdeteksi.
          </p>
        </div>

        {/* ISO 27001 Score Card */}
        <div className={`p-5 rounded-2xl border ${
          summary.iso_27001_compliance_status.includes('COMPLIANT') 
            ? 'bg-emerald-950/40 border-emerald-800/80' 
            : 'bg-amber-950/40 border-amber-800/80'
        }`}>
          <div className="flex justify-between items-start">
            <div>
              <span className="text-xs font-bold uppercase tracking-wider text-slate-400">Information Security Management</span>
              <h3 className="text-xl font-extrabold text-slate-100 mt-1">ISO/IEC 27001:2022</h3>
              <div className="flex items-center gap-2 mt-2">
                <span className={`text-2xl font-black ${
                  summary.iso_27001_compliance_status.includes('COMPLIANT') ? 'text-emerald-400' : 'text-amber-400'
                }`}>
                  {summary.iso_27001_score}
                </span>
                <span className={`text-xs font-bold px-2.5 py-0.5 rounded-full ${
                  summary.iso_27001_compliance_status.includes('COMPLIANT')
                    ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/30'
                    : 'bg-amber-500/20 text-amber-300 border border-amber-500/30'
                }`}>
                  {summary.iso_27001_compliance_status}
                </span>
              </div>
            </div>
            <ShieldCheck className={`w-8 h-8 ${
              summary.iso_27001_compliance_status.includes('COMPLIANT') ? 'text-emerald-400' : 'text-amber-400'
            }`} />
          </div>
          <p className="text-xs text-slate-400 mt-3">
            {standards.iso_27001_violations_count} Kontrol keamanan ISO (Annex A.8.28 & A.8.8) membutuhkan tindakan.
          </p>
        </div>

      </div>

      {/* OWASP Top 10 Breakdown Table */}
      <div className="bg-slate-900/80 border border-slate-800 rounded-2xl p-5 space-y-4">
        <h4 className="text-sm font-bold text-slate-200 flex items-center gap-2">
          <FileText className="w-4 h-4 text-cyan-400" />
          <span>Distribusi Kepatuhan OWASP Top 10 (2021)</span>
        </h4>
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
          {Object.entries(standards.owasp_top_10_distribution).map(([cat, count], idx) => (
            <div key={idx} className="bg-slate-950/60 border border-slate-800 rounded-xl p-3 flex justify-between items-center text-xs">
              <span className="font-mono text-cyan-300">{cat}</span>
              <span className="px-2 py-0.5 rounded bg-rose-500/20 text-rose-300 font-bold border border-rose-500/30">
                {count} Findings
              </span>
            </div>
          ))}
        </div>
      </div>

    </div>
  );
}
