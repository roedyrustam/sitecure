import React, { useState } from 'react';
import { Shield, ShieldAlert, Copy, Check, Terminal, ExternalLink, X } from 'lucide-react';
import axios from 'axios';

export default function VirtualPatchModal({ vulnerability, onClose }) {
  const [loading, setLoading] = useState(false);
  const [patchData, setPatchData] = useState(null);
  const [activeTab, setActiveTab] = useState('fastapi');
  const [copiedTab, setCopiedTab] = useState(null);

  React.useEffect(() => {
    if (vulnerability) {
      fetchVirtualPatch();
    }
  }, [vulnerability]);

  const fetchVirtualPatch = async () => {
    setLoading(true);
    try {
      const res = await axios.post(`http://localhost:8000/api/v1/vulnerabilities/virtual-patch/${vulnerability.id}`);
      setPatchData(res.data);
    } catch (err) {
      console.error('Failed to fetch virtual patch:', err);
    } finally {
      setLoading(false);
    }
  };

  const copyToClipboard = (text, tabKey) => {
    navigator.clipboard.writeText(text);
    setCopiedTab(tabKey);
    setTimeout(() => setCopiedTab(null), 2000);
  };

  if (!vulnerability) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-slate-950/80 backdrop-blur-md p-4 animate-in fade-in">
      <div className="bg-slate-900 border border-slate-700/80 rounded-2xl w-full max-w-3xl shadow-2xl overflow-hidden flex flex-col max-h-[90vh]">
        
        {/* Header */}
        <div className="p-6 border-b border-slate-800 bg-slate-900/50 flex justify-between items-start">
          <div className="flex items-center gap-3">
            <div className="p-2.5 rounded-xl bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">
              <Shield className="w-6 h-6" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="text-xs font-semibold px-2.5 py-0.5 rounded-md bg-cyan-500/20 text-cyan-300 border border-cyan-500/30">
                  Instant Virtual Patch & WAF Shield
                </span>
                <span className="text-xs text-slate-400 font-mono">{vulnerability.cwe_id || 'CWE-Security'}</span>
              </div>
              <h2 className="text-xl font-bold text-slate-100 mt-1">{vulnerability.title}</h2>
            </div>
          </div>
          <button onClick={onClose} className="text-slate-400 hover:text-slate-200 p-1.5 rounded-lg hover:bg-slate-800">
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Content */}
        <div className="p-6 overflow-y-auto flex-1 space-y-6">
          
          <div className="bg-cyan-950/30 border border-cyan-800/40 rounded-xl p-4 flex gap-3 text-sm text-cyan-200">
            <ShieldAlert className="w-5 h-5 text-cyan-400 shrink-0 mt-0.5" />
            <div>
              <strong className="text-cyan-300">5-Second Protection Mechanism:</strong> Virtual Patch memblokir serangan aktif pada layer WAF/Middleware sebelum perbaikan kode permanen selesai dideploy.
            </div>
          </div>

          {loading ? (
            <div className="py-12 text-center text-slate-400 flex flex-col items-center gap-2">
              <div className="w-8 h-8 border-2 border-cyan-500 border-t-transparent rounded-full animate-spin"></div>
              Generasi Virtual Patch Shield...
            </div>
          ) : patchData ? (
            <div className="space-y-4">
              
              {/* Tab Selector */}
              <div className="flex gap-2 border-b border-slate-800 pb-2">
                <button
                  onClick={() => setActiveTab('fastapi')}
                  className={`px-4 py-2 text-xs font-medium rounded-lg transition-all ${
                    activeTab === 'fastapi'
                      ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40'
                      : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'
                  }`}
                >
                  FastAPI / App Middleware
                </button>
                <button
                  onClick={() => setActiveTab('nginx')}
                  className={`px-4 py-2 text-xs font-medium rounded-lg transition-all ${
                    activeTab === 'nginx'
                      ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40'
                      : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'
                  }`}
                >
                  Nginx ModSecurity WAF
                </button>
                <button
                  onClick={() => setActiveTab('cloudflare')}
                  className={`px-4 py-2 text-xs font-medium rounded-lg transition-all ${
                    activeTab === 'cloudflare'
                      ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40'
                      : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'
                  }`}
                >
                  Cloudflare WAF Expression
                </button>
              </div>

              {/* Code Snippet Box */}
              <div className="relative bg-slate-950 border border-slate-800 rounded-xl p-4 font-mono text-xs overflow-x-auto text-slate-300">
                <div className="flex justify-between items-center pb-2 mb-2 border-b border-slate-800/60 text-slate-400">
                  <span className="flex items-center gap-1.5">
                    <Terminal className="w-4 h-4 text-cyan-400" />
                    {activeTab === 'fastapi' && 'Python Security Middleware Guard'}
                    {activeTab === 'nginx' && '/etc/nginx/modsec/main.conf Rule'}
                    {activeTab === 'cloudflare' && 'Cloudflare Custom WAF Expression'}
                  </span>
                  <button
                    onClick={() => copyToClipboard(
                      activeTab === 'fastapi' ? patchData.virtual_patches.fastapi_middleware :
                      activeTab === 'nginx' ? patchData.virtual_patches.nginx_modsecurity :
                      patchData.virtual_patches.cloudflare_waf,
                      activeTab
                    )}
                    className="flex items-center gap-1 text-xs px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-200 transition"
                  >
                    {copiedTab === activeTab ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                    {copiedTab === activeTab ? 'Copied!' : 'Copy Rule'}
                  </button>
                </div>

                <pre className="whitespace-pre-wrap leading-relaxed text-cyan-100">
                  {activeTab === 'fastapi' && patchData.virtual_patches.fastapi_middleware}
                  {activeTab === 'nginx' && patchData.virtual_patches.nginx_modsecurity}
                  {activeTab === 'cloudflare' && patchData.virtual_patches.cloudflare_waf}
                </pre>
              </div>

              {/* Guide */}
              <div className="bg-slate-950/40 border border-slate-800/80 rounded-xl p-3.5 text-xs text-slate-300 flex items-start gap-2">
                <ExternalLink className="w-4 h-4 text-cyan-400 shrink-0 mt-0.5" />
                <div>
                  <strong className="text-slate-200">Panduan Pemasangan: </strong>
                  {activeTab === 'fastapi' && patchData.installation_guide.fastapi}
                  {activeTab === 'nginx' && patchData.installation_guide.nginx}
                  {activeTab === 'cloudflare' && patchData.installation_guide.cloudflare}
                </div>
              </div>

            </div>
          ) : null}

        </div>

        {/* Footer */}
        <div className="p-4 border-t border-slate-800 bg-slate-900/50 flex justify-end">
          <button
            onClick={onClose}
            className="px-5 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-200 text-sm font-medium transition"
          >
            Tutup
          </button>
        </div>

      </div>
    </div>
  );
}
