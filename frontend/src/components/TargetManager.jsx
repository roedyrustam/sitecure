import React, { useState } from 'react';
import { Plus, Globe, Server, Code, Trash2, Play, Check, AlertCircle } from 'lucide-react';
import axios from 'axios';

export default function TargetManager({ targets, onTargetAdded, onTargetDeleted, onTriggerScan }) {
  const [name, setName] = useState('');
  const [targetUrl, setTargetUrl] = useState('');
  const [assetType, setAssetType] = useState('web');
  const [environment, setEnvironment] = useState('internal');
  const [description, setDescription] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!name || !targetUrl) {
      setError('Nama Target dan URL/IP wajib diisi.');
      return;
    }

    try {
      setLoading(true);
      setError('');
      const res = await axios.post('/api/v1/targets/', {
        name,
        target_url: targetUrl,
        asset_type: assetType,
        environment,
        description
      });
      onTargetAdded(res.data);
      setName('');
      setTargetUrl('');
      setDescription('');
    } catch (err) {
      setError(err.response?.data?.detail || 'Gagal menambahkan target asset.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Target Asset Registration Card */}
      <div className="glass-panel rounded-2xl p-6 border border-slate-800">
        <h2 className="text-lg font-bold text-white mb-2 flex items-center space-x-2">
          <Globe className="w-5 h-5 text-cyan-400" />
          <span>Register Internal Target Asset</span>
        </h2>
        <p className="text-xs text-slate-400 mb-6">
          Tambahkan URL, IP Address, atau repositori internal yang ingin diaudit kerentanannya oleh SiteCure.
        </p>

        {error && (
          <div className="mb-4 p-3 rounded-xl bg-red-950/80 border border-red-800 text-red-300 text-xs flex items-center space-x-2">
            <AlertCircle className="w-4 h-4 text-red-400 shrink-0" />
            <span>{error}</span>
          </div>
        )}

        <form onSubmit={handleSubmit} className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
          <div>
            <label className="block text-xs font-semibold text-slate-300 mb-1.5">Nama Target Asset</label>
            <input
              type="text"
              placeholder="e.g. HRIS Web Portal Internal"
              value={name}
              onChange={(e) => setName(e.target.value)}
              className="w-full px-3.5 py-2.5 rounded-xl bg-slate-900 border border-slate-700 text-slate-100 text-xs focus:outline-none focus:border-cyan-500 transition"
            />
          </div>

          <div>
            <label className="block text-xs font-semibold text-slate-300 mb-1.5">Target URL / Host IP / Production Domain</label>
            <input
              type="text"
              placeholder="e.g. https://my-app.com or http://192.168.1.50:8080"
              value={targetUrl}
              onChange={(e) => setTargetUrl(e.target.value)}
              className="w-full px-3.5 py-2.5 rounded-xl bg-slate-900 border border-slate-700 text-slate-100 text-xs focus:outline-none focus:border-cyan-500 font-mono transition"
            />
          </div>

          <div>
            <label className="block text-xs font-semibold text-slate-300 mb-1.5">Environment Tag</label>
            <select
              value={environment}
              onChange={(e) => setEnvironment(e.target.value)}
              className="w-full px-3.5 py-2.5 rounded-xl bg-slate-900 border border-slate-700 text-slate-100 text-xs focus:outline-none focus:border-cyan-500 transition"
            >
              <option value="prod">Production (Live Deployed Web)</option>
              <option value="internal">Internal Network</option>
              <option value="staging">Staging / QA</option>
              <option value="dev">Development</option>
            </select>
          </div>

          <div className="flex items-end">
            <button
              type="submit"
              disabled={loading}
              className="w-full py-2.5 rounded-xl bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-slate-950 font-bold text-xs shadow-md shadow-cyan-500/20 flex items-center justify-center space-x-2 transition disabled:opacity-50"
            >
              <Plus className="w-4 h-4" />
              <span>{loading ? 'Adding Target...' : 'Add Target Asset'}</span>
            </button>
          </div>
        </form>
      </div>

      {/* Target Asset Inventory List */}
      <div className="glass-panel rounded-2xl p-6">
        <h3 className="text-md font-bold text-white mb-4">Target Assets Inventory ({targets.length})</h3>

        {targets.length === 0 ? (
          <div className="text-center py-12 text-slate-500 text-xs">
            Belum ada target asset registered. Tambahkan URL atau IP internal di atas untuk memulai pemindaian.
          </div>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {targets.map((target) => (
              <div key={target.id} className="glass-card rounded-xl p-4 flex flex-col justify-between border border-slate-800 hover:border-cyan-500/40 transition">
                <div>
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-bold text-cyan-400 uppercase tracking-wider px-2 py-0.5 rounded bg-cyan-950 border border-cyan-800">
                      {target.environment}
                    </span>
                    <button
                      onClick={() => onTargetDeleted(target.id)}
                      className="p-1.5 rounded-lg text-slate-500 hover:text-red-400 hover:bg-slate-800 transition"
                      title="Delete Target"
                    >
                      <Trash2 className="w-4 h-4" />
                    </button>
                  </div>

                  <h4 className="text-base font-bold text-white mt-2">{target.name}</h4>
                  <p className="text-xs font-mono text-slate-400 mt-1 break-all bg-slate-900/60 p-2 rounded-lg border border-slate-800">
                    {target.target_url}
                  </p>
                </div>

                <div className="mt-4 pt-3 border-t border-slate-800/80 flex items-center justify-between">
                  <span className="text-[11px] text-slate-500">
                    Registered: {new Date(target.created_at).toLocaleDateString()}
                  </span>

                  <button
                    onClick={() => onTriggerScan(target.id)}
                    className="px-3 py-1.5 rounded-lg bg-cyan-500/10 hover:bg-cyan-500/20 text-cyan-400 border border-cyan-500/30 text-xs font-semibold flex items-center space-x-1.5 transition"
                  >
                    <Play className="w-3.5 h-3.5 fill-cyan-400" />
                    <span>Launch Scan</span>
                  </button>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
