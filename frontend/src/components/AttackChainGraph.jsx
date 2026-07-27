import React, { useEffect, useState } from 'react';
import { GitCommit, ShieldAlert, ArrowRight, Activity, Zap, Info } from 'lucide-react';
import axios from 'axios';

export default function AttackChainGraph({ scanId }) {
  const [loading, setLoading] = useState(false);
  const [data, setData] = useState(null);

  useEffect(() => {
    if (scanId) {
      fetchAttackChain();
    }
  }, [scanId]);

  const fetchAttackChain = async () => {
    setLoading(true);
    try {
      const res = await axios.get(`http://localhost:8000/api/v1/scans/${scanId}/attack-chain`);
      setData(res.data);
    } catch (err) {
      console.error('Failed to fetch attack chain:', err);
    } finally {
      setLoading(false);
    }
  };

  if (loading) {
    return (
      <div className="py-12 text-center text-slate-400 flex flex-col items-center gap-2">
        <div className="w-8 h-8 border-2 border-indigo-500 border-t-transparent rounded-full animate-spin"></div>
        Analisis Rantai Serangan (Hybrid Attack Chain Correlation)...
      </div>
    );
  }

  if (!data || !data.attack_chains || data.attack_chains.length === 0) {
    return (
      <div className="p-8 text-center text-slate-400 bg-slate-900/50 border border-slate-800 rounded-2xl">
        <Info className="w-8 h-8 text-slate-500 mx-auto mb-2" />
        Tidak ada rantai serangan berisiko tinggi yang terdeteksi untuk hasil pemindaian ini.
      </div>
    );
  }

  return (
    <div className="space-y-6">
      
      {/* Overview Cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-4 flex items-center gap-3">
          <div className="p-3 bg-indigo-500/10 text-indigo-400 rounded-xl border border-indigo-500/20">
            <Activity className="w-5 h-5" />
          </div>
          <div>
            <div className="text-xs text-slate-400">Total Kerentanan Terkorelasi</div>
            <div className="text-xl font-bold text-slate-100">{data.total_vulnerabilities}</div>
          </div>
        </div>

        <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-4 flex items-center gap-3">
          <div className="p-3 bg-purple-500/10 text-purple-400 rounded-xl border border-purple-500/20">
            <GitCommit className="w-5 h-5" />
          </div>
          <div>
            <div className="text-xs text-slate-400">Korelasi DAST-SAST Match</div>
            <div className="text-xl font-bold text-slate-100">{data.correlated_pairs_count} Pairs</div>
          </div>
        </div>

        <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-4 flex items-center gap-3">
          <div className="p-3 bg-rose-500/10 text-rose-400 rounded-xl border border-rose-500/20">
            <Zap className="w-5 h-5" />
          </div>
          <div>
            <div className="text-xs text-slate-400">Rantai Serangan Aktif</div>
            <div className="text-xl font-bold text-slate-100">{data.attack_chains_count} Threat Chains</div>
          </div>
        </div>
      </div>

      {/* Attack Chains List */}
      <div className="space-y-4">
        {data.attack_chains.map((chain, index) => (
          <div key={index} className="bg-slate-900/80 border border-slate-800 rounded-2xl p-5 space-y-4">
            
            <div className="flex justify-between items-start">
              <div>
                <div className="flex items-center gap-2">
                  <span className={`text-xs font-semibold px-2.5 py-0.5 rounded-full ${
                    chain.risk === 'CRITICAL' ? 'bg-rose-500/20 text-rose-300 border border-rose-500/40' :
                    chain.risk === 'HIGH' ? 'bg-amber-500/20 text-amber-300 border border-amber-500/40' :
                    'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40'
                  }`}>
                    {chain.risk} ATTACK CHAIN
                  </span>
                  <h3 className="text-base font-bold text-slate-100">{chain.title}</h3>
                </div>
                <p className="text-xs text-slate-400 mt-1">{chain.description}</p>
              </div>
            </div>

            {/* Interactive Attack Chain Flow Nodes */}
            <div className="bg-slate-950/60 border border-slate-800/80 rounded-xl p-4">
              <div className="flex flex-col md:flex-row items-center justify-between gap-3">
                {chain.nodes.map((node, nIdx) => (
                  <React.Fragment key={nIdx}>
                    <div className="flex-1 w-full bg-slate-900 border border-slate-800 rounded-xl p-3 text-center space-y-1">
                      <div className="text-[10px] uppercase font-semibold text-indigo-400 tracking-wider">
                        Step {node.step}: {node.type}
                      </div>
                      <div className="text-xs font-medium text-slate-200">{node.label}</div>
                    </div>

                    {nIdx < chain.nodes.length - 1 && (
                      <ArrowRight className="w-5 h-5 text-indigo-400 shrink-0 hidden md:block" />
                    )}
                  </React.Fragment>
                ))}
              </div>
            </div>

          </div>
        ))}
      </div>

    </div>
  );
}
