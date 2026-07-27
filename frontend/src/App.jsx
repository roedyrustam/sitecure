import React, { useState, useEffect } from 'react';
import axios from 'axios';
import Header from './components/Header';
import Dashboard from './components/Dashboard';
import TargetManager from './components/TargetManager';
import ScannerControl from './components/ScannerControl';
import AIRemediationModal from './components/AIRemediationModal';
import VirtualPatchModal from './components/VirtualPatchModal';
import CommandPalette from './components/CommandPalette';
import ReportExporter from './components/ReportExporter';

export default function App() {
  const [activeTab, setActiveTab] = useState('dashboard');
  const [targets, setTargets] = useState([]);
  const [scans, setScans] = useState([]);
  const [vulnerabilities, setVulnerabilities] = useState([]);
  const [selectedPatchVuln, setSelectedPatchVuln] = useState(null);
  const [selectedVirtualPatchVuln, setSelectedVirtualPatchVuln] = useState(null);
  const [isCommandPaletteOpen, setIsCommandPaletteOpen] = useState(false);
  const [exportScanId, setExportScanId] = useState(null);
  const [loading, setLoading] = useState(true);


  const fetchData = async () => {
    try {
      setLoading(true);
      const [targetRes, scanRes, vulnRes] = await Promise.all([
        axios.get('/api/v1/targets/'),
        axios.get('/api/v1/scans/'),
        axios.get('/api/v1/vulnerabilities/')
      ]);
      setTargets(targetRes.data);
      setScans(scanRes.data);
      setVulnerabilities(vulnRes.data);
    } catch (err) {
      console.error('Error loading initial data', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
  }, []);

  const handleTargetAdded = (newTarget) => {
    setTargets((prev) => [newTarget, ...prev]);
  };

  const handleTargetDeleted = async (targetId) => {
    try {
      await axios.delete(`/api/v1/targets/${targetId}`);
      setTargets((prev) => prev.filter((t) => t.id !== targetId));
    } catch (err) {
      alert('Gagal menghapus target.');
    }
  };

  const handleTriggerScan = async (targetId) => {
    try {
      const res = await axios.post('/api/v1/scans/', {
        target_id: targetId,
        scan_type: 'full'
      });
      setScans((prev) => [res.data, ...prev]);
      setActiveTab('scanner');
    } catch (err) {
      alert('Gagal memulai scan job.');
    }
  };

  const handleScanStarted = (newScan) => {
    setScans((prev) => [newScan, ...prev]);
  };

  const activeScansCount = scans.filter((s) => s.status === 'running').length;

  return (
    <div className="min-h-screen pb-12 bg-slate-950 text-slate-100">
      <Header
        activeTab={activeTab}
        setActiveTab={setActiveTab}
        targetCount={targets.length}
        activeScansCount={activeScansCount}
        onOpenCommandPalette={() => setIsCommandPaletteOpen(true)}
      />

      <main className="max-w-7xl mx-auto px-6 space-y-6">
        {exportScanId && (
          <div className="relative">
            <ReportExporter scanId={exportScanId} />
            <button
              onClick={() => setExportScanId(null)}
              className="absolute top-3 right-3 text-xs text-slate-400 hover:text-white font-bold"
            >
              ✕ Tutup
            </button>
          </div>
        )}

        {loading ? (
          <div className="flex flex-col items-center justify-center py-24 space-y-3">
            <div className="w-10 h-10 rounded-full border-4 border-cyan-500/30 border-t-cyan-400 animate-spin"></div>
            <p className="text-xs font-semibold text-cyan-300">Memuat Dashboard Security SiteCure...</p>
          </div>
        ) : (
          <>
            {activeTab === 'dashboard' && (
              <Dashboard
                targets={targets}
                scans={scans}
                vulnerabilities={vulnerabilities}
                onLaunchScan={() => setActiveTab('scanner')}
                onOpenPatchModal={(vuln) => setSelectedPatchVuln(vuln)}
                onOpenVirtualPatchModal={(vuln) => setSelectedVirtualPatchVuln(vuln)}
                onExportReport={(scanId) => setExportScanId(scanId)}
                refreshData={fetchData}
              />
            )}

            {activeTab === 'targets' && (
              <TargetManager
                targets={targets}
                onTargetAdded={handleTargetAdded}
                onTargetDeleted={handleTargetDeleted}
                onTriggerScan={handleTriggerScan}
              />
            )}

            {activeTab === 'scanner' && (
              <ScannerControl
                targets={targets}
                scans={scans}
                onScanStarted={handleScanStarted}
              />
            )}
          </>
        )}
      </main>

      {/* AI Remediation Patch Modal */}
      {selectedPatchVuln && (
        <AIRemediationModal
          vulnerability={selectedPatchVuln}
          onClose={() => setSelectedPatchVuln(null)}
          refreshData={fetchData}
        />
      )}

      {/* Virtual Patch & WAF Shield Modal */}
      {selectedVirtualPatchVuln && (
        <VirtualPatchModal
          vulnerability={selectedVirtualPatchVuln}
          onClose={() => setSelectedVirtualPatchVuln(null)}
        />
      )}

      {/* Command Palette Global Modal */}
      <CommandPalette
        isOpen={isCommandPaletteOpen}
        onClose={() => setIsCommandPaletteOpen(false)}
        vulnerabilities={vulnerabilities}
        targets={targets}
        onSelectVuln={(vuln) => setSelectedPatchVuln(vuln)}
        onSelectTarget={() => setActiveTab('targets')}
      />
    </div>
  );
}
