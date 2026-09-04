import React, { useState } from 'react';
import { ShieldCheck, ChevronLeft, Sun, Moon, Terminal, Activity, Database } from 'lucide-react';
import { User, ScanResult } from './types';
import Dashboard from './components/Dashboard';
import ReportView from './components/ReportView';
import { useTheme } from './components/ThemeProvider';

const DEFAULT_OFFICIAL_USER: User = {
  id: 'usr_soc_official_master',
  email: 'official@cyberguard.gov',
  fullName: 'Cyber Security Official (SOC Lead)',
  mobileNumber: '+1 (800) CYBER-SOC',
  role: 'admin',
  plan: 'pro',
  scansThisMonth: 0,
  createdAt: new Date().toISOString()
};

export default function App() {
  const { theme, toggleTheme } = useTheme();
  const [user, setUser] = useState<User>(DEFAULT_OFFICIAL_USER);
  const [token] = useState<string>('cyberguard_soc_official_master_token_2026');
  const [gmailToken, setGmailToken] = useState<string | null>(null);
  const [activeView, setActiveView] = useState<'dashboard' | 'report'>('dashboard');
  const [selectedScan, setSelectedScan] = useState<ScanResult | null>(null);

  const handleSelectReport = (scan: ScanResult) => {
    setSelectedScan(scan);
    setActiveView('report');
  };

  const handleUserUpdate = (updatedUser: User) => {
    setUser(updatedUser);
  };

  return (
    <div className={`min-h-screen bg-[#090D14] text-[#ECEFF4] flex flex-col font-sans ${theme === 'midnight' ? 'theme-midnight' : ''}`}>
      
      {/* TACTICAL 2030 QUANTUM COMMAND HEADER */}
      <header className="sticky top-0 z-40 bg-[#0D131F] border-b border-[#202D42] px-4 py-2 flex items-center justify-between print:hidden shadow-lg">
        <div 
          onClick={() => setActiveView('dashboard')}
          className="flex items-center gap-3 cursor-pointer select-none"
        >
          <div className="w-8 h-8 bg-[#131B2A] border border-[#00E5FF]/40 rounded-sm flex items-center justify-center text-[#00E5FF] shadow-[0_0_12px_rgba(0,229,255,0.25)]">
            <ShieldCheck className="w-5 h-5 text-[#00E5FF]" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h1 className="text-sm font-bold tracking-wider font-display uppercase text-white flex items-center gap-1.5">
                CYBERGUARD <span className="text-[#00E5FF] font-mono text-xs font-normal">// 2030 QUANTUM SOC</span>
              </h1>
              <span className="px-1.5 py-0.5 rounded-sm text-[9px] font-mono font-bold bg-[#A855F7]/15 text-[#C084FC] border border-[#A855F7]/40 shadow-[0_0_8px_rgba(168,85,247,0.2)]">
                v2030.1.0-PQC
              </span>
            </div>
            <span className="text-[10px] font-mono tracking-wide text-[#8392A5] block -mt-0.5">
              Autonomous AI Swarm & Post-Quantum Forensics Console
            </span>
          </div>
        </div>

        {/* 2030 Telemetry Status Bar & Utility Actions */}
        <div className="flex items-center gap-3 font-mono text-[10px]">
          <div className="hidden lg:flex items-center gap-3 border-r border-[#202D42] pr-3 text-[#8392A5]">
            <span className="flex items-center gap-1">
              <span className="w-2 h-2 rounded-full bg-[#10B981] animate-pulse"></span>
              PQC (FIPS 203): <strong className="text-[#F0F4F8]">READY</strong>
            </span>
            <span className="flex items-center gap-1">
              <Activity className="w-3 h-3 text-[#A855F7]" />
              AI SWARM: <strong className="text-[#F0F4F8]">4/4 ACTIVE</strong>
            </span>
            <span className="flex items-center gap-1">
              <Database className="w-3 h-3 text-[#00E5FF]" />
              LEO MESH: <strong className="text-[#F0F4F8]">ATTESTED</strong>
            </span>
            <span className="flex items-center gap-1">
              <Terminal className="w-3 h-3 text-[#F59E0B]" />
              STIX 3.0: <strong className="text-[#F0F4F8]">ARMED</strong>
            </span>
          </div>

          <button
            onClick={toggleTheme}
            className="btn-soc px-2.5 py-1 flex items-center gap-1.5 text-[10px]"
            title="Toggle contrast visual density"
          >
            {theme === 'slate' ? (
              <>
                <Moon className="w-3 h-3 text-[#00E5FF]" />
                <span>MIDNIGHT</span>
              </>
            ) : (
              <>
                <Sun className="w-3 h-3 text-[#F59E0B]" />
                <span>CYBER SLATE</span>
              </>
            )}
          </button>

          {activeView !== 'dashboard' && (
            <button
              onClick={() => setActiveView('dashboard')}
              className="btn-soc px-2.5 py-1 flex items-center gap-1.5 text-[10px]"
            >
              <ChevronLeft className="w-3.5 h-3.5 text-[#00E5FF]" />
              <span>RETURN TO WORKSTATION</span>
            </button>
          )}
        </div>
      </header>

      {/* MASTER HIGH-DENSITY CANVAS */}
      <main className="flex-1 w-full max-w-[1680px] mx-auto px-3 py-4 print:p-0">
        {activeView === 'dashboard' && (
          <Dashboard
            user={user}
            token={token}
            gmailToken={gmailToken}
            setGmailToken={setGmailToken}
            onSelectReport={handleSelectReport}
            onUserUpdate={handleUserUpdate}
          />
        )}

        {activeView === 'report' && selectedScan && (
          <ReportView
            scan={selectedScan}
            onBack={() => setActiveView('dashboard')}
          />
        )}
      </main>

      {/* COMPACT 2030 COMMAND FOOTER */}
      <footer className="border-t border-[#202D42] py-2.5 px-4 text-center text-[10px] font-mono text-[#8392A5] bg-[#0D131F] print:hidden">
        <div className="flex flex-col sm:flex-row items-center justify-between gap-2 max-w-[1680px] mx-auto">
          <span>CYBERGUARD 2030 QUANTUM COMMAND INFRASTRUCTURE • STRICT ZERO-RETENTION FORENSIC PROTOCOL</span>
          <span>NIST FIPS 203/204/205 POST-QUANTUM COMPLIANT • AUTONOMOUS AI SWARM • STIX 3.0 EVIDENCE ENGINE</span>
        </div>
      </footer>

    </div>
  );
}
