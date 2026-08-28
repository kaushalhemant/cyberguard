import React, { useState } from 'react';
import { ShieldCheck, ChevronLeft, Sun, Moon, Terminal, Activity, Database } from 'lucide-react';
import { Analytics } from '@vercel/analytics/react';
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
      
      {/* TACTICAL COMMAND HEADER (1px solid grid lines, 0 blur) */}
      <header className="sticky top-0 z-40 bg-[#111622] border-b border-[#263147] px-4 py-2 flex items-center justify-between print:hidden">
        <div 
          onClick={() => setActiveView('dashboard')}
          className="flex items-center gap-3 cursor-pointer select-none"
        >
          <div className="w-8 h-8 bg-[#181F2E] border border-[#263147] rounded-sm flex items-center justify-center text-[#00E5FF]">
            <ShieldCheck className="w-5 h-5 text-[#00E5FF]" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h1 className="text-sm font-bold tracking-wider font-display uppercase text-white flex items-center gap-1.5">
                CYBERGUARD <span className="text-[#00E5FF] font-mono text-xs font-normal">// SIEM WORKSTATION</span>
              </h1>
              <span className="px-1.5 py-0.5 rounded-sm text-[9px] font-mono font-bold bg-[#181F2E] text-[#00E5FF] border border-[#263147]">
                v4.2.0-PROD
              </span>
            </div>
            <span className="text-[10px] font-mono tracking-wide text-[#7E8B9B] block -mt-0.5">
              Threat Intelligence & Forensics Operations Console
            </span>
          </div>
        </div>

        {/* Telemetry Status Bar & Utility Actions */}
        <div className="flex items-center gap-3 font-mono text-[10px]">
          <div className="hidden md:flex items-center gap-3 border-r border-[#263147] pr-3 text-[#7E8B9B]">
            <span className="flex items-center gap-1">
              <Activity className="w-3 h-3 text-[#00E676]" />
              ENGINE: <strong className="text-[#ECEFF4]">ACTIVE</strong>
            </span>
            <span className="flex items-center gap-1">
              <Database className="w-3 h-3 text-[#00E5FF]" />
              CVE DB: <strong className="text-[#ECEFF4]">NVD v2.0</strong>
            </span>
            <span className="flex items-center gap-1">
              <Terminal className="w-3 h-3 text-[#FF9900]" />
              STIX 2.1: <strong className="text-[#ECEFF4]">READY</strong>
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
                <Sun className="w-3 h-3 text-[#FF9900]" />
                <span>DARK SLATE</span>
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
      <main className="flex-1 w-full max-w-[1600px] mx-auto px-3 py-4 print:p-0">
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

      {/* COMPACT COMMAND FOOTER */}
      <footer className="border-t border-[#263147] py-2.5 px-4 text-center text-[10px] font-mono text-[#7E8B9B] bg-[#111622] print:hidden">
        <div className="flex flex-col sm:flex-row items-center justify-between gap-2 max-w-[1600px] mx-auto">
          <span>CYBERGUARD COMMAND INFRASTRUCTURE • STRICT ZERO-RETENTION FORENSIC PROTOCOL</span>
          <span>NVD v2.0 FEED • STIX 2.1 EVIDENCE ENGINE • SHA-256 SESSION INTEGRITY</span>
        </div>
      </footer>

      <Analytics />
    </div>
  );
}
