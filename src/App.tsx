import React, { useState } from 'react';
import { ShieldCheck, ChevronLeft, Sun, Moon } from 'lucide-react';
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
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col font-sans selection:bg-sky-500/20 selection:text-white">
      
      {/* GLOBAL APPLICATION HEADER */}
      <header className="sticky top-0 z-40 glass-header px-6 py-3.5 flex items-center justify-between print:hidden border-b border-slate-800 shadow-md">
        <div 
          onClick={() => setActiveView('dashboard')}
          className="flex items-center gap-3 cursor-pointer group"
        >
          <div className="w-10 h-10 bg-slate-900 border border-sky-500/30 rounded-xl flex items-center justify-center text-sky-400 group-hover:border-sky-400 transition-all shadow-sm">
            <ShieldCheck className="w-6 h-6 text-sky-400" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h1 className="text-lg font-bold tracking-tight font-display text-white flex items-center gap-1.5">
                CyberGuard
              </h1>
              <span className="px-2.5 py-0.5 rounded-full text-[9px] font-mono font-bold bg-sky-500/10 text-sky-300 border border-sky-500/30 tracking-wider">
                VERIFIED SECURITY HUB
              </span>
            </div>
            <span className="text-[10px] font-mono tracking-wider text-slate-400 block -mt-0.5">
              Rule-Based Threat Diagnostics & NIST CVE Forensic Engine
            </span>
          </div>
        </div>

        <div className="flex items-center gap-3">
          {/* Theme Toggle Button */}
          <button
            onClick={toggleTheme}
            className="text-slate-300 hover:text-white transition-all font-mono text-[10px] font-bold flex items-center gap-2 bg-slate-900/80 border border-slate-800 hover:border-sky-500/40 px-3 py-1.5 rounded-xl cursor-pointer shadow-sm"
            title={theme === 'slate' ? 'Switch to High-Contrast Midnight Theme' : 'Switch to Slate Theme'}
          >
            {theme === 'slate' ? (
              <>
                <Moon className="w-3.5 h-3.5 text-indigo-400" />
                <span className="hidden sm:inline">MIDNIGHT</span>
              </>
            ) : (
              <>
                <Sun className="w-3.5 h-3.5 text-amber-400" />
                <span className="hidden sm:inline">DARK SLATE</span>
              </>
            )}
          </button>

          {activeView !== 'dashboard' && (
            <button
              onClick={() => setActiveView('dashboard')}
              className="text-xs text-slate-300 hover:text-white transition-all font-mono font-semibold flex items-center gap-1.5 bg-slate-900 border border-slate-800 hover:border-sky-500/40 px-3 py-1.5 rounded-xl cursor-pointer"
            >
              <ChevronLeft className="w-4 h-4 text-sky-400" />
              DASHBOARD
            </button>
          )}

          <div className="bg-slate-900/80 border border-emerald-500/30 px-3 py-1.5 rounded-xl flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse"></span>
            <span className="text-[10px] uppercase font-mono text-emerald-400 font-bold hidden sm:inline">ENGINE ACTIVE</span>
          </div>
        </div>
      </header>

      {/* MASTER CENTRAL CANVAS CONTAINER */}
      <main className="flex-1 w-full max-w-7xl mx-auto px-4 py-6 md:px-6 relative z-10 print:p-0">
        
        {/* Background ambient lighting */}
        <div className="absolute top-1/4 left-1/10 w-96 h-96 bg-sky-500/5 rounded-full blur-3xl pointer-events-none print:hidden"></div>
        <div className="absolute bottom-1/4 right-1/10 w-96 h-96 bg-teal-500/5 rounded-full blur-3xl pointer-events-none print:hidden"></div>

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

      {/* FOOTER AREA */}
      <footer className="border-t border-slate-900 py-5 text-center text-[11px] font-mono text-slate-500 print:hidden mt-12 bg-slate-950">
        <p>© 2026 CyberGuard Official Command. Powered by Rule-Based Cyber Forensic Engine.</p>
        <p className="mt-1 text-slate-600">Deterministic Threat Inspection • NIST NVD v2.0 Live Query Feed • STIX 2.1 Evidence Bundling.</p>
      </footer>

    </div>
  );
}
