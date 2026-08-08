import React, { useState, useEffect } from 'react';
import { ShieldCheck, RefreshCw, ChevronLeft, Sun, Moon, Lock, ShieldAlert, Award } from 'lucide-react';
import { SpeedInsights } from '@vercel/speed-insights/react';
import { User, ScanResult } from './types';
import Dashboard from './components/Dashboard';
import ReportView from './components/ReportView';
import AdminPanel from './components/AdminPanel';
import { useTheme } from './components/ThemeProvider';
import { safeJsonResponse } from './lib/api';

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
  const [token, setToken] = useState<string>('cyberguard_soc_official_master_token_2026');
  const [gmailToken, setGmailToken] = useState<string | null>(null);
  const [activeView, setActiveView] = useState<'dashboard' | 'report' | 'admin'>('dashboard');
  const [selectedScan, setSelectedScan] = useState<ScanResult | null>(null);

  // Sync user profile on mount
  useEffect(() => {
    localStorage.setItem('cyberguard_token', token);
    const syncSession = async () => {
      try {
        const response = await fetch('/api/auth/me', {
          headers: {
            'Authorization': `Bearer ${token}`
          }
        });
        if (response.ok) {
          const data = await safeJsonResponse(response);
          if (data?.user) {
            setUser(data.user);
          }
        }
      } catch (err) {
        console.warn('Session sync warning:', err);
      }
    };
    syncSession();
  }, []);

  const handleResetSession = () => {
    setSelectedScan(null);
    setActiveView('dashboard');
  };

  const handleSelectReport = (scan: ScanResult) => {
    setSelectedScan(scan);
    setActiveView('report');
  };

  const handleUserUpdate = (updatedUser: User) => {
    setUser(updatedUser);
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col font-sans selection:bg-cyan-500/30 selection:text-white">
      
      {/* GLOBAL APPLICATION HEADER - APPLE / MICROSOFT GLASS STYLING */}
      <header className="sticky top-0 z-40 glass-header px-6 py-3.5 flex items-center justify-between print:hidden border-b border-cyan-500/20 shadow-[0_4px_20px_rgba(0,0,0,0.4)]">
        <div 
          onClick={() => setActiveView('dashboard')}
          className="flex items-center gap-3 cursor-pointer group"
        >
          <div className="w-10 h-10 bg-gradient-to-br from-cyan-950 to-slate-900 border border-cyan-500/40 rounded-xl flex items-center justify-center text-cyan-400 group-hover:border-cyan-400 group-hover:shadow-[0_0_20px_rgba(6,182,212,0.4)] transition-all">
            <ShieldCheck className="w-6 h-6 text-cyan-400" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h1 className="text-lg font-bold tracking-tight font-display text-white flex items-center gap-1.5">
                CyberGuard
              </h1>
              <span className="px-2.5 py-0.5 rounded-full text-[9px] font-mono font-bold bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 tracking-wider shadow-[0_0_10px_rgba(6,182,212,0.2)]">
                OFFICIAL SOC COMMAND
              </span>
            </div>
            <span className="text-[10px] font-mono tracking-wider text-slate-400 block -mt-0.5">
              Threat Intelligence & Cyber Forensic Investigation Platform
            </span>
          </div>
        </div>

        <div className="flex items-center gap-3">
          {/* Active Officer Identity Badge */}
          <div className="hidden md:flex items-center gap-2 bg-slate-900/90 border border-cyan-500/30 px-3 py-1.5 rounded-xl text-xs font-mono">
            <Award className="w-4 h-4 text-cyan-400" />
            <span className="text-slate-300">{user.fullName || 'Official SOC Lead'}</span>
            <span className="text-[10px] bg-emerald-500/20 text-emerald-400 border border-emerald-500/30 px-1.5 py-0.5 rounded font-bold uppercase">PRO</span>
          </div>

          {/* Theme Toggle Button */}
          <button
            onClick={toggleTheme}
            className="text-slate-300 hover:text-white transition-all font-mono text-[10px] font-bold flex items-center gap-2 bg-slate-900/80 border border-slate-800 hover:border-cyan-500/40 px-3 py-1.5 rounded-xl cursor-pointer shadow-sm"
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
              className="text-xs text-slate-300 hover:text-white transition-all font-mono font-semibold flex items-center gap-1.5 bg-slate-900 border border-slate-800 hover:border-cyan-500/40 px-3 py-1.5 rounded-xl cursor-pointer"
            >
              <ChevronLeft className="w-4 h-4 text-cyan-400" />
              SOC DASHBOARD
            </button>
          )}

          <div className="bg-slate-900/80 border border-emerald-500/40 px-3 py-1.5 rounded-xl flex items-center gap-2 shadow-[0_0_15px_rgba(16,185,129,0.15)]">
            <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse"></span>
            <span className="text-[10px] uppercase font-mono text-emerald-400 font-bold hidden sm:inline">SOC ACTIVE</span>
          </div>
        </div>
      </header>

      {/* MASTER CENTRAL CANVAS CONTAINER */}
      <main className="flex-1 w-full max-w-7xl mx-auto px-4 py-6 md:px-6 relative z-10 print:p-0">
        
        {/* Background ambient lighting */}
        <div className="absolute top-1/4 left-1/10 w-96 h-96 bg-cyan-500/5 rounded-full blur-3xl pointer-events-none print:hidden"></div>
        <div className="absolute bottom-1/4 right-1/10 w-96 h-96 bg-emerald-500/5 rounded-full blur-3xl pointer-events-none print:hidden"></div>

        {activeView === 'dashboard' && (
          <Dashboard
            user={user}
            token={token}
            gmailToken={gmailToken}
            setGmailToken={setGmailToken}
            onLogout={handleResetSession}
            onSelectReport={handleSelectReport}
            onUserUpdate={handleUserUpdate}
            onNavigateAdmin={() => setActiveView('admin')}
          />
        )}

        {activeView === 'report' && selectedScan && (
          <ReportView
            scan={selectedScan}
            onBack={() => setActiveView('dashboard')}
          />
        )}

        {activeView === 'admin' && (
          <AdminPanel token={token} />
        )}

      </main>

      {/* FOOTER AREA */}
      <footer className="border-t border-slate-900 py-5 text-center text-[11px] font-mono text-slate-500 print:hidden mt-12 bg-slate-950">
        <p>© 2026 CyberGuard Official Command. Powered by CyberGuard Native Neural AI Engine.</p>
        <p className="mt-1 text-slate-600">Enterprise Cybersecurity Official Edition - All Threat Scanning & Forensic Suite Features Unlocked.</p>
      </footer>

      <SpeedInsights />
    </div>
  );
}

