import React, { useState, useEffect } from 'react';
import { ShieldCheck, RefreshCw, ChevronLeft, Sun, Moon, Lock, ShieldAlert, Award, LogOut, User as UserIcon, Key } from 'lucide-react';
import { User, ScanResult } from './types';
import Dashboard from './components/Dashboard';
import ReportView from './components/ReportView';
import AdminPanel from './components/AdminPanel';
import Auth from './components/Auth';
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
  const [user, setUser] = useState<User | null>(null);
  const [token, setToken] = useState<string>('');
  const [gmailToken, setGmailToken] = useState<string | null>(null);
  const [activeView, setActiveView] = useState<'auth' | 'dashboard' | 'report' | 'admin'>('dashboard');
  const [selectedScan, setSelectedScan] = useState<ScanResult | null>(null);
  const [isInitializing, setIsInitializing] = useState(true);

  // Sync user profile on mount
  useEffect(() => {
    const savedToken = localStorage.getItem('cyberguard_token');
    const tokenToUse = savedToken || 'cyberguard_soc_official_master_token_2026';

    const syncSession = async () => {
      try {
        const response = await fetch('/api/auth/me', {
          headers: {
            'Authorization': `Bearer ${tokenToUse}`
          }
        });
        if (response.ok) {
          const data = await safeJsonResponse(response);
          if (data?.user) {
            setUser(data.user);
            setToken(tokenToUse);
            localStorage.setItem('cyberguard_token', tokenToUse);
            setActiveView('dashboard');
            return;
          }
        }
      } catch (err) {
        console.warn('Session sync warning:', err);
      } finally {
        setIsInitializing(false);
      }

      // Default fallback if no token existed or server unreachable
      setUser(DEFAULT_OFFICIAL_USER);
      setToken('cyberguard_soc_official_master_token_2026');
      localStorage.setItem('cyberguard_token', 'cyberguard_soc_official_master_token_2026');
      setActiveView('dashboard');
    };

    syncSession();
  }, []);

  const handleAuthSuccess = (authenticatedUser: User, authToken: string) => {
    setUser(authenticatedUser);
    setToken(authToken);
    localStorage.setItem('cyberguard_token', authToken);
    setActiveView('dashboard');
  };

  const handleDemoAccess = () => {
    setUser(DEFAULT_OFFICIAL_USER);
    const demoToken = 'cyberguard_soc_official_master_token_2026';
    setToken(demoToken);
    localStorage.setItem('cyberguard_token', demoToken);
    setActiveView('dashboard');
  };

  const handleLogout = () => {
    localStorage.removeItem('cyberguard_token');
    setUser(null);
    setToken('');
    setSelectedScan(null);
    setActiveView('auth');
  };

  const handleSelectReport = (scan: ScanResult) => {
    setSelectedScan(scan);
    setActiveView('report');
  };

  const handleUserUpdate = (updatedUser: User) => {
    setUser(updatedUser);
  };

  if (isInitializing) {
    return (
      <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col items-center justify-center font-sans">
        <div className="flex flex-col items-center gap-3">
          <div className="w-12 h-12 rounded-2xl bg-cyan-950/60 border border-cyan-500/40 flex items-center justify-center text-cyan-400 animate-pulse shadow-[0_0_25px_rgba(6,182,212,0.3)]">
            <ShieldCheck className="w-7 h-7" />
          </div>
          <div className="text-center space-y-1">
            <h2 className="text-lg font-bold font-display text-white tracking-wide">CyberGuard Neural Operations</h2>
            <p className="text-xs font-mono text-cyan-400">Verifying session token & database connection...</p>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col font-sans selection:bg-cyan-500/30 selection:text-white">
      
      {/* GLOBAL APPLICATION HEADER */}
      <header className="sticky top-0 z-40 glass-header px-6 py-3.5 flex items-center justify-between print:hidden border-b border-cyan-500/20 shadow-[0_4px_20px_rgba(0,0,0,0.4)]">
        <div 
          onClick={() => {
            if (user) setActiveView('dashboard');
          }}
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
          {/* Active User Identity Badge */}
          {user ? (
            <div className="hidden md:flex items-center gap-2 bg-slate-900/90 border border-cyan-500/30 px-3 py-1.5 rounded-xl text-xs font-mono">
              <Award className="w-4 h-4 text-cyan-400" />
              <span className="text-slate-300 max-w-[160px] truncate">{user.fullName || user.email}</span>
              <span className="text-[10px] bg-emerald-500/20 text-emerald-400 border border-emerald-500/30 px-1.5 py-0.5 rounded font-bold uppercase">PRO</span>
            </div>
          ) : (
            <button
              onClick={() => setActiveView('auth')}
              className="text-xs text-cyan-400 hover:text-cyan-300 transition-all font-mono font-semibold flex items-center gap-1.5 bg-cyan-950/40 border border-cyan-500/40 px-3 py-1.5 rounded-xl cursor-pointer"
            >
              <Key className="w-3.5 h-3.5" />
              SIGN IN / REGISTER
            </button>
          )}

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

          {user && activeView !== 'dashboard' && (
            <button
              onClick={() => setActiveView('dashboard')}
              className="text-xs text-slate-300 hover:text-white transition-all font-mono font-semibold flex items-center gap-1.5 bg-slate-900 border border-slate-800 hover:border-cyan-500/40 px-3 py-1.5 rounded-xl cursor-pointer"
            >
              <ChevronLeft className="w-4 h-4 text-cyan-400" />
              SOC DASHBOARD
            </button>
          )}

          {user && (
            <button
              onClick={handleLogout}
              className="text-xs text-rose-400 hover:text-rose-300 transition-all font-mono font-semibold flex items-center gap-1.5 bg-slate-900/80 border border-rose-500/30 hover:border-rose-500/60 px-3 py-1.5 rounded-xl cursor-pointer"
              title="Sign Out of Session"
            >
              <LogOut className="w-3.5 h-3.5" />
              <span className="hidden sm:inline">LOGOUT</span>
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

        {(!user || activeView === 'auth') && (
          <div className="py-8">
            <Auth onAuthSuccess={handleAuthSuccess} onDemoAccess={handleDemoAccess} />
          </div>
        )}

        {user && activeView === 'dashboard' && (
          <Dashboard
            user={user}
            token={token}
            gmailToken={gmailToken}
            setGmailToken={setGmailToken}
            onLogout={handleLogout}
            onSelectReport={handleSelectReport}
            onUserUpdate={handleUserUpdate}
            onNavigateAdmin={() => setActiveView('admin')}
          />
        )}

        {user && activeView === 'report' && selectedScan && (
          <ReportView
            scan={selectedScan}
            onBack={() => setActiveView('dashboard')}
          />
        )}

        {user && activeView === 'admin' && (
          <AdminPanel token={token} />
        )}

      </main>

      {/* FOOTER AREA */}
      <footer className="border-t border-slate-900 py-5 text-center text-[11px] font-mono text-slate-500 print:hidden mt-12 bg-slate-950">
        <p>© 2026 CyberGuard Official Command. Powered by CyberGuard Native Neural AI Engine.</p>
        <p className="mt-1 text-slate-600">Enterprise Cybersecurity Official Edition - All Threat Scanning & Forensic Suite Features Unlocked.</p>
      </footer>

    </div>
  );
}

