import React, { useState, useEffect } from 'react';
import { Shield, ShieldCheck, RefreshCw, ChevronLeft, ShieldAlert, BookOpen, AlertCircle, Sun, Moon } from 'lucide-react';
import { User, ScanResult } from './types';
import Auth from './components/Auth';
import Dashboard from './components/Dashboard';
import ReportView from './components/ReportView';
import AdminPanel from './components/AdminPanel';
import { useTheme } from './components/ThemeProvider';

export default function App() {
  const { theme, toggleTheme } = useTheme();
  const [user, setUser] = useState<User | null>(null);
  const [token, setToken] = useState<string | null>(null);
  const [gmailToken, setGmailToken] = useState<string | null>(null);
  const [activeView, setActiveView] = useState<'auth' | 'dashboard' | 'report' | 'admin'>('auth');
  const [selectedScan, setSelectedScan] = useState<ScanResult | null>(null);
  const [initializing, setInitializing] = useState(true);

  // Restore authenticated session on load
  useEffect(() => {
    const savedToken = localStorage.getItem('cyberguard_token');
    if (!savedToken) {
      setInitializing(false);
      return;
    }

    const verifySession = async () => {
      try {
        const response = await fetch('/api/auth/me', {
          headers: {
            'Authorization': `Bearer ${savedToken}`
          }
        });

        if (response.ok) {
          const data = await response.json();
          setUser(data.user);
          setToken(savedToken);
          setActiveView('dashboard');
        } else {
          // Token expired or invalid
          localStorage.removeItem('cyberguard_token');
        }
      } catch (err) {
        console.error('Session restoration failed:', err);
      } finally {
        setInitializing(false);
      }
    };

    verifySession();
  }, []);

  const handleAuthSuccess = (authenticatedUser: User, sessionToken: string, googleToken?: string | null) => {
    setUser(authenticatedUser);
    setToken(sessionToken);
    if (googleToken) {
      setGmailToken(googleToken);
    }
    setActiveView('dashboard');
  };

  const handleLogout = () => {
    localStorage.removeItem('cyberguard_token');
    setUser(null);
    setToken(null);
    setSelectedScan(null);
    setGmailToken(null);
    setActiveView('auth');
  };

  const handleSelectReport = (scan: ScanResult) => {
    setSelectedScan(scan);
    setActiveView('report');
  };

  const handleUserUpdate = (updatedUser: User) => {
    setUser(updatedUser);
  };

  if (initializing) {
    return (
      <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col items-center justify-center font-mono gap-3.5">
        <div className="w-14 h-14 rounded-2xl bg-cyan-950/60 border border-cyan-500/30 flex items-center justify-center animate-pulse shadow-[0_0_30px_rgba(6,182,212,0.2)]">
          <ShieldCheck className="w-7 h-7 text-cyan-400" />
        </div>
        <div className="flex items-center gap-2 text-xs text-slate-400">
          <RefreshCw className="w-3.5 h-3.5 animate-spin text-cyan-400" />
          <span>Restoring CyberGuard Security Vault...</span>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col font-sans selection:bg-cyan-500/30 selection:text-white">
      
      {/* GLOBAL APPLICATION HEADER - APPLE / MICROSOFT GLASS STYLING */}
      <header className="sticky top-0 z-40 glass-header px-6 py-3.5 flex items-center justify-between print:hidden">
        <div 
          onClick={() => user && setActiveView('dashboard')}
          className="flex items-center gap-3 cursor-pointer group"
        >
          <div className="w-10 h-10 bg-gradient-to-br from-cyan-950 to-slate-900 border border-cyan-500/30 rounded-xl flex items-center justify-center text-cyan-400 group-hover:border-cyan-400 group-hover:shadow-[0_0_20px_rgba(6,182,212,0.3)] transition-all">
            <ShieldCheck className="w-5 h-5" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h1 className="text-lg font-bold tracking-tight font-display text-white">CyberGuard</h1>
              <span className="px-2 py-0.5 rounded-full text-[9px] font-mono font-bold bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">
                PRO ASSISTANT
              </span>
            </div>
            <span className="text-[10px] font-mono tracking-wider text-slate-400 block -mt-0.5">Honest Digital Safety & Threat Intelligence</span>
          </div>
        </div>

        <div className="flex items-center gap-3">
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

          {user && (
            <div className="flex items-center gap-3">
              {activeView !== 'dashboard' && (
                <button
                  onClick={() => setActiveView('dashboard')}
                  className="text-xs text-slate-300 hover:text-white transition-all font-mono font-semibold flex items-center gap-1.5 bg-slate-900 border border-slate-800 hover:border-cyan-500/40 px-3 py-1.5 rounded-xl cursor-pointer"
                >
                  <ChevronLeft className="w-4 h-4 text-cyan-400" />
                  DASHBOARD
                </button>
              )}

              <div className="bg-slate-900/80 border border-emerald-500/30 px-3.5 py-1.5 rounded-xl flex items-center gap-2 shadow-[0_0_15px_rgba(16,185,129,0.1)]">
                <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse"></span>
                <span className="text-[10px] uppercase font-mono text-emerald-400 font-bold">100% PROTECTED</span>
              </div>
            </div>
          )}
        </div>
      </header>


      {/* MASTER CENTRAL CANVAS CONTAINER */}
      <main className="flex-1 w-full max-w-7xl mx-auto px-4 py-8 md:px-6 relative z-10 print:p-0">
        
        {/* Background ambient lighting */}
        <div className="absolute top-1/4 left-1/10 w-96 h-96 bg-cyan-500/5 rounded-full blur-3xl pointer-events-none print:hidden"></div>
        <div className="absolute bottom-1/4 right-1/10 w-96 h-96 bg-emerald-500/5 rounded-full blur-3xl pointer-events-none print:hidden"></div>

        {activeView === 'auth' && (
          <div className="py-12 md:py-16">
            <Auth onAuthSuccess={handleAuthSuccess} />
          </div>
        )}

        {activeView === 'dashboard' && user && token && (
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

        {activeView === 'report' && selectedScan && (
          <ReportView
            scan={selectedScan}
            onBack={() => setActiveView('dashboard')}
          />
        )}

        {activeView === 'admin' && token && (
          <AdminPanel token={token} />
        )}

      </main>

      {/* FOOTER AREA */}
      <footer className="border-t border-slate-900 py-6 text-center text-[11px] font-mono text-slate-600 print:hidden mt-12 bg-slate-950">
        <p>© 2026 CyberGuard Honest Hub. Powered by CyberGuard Native Neural AI Engine.</p>
        <p className="mt-1 text-slate-700">Protected under 256-bit AES-256-CBC database encryption pipelines. Enterprise Edition - All Features Unlocked.</p>
      </footer>

    </div>
  );
}
