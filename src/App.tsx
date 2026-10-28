import React, { useState } from 'react';
import { User, ScanResult } from './types';
import Dashboard from './components/Dashboard';
import ReportView from './components/ReportView';
import { useTheme } from './components/ThemeProvider';
import { ShieldCheck, ChevronLeft } from 'lucide-react';

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
  const { theme } = useTheme();
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
    <div className={`min-h-screen bg-[#080C14] text-[#F1F5F9] font-sans ${theme === 'midnight' ? 'theme-midnight' : ''}`}>
      {activeView === 'dashboard' ? (
        <Dashboard
          user={user}
          token={token}
          gmailToken={gmailToken}
          setGmailToken={setGmailToken}
          onSelectReport={handleSelectReport}
          onUserUpdate={handleUserUpdate}
        />
      ) : (
        selectedScan && (
          <div className="min-h-screen p-4 sm:p-6 lg:p-8 max-w-5xl mx-auto space-y-4">
            <div className="flex items-center justify-between border-b border-[#1C273C] pb-3 print:hidden">
              <button
                onClick={() => setActiveView('dashboard')}
                className="px-3 py-1.5 rounded bg-[#121B2D] hover:bg-[#18243C] text-slate-200 border border-[#1C273C] font-mono text-xs flex items-center gap-1.5 transition-colors cursor-pointer"
              >
                <ChevronLeft className="w-4 h-4 text-blue-400" />
                <span>Return to Command Center</span>
              </button>

              <div className="flex items-center gap-2">
                <ShieldCheck className="w-4 h-4 text-emerald-400" />
                <span className="font-mono text-xs text-slate-400">Deterministic Chain-of-Custody</span>
              </div>
            </div>

            <ReportView
              scan={selectedScan}
              onBack={() => setActiveView('dashboard')}
            />
          </div>
        )
      )}
    </div>
  );
}
