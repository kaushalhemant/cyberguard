import React, { useState } from 'react';
import { 
  Search, Terminal as TerminalIcon, Sun, Moon, Shield, Plus,
  Menu, X, Bell, User as UserIcon, Check, ChevronDown
} from 'lucide-react';
import { User } from '../../types';
import { useTheme } from '../ThemeProvider';

interface HeaderProps {
  user: User;
  onOpenMobileSidebar: () => void;
  onToggleTerminal: () => void;
  onQuickSearch: (query: string) => void;
  onStartInvestigation: () => void;
  onNewIncident: () => void;
  currentTitle: string;
}

export default function Header({
  user,
  onOpenMobileSidebar,
  onToggleTerminal,
  onQuickSearch,
  onStartInvestigation,
  onNewIncident,
  currentTitle
}: HeaderProps) {
  const { theme, toggleTheme } = useTheme();
  const [searchQuery, setSearchQuery] = useState('');
  const [showProfileMenu, setShowProfileMenu] = useState(false);

  const handleSearchSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (searchQuery.trim()) {
      onQuickSearch(searchQuery.trim());
      setSearchQuery('');
    }
  };

  return (
    <header className="sticky top-0 z-30 h-14 bg-[#0B0F19]/95 backdrop-blur-md border-b border-[#1C273C] px-3 sm:px-4 flex items-center justify-between gap-3 select-none">
      {/* Left: Mobile Toggle & Page Title */}
      <div className="flex items-center gap-3">
        <button
          onClick={onOpenMobileSidebar}
          className="lg:hidden p-1.5 rounded-md text-slate-400 hover:text-white hover:bg-slate-800/60"
          title="Open menu"
        >
          <Menu className="w-5 h-5" />
        </button>

        <div className="hidden sm:flex items-center gap-2">
          <span className="font-mono text-xs font-semibold uppercase tracking-wider text-slate-300">
            {currentTitle}
          </span>
          <span className="hidden md:inline-block w-1 h-1 rounded-full bg-slate-600" />
          <span className="hidden md:inline-block font-mono text-[11px] text-slate-400">
            Real-Time Forensics
          </span>
        </div>
      </div>

      {/* Center: Global Search & Quick Investigation Field */}
      <div className="flex-1 max-w-xl mx-2">
        <form onSubmit={handleSearchSubmit} className="relative">
          <Search className="w-4 h-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search indicator (IP, URL, Hash, CVE, Email, Incident ID)..."
            className="w-full h-8.5 pl-9 pr-14 bg-[#111827] border border-[#1C273C] rounded-md text-xs text-slate-200 placeholder-slate-400 focus:border-blue-500 focus:bg-[#131C2E] transition-all"
          />
          <button
            type="submit"
            className="absolute right-1.5 top-1/2 -translate-y-1/2 px-2 py-0.5 rounded bg-blue-600/30 hover:bg-blue-600/50 text-blue-300 text-[10px] font-mono border border-blue-500/40 transition-colors"
          >
            SCAN
          </button>
        </form>
      </div>

      {/* Right: Actions, Telemetry & User Profile */}
      <div className="flex items-center gap-2">
        {/* Quick Investigation Button */}
        <button
          onClick={onStartInvestigation}
          className="hidden sm:flex items-center gap-1.5 px-3 py-1.5 rounded-md bg-blue-600 hover:bg-blue-500 text-white text-xs font-medium font-sans shadow-[0_0_12px_rgba(59,130,246,0.3)] transition-all cursor-pointer"
        >
          <Plus className="w-3.5 h-3.5" />
          <span className="font-semibold">Investigate</span>
        </button>

        {/* System Telemetry Pills */}
        <div className="hidden xl:flex items-center gap-2 font-mono text-[10px] border-r border-[#1C273C] pr-3 text-slate-400">
          <span className="flex items-center gap-1">
            <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
            ENGINE: <strong className="text-slate-200">ACTIVE</strong>
          </span>
          <span className="text-slate-500">•</span>
          <span>
            NVD: <strong className="text-cyan-400">v2.0</strong>
          </span>
          <span className="text-slate-500">•</span>
          <span>
            PQC: <strong className="text-purple-400">FIPS 203</strong>
          </span>
        </div>

        {/* Terminal Toggle */}
        <button
          onClick={onToggleTerminal}
          className="p-1.5 rounded-md bg-[#111827] border border-[#1C273C] text-slate-400 hover:text-white hover:border-blue-500/50 transition-colors"
          title="Toggle SOC Terminal (Ctrl + `)"
        >
          <TerminalIcon className="w-4 h-4 text-cyan-400" />
        </button>

        {/* Theme Toggle */}
        <button
          onClick={toggleTheme}
          className="p-1.5 rounded-md bg-[#111827] border border-[#1C273C] text-slate-400 hover:text-white hover:border-blue-500/50 transition-colors"
          title="Toggle Theme"
        >
          {theme === 'midnight' ? (
            <Sun className="w-4 h-4 text-amber-400" />
          ) : (
            <Moon className="w-4 h-4 text-blue-400" />
          )}
        </button>

        {/* User Profile Badge & Menu */}
        <div className="relative">
          <button
            onClick={() => setShowProfileMenu(prev => !prev)}
            className="flex items-center gap-2 p-1 pl-1.5 pr-2 rounded-md bg-[#111827] border border-[#1C273C] hover:border-slate-700 transition-colors cursor-pointer"
          >
            <div className="w-6 h-6 rounded bg-blue-500/20 text-blue-400 flex items-center justify-center font-bold text-xs">
              {user.email.charAt(0).toUpperCase()}
            </div>
            <div className="hidden md:flex flex-col text-left">
              <span className="text-[11px] font-medium text-slate-200 leading-tight">
                {user.fullName || user.email.split('@')[0]}
              </span>
              <span className="text-[9px] font-mono text-slate-400 leading-tight">
                {user.role === 'admin' ? 'SOC Lead' : 'Security Analyst'}
              </span>
            </div>
            <ChevronDown className="w-3 h-3 text-slate-400" />
          </button>

          {showProfileMenu && (
            <div 
              className="absolute right-0 mt-1.5 w-60 bg-[#0E1524] border border-[#1C273C] rounded-lg shadow-xl p-3 z-50 text-xs font-sans space-y-2.5"
              onMouseLeave={() => setShowProfileMenu(false)}
            >
              <div className="border-b border-[#1C273C] pb-2">
                <div className="font-semibold text-white">{user.fullName || 'Security Official'}</div>
                <div className="font-mono text-[11px] text-slate-400 truncate">{user.email}</div>
                <div className="flex items-center gap-2 mt-1.5">
                  <span className="px-1.5 py-0.5 rounded text-[9px] font-mono bg-blue-500/20 text-blue-300 border border-blue-500/40">
                    PLAN: {user.plan.toUpperCase()}
                  </span>
                  <span className="px-1.5 py-0.5 rounded text-[9px] font-mono bg-emerald-500/20 text-emerald-300 border border-emerald-500/40">
                    ROLE: {user.role.toUpperCase()}
                  </span>
                </div>
              </div>

              <div className="space-y-1 text-slate-300">
                <div className="flex justify-between py-1 border-b border-[#1C273C]/50 text-[11px]">
                  <span className="text-slate-400 font-mono">Session ID</span>
                  <span className="font-mono text-slate-300">SOC-LIVE-2026</span>
                </div>
                <div className="flex justify-between py-1 border-b border-[#1C273C]/50 text-[11px]">
                  <span className="text-slate-400 font-mono">Scans Conducted</span>
                  <span className="font-mono text-emerald-400 font-bold">{user.scansThisMonth || 0}</span>
                </div>
                <div className="flex justify-between py-1 text-[11px]">
                  <span className="text-slate-400 font-mono">Zero-Retention</span>
                  <span className="font-mono text-blue-400">Strict Enforced</span>
                </div>
              </div>

              <div className="pt-1 border-t border-[#1C273C]">
                <button
                  onClick={onNewIncident}
                  className="w-full py-1.5 px-2 rounded bg-[#162136] hover:bg-[#1E2D48] text-slate-200 text-center font-medium font-sans transition-colors"
                >
                  + Create Incident Case
                </button>
              </div>
            </div>
          )}
        </div>
      </div>
    </header>
  );
}
