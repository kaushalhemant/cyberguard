import React, { useState, useEffect } from 'react';
import { ShieldCheck, ShieldAlert, Lock, RefreshCw, Server, Activity, Users, Search, HardDrive, Terminal, CheckCircle2, AlertTriangle, Key, LogOut, Cpu, ArrowUpRight, Zap, Globe, Layers, Eye, Filter, Database, Shield } from 'lucide-react';

interface ActivityLog {
  id: string;
  timestamp: string;
  email: string;
  action: string;
  details: string;
  ip: string;
  status: 'success' | 'warning' | 'failed';
}

interface SystemLog {
  id: string;
  timestamp: string;
  level: 'info' | 'warn' | 'error' | 'http';
  category: string;
  message: string;
  metadata?: Record<string, any>;
}

interface SystemStats {
  status: string;
  uptimeSeconds: number;
  memoryMb: { rss: string; heapTotal: string; heapUsed: string };
  nodeVersion: string;
  platform: string;
  totalUsers: number;
  totalScansExecuted: number;
  totalActivityLogs: number;
  totalSystemLogs: number;
  users: any[];
}

async function safeJsonResponse<T = any>(res: Response, defaultErr = 'Invalid response'): Promise<T> {
  const contentType = res.headers.get('content-type') || '';
  if (contentType.includes('application/json')) {
    try {
      return await res.json();
    } catch {
      throw new Error(defaultErr);
    }
  }
  const text = await res.text();
  const clean = text.replace(/<[^>]*>/g, '').trim().substring(0, 120);
  if (!res.ok) throw new Error(`Server error (${res.status}): ${clean || res.statusText}`);
  throw new Error(`Server returned non-JSON response (${res.status}): ${clean}`);
}

export default function AdminApp() {
  const [adminToken, setAdminToken] = useState<string | null>(() => localStorage.getItem('cg_admin_master_token'));
  const [passcode, setPasscode] = useState('');
  const [loginError, setLoginError] = useState<string | null>(null);
  const [loginLoading, setLoginLoading] = useState(false);

  const [activeTab, setActiveTab] = useState<'overview' | 'users' | 'activity' | 'telemetry'>('overview');
  const [autoRefresh, setAutoRefresh] = useState(true);
  const [loading, setLoading] = useState(false);

  const [stats, setStats] = useState<SystemStats | null>(null);
  const [activityLogs, setActivityLogs] = useState<ActivityLog[]>([]);
  const [systemLogs, setSystemLogs] = useState<SystemLog[]>([]);
  const [searchTerm, setSearchTerm] = useState('');
  const [logFilter, setLogFilter] = useState<'all' | 'error' | 'warn' | 'info' | 'http'>('all');
  const [actionCategory, setActionCategory] = useState<'all' | 'LOGIN' | 'SCAN' | 'REGISTER'>('all');

  const [selectedLog, setSelectedLog] = useState<ActivityLog | SystemLog | null>(null);
  const [userSearch, setUserSearch] = useState('');
  const [logSearch, setLogSearch] = useState('');
  const [selectedUser, setSelectedUser] = useState<any | null>(null);

  // Login handler
  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!passcode.trim()) return;

    setLoginLoading(true);
    setLoginError(null);

    try {
      const res = await fetch('/api/admin/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ passcode: passcode.trim() })
      });
      const data = await safeJsonResponse(res, 'Master Admin passcode verification failed.');
      if (!res.ok) {
        throw new Error(data.error || 'Master Admin passcode verification failed.');
      }
      localStorage.setItem('cg_admin_master_token', data.token);
      setAdminToken(data.token);
      setPasscode('');
    } catch (err: any) {
      setLoginError(err.message || 'Access Denied');
    } finally {
      setLoginLoading(false);
    }
  };

  const handleLogout = () => {
    localStorage.removeItem('cg_admin_master_token');
    setAdminToken(null);
  };

  // Fetch Data handler
  const fetchAdminData = async () => {
    if (!adminToken) return;
    setLoading(true);
    try {
      const statsRes = await fetch('/api/admin/system-stats', {
        headers: {
          'Authorization': `Bearer ${adminToken}`,
          'X-CyberGuard-Admin-Key': adminToken
        }
      });

      if (statsRes.status === 401 || statsRes.status === 403) {
        handleLogout();
        return;
      }

      const statsData = await safeJsonResponse(statsRes, 'Failed to parse stats telemetry');
      setStats(statsData);

      const logsRes = await fetch('/api/admin/logs', {
        headers: {
          'Authorization': `Bearer ${adminToken}`,
          'X-CyberGuard-Admin-Key': adminToken
        }
      });
      const logsData = await safeJsonResponse(logsRes, 'Failed to parse logs telemetry');
      setActivityLogs(logsData.activityLogs || []);
      setSystemLogs(logsData.systemLogs || []);
    } catch (err) {
      console.error('Failed to fetch admin telemetry:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (adminToken) {
      fetchAdminData();
    }
  }, [adminToken]);

  // Auto-refresh interval
  useEffect(() => {
    if (!adminToken || !autoRefresh) return;
    const interval = setInterval(() => {
      fetchAdminData();
    }, 5000);
    return () => clearInterval(interval);
  }, [adminToken, autoRefresh]);

  // Filtered views
  const filteredActivities = activityLogs.filter(a => {
    if (actionCategory !== 'all' && !a.action.includes(actionCategory)) return false;
    const q = searchTerm.toLowerCase();
    return a.email.toLowerCase().includes(q) || a.action.toLowerCase().includes(q) || a.details.toLowerCase().includes(q) || a.ip.includes(q);
  });

  const filteredSystemLogs = systemLogs.filter(s => {
    if (logFilter !== 'all' && s.level !== logFilter) return false;
    const q = searchTerm.toLowerCase();
    return s.category.toLowerCase().includes(q) || s.message.toLowerCase().includes(q) || s.level.toLowerCase().includes(q);
  });

  // Login Screen
  if (!adminToken) {
    return (
      <div className="min-h-screen bg-slate-950 text-slate-100 flex items-center justify-center p-4 font-sans selection:bg-cyan-500/30 selection:text-white relative overflow-hidden">
        {/* Ambient Glowing Orbs */}
        <div className="absolute top-1/4 left-1/4 w-[30rem] h-[30rem] bg-cyan-500/10 rounded-full blur-[140px] pointer-events-none"></div>
        <div className="absolute bottom-1/4 right-1/4 w-[30rem] h-[30rem] bg-indigo-500/10 rounded-full blur-[140px] pointer-events-none"></div>

        <div className="w-full max-w-md glass-card p-8 relative z-10 space-y-6 border border-white/10 shadow-[0_25px_60px_rgba(0,0,0,0.9)]">
          <div className="text-center space-y-3">
            <div className="w-16 h-16 bg-gradient-to-br from-cyan-950 via-slate-900 to-indigo-950 border border-cyan-500/40 rounded-2xl mx-auto flex items-center justify-center text-cyan-400 shadow-[0_0_40px_rgba(6,182,212,0.25)]">
              <ShieldCheck className="w-8 h-8" />
            </div>
            <div>
              <h1 className="text-2xl font-extrabold font-display tracking-tight text-white mt-2">CyberGuard SOC Center</h1>
              <span className="text-[10px] font-mono font-semibold tracking-widest text-cyan-400 uppercase block mt-1">Master Telemetry & Audit Portal</span>
            </div>
          </div>

          <div className="p-3.5 bg-amber-500/10 border border-amber-500/25 rounded-2xl text-amber-300 text-[11px] flex gap-2.5 font-mono shadow-inner">
            <ShieldAlert className="w-4 h-4 shrink-0 text-amber-400 mt-0.5" />
            <span>RESTRICTED EXECUTIVE CONTROL: Authorization required. Enter Master Security Passcode.</span>
          </div>

          {loginError && (
            <div className="p-3.5 bg-rose-500/10 border border-rose-500/30 rounded-2xl text-rose-300 text-xs flex gap-2.5 font-sans">
              <AlertTriangle className="w-4 h-4 shrink-0 mt-0.5 text-rose-400" />
              <span>{loginError}</span>
            </div>
          )}

          <form onSubmit={handleLogin} className="space-y-4">
            <div className="space-y-1.5">
              <label className="text-[10px] font-mono font-bold text-slate-400 uppercase tracking-wider block">Master Security Passcode</label>
              <div className="relative">
                <span className="absolute inset-y-0 left-0 pl-3.5 flex items-center pointer-events-none text-slate-500">
                  <Key className="w-4 h-4" />
                </span>
                <input
                  type="password"
                  value={passcode}
                  onChange={(e) => setPasscode(e.target.value)}
                  placeholder="Enter Master Security Key..."
                  className="w-full bg-slate-950 border border-slate-800 rounded-xl pl-10 pr-4 py-3 text-xs text-white placeholder-slate-600 focus:outline-none focus:border-cyan-500 transition-all font-mono shadow-inner"
                  required
                />
              </div>
            </div>

            <button
              type="submit"
              disabled={loginLoading}
              className="w-full btn-primary py-3.5 text-xs flex items-center justify-center gap-2 cursor-pointer disabled:opacity-50 font-bold tracking-wider font-mono uppercase shadow-lg shadow-cyan-500/20"
            >
              {loginLoading ? <RefreshCw className="w-4 h-4 animate-spin" /> : <Lock className="w-4 h-4" />}
              <span>Authenticate Control Center</span>
            </button>
          </form>

          <p className="text-[10px] text-center font-mono text-slate-500">Default Master Passcode: <code className="text-cyan-400 font-bold">CyberGuardMaster2026!</code></p>
        </div>
      </div>
    );
  }

  // Standalone Master Dashboard Screen
  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col font-sans selection:bg-cyan-500/30 selection:text-white">
      
      {/* APPLE / MICROSOFT FLUENT HEADER */}
      <header className="sticky top-0 z-40 glass-header px-6 py-4 flex items-center justify-between border-b border-white/10 shadow-lg">
        <div className="flex items-center gap-3.5">
          <div className="w-10 h-10 bg-gradient-to-br from-cyan-950 to-slate-900 border border-cyan-500/40 rounded-xl flex items-center justify-center text-cyan-400 shadow-[0_0_20px_rgba(6,182,212,0.2)]">
            <ShieldCheck className="w-6 h-6" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h1 className="text-base font-bold font-display text-white tracking-wide">CyberGuard SOC Command Center</h1>
              <span className="px-2.5 py-0.5 rounded-full text-[9px] font-mono font-bold bg-cyan-500/15 text-cyan-300 border border-cyan-500/30 uppercase tracking-wider flex items-center gap-1">
                <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 animate-pulse"></span>
                PORT 3001 STANDALONE
              </span>
            </div>
            <span className="text-[10px] font-mono text-slate-400 block -mt-0.5">Real-time Application Telemetry & Security Audit Ledger</span>
          </div>
        </div>

        <div className="flex items-center gap-3 font-mono text-xs">
          <button
            onClick={() => setAutoRefresh(!autoRefresh)}
            className={`px-3.5 py-1.5 rounded-xl border text-[10px] font-bold flex items-center gap-1.5 transition-all cursor-pointer shadow-sm ${
              autoRefresh ? 'bg-emerald-500/15 border-emerald-500/40 text-emerald-400' : 'bg-slate-900 border-slate-800 text-slate-500'
            }`}
          >
            <span className={`w-2 h-2 rounded-full ${autoRefresh ? 'bg-emerald-400 animate-pulse' : 'bg-slate-600'}`}></span>
            <span>AUTO-SYNC (5s)</span>
          </button>

          <button
            onClick={fetchAdminData}
            disabled={loading}
            className="bg-slate-900 hover:bg-slate-800 border border-slate-800 text-slate-200 px-3.5 py-1.5 rounded-xl transition-all cursor-pointer flex items-center gap-1.5 text-[10px] font-bold shadow-sm"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
            <span>REFRESH LOGS</span>
          </button>

          <button
            onClick={handleLogout}
            className="bg-rose-500/10 hover:bg-rose-500/20 text-rose-400 border border-rose-500/30 p-2 rounded-xl transition-all cursor-pointer shadow-sm"
            title="Lock Portal & Exit"
          >
            <LogOut className="w-4 h-4" />
          </button>
        </div>
      </header>

      {/* MAIN CONTAINER */}
      <main className="flex-1 w-full max-w-7xl mx-auto px-4 py-8 md:px-6 space-y-6">

        {/* HERO COMMAND TELEMETRY BANNER */}
        <div className="relative rounded-3xl p-6 md:p-8 overflow-hidden bg-gradient-to-r from-slate-900 via-slate-950 to-slate-900 border border-white/10 shadow-[0_20px_50px_rgba(0,0,0,0.8)]">
          <div className="absolute top-0 right-0 w-96 h-96 bg-cyan-500/10 rounded-full blur-[100px] pointer-events-none"></div>
          
          <div className="relative z-10 flex flex-col lg:flex-row lg:items-center justify-between gap-6">
            <div className="space-y-2">
              <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-cyan-500/10 border border-cyan-500/20 text-cyan-400 font-mono text-[10px] font-bold uppercase tracking-wider">
                <Globe className="w-3.5 h-3.5 animate-pulse text-cyan-400" />
                <span>CYBERGUARD EXECUTIVE TELEMETRY ENGINE</span>
              </div>
              <h2 className="text-2xl md:text-3xl font-extrabold text-white font-display tracking-tight">
                Live Audit & Telemetry Control Center
              </h2>
              <p className="text-xs text-slate-400 max-w-2xl font-sans">
                Real-time tracking of all user actions, security scans, HTTP requests, system memory, and server operations across both standalone ports.
              </p>
            </div>

            {stats && (
              <div className="flex flex-wrap items-center gap-3 font-mono text-xs">
                <div className="bg-slate-950/80 border border-slate-800/80 px-4 py-2.5 rounded-2xl">
                  <span className="text-[9px] text-slate-500 uppercase block">Engine Status</span>
                  <span className="text-emerald-400 font-bold flex items-center gap-1.5">
                    <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse"></span>
                    {stats.status}
                  </span>
                </div>

                <div className="bg-slate-950/80 border border-slate-800/80 px-4 py-2.5 rounded-2xl">
                  <span className="text-[9px] text-slate-500 uppercase block">Node.js Heap Memory</span>
                  <div className="w-36 h-2 bg-slate-900 rounded-full overflow-hidden mt-1.5 border border-slate-800">
                    <div 
                      className="h-full bg-gradient-to-r from-cyan-500 to-indigo-500 rounded-full"
                      style={{ width: `${Math.min(100, (parseFloat(stats.memoryMb.heapUsed) / parseFloat(stats.memoryMb.rss)) * 100)}%` }}
                    ></div>
                  </div>
                  <span className="text-[10px] text-indigo-300 font-bold block mt-1">{stats.memoryMb.heapUsed} MB / {stats.memoryMb.rss} MB</span>
                </div>
              </div>
            )}
          </div>
        </div>

        {/* SYSTEM STATUS STATS CARDS */}
        {stats && (
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 font-mono">
            <div className="bento-card p-5 flex items-center justify-between">
              <div>
                <span className="text-[10px] uppercase text-slate-400 font-bold tracking-wider block">System Uptime</span>
                <span className="text-xl font-extrabold text-emerald-400 mt-1 block">{Math.floor(stats.uptimeSeconds / 60)} Mins</span>
                <span className="text-[10px] text-slate-500 block mt-0.5">Platform: {stats.platform} ({stats.nodeVersion})</span>
              </div>
              <div className="w-12 h-12 rounded-2xl bg-emerald-950/50 border border-emerald-500/30 flex items-center justify-center text-emerald-400 shadow-inner">
                <Server className="w-6 h-6" />
              </div>
            </div>

            <div className="bento-card p-5 flex items-center justify-between">
              <div>
                <span className="text-[10px] uppercase text-slate-400 font-bold tracking-wider block">Total User Audits</span>
                <span className="text-xl font-extrabold text-cyan-400 mt-1 block">{stats.totalActivityLogs} Events</span>
                <span className="text-[10px] text-slate-500 block mt-0.5">Active Action Tracing</span>
              </div>
              <div className="w-12 h-12 rounded-2xl bg-cyan-950/50 border border-cyan-500/30 flex items-center justify-center text-cyan-400 shadow-inner">
                <Activity className="w-6 h-6" />
              </div>
            </div>

            <div className="bento-card p-5 flex items-center justify-between">
              <div>
                <span className="text-[10px] uppercase text-slate-400 font-bold tracking-wider block">System Logs</span>
                <span className="text-xl font-extrabold text-indigo-300 mt-1 block">{stats.totalSystemLogs} Telemetry Logs</span>
                <span className="text-[10px] text-slate-500 block mt-0.5">HTTP & Diagnostics</span>
              </div>
              <div className="w-12 h-12 rounded-2xl bg-indigo-950/50 border border-indigo-500/30 flex items-center justify-center text-indigo-400 shadow-inner">
                <Terminal className="w-6 h-6" />
              </div>
            </div>

            <div className="bento-card p-5 flex items-center justify-between">
              <div>
                <span className="text-[10px] uppercase text-slate-400 font-bold tracking-wider block">Registered Accounts</span>
                <span className="text-xl font-extrabold text-amber-300 mt-1 block">{stats.totalUsers} Users</span>
                <span className="text-[10px] text-slate-500 block mt-0.5">Total Scans: {stats.totalScansExecuted}</span>
              </div>
              <div className="w-12 h-12 rounded-2xl bg-amber-950/50 border border-amber-500/30 flex items-center justify-center text-amber-400 shadow-inner">
                <Users className="w-6 h-6" />
              </div>
            </div>
          </div>
        )}

        {/* LOG AUDIT WORKSPACE CARD */}
        <div className="bento-card p-6 space-y-5">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-800 pb-5">
            
            {/* MICROSOFT FLUENT PILL TAB SELECTOR */}
            <div className="flex items-center gap-2 font-mono text-xs font-bold bg-slate-950/60 p-1.5 rounded-2xl border border-slate-800/80">
              <button
                type="button"
                onClick={() => setActiveTab('activity')}
                className={`px-4 py-2 rounded-xl transition-all cursor-pointer flex items-center gap-2 ${
                  activeTab === 'activity'
                    ? 'bg-cyan-500 text-slate-950 font-extrabold shadow-md'
                    : 'text-slate-400 hover:text-white'
                }`}
              >
                <Activity className="w-4 h-4" />
                <span>USER ACTION AUDITS ({activityLogs.length})</span>
              </button>

              <button
                type="button"
                onClick={() => setActiveTab('system')}
                className={`px-4 py-2 rounded-xl transition-all cursor-pointer flex items-center gap-2 ${
                  activeTab === 'system'
                    ? 'bg-indigo-500 text-slate-950 font-extrabold shadow-md'
                    : 'text-slate-400 hover:text-white'
                }`}
              >
                <Terminal className="w-4 h-4" />
                <span>SYSTEM LOGS ({systemLogs.length})</span>
              </button>

              <button
                type="button"
                onClick={() => setActiveTab('users')}
                className={`px-4 py-2 rounded-xl transition-all cursor-pointer flex items-center gap-2 ${
                  activeTab === 'users'
                    ? 'bg-amber-500 text-slate-950 font-extrabold shadow-md'
                    : 'text-slate-400 hover:text-white'
                }`}
              >
                <Users className="w-4 h-4" />
                <span>USER VAULT ({stats?.users.length || 0})</span>
              </button>
            </div>

            {/* FILTER SEARCH BAR & CATEGORY FILTER */}
            <div className="flex items-center gap-2 font-mono text-xs">
              {activeTab === 'activity' && (
                <select
                  value={actionCategory}
                  onChange={(e: any) => setActionCategory(e.target.value)}
                  className="bg-slate-950 border border-slate-800 rounded-xl px-3 py-2 text-xs text-slate-300 font-mono focus:outline-none focus:border-cyan-500"
                >
                  <option value="all">ALL ACTIONS</option>
                  <option value="LOGIN">LOGINS</option>
                  <option value="SCAN">SECURITY SCANS</option>
                  <option value="REGISTER">REGISTRATIONS</option>
                </select>
              )}

              {activeTab === 'system' && (
                <select
                  value={logFilter}
                  onChange={(e: any) => setLogFilter(e.target.value)}
                  className="bg-slate-950 border border-slate-800 rounded-xl px-3 py-2 text-xs text-slate-300 font-mono focus:outline-none focus:border-indigo-500"
                >
                  <option value="all">ALL LOG LEVELS</option>
                  <option value="http">HTTP REQUESTS</option>
                  <option value="info">INFO</option>
                  <option value="warn">WARN</option>
                  <option value="error">ERROR</option>
                </select>
              )}

              <div className="relative w-full sm:w-64">
                <span className="absolute inset-y-0 left-0 pl-3.5 flex items-center pointer-events-none text-slate-500">
                  <Search className="w-3.5 h-3.5" />
                </span>
                <input
                  type="text"
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)}
                  placeholder="Filter logs by keyword..."
                  className="w-full bg-slate-950 border border-slate-800 rounded-xl pl-9 pr-3.5 py-2 text-xs text-white placeholder-slate-600 focus:outline-none focus:border-cyan-500 transition-all font-mono"
                />
              </div>
            </div>
          </div>

          {/* 1. USER ACTIVITY AUDIT TABLE */}
          {activeTab === 'activity' && (
            <div className="overflow-x-auto rounded-2xl border border-slate-800/80">
              <table className="w-full text-left text-xs border-collapse font-mono">
                <thead>
                  <tr className="bg-slate-900/60 text-slate-400 border-b border-slate-800 uppercase text-[10px] tracking-wider">
                    <th className="p-3.5 font-bold">Timestamp</th>
                    <th className="p-3.5 font-bold">User Identity</th>
                    <th className="p-3.5 font-bold">Action Executed</th>
                    <th className="p-3.5 font-bold">IP Address</th>
                    <th className="p-3.5 font-bold">Audit Details</th>
                    <th className="p-3.5 font-bold text-right">Status</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/50 bg-slate-950/40">
                  {filteredActivities.length === 0 ? (
                    <tr>
                      <td colSpan={6} className="p-8 text-center text-slate-500">No activity logs match the search filter.</td>
                    </tr>
                  ) : (
                    filteredActivities.map((log) => (
                      <tr 
                        key={log.id} 
                        onClick={() => setSelectedLog(log)}
                        className="hover:bg-slate-900/60 transition-colors cursor-pointer"
                      >
                        <td className="p-3.5 text-slate-400 text-[10px] whitespace-nowrap">{new Date(log.timestamp).toLocaleTimeString()}</td>
                        <td className="p-3.5 text-cyan-400 font-bold">{log.email}</td>
                        <td className="p-3.5 text-white font-bold tracking-wide">
                          <span className="px-2.5 py-1 rounded bg-slate-900 border border-slate-800 text-slate-200">
                            {log.action}
                          </span>
                        </td>
                        <td className="p-3.5 text-slate-400 text-[10px] font-mono">{log.ip}</td>
                        <td className="p-3.5 text-slate-300 text-[11px] font-sans">{log.details}</td>
                        <td className="p-3.5 text-right">
                          <span className={`px-2.5 py-1 rounded-full text-[9px] font-bold uppercase border tracking-wider ${
                            log.status === 'success' ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30 shadow-[0_0_10px_rgba(16,185,129,0.2)]' :
                            log.status === 'warning' ? 'bg-amber-500/10 text-amber-400 border-amber-500/30' :
                            'bg-rose-500/10 text-rose-400 border-rose-500/30'
                          }`}>
                            {log.status}
                          </span>
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          )}

          {/* 2. SYSTEM LOGS TABLE */}
          {activeTab === 'system' && (
            <div className="overflow-x-auto rounded-2xl border border-slate-800/80">
              <table className="w-full text-left text-xs border-collapse font-mono">
                <thead>
                  <tr className="bg-slate-900/60 text-slate-400 border-b border-slate-800 uppercase text-[10px] tracking-wider">
                    <th className="p-3.5 font-bold">Timestamp</th>
                    <th className="p-3.5 font-bold">Level</th>
                    <th className="p-3.5 font-bold">Category</th>
                    <th className="p-3.5 font-bold">Telemetry Payload Message</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/50 bg-slate-950/40">
                  {filteredSystemLogs.length === 0 ? (
                    <tr>
                      <td colSpan={4} className="p-8 text-center text-slate-500">No system logs match the filter criteria.</td>
                    </tr>
                  ) : (
                    filteredSystemLogs.map((log) => (
                      <tr 
                        key={log.id} 
                        onClick={() => setSelectedLog(log)}
                        className="hover:bg-slate-900/60 transition-colors cursor-pointer"
                      >
                        <td className="p-3.5 text-slate-400 text-[10px] whitespace-nowrap">{new Date(log.timestamp).toLocaleTimeString()}</td>
                        <td className="p-3.5">
                          <span className={`px-2.5 py-1 rounded-full text-[9px] font-bold uppercase border tracking-wider ${
                            log.level === 'error' ? 'bg-rose-500/15 text-rose-400 border-rose-500/40' :
                            log.level === 'warn' ? 'bg-amber-500/15 text-amber-400 border-amber-500/40' :
                            log.level === 'http' ? 'bg-cyan-500/15 text-cyan-300 border-cyan-500/40' :
                            'bg-slate-800 text-slate-300 border-slate-700'
                          }`}>
                            {log.level}
                          </span>
                        </td>
                        <td className="p-3.5 text-cyan-400 font-bold text-[11px]">{log.category}</td>
                        <td className="p-3.5 text-slate-300 text-[11px]">{log.message}</td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          )}

          {/* 3. USER VAULT DIRECTORY */}
          {activeTab === 'users' && (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 font-mono">
              {(stats?.users || []).map((u) => (
                <div key={u.id} className="bg-slate-950/60 p-5 rounded-2xl border border-slate-800/80 hover:border-cyan-500/40 transition-all flex flex-col justify-between gap-3 shadow-sm">
                  <div className="flex items-start justify-between gap-2">
                    <div>
                      <span className="font-bold text-white block text-sm">{u.email}</span>
                      <span className="text-[10px] text-slate-500 block mt-0.5">Joined: {new Date(u.createdAt).toLocaleDateString()}</span>
                    </div>
                    <span className="px-3 py-1 rounded-full text-[9px] font-bold uppercase bg-emerald-500/15 text-emerald-300 border border-emerald-500/30">
                      PRO ENTERPRISE
                    </span>
                  </div>

                  <div className="border-t border-slate-800/80 pt-3 flex items-center justify-between text-xs text-slate-400">
                    <span>Mobile: <strong className="text-slate-200">{u.mobileNumber || 'N/A'}</strong></span>
                    <span>Total Scans: <strong className="text-cyan-400">{u.scansThisMonth}</strong></span>
                  </div>
                </div>
              ))}
            </div>
          )}

        </div>
      </main>

      {/* LOG DETAILS MODAL DRAWER */}
      {selectedLog && (
        <div className="fixed inset-0 z-50 bg-slate-950/80 backdrop-blur-md flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-3xl p-6 w-full max-w-xl space-y-4 shadow-2xl font-mono">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div className="flex items-center gap-2 text-cyan-400 font-bold text-sm">
                <Terminal className="w-4 h-4" />
                <span>LOG TELEMETRY RECORD</span>
              </div>
              <button 
                onClick={() => setSelectedLog(null)}
                className="text-slate-500 hover:text-white text-xs px-2 py-1 bg-slate-800 rounded-lg"
              >
                CLOSE [ESC]
              </button>
            </div>

            <div className="bg-slate-950 p-4 rounded-xl border border-slate-800 overflow-x-auto">
              <pre className="text-xs text-cyan-300 whitespace-pre-wrap">{JSON.stringify(selectedLog, null, 2)}</pre>
            </div>
          </div>
        </div>
      )}

    </div>
  );
}
