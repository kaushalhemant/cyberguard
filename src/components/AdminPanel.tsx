import React, { useState, useEffect } from 'react';
import { DollarSign, Users, ShieldAlert, Check, X, Search, Activity, RefreshCw, Layers, Terminal as TerminalIcon, ShieldCheck } from 'lucide-react';
import { PaymentRequest, User } from '../types';
import { safeJsonResponse } from '../lib/api';

interface AdminPanelProps {
  token: string;
}

interface AdminStats {
  totalUsers: number;
  proUsers: number;
  freeUsers: number;
  pendingPayments: number;
  totalRevenue: number;
  users: User[];
}

export default function AdminPanel({ token }: AdminPanelProps) {
  const [stats, setStats] = useState<AdminStats | null>(null);
  const [activityLogs, setActivityLogs] = useState<any[]>([]);
  const [systemLogs, setSystemLogs] = useState<any[]>([]);
  const [logTab, setLogTab] = useState<'users' | 'activity' | 'system'>('users');
  const [loading, setLoading] = useState(true);
  const [searchTerm, setSearchTerm] = useState('');

  const fetchAdminData = async () => {
    setLoading(true);
    try {
      const statsRes = await fetch('/api/admin/stats', {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      const statsData = await safeJsonResponse<AdminStats>(statsRes, 'Failed to load admin analytics');
      setStats(statsData);

      const logsRes = await fetch('/api/logs', {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      if (logsRes.ok) {
        const logsData = await safeJsonResponse<any>(logsRes);
        setActivityLogs(logsData.activityLogs || []);
        setSystemLogs(logsData.systemLogs || []);
      }
    } catch (err) {
      console.error('Failed to load admin dataset:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchAdminData();
  }, [token]);

  const filteredUsers = (stats?.users || []).filter(u => {
    const q = searchTerm.toLowerCase();
    return u.email.toLowerCase().includes(q) || u.role.toLowerCase().includes(q);
  });

  const filteredActivity = activityLogs.filter(l => {
    const q = searchTerm.toLowerCase();
    return (l.email || '').toLowerCase().includes(q) || (l.action || '').toLowerCase().includes(q) || (l.details || '').toLowerCase().includes(q);
  });

  const filteredSystem = systemLogs.filter(l => {
    const q = searchTerm.toLowerCase();
    return (l.category || '').toLowerCase().includes(q) || (l.message || '').toLowerCase().includes(q) || (l.level || '').toLowerCase().includes(q);
  });

  return (
    <div className="space-y-6">
      {/* Admin header with refresh */}
      <div className="flex flex-col sm:flex-row justify-between sm:items-center gap-3">
        <div>
          <h2 className="text-xl font-bold font-display text-white flex items-center gap-2">
            <ShieldCheck className="w-5 h-5 text-cyan-400" />
            Central Security & Telemetry Command
          </h2>
          <p className="text-xs text-slate-400">Monitor enterprise accounts, real-time Supabase telemetry logs, and zero-trust audit trails.</p>
        </div>
        <button
          onClick={fetchAdminData}
          disabled={loading}
          className="bg-slate-900 hover:bg-slate-800 text-slate-300 border border-slate-800 px-3 py-2 rounded-xl transition-all cursor-pointer flex items-center gap-1.5 text-xs font-semibold self-start sm:self-auto"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
          Reload Telemetry
        </button>
      </div>

      {/* Grid Stats */}
      {stats && (
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
          <div className="bento-card p-4 flex items-center gap-4">
            <div className="w-10 h-10 rounded-xl bg-cyan-950/50 border border-cyan-500/25 flex items-center justify-center text-cyan-400">
              <Users className="w-5 h-5" />
            </div>
            <div>
              <span className="text-[10px] uppercase font-mono tracking-wider text-slate-500 block">Total Registered Users</span>
              <span className="text-xl font-bold text-white font-mono font-display">{stats.totalUsers}</span>
            </div>
          </div>

          <div className="bento-card p-4 flex items-center gap-4">
            <div className="w-10 h-10 rounded-xl bg-emerald-950/50 border border-emerald-500/25 flex items-center justify-center text-emerald-400">
              <Layers className="w-5 h-5" />
            </div>
            <div>
              <span className="text-[10px] uppercase font-mono tracking-wider text-slate-500 block">Supabase Telemetry Sync</span>
              <span className="text-xl font-bold text-emerald-400 font-mono font-display">ACTIVE & LOGGED</span>
            </div>
          </div>

          <div className="bento-card p-4 flex items-center gap-4">
            <div className="w-10 h-10 rounded-xl bg-indigo-950/50 border border-indigo-500/25 flex items-center justify-center text-indigo-400">
              <Activity className="w-5 h-5" />
            </div>
            <div>
              <span className="text-[10px] uppercase font-mono tracking-wider text-slate-500 block">Audited Log Records</span>
              <span className="text-xl font-bold text-white font-mono font-display">{activityLogs.length + systemLogs.length} Events</span>
            </div>
          </div>
        </div>
      )}

      {/* Audited Directory & Log Tabs */}
      <div className="bento-card p-5">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 mb-4">
          <div className="flex items-center gap-2 bg-slate-950/60 border border-slate-800 p-1 rounded-xl">
            <button
              onClick={() => setLogTab('users')}
              className={`px-3 py-1.5 rounded-lg text-xs font-mono font-bold transition-all cursor-pointer ${logTab === 'users' ? 'bg-cyan-500 text-slate-950' : 'text-slate-400 hover:text-white'}`}
            >
              Users Directory ({stats?.totalUsers || 0})
            </button>
            <button
              onClick={() => setLogTab('activity')}
              className={`px-3 py-1.5 rounded-lg text-xs font-mono font-bold transition-all cursor-pointer ${logTab === 'activity' ? 'bg-cyan-500 text-slate-950' : 'text-slate-400 hover:text-white'}`}
            >
              User Activity Logs ({activityLogs.length})
            </button>
            <button
              onClick={() => setLogTab('system')}
              className={`px-3 py-1.5 rounded-lg text-xs font-mono font-bold transition-all cursor-pointer ${logTab === 'system' ? 'bg-cyan-500 text-slate-950' : 'text-slate-400 hover:text-white'}`}
            >
              System Telemetry Logs ({systemLogs.length})
            </button>
          </div>

          <div className="relative max-w-xs w-full">
            <span className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none text-slate-500">
              <Search className="w-4 h-4" />
            </span>
            <input
              type="text"
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              placeholder="Search logs or emails..."
              className="w-full bg-slate-950 border border-slate-800 rounded-xl pl-9 pr-4 py-1.5 text-xs text-white placeholder-slate-600 focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500 transition-all"
            />
          </div>
        </div>

        {loading ? (
          <div className="p-8 text-center text-slate-500 flex flex-col items-center justify-center gap-2">
            <RefreshCw className="w-6 h-6 animate-spin text-cyan-400" />
            <span className="text-sm font-mono">Querying Supabase telemetry node...</span>
          </div>
        ) : logTab === 'users' ? (
          filteredUsers.length === 0 ? (
            <div className="p-8 text-center text-slate-500">
              <span className="text-sm">No accounts match search query.</span>
            </div>
          ) : (
            <div className="space-y-2">
              {filteredUsers.map(u => (
                <div key={u.id} className="flex justify-between items-center bg-slate-950/40 p-3.5 rounded-xl border border-slate-800/60 text-xs hover:border-cyan-500/50 transition-colors">
                  <div>
                    <span className="font-semibold text-white block">{u.email}</span>
                    <span className="text-[10px] text-slate-500 block">Account Created: {new Date(u.createdAt).toLocaleDateString()}</span>
                  </div>
                  <div className="flex items-center gap-3">
                    <span className="font-mono text-[10px] text-slate-400">Scans Executed: {u.scansThisMonth}</span>
                    <span className="px-2.5 py-1 rounded font-mono font-bold text-[9px] uppercase bg-cyan-950/50 border border-cyan-500/25 text-cyan-400">
                      ENTERPRISE PRO
                    </span>
                  </div>
                </div>
              ))}
            </div>
          )
        ) : logTab === 'activity' ? (
          filteredActivity.length === 0 ? (
            <div className="p-8 text-center text-slate-500 font-mono text-xs">
              No user activity logs found.
            </div>
          ) : (
            <div className="space-y-2 max-h-[500px] overflow-y-auto pr-1">
              {filteredActivity.map((log: any) => (
                <div key={log.id} className="bg-slate-950/60 p-3 rounded-xl border border-slate-800/80 font-mono text-xs space-y-1">
                  <div className="flex items-center justify-between">
                    <span className="text-cyan-400 font-bold">{log.action}</span>
                    <span className="text-[10px] text-slate-500">{new Date(log.timestamp).toLocaleString()}</span>
                  </div>
                  <div className="text-slate-300 text-[11px]">{log.details}</div>
                  <div className="flex items-center justify-between text-[10px] text-slate-500 pt-1">
                    <span>User: <span className="text-slate-400">{log.email}</span></span>
                    <span>IP: <span className="text-slate-400">{log.ip}</span></span>
                  </div>
                </div>
              ))}
            </div>
          )
        ) : (
          filteredSystem.length === 0 ? (
            <div className="p-8 text-center text-slate-500 font-mono text-xs">
              No system telemetry logs found.
            </div>
          ) : (
            <div className="space-y-2 max-h-[500px] overflow-y-auto pr-1">
              {filteredSystem.map((log: any) => (
                <div key={log.id} className="bg-slate-950/60 p-3 rounded-xl border border-slate-800/80 font-mono text-xs space-y-1">
                  <div className="flex items-center justify-between">
                    <span className={`font-bold px-2 py-0.5 rounded text-[10px] uppercase ${log.level === 'error' || log.level === 'warn' ? 'bg-rose-500/20 text-rose-400 border border-rose-500/30' : 'bg-cyan-500/20 text-cyan-400 border border-cyan-500/30'}`}>
                      {log.level} | {log.category}
                    </span>
                    <span className="text-[10px] text-slate-500">{new Date(log.timestamp).toLocaleString()}</span>
                  </div>
                  <div className="text-slate-300 text-[11px] font-mono break-all">{log.message}</div>
                </div>
              ))}
            </div>
          )
        )}
      </div>
    </div>
  );
}
