import React, { useState, useEffect } from 'react';
import { DollarSign, Users, ShieldAlert, Check, X, Search, Activity, RefreshCw, Layers } from 'lucide-react';
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

  return (
    <div className="space-y-6">
      {/* Admin header with refresh */}
      <div className="flex justify-between items-center">
        <div>
          <h2 className="text-xl font-bold font-display text-white">Central Security Operations Panel</h2>
          <p className="text-xs text-slate-400">Monitor enterprise accounts, system node metrics, and zero-trust audit trails.</p>
        </div>
        <button
          onClick={fetchAdminData}
          disabled={loading}
          className="bg-slate-900 hover:bg-slate-800 text-slate-300 border border-slate-800 p-2 rounded-xl transition-all cursor-pointer flex items-center gap-1.5 text-xs font-semibold"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
          Reload Analytics
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
              <span className="text-[10px] uppercase font-mono tracking-wider text-slate-500 block">Total Enterprise Users</span>
              <span className="text-xl font-bold text-white font-mono font-display">{stats.totalUsers}</span>
            </div>
          </div>

          <div className="bento-card p-4 flex items-center gap-4">
            <div className="w-10 h-10 rounded-xl bg-emerald-950/50 border border-emerald-500/25 flex items-center justify-center text-emerald-400">
              <Layers className="w-5 h-5" />
            </div>
            <div>
              <span className="text-[10px] uppercase font-mono tracking-wider text-slate-500 block">Enterprise Access Level</span>
              <span className="text-xl font-bold text-emerald-400 font-mono font-display">100% UNLOCKED</span>
            </div>
          </div>

          <div className="bento-card p-4 flex items-center gap-4">
            <div className="w-10 h-10 rounded-xl bg-indigo-950/50 border border-indigo-500/25 flex items-center justify-center text-indigo-400">
              <Activity className="w-5 h-5" />
            </div>
            <div>
              <span className="text-[10px] uppercase font-mono tracking-wider text-slate-500 block">CyberGuard AI Engine</span>
              <span className="text-xl font-bold text-white font-mono font-display">ACTIVE / 0ms LATENCY</span>
            </div>
          </div>
        </div>
      )}

      {/* Audited Users Ledger */}
      <div className="bento-card p-5">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 mb-4">
          <h3 className="font-bold text-sm text-white font-display">Enterprise Account Directory</h3>
          <div className="relative max-w-xs w-full">
            <span className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none text-slate-500">
              <Search className="w-4 h-4" />
            </span>
            <input
              type="text"
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              placeholder="Search user email..."
              className="w-full bg-slate-950 border border-slate-800 rounded-xl pl-9 pr-4 py-1.5 text-xs text-white placeholder-slate-600 focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500 transition-all"
            />
          </div>
        </div>

        {loading ? (
          <div className="p-8 text-center text-slate-500 flex flex-col items-center justify-center gap-2">
            <RefreshCw className="w-6 h-6 animate-spin text-cyan-400" />
            <span className="text-sm font-mono">Querying directory node...</span>
          </div>
        ) : filteredUsers.length === 0 ? (
          <div className="p-8 text-center text-slate-500">
            <span className="text-sm">No accounts match search query.</span>
          </div>
        ) : (
          <div className="space-y-2">
            {filteredUsers.map(u => (
              <div key={u.id} className="flex justify-between items-center bg-slate-950/20 p-3.5 rounded-xl border border-slate-800/40 text-xs scan-line border-l-2 !border-slate-800/50 hover:!border-cyan-500 transition-colors">
                <div>
                  <span className="font-semibold text-white block">{u.email}</span>
                  <span className="text-[10px] text-slate-500 block">Account Created: {new Date(u.createdAt).toLocaleDateString()}</span>
                </div>
                <div className="flex items-center gap-3">
                  <span className="font-mono text-[10px] text-slate-400">Total Scans Executed: {u.scansThisMonth}</span>
                  <span className="px-2.5 py-1 rounded font-mono font-bold text-[9px] uppercase bg-cyan-950/50 border border-cyan-500/25 text-cyan-400">
                    ENTERPRISE PRO
                  </span>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
