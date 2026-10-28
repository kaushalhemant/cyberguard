import React, { useState } from 'react';
import { 
  Mail, Search, AlertTriangle, ShieldCheck, CheckCircle2, 
  RefreshCw, Lock, FileText, Database, ShieldAlert
} from 'lucide-react';
import { ScanResult } from '../../types';
import StatusBadge from '../common/StatusBadge';

interface EmailBreachViewProps {
  token: string;
  onScanEmail: (email: string) => Promise<ScanResult | null>;
  currentScan: ScanResult | null;
  loading: boolean;
  error: string | null;
  onSelectReport: (scan: ScanResult) => void;
}

export default function EmailBreachView({
  token,
  onScanEmail,
  currentScan,
  loading,
  error,
  onSelectReport
}: EmailBreachViewProps) {
  const [emailInput, setEmailInput] = useState('');

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!emailInput.trim()) return;
    await onScanEmail(emailInput.trim());
  };

  const handleSample = async (sampleEmail: string) => {
    setEmailInput(sampleEmail);
    await onScanEmail(sampleEmail);
  };

  return (
    <div className="space-y-4">
      {/* Header Banner */}
      <div className="command-card p-4 sm:p-5 flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <div className="w-8 h-8 rounded bg-emerald-500/10 border border-emerald-500/30 flex items-center justify-center text-emerald-400">
              <Mail className="w-4 h-4" />
            </div>
            <h2 className="text-base font-bold font-display uppercase tracking-wider text-white">
              Identity Exposure & Email Breach Auditor
            </h2>
            <span className="px-1.5 py-0.5 rounded text-[9px] font-mono font-bold bg-emerald-500/20 text-emerald-300 border border-emerald-500/40">
              CREDENTIAL EXPOSURE INDEX
            </span>
          </div>
          <p className="text-xs text-slate-400 font-sans mt-1 max-w-3xl">
            Audit compromised account credentials, leaked identity records, password hash disclosures, and exfiltrated enterprise database dumps with zero data retention.
          </p>
        </div>

        {/* 1-Click Samples */}
        <div className="flex flex-wrap items-center gap-2">
          <span className="text-[10px] font-mono text-slate-400 uppercase">Presets:</span>
          <button
            onClick={() => handleSample('usxr@yahoo.com')}
            className="px-2 py-1 rounded bg-[#131C2E] hover:bg-[#1A263D] border border-red-500/30 text-red-300 text-[10px] font-mono transition-colors"
          >
            🚨 Compromised Target (usxr@yahoo.com)
          </button>
          <button
            onClick={() => handleSample('secure@cyberguard.gov')}
            className="px-2 py-1 rounded bg-[#131C2E] hover:bg-[#1A263D] border border-emerald-500/30 text-emerald-300 text-[10px] font-mono transition-colors"
          >
            🟢 Verified Clean (secure@cyberguard.gov)
          </button>
        </div>
      </div>

      {/* Main Grid: Input Form (5 cols) & Results (7 cols) */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
        {/* Left Column: Input Form (5 cols) */}
        <div className="lg:col-span-5 space-y-4">
          <div className="command-card p-4 space-y-4">
            <h3 className="text-xs font-bold font-mono uppercase tracking-wider text-white">
              Target Email Address
            </h3>

            <form onSubmit={handleSubmit} className="space-y-3">
              <div className="space-y-1">
                <label className="text-[11px] font-mono text-slate-400 uppercase">
                  Target Identity Email
                </label>
                <div className="relative">
                  <Mail className="w-4 h-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
                  <input
                    type="email"
                    value={emailInput}
                    onChange={(e) => setEmailInput(e.target.value)}
                    placeholder="e.g. employee@company.com"
                    className="w-full h-9 pl-9 pr-3 bg-[#111827] border border-[#1C273C] rounded text-xs text-slate-200 placeholder-slate-500 focus:border-emerald-500 font-mono"
                  />
                </div>
              </div>

              {error && (
                <div className="p-2.5 rounded bg-red-500/15 border border-red-500/40 text-red-300 text-xs font-mono flex items-center gap-2">
                  <AlertTriangle className="w-4 h-4 shrink-0 text-red-400" />
                  <span>{error}</span>
                </div>
              )}

              <button
                type="submit"
                disabled={!emailInput.trim() || loading}
                className="w-full py-2.5 px-4 rounded-md bg-emerald-600 hover:bg-emerald-500 text-slate-950 font-bold font-sans text-xs uppercase tracking-wider transition-all shadow-[0_0_12px_rgba(16,185,129,0.3)] flex items-center justify-center gap-2 cursor-pointer disabled:opacity-40 disabled:cursor-not-allowed"
              >
                {loading ? (
                  <>
                    <RefreshCw className="w-4 h-4 animate-spin text-slate-950" />
                    <span>Auditing Deterministic Ledger...</span>
                  </>
                ) : (
                  <>
                    <Search className="w-4 h-4 text-slate-950" />
                    <span>Execute Breach Audit</span>
                  </>
                )}
              </button>
            </form>

            <div className="text-[10px] font-mono text-slate-400 space-y-1 pt-1 border-t border-[#1C273C]">
              <div className="flex items-center gap-1.5">
                <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
                <span>Zero-Retention Enforced: Target email is not stored or shared</span>
              </div>
              <div className="flex items-center gap-1.5">
                <CheckCircle2 className="w-3.5 h-3.5 text-blue-400" />
                <span>Deterministic Scoring: Full score breakdown provided</span>
              </div>
            </div>
          </div>
        </div>

        {/* Right Column: Forensic Results (7 cols) */}
        <div className="lg:col-span-7 space-y-4">
          {!currentScan || currentScan.scanType === 'link' || currentScan.scanType === 'image' ? (
            <div className="command-card p-8 flex flex-col items-center justify-center text-center space-y-3 min-h-[360px]">
              <div className="w-14 h-14 rounded-full bg-emerald-500/10 border border-emerald-500/30 flex items-center justify-center text-emerald-400">
                <Mail className="w-7 h-7" />
              </div>
              <h4 className="text-sm font-bold font-sans text-white">
                No Email Exposure Audit Executed Yet
              </h4>
              <p className="text-xs text-slate-400 max-w-md font-sans">
                Enter an email address to query deterministic leak records, exposed passwords, and mitigation advice.
              </p>
            </div>
          ) : (
            <div className="space-y-4">
              {/* Verdict Summary Card */}
              <div className="command-card p-4 space-y-3 border-emerald-500/30">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-[#1C273C] pb-3">
                  <div>
                    <div className="flex items-center gap-2">
                      <span className="text-xs font-mono text-slate-400 uppercase">Target:</span>
                      <span className="font-mono text-xs font-bold text-white truncate max-w-xs">
                        {currentScan.targetEmail}
                      </span>
                    </div>
                    <span className="text-[10px] font-mono text-slate-400">
                      Audited: {new Date(currentScan.timestamp).toLocaleTimeString()} • Breaches: {currentScan.breaches.length}
                    </span>
                  </div>

                  <div className="flex items-center gap-2">
                    <StatusBadge 
                      severity={currentScan.riskScore >= 70 ? 'critical' : (currentScan.riskScore >= 40 ? 'high' : 'low')} 
                      label={currentScan.riskScore >= 70 ? 'CRITICAL EXPOSURE' : (currentScan.riskScore >= 40 ? 'ELEVATED RISK' : 'CLEAN IDENTITY')}
                      size="md"
                    />
                    <button
                      onClick={() => onSelectReport(currentScan)}
                      className="px-2 py-1 rounded bg-blue-600/20 hover:bg-blue-600/40 text-blue-300 font-mono text-[10px] border border-blue-500/40 flex items-center gap-1 transition-colors"
                    >
                      <FileText className="w-3 h-3" />
                      <span>PDF Brief</span>
                    </button>
                  </div>
                </div>

                {/* Score Bar */}
                <div className="space-y-1.5">
                  <div className="flex justify-between items-center text-xs font-mono">
                    <span className="text-slate-300">Identity Risk Score:</span>
                    <span className={`font-bold ${
                      currentScan.riskScore >= 70 ? 'text-red-400' : (currentScan.riskScore >= 40 ? 'text-amber-400' : 'text-emerald-400')
                    }`}>
                      {currentScan.riskScore} / 100
                    </span>
                  </div>
                  <div className="w-full h-2.5 bg-[#090D14] border border-[#1C273C] rounded-full overflow-hidden flex">
                    <div 
                      className={`h-full ${
                        currentScan.riskScore >= 70 
                          ? 'bg-red-500' 
                          : (currentScan.riskScore >= 40 ? 'bg-amber-500' : 'bg-emerald-500')
                      }`} 
                      style={{ width: `${Math.max(currentScan.riskScore, 5)}%` }} 
                    />
                  </div>
                </div>
              </div>

              {/* Breaches List */}
              {currentScan.breaches && currentScan.breaches.length > 0 && (
                <div className="command-card p-4 space-y-3">
                  <h4 className="text-xs font-bold font-mono uppercase tracking-wider text-red-400 flex items-center gap-1.5">
                    <ShieldAlert className="w-3.5 h-3.5" />
                    <span>Identified Exfiltrated Database Dumps</span>
                  </h4>

                  <div className="space-y-2">
                    {currentScan.breaches.map((b) => (
                      <div key={b.id} className="p-3 rounded bg-[#101726] border border-[#1C273C] space-y-1.5">
                        <div className="flex items-center justify-between">
                          <span className="font-bold text-xs text-white">{b.Title}</span>
                          <StatusBadge severity={b.severity} />
                        </div>
                        <p className="text-xs font-sans text-slate-300" dangerouslySetInnerHTML={{ __html: b.Description }} />
                        <div className="flex flex-wrap gap-1 pt-1">
                          {b.DataClasses.map((dc, i) => (
                            <span key={i} className="px-1.5 py-0.2 rounded bg-[#162136] border border-[#202E48] text-slate-300 font-mono text-[9px]">
                              {dc}
                            </span>
                          ))}
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
