import React, { useState } from 'react';
import { 
  ShieldCheck, Trash2, Lock, AlertTriangle, CheckCircle2, 
  RefreshCw, FileText, Download, UserCheck
} from 'lucide-react';
import { User } from '../../types';

interface ComplianceViewProps {
  token: string;
  user: User;
  onClearAllScans: () => Promise<void>;
  isClearing: boolean;
}

export default function ComplianceView({
  token,
  user,
  onClearAllScans,
  isClearing
}: ComplianceViewProps) {
  const [confirmErasure, setConfirmErasure] = useState(false);
  const [erasureSuccess, setErasureSuccess] = useState(false);

  const handleWipe = async () => {
    await onClearAllScans();
    setErasureSuccess(true);
    setConfirmErasure(false);
    setTimeout(() => setErasureSuccess(false), 4000);
  };

  return (
    <div className="space-y-4">
      {/* Header Banner */}
      <div className="command-card p-4 sm:p-5 flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <div className="w-8 h-8 rounded bg-emerald-500/10 border border-emerald-500/30 flex items-center justify-center text-emerald-400">
              <ShieldCheck className="w-4 h-4" />
            </div>
            <h2 className="text-base font-bold font-display uppercase tracking-wider text-white">
              Compliance, Data Rights & Zero-Retention Security
            </h2>
            <span className="px-1.5 py-0.5 rounded text-[9px] font-mono font-bold bg-emerald-500/20 text-emerald-300 border border-emerald-500/40">
              GDPR ARTICLE 17 COMPLIANT
            </span>
          </div>
          <p className="text-xs text-slate-400 font-sans mt-1 max-w-3xl">
            CyberGuard enforces strict transient in-memory processing. User queries, analyzed email bodies, and uploaded payloads are purged immediately after execution.
          </p>
        </div>
      </div>

      {/* Grid: Guarantees & Erasure Desk */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
        {/* Left Column: Guarantees (7 cols) */}
        <div className="lg:col-span-7 space-y-4">
          <div className="command-card p-4 space-y-3">
            <h3 className="text-xs font-bold font-mono uppercase tracking-wider text-white">
              Deterministic Privacy Commitments
            </h3>

            <div className="space-y-2.5 font-sans text-xs">
              <div className="p-3 rounded bg-[#101726] border border-[#1C273C] space-y-1">
                <div className="font-bold text-white flex items-center gap-1.5 font-mono text-[11px]">
                  <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                  <span>TRANSIENT INBOX & PAYLOAD AUDITING</span>
                </div>
                <p className="text-slate-300">
                  Email headers, link structures, and binary files are inspected exclusively in volatile memory. No permanent storage or disk caching of raw payload content.
                </p>
              </div>

              <div className="p-3 rounded bg-[#101726] border border-[#1C273C] space-y-1">
                <div className="font-bold text-white flex items-center gap-1.5 font-mono text-[11px]">
                  <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                  <span>NO DATA BROKERAGE OR COMMERCIAL MONETIZATION</span>
                </div>
                <p className="text-slate-300">
                  Target search queries and vulnerability checks are never syndicated, sold to third parties, or used to build targeted advertising profiles.
                </p>
              </div>

              <div className="p-3 rounded bg-[#101726] border border-[#1C273C] space-y-1">
                <div className="font-bold text-white flex items-center gap-1.5 font-mono text-[11px]">
                  <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                  <span>DETERMINISTIC TRANSPARENCY</span>
                </div>
                <p className="text-slate-300">
                  Every score is directly attributed to explicit rule-based scoring rubrics. No black-box machine learning guesswork or fabricated metrics.
                </p>
              </div>
            </div>
          </div>
        </div>

        {/* Right Column: GDPR Erasure Desk (5 cols) */}
        <div className="lg:col-span-5 space-y-4">
          <div className="command-card p-4 space-y-3.5 border-red-500/30">
            <h3 className="text-xs font-bold font-mono uppercase tracking-wider text-red-400 flex items-center gap-2">
              <Trash2 className="w-4 h-4" />
              <span>Right to Erasure (GDPR Art. 17)</span>
            </h3>

            <p className="text-xs font-sans text-slate-300">
              Permanently wipe all session investigation records, cached scan outputs, and forensic telemetry associated with your account from memory.
            </p>

            {erasureSuccess && (
              <div className="p-2.5 rounded bg-emerald-500/15 border border-emerald-500/40 text-emerald-300 text-xs font-mono flex items-center gap-2">
                <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                <span>All investigation history successfully purged.</span>
              </div>
            )}

            {!confirmErasure ? (
              <button
                onClick={() => setConfirmErasure(true)}
                className="w-full py-2 px-3 rounded bg-red-500/10 hover:bg-red-500/20 text-red-400 font-mono text-xs font-bold uppercase tracking-wider border border-red-500/30 transition-colors cursor-pointer"
              >
                Initiate Cryptographic History Wipe
              </button>
            ) : (
              <div className="p-3 rounded bg-[#101726] border border-red-500/40 space-y-2.5">
                <span className="text-xs font-mono text-red-300 block">
                  Confirm permanent purge of all investigation records?
                </span>
                <div className="flex gap-2">
                  <button
                    onClick={handleWipe}
                    disabled={isClearing}
                    className="flex-1 py-1.5 rounded bg-red-600 hover:bg-red-500 text-white font-mono text-xs font-bold uppercase transition-colors"
                  >
                    {isClearing ? 'Purging...' : 'Yes, Purge Now'}
                  </button>
                  <button
                    onClick={() => setConfirmErasure(false)}
                    className="flex-1 py-1.5 rounded bg-[#162136] hover:bg-[#1E2D48] text-slate-300 font-mono text-xs transition-colors"
                  >
                    Cancel
                  </button>
                </div>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
