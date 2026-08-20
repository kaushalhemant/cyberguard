import React, { useState } from 'react';
import { X, Shield, Lock, Trash2, Mail, CheckCircle2, AlertTriangle, Eye, Server, RefreshCw } from 'lucide-react';

interface PrivacyStatementModalProps {
  isOpen: boolean;
  onClose: () => void;
  isLoggedIn?: boolean;
  userEmail?: string;
  onWipeData?: () => Promise<void>;
}

export default function PrivacyStatementModal({
  isOpen,
  onClose,
  isLoggedIn = false,
  userEmail,
  onWipeData
}: PrivacyStatementModalProps) {
  const [confirmWipe, setConfirmWipe] = useState(false);
  const [isWiping, setIsWiping] = useState(false);
  const [wipeSuccess, setWipeSuccess] = useState(false);
  const [error, setError] = useState<string | null>(null);

  if (!isOpen) return null;

  const handleExecuteWipe = async () => {
    if (!onWipeData) return;
    setIsWiping(true);
    setError(null);
    try {
      await onWipeData();
      setWipeSuccess(true);
      setConfirmWipe(false);
      setTimeout(() => {
        setWipeSuccess(false);
      }, 5000);
    } catch (err: any) {
      setError(err.message || "Failed to execute data erasure. Please contact support.");
    } finally {
      setIsWiping(false);
    }
  };

  return (
    <div className="fixed inset-0 bg-slate-950/85 backdrop-blur-md z-50 flex items-center justify-center p-4 overflow-y-auto animate-fade-in">
      <div 
        id="privacy-statement-modal"
        className="bg-slate-900 border border-slate-800 rounded-3xl p-6 md:p-8 max-w-2xl w-full text-slate-300 shadow-2xl relative overflow-y-auto max-h-[90vh] space-y-6"
      >
        {/* Close Button */}
        <button
          onClick={onClose}
          className="absolute top-4 right-4 text-slate-500 hover:text-slate-300 transition-colors p-2 cursor-pointer rounded-full hover:bg-slate-800/50"
          title="Close privacy modal"
        >
          <X className="w-5 h-5" />
        </button>

        {/* Modal Header */}
        <div className="border-b border-slate-800 pb-4">
          <div className="flex items-center gap-2 text-cyan-400 font-mono text-[10px] font-bold tracking-wider mb-1">
            <Shield className="w-4 h-4 text-cyan-400" />
            <span>CYBERGUARD PRIVACY ASSURANCE CORE</span>
          </div>
          <h2 className="text-xl md:text-2xl font-bold font-display text-white">Privacy Statement & Data Rights</h2>
          <p className="text-xs text-slate-500 mt-1">
            Last Updated: July 2026 • Verified Compliance with EU GDPR, CCPA, and Google OAuth Policies
          </p>
        </div>

        {/* Core Sections */}
        <div className="space-y-5 text-xs md:text-sm leading-relaxed">
          
          {/* Section 1: Data Retention */}
          <div className="bg-slate-950/45 border border-slate-850 rounded-2xl p-4 md:p-5 space-y-2.5">
            <h3 className="font-bold text-white font-display flex items-center gap-2 text-sm">
              <Server className="w-4 h-4 text-cyan-400" />
              <span>1. Strict Zero-Retention Data Policy</span>
            </h3>
            <p className="text-slate-400 text-xs">
              CyberGuard operates under defensive security paradigms which dictate that data we do not retain is data that cannot be compromised.
            </p>
            <ul className="list-disc pl-5 space-y-1 text-slate-500 text-xs">
              <li>
                <strong className="text-slate-300">URL, Text, and Document Assets:</strong> Submitted malicious links, images, or log text are analyzed in-memory and immediately destroyed. We do not store persistent copies of files or scanned strings.
              </li>
              <li>
                <strong className="text-slate-300">Audit Histories:</strong> To maintain your timeline of scan statistics (vulnerability ratings, file sizes, timestamps), we store minimal cryptographic metadata (risk scores, summary classifications).
              </li>
            </ul>
          </div>

          {/* Section 2: Local Security Engine */}
          <div className="bg-slate-950/45 border border-slate-850 rounded-2xl p-4 md:p-5 space-y-2.5">
            <h3 className="font-bold text-white font-display flex items-center gap-2 text-sm">
              <Eye className="w-4 h-4 text-cyan-400" />
              <span>2. High-Performance Security Engine Processing</span>
            </h3>
            <p className="text-slate-400 text-xs">
              Our advanced threat scanning features run using deterministic, high-performance security heuristics. All integrations enforce high-security standards:
            </p>
            <ul className="list-disc pl-5 space-y-1 text-slate-500 text-xs">
              <li>
                <strong className="text-slate-300">Data Sovereignty:</strong> Scanned data is processed locally without transmission to third-party AI training APIs.
              </li>
              <li>
                <strong className="text-slate-300">Encrypted Transport:</strong> All session traffic is encrypted in transit using industry-standard TLS 1.3 / 256-bit AES mechanisms.
              </li>
            </ul>
          </div>

          {/* Section 3: Data Deletion & Erasure */}
          <div className="bg-slate-950/45 border border-slate-850 rounded-2xl p-4 md:p-5 space-y-2.5">
            <h3 className="font-bold text-white font-display flex items-center gap-2 text-sm">
              <Trash2 className="w-4 h-4 text-rose-400" />
              <span>3. GDPR Article 17 Right to Erasure & Deletion Mechanisms</span>
            </h3>
            <p className="text-slate-400 text-xs">
              You possess complete, absolute sovereignty over your telemetry. You can purge or revoke permissions through the following pathways at any moment:
            </p>
            <div className="space-y-3 pt-1">
              <div className="text-[11px] text-slate-500 space-y-1 bg-slate-900/60 p-3 rounded-xl border border-slate-950">
                <p>
                  <strong>Option A (Immediate Database Purge):</strong> You can wipe all previous threat logs and records instantly from our cloud Firestore cluster. This is an irreversible action.
                </p>
                <p>
                  <strong>Option B (Total Profile Erasure):</strong> To delete your entire user account, verified email credentials, and profile completely from our servers, send an explicit request to: 
                  <a href="mailto:hemantkaushal72@gmail.com" className="text-cyan-400 font-mono underline select-all ml-1">hemantkaushal72@gmail.com</a>. We process complete profile destructions within 24 hours.
                </p>
                <p>
                  <strong>Option C (Google OAuth Revocation):</strong> If you linked your Google/Gmail account, you can revoke access at any time directly through your <a href="https://myaccount.google.com/permissions" target="_blank" rel="noopener noreferrer" className="text-cyan-400 underline">Google Account Security Permissions page</a>.
                </p>
              </div>

              {/* Functional Wipe Tool inside Modal */}
              {isLoggedIn && onWipeData && (
                <div className="pt-2 border-t border-slate-900/60">
                  {wipeSuccess ? (
                    <div className="bg-emerald-950/50 border border-emerald-500/20 rounded-xl p-3 text-emerald-400 text-xs flex items-center gap-2 font-mono">
                      <CheckCircle2 className="w-4 h-4" />
                      <span>Data erasure successful! Your telemetry history is now completely empty.</span>
                    </div>
                  ) : confirmWipe ? (
                    <div className="bg-rose-950/20 border border-rose-500/25 p-3 rounded-xl space-y-3">
                      <div className="flex items-start gap-2 text-rose-300">
                        <AlertTriangle className="w-4 h-4 shrink-0 text-rose-400 mt-0.5" />
                        <span className="text-xs font-semibold uppercase font-mono tracking-wider">Confirm Irreversible Telemetry Purge</span>
                      </div>
                      <p className="text-[11px] text-slate-400">
                        This will permanently destroy all scan metadata, threat risk scores, and logs linked to <span className="font-bold text-slate-200">{userEmail}</span>. This cannot be undone.
                      </p>
                      <div className="flex gap-2">
                        <button
                          type="button"
                          disabled={isWiping}
                          onClick={handleExecuteWipe}
                          className="bg-rose-600 hover:bg-rose-500 text-white font-bold text-xs py-1.5 px-3 rounded-lg cursor-pointer disabled:opacity-50 font-mono"
                        >
                          {isWiping ? "Erasing Logs..." : "CONFIRM PURGE"}
                        </button>
                        <button
                          type="button"
                          onClick={() => setConfirmWipe(false)}
                          className="bg-slate-900 border border-slate-800 text-slate-300 font-bold text-xs py-1.5 px-3 rounded-lg cursor-pointer"
                        >
                          Cancel
                        </button>
                      </div>
                    </div>
                  ) : (
                    <button
                      type="button"
                      onClick={() => setConfirmWipe(true)}
                      className="w-full bg-rose-500/10 hover:bg-rose-500/20 border border-rose-500/20 text-rose-400 font-bold font-mono text-xs py-2 px-4 rounded-xl transition-all flex items-center justify-center gap-1.5 cursor-pointer"
                    >
                      <Trash2 className="w-3.5 h-3.5" />
                      <span>Execute Immediate GDPR Right to Erasure (Purge Logs)</span>
                    </button>
                  )}
                  {error && (
                    <p className="text-rose-400 text-xs font-mono mt-2">{error}</p>
                  )}
                </div>
              )}
            </div>
          </div>

        </div>

        {/* Modal Footer / Legal Acknowledgment */}
        <div className="border-t border-slate-800 pt-4 flex flex-col sm:flex-row items-center justify-between gap-4 text-[10px] text-slate-500 font-mono">
          <div className="flex items-center gap-1.5">
            <Lock className="w-3.5 h-3.5 text-cyan-500" />
            <span>SECURE ENCRYPTED DIALOG CORE</span>
          </div>
          <button
            onClick={onClose}
            className="bg-cyan-500/10 hover:bg-cyan-500/20 text-cyan-400 border border-cyan-500/25 font-bold px-4 py-2 rounded-xl transition-all text-xs cursor-pointer"
          >
            I Acknowledge My Rights
          </button>
        </div>
      </div>
    </div>
  );
}
