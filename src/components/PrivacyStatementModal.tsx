import React, { useState } from 'react';
import { X, Shield, Lock, Trash2, CheckCircle2, AlertTriangle, Eye, Server } from 'lucide-react';

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
    <div className="fixed inset-0 bg-[#090D14]/90 z-50 flex items-center justify-center p-4 overflow-y-auto font-sans">
      <div 
        id="privacy-statement-modal"
        className="bg-[#111622] border border-[#263147] rounded-sm p-6 max-w-2xl w-full text-[#ECEFF4] relative overflow-y-auto max-h-[90vh] space-y-4"
      >
        {/* Close Button */}
        <button
          onClick={onClose}
          className="absolute top-4 right-4 text-[#7E8B9B] hover:text-white p-1 cursor-pointer"
          title="Close privacy modal"
        >
          <X className="w-5 h-5" />
        </button>

        {/* Modal Header */}
        <div className="border-b border-[#263147] pb-3">
          <div className="flex items-center gap-2 text-[#00E5FF] font-mono text-[10px] font-bold uppercase mb-1">
            <Shield className="w-4 h-4 text-[#00E5FF]" />
            <span>CYBERGUARD PRIVACY ASSURANCE CORE</span>
          </div>
          <h2 className="text-lg font-bold font-display uppercase text-white">Privacy Statement & Data Rights</h2>
          <p className="text-[11px] font-mono text-[#7E8B9B] mt-0.5">
            Verified Compliance with EU GDPR Art. 17, CCPA, and Enterprise OAuth Policies
          </p>
        </div>

        {/* Core Sections */}
        <div className="space-y-4 text-xs font-mono leading-relaxed text-[#7E8B9B]">
          
          {/* Section 1: Data Retention */}
          <div className="bg-[#090D14] border border-[#263147] p-4 space-y-2">
            <h3 className="font-bold text-white font-display flex items-center gap-2 text-xs uppercase">
              <Server className="w-4 h-4 text-[#00E5FF]" />
              <span>1. Strict Zero-Retention Data Policy</span>
            </h3>
            <p className="text-[#ECEFF4] text-[11px]">
              CyberGuard operates under defensive security paradigms which dictate that data we do not retain is data that cannot be compromised.
            </p>
            <ul className="list-disc pl-4 space-y-1 text-[#7E8B9B] text-[11px]">
              <li>
                <strong className="text-[#ECEFF4]">URL & Visual Assets:</strong> Submitted links and image artifacts are analyzed in-memory and destroyed immediately after processing.
              </li>
              <li>
                <strong className="text-[#ECEFF4]">Audit Histories:</strong> Only minimal cryptographic metadata (risk scores, classifications, timestamps) is stored for timeline auditing.
              </li>
            </ul>
          </div>

          {/* Section 2: GDPR Erasure */}
          <div className="bg-[#090D14] border border-[#263147] p-4 space-y-2">
            <h3 className="font-bold text-white font-display flex items-center gap-2 text-xs uppercase">
              <Lock className="w-4 h-4 text-[#00E5FF]" />
              <span>2. GDPR Article 17 Right to Erasure</span>
            </h3>
            <p className="text-[#ECEFF4] text-[11px]">
              Under GDPR Article 17, you hold full legal rights to request immediate and permanent purging of all logged data associated with your session.
            </p>

            {onWipeData && (
              <div className="pt-2 border-t border-[#263147]">
                {wipeSuccess ? (
                  <div className="p-2 bg-[#00E676]/10 border border-[#00E676]/30 text-[#00E676] text-[11px] flex items-center gap-2">
                    <CheckCircle2 className="w-4 h-4 text-[#00E676]" />
                    <span>All threat scan histories have been purged permanently.</span>
                  </div>
                ) : confirmWipe ? (
                  <div className="space-y-2 bg-[#FF334B]/10 border border-[#FF334B]/30 p-3">
                    <div className="flex items-center gap-2 text-[#FF334B] text-[11px] font-bold uppercase">
                      <AlertTriangle className="w-4 h-4 shrink-0" />
                      <span>PERMANENTLY ERASE ALL SCAN RECORDS?</span>
                    </div>
                    <div className="flex gap-2 pt-1">
                      <button
                        type="button"
                        disabled={isWiping}
                        onClick={handleExecuteWipe}
                        className="flex-1 bg-[#FF334B] text-white font-bold text-[11px] py-1.5 cursor-pointer disabled:opacity-50"
                      >
                        {isWiping ? 'PURGING...' : 'YES, PURGE DATA'}
                      </button>
                      <button
                        type="button"
                        onClick={() => setConfirmWipe(false)}
                        className="btn-soc px-3 py-1.5 text-[11px]"
                      >
                        CANCEL
                      </button>
                    </div>
                  </div>
                ) : (
                  <button
                    type="button"
                    onClick={() => setConfirmWipe(true)}
                    className="btn-soc border-[#FF334B]/40 text-[#FF334B] hover:bg-[#FF334B]/10 px-3 py-1.5 text-[11px] flex items-center gap-2 cursor-pointer"
                  >
                    <Trash2 className="w-3.5 h-3.5" />
                    <span>EXECUTE GDPR DATA ERASURE</span>
                  </button>
                )}

                {error && (
                  <div className="mt-2 text-[#FF334B] text-[10px]">
                    {error}
                  </div>
                )}
              </div>
            )}
          </div>

        </div>

        {/* Modal Footer */}
        <div className="border-t border-[#263147] pt-3 flex items-center justify-between text-[10px] font-mono text-[#7E8B9B]">
          <span>CYBERGUARD COMPLIANCE MATRIX</span>
          <button
            onClick={onClose}
            className="btn-soc px-3 py-1 text-[10px]"
          >
            CLOSE
          </button>
        </div>

      </div>
    </div>
  );
}
