import React, { useState } from 'react';
import { 
  FileText, Download, Copy, Check, ExternalLink, ShieldCheck, 
  RefreshCw, Code, ArrowUpRight
} from 'lucide-react';

interface StixBundlerViewProps {
  token: string;
  onGenerateStix: (target: string, indicatorType?: string) => Promise<any>;
  loading: boolean;
}

export default function StixBundlerView({
  token,
  onGenerateStix,
  loading
}: StixBundlerViewProps) {
  const [targetInput, setTargetInput] = useState('malicious-c2-node.org');
  const [indicatorType, setIndicatorType] = useState('malicious-activity');
  const [stixBundle, setStixBundle] = useState<any | null>(null);
  const [copied, setCopied] = useState(false);

  const handleGenerate = async (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    if (!targetInput.trim()) return;
    const res = await onGenerateStix(targetInput.trim(), indicatorType);
    if (res?.bundle || res?.stixBundle) {
      setStixBundle(res.bundle || res.stixBundle);
    }
  };

  const handleCopy = () => {
    if (!stixBundle) return;
    navigator.clipboard.writeText(JSON.stringify(stixBundle, null, 2));
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleDownload = () => {
    if (!stixBundle) return;
    const blob = new Blob([JSON.stringify(stixBundle, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `stix-bundle-${targetInput.replace(/[^a-zA-Z0-9]/g, '_')}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="space-y-4">
      {/* Header Banner */}
      <div className="command-card p-4 sm:p-5 flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <div className="w-8 h-8 rounded bg-blue-500/10 border border-blue-500/30 flex items-center justify-center text-blue-400">
              <FileText className="w-4 h-4" />
            </div>
            <h2 className="text-base font-bold font-display uppercase tracking-wider text-white">
              OASIS STIX 2.1 & 3.0 DFIR Evidence Bundler
            </h2>
            <span className="px-1.5 py-0.5 rounded text-[9px] font-mono font-bold bg-blue-500/20 text-blue-300 border border-blue-500/40">
              OASIS OPEN STANDARD
            </span>
          </div>
          <p className="text-xs text-slate-400 font-sans mt-1 max-w-3xl">
            Export structured Cyber Threat Intelligence (CTI) graphs complying with OASIS STIX 2.1 & STIX 3.0 specifications for ingestion by OpenCTI, MISP, Sentinel, and SIEM pipelines.
          </p>
        </div>
      </div>

      {/* Main Grid: Controls (5 cols) & Live STIX JSON (7 cols) */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
        {/* Left Column: Form Controls (5 cols) */}
        <div className="lg:col-span-5 space-y-4">
          <div className="command-card p-4 space-y-4">
            <h3 className="text-xs font-bold font-mono uppercase tracking-wider text-white">
              Indicator Specification
            </h3>

            <form onSubmit={handleGenerate} className="space-y-3">
              <div className="space-y-1">
                <label className="text-[11px] font-mono text-slate-400 uppercase">
                  Indicator Target Pattern (Domain, IP, Hash)
                </label>
                <input
                  type="text"
                  value={targetInput}
                  onChange={(e) => setTargetInput(e.target.value)}
                  placeholder="e.g. malicious-c2.org or 185.220.101.5"
                  className="w-full h-8 px-3 bg-[#111827] border border-[#1C273C] rounded text-xs text-slate-200 placeholder-slate-500 focus:border-blue-500 font-mono"
                />
              </div>

              <div className="space-y-1">
                <label className="text-[11px] font-mono text-slate-400 uppercase">
                  STIX Indicator Type
                </label>
                <select
                  value={indicatorType}
                  onChange={(e) => setIndicatorType(e.target.value)}
                  className="w-full h-8 px-2 bg-[#111827] border border-[#1C273C] rounded text-xs text-slate-300 focus:border-blue-500 cursor-pointer"
                >
                  <option value="malicious-activity">malicious-activity</option>
                  <option value="anomalous-activity">anomalous-activity</option>
                  <option value="attribution">attribution</option>
                  <option value="compromised">compromised</option>
                </select>
              </div>

              <button
                type="submit"
                disabled={!targetInput.trim() || loading}
                className="w-full py-2.5 px-4 rounded-md bg-blue-600 hover:bg-blue-500 text-white font-bold font-sans text-xs uppercase tracking-wider transition-all shadow-[0_0_12px_rgba(59,130,246,0.3)] flex items-center justify-center gap-2 cursor-pointer disabled:opacity-40"
              >
                {loading ? (
                  <>
                    <RefreshCw className="w-4 h-4 animate-spin text-white" />
                    <span>Compiling STIX Objects...</span>
                  </>
                ) : (
                  <>
                    <Code className="w-4 h-4" />
                    <span>Generate STIX 2.1 / 3.0 Bundle</span>
                  </>
                )}
              </button>
            </form>

            <div className="text-[10px] font-mono text-slate-400 space-y-1 pt-1 border-t border-[#1C273C]">
              <div>Objects Generated: <strong className="text-white">Identity, Indicator, Sighting</strong></div>
              <div>Standard: <strong className="text-cyan-400">OASIS STIX v2.1 RFC Compliance</strong></div>
            </div>
          </div>
        </div>

        {/* Right Column: Live STIX Viewer (7 cols) */}
        <div className="lg:col-span-7 space-y-4">
          <div className="command-card p-4 space-y-3">
            <div className="flex items-center justify-between border-b border-[#1C273C] pb-2.5">
              <span className="font-mono text-xs font-bold text-white uppercase">
                Compiled STIX JSON Bundle
              </span>

              {stixBundle && (
                <div className="flex items-center gap-1.5">
                  <button
                    onClick={handleCopy}
                    className="px-2.5 py-1 rounded bg-[#162136] hover:bg-[#1E2D48] text-slate-300 font-mono text-[10px] border border-[#202E48] flex items-center gap-1 transition-colors cursor-pointer"
                  >
                    {copied ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                    <span>{copied ? 'Copied' : 'Copy JSON'}</span>
                  </button>
                  <button
                    onClick={handleDownload}
                    className="px-2.5 py-1 rounded bg-blue-600 hover:bg-blue-500 text-white font-mono text-[10px] flex items-center gap-1 transition-colors cursor-pointer"
                  >
                    <Download className="w-3 h-3" />
                    <span>Download</span>
                  </button>
                </div>
              )}
            </div>

            {!stixBundle ? (
              <div className="py-16 text-center text-slate-400 font-mono text-xs">
                Click "Generate STIX 2.1 / 3.0 Bundle" to compile structured threat intelligence JSON.
              </div>
            ) : (
              <pre className="p-3 bg-[#090D14] border border-[#1C273C] rounded-md font-mono text-[11px] text-cyan-300 overflow-x-auto max-h-[460px] leading-relaxed">
                {JSON.stringify(stixBundle, null, 2)}
              </pre>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
