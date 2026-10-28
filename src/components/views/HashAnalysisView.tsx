import React, { useState, useRef } from 'react';
import { 
  FileCode, UploadCloud, Search, AlertTriangle, ShieldCheck, 
  CheckCircle2, RefreshCw, Copy, Check, Binary, Zap, FileText
} from 'lucide-react';
import { HashAnalysisResult } from '../../types';
import StatusBadge from '../common/StatusBadge';

interface HashAnalysisViewProps {
  token: string;
  onAnalyzeHash: (hash: string, fileName?: string, filePayload?: string) => Promise<HashAnalysisResult | null>;
  currentResult: HashAnalysisResult | null;
  loading: boolean;
  error: string | null;
}

export default function HashAnalysisView({
  token,
  onAnalyzeHash,
  currentResult,
  loading,
  error
}: HashAnalysisViewProps) {
  const [hashInput, setHashInput] = useState('');
  const [fileNameInput, setFileNameInput] = useState('');
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [copied, setCopied] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const handleFileUpload = async (file: File) => {
    setSelectedFile(file);
    setFileNameInput(file.name);

    // Read as base64
    const reader = new FileReader();
    reader.onload = async () => {
      const base64 = (reader.result as string).replace(/^data:.*?;base64,/, '');
      await onAnalyzeHash('', file.name, base64);
    };
    reader.readAsDataURL(file);
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!hashInput.trim() && !selectedFile) return;
    await onAnalyzeHash(hashInput.trim(), fileNameInput.trim() || undefined);
  };

  const handleSample = async (hash: string, name: string) => {
    setHashInput(hash);
    setFileNameInput(name);
    setSelectedFile(null);
    await onAnalyzeHash(hash, name);
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="space-y-4">
      {/* Header Banner */}
      <div className="command-card p-4 sm:p-5 flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <div className="w-8 h-8 rounded bg-amber-500/10 border border-amber-500/30 flex items-center justify-center text-amber-400">
              <FileCode className="w-4 h-4" />
            </div>
            <h2 className="text-base font-bold font-display uppercase tracking-wider text-white">
              Malware Hash & Binary Payload Forensics
            </h2>
            <span className="px-1.5 py-0.5 rounded text-[9px] font-mono font-bold bg-amber-500/20 text-amber-300 border border-amber-500/40">
              SHANNON ENTROPY LAB
            </span>
          </div>
          <p className="text-xs text-slate-400 font-sans mt-1 max-w-3xl">
            Evaluate cryptographic hashes (MD5, SHA-1, SHA-256) or drop raw binaries to detect packed executables, high Shannon entropy (0 to 8 bits), header magic bytes, and compiled YARA rule matches.
          </p>
        </div>

        {/* 1-Click Samples */}
        <div className="flex flex-wrap items-center gap-2">
          <span className="text-[10px] font-mono text-slate-400 uppercase">Presets:</span>
          <button
            onClick={() => handleSample('44d88612fea8a8f36de82e1278abb02f', 'dropper_payload.exe')}
            className="px-2 py-1 rounded bg-[#131C2E] hover:bg-[#1A263D] border border-red-500/30 text-red-300 text-[10px] font-mono transition-colors"
          >
            🚨 AsyncRAT Dropper
          </button>
          <button
            onClick={() => handleSample('c1b2a3f4e5d6c7b8a9f0e1d2c3b4a5f6', 'encoded_mimikatz.bin')}
            className="px-2 py-1 rounded bg-[#131C2E] hover:bg-[#1A263D] border border-amber-500/30 text-amber-300 text-[10px] font-mono transition-colors"
          >
            ⚠️ High Entropy Binary
          </button>
          <button
            onClick={() => handleSample('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', 'clean_system_host.dll')}
            className="px-2 py-1 rounded bg-[#131C2E] hover:bg-[#1A263D] border border-emerald-500/30 text-emerald-300 text-[10px] font-mono transition-colors"
          >
            🟢 Clean Windows DLL
          </button>
        </div>
      </div>

      {/* Main Grid: Input / Upload (5 cols) & Results (7 cols) */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
        {/* Left Column: Input Form & File Dropzone (5 cols) */}
        <div className="lg:col-span-5 space-y-4">
          <div className="command-card p-4 space-y-4">
            <h3 className="text-xs font-bold font-mono uppercase tracking-wider text-white">
              Target Binary or Cryptographic Hash
            </h3>

            {/* Direct Binary File Upload Option */}
            <div
              onClick={() => fileInputRef.current?.click()}
              className="border border-dashed border-[#1E2B42] hover:border-amber-500/50 hover:bg-[#111A2E] rounded-lg p-4 text-center cursor-pointer transition-all"
            >
              <UploadCloud className="w-6 h-6 text-amber-400 mx-auto mb-1.5" />
              <div className="text-xs font-sans text-slate-200 font-semibold">
                Drop binary payload or click to select
              </div>
              <div className="text-[10px] font-mono text-slate-400 mt-0.5">
                Calculates real SHA-256, Shannon entropy & magic bytes
              </div>
              <input
                ref={fileInputRef}
                type="file"
                onChange={(e) => {
                  if (e.target.files && e.target.files[0]) {
                    handleFileUpload(e.target.files[0]);
                  }
                }}
                className="hidden"
              />
            </div>

            <div className="flex items-center gap-2">
              <div className="flex-1 border-t border-[#1C273C]" />
              <span className="text-[10px] font-mono text-slate-500 uppercase">OR PASTE HASH</span>
              <div className="flex-1 border-t border-[#1C273C]" />
            </div>

            <form onSubmit={handleSubmit} className="space-y-3">
              <div className="space-y-1">
                <label className="text-[11px] font-mono text-slate-400 uppercase">
                  Hash Value (MD5, SHA-1, or SHA-256)
                </label>
                <input
                  type="text"
                  value={hashInput}
                  onChange={(e) => setHashInput(e.target.value)}
                  placeholder="e.g. 44d88612fea8a8f36de82e1278abb02f"
                  className="w-full h-8 px-3 bg-[#111827] border border-[#1C273C] rounded text-xs text-slate-200 placeholder-slate-500 focus:border-amber-500 font-mono"
                />
              </div>

              <div className="space-y-1">
                <label className="text-[11px] font-mono text-slate-400 uppercase">
                  Optional Payload Filename
                </label>
                <input
                  type="text"
                  value={fileNameInput}
                  onChange={(e) => setFileNameInput(e.target.value)}
                  placeholder="e.g. payload.exe, invoice.pdf"
                  className="w-full h-8 px-3 bg-[#111827] border border-[#1C273C] rounded text-xs text-slate-200 placeholder-slate-500 focus:border-amber-500 font-mono"
                />
              </div>

              {error && (
                <div className="p-2.5 rounded bg-red-500/15 border border-red-500/40 text-red-300 text-xs font-mono flex items-center gap-2">
                  <AlertTriangle className="w-4 h-4 shrink-0 text-red-400" />
                  <span>{error}</span>
                </div>
              )}

              <button
                type="submit"
                disabled={(!hashInput.trim() && !selectedFile) || loading}
                className="w-full py-2 px-4 rounded-md bg-amber-600 hover:bg-amber-500 text-slate-950 font-bold font-sans text-xs uppercase tracking-wider transition-all shadow-[0_0_12px_rgba(245,158,11,0.25)] flex items-center justify-center gap-2 cursor-pointer disabled:opacity-40 disabled:cursor-not-allowed"
              >
                {loading ? (
                  <>
                    <RefreshCw className="w-4 h-4 animate-spin" />
                    <span>Analyzing Payload...</span>
                  </>
                ) : (
                  <>
                    <Zap className="w-4 h-4" />
                    <span>Execute Forensics</span>
                  </>
                )}
              </button>
            </form>
          </div>
        </div>

        {/* Right Column: Forensic Results (7 cols) */}
        <div className="lg:col-span-7 space-y-4">
          {!currentResult ? (
            <div className="command-card p-8 flex flex-col items-center justify-center text-center space-y-3 min-h-[360px]">
              <div className="w-14 h-14 rounded-full bg-amber-500/10 border border-amber-500/30 flex items-center justify-center text-amber-400">
                <Binary className="w-7 h-7" />
              </div>
              <h4 className="text-sm font-bold font-sans text-white">
                No Binary Forensics Executed Yet
              </h4>
              <p className="text-xs text-slate-400 max-w-md font-sans">
                Paste a hash or upload a binary file on the left to compute Shannon entropy, match YARA rules, and view classification metrics.
              </p>
            </div>
          ) : (
            <div className="space-y-4">
              {/* Verdict Summary Card */}
              <div className="command-card p-4 space-y-3 border-amber-500/30">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-[#1C273C] pb-3">
                  <div>
                    <div className="flex items-center gap-2">
                      <span className="text-xs font-mono text-slate-400 uppercase">Hash:</span>
                      <span className="font-mono text-xs font-bold text-amber-400 truncate max-w-xs" title={currentResult.hash}>
                        {currentResult.hash}
                      </span>
                    </div>
                    {currentResult.fileName && (
                      <span className="text-[11px] font-mono text-slate-300 block">
                        Filename: {currentResult.fileName}
                      </span>
                    )}
                  </div>

                  <StatusBadge 
                    status={currentResult.malwareClassification} 
                    severity={currentResult.malwareClassification === 'malicious' ? 'critical' : (currentResult.malwareClassification === 'suspicious' ? 'high' : 'low')}
                    size="md"
                  />
                </div>

                {/* Key Metrics Grid */}
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 font-mono text-[10px]">
                  <div className="bg-[#111827] border border-[#1C273C] p-2 rounded">
                    <span className="text-slate-400 block">Shannon Entropy</span>
                    <span className={`font-bold text-xs ${currentResult.entropyScore > 7.0 ? 'text-red-400' : 'text-emerald-400'}`}>
                      {currentResult.entropyScore} / 8.0
                    </span>
                  </div>
                  <div className="bg-[#111827] border border-[#1C273C] p-2 rounded">
                    <span className="text-slate-400 block">Packing Status</span>
                    <span className={`font-bold text-xs ${currentResult.isPackedOrEncrypted ? 'text-red-400' : 'text-emerald-400'}`}>
                      {currentResult.isPackedOrEncrypted ? 'PACKED/ENCRYPTED' : 'UNPACKED'}
                    </span>
                  </div>
                  <div className="bg-[#111827] border border-[#1C273C] p-2 rounded">
                    <span className="text-slate-400 block">Format Detected</span>
                    <span className="font-bold text-xs text-cyan-400">
                      {currentResult.detectedFormat}
                    </span>
                  </div>
                  <div className="bg-[#111827] border border-[#1C273C] p-2 rounded">
                    <span className="text-slate-400 block">Magic Bytes</span>
                    <span className="font-bold text-xs text-purple-300">
                      {currentResult.magicBytes || 'N/A'}
                    </span>
                  </div>
                </div>

                {/* Recommendation */}
                <div className="p-2.5 rounded bg-[#101726] border border-[#1C273C] text-xs font-sans text-slate-300">
                  <strong className="text-amber-400 block font-mono text-[10px] uppercase mb-0.5">Analyst Recommendation:</strong>
                  {currentResult.recommendation}
                </div>
              </div>

              {/* Matched YARA Rules */}
              {currentResult.matchedYaraRules && currentResult.matchedYaraRules.length > 0 && (
                <div className="command-card p-4 space-y-2">
                  <h4 className="text-xs font-bold font-mono uppercase tracking-wider text-red-400 flex items-center gap-1.5">
                    <AlertTriangle className="w-3.5 h-3.5" />
                    <span>Matched YARA Signatures</span>
                  </h4>
                  <div className="flex flex-wrap gap-1.5">
                    {currentResult.matchedYaraRules.map((rule, idx) => (
                      <span key={idx} className="px-2 py-0.5 rounded bg-red-500/15 border border-red-500/30 text-red-300 font-mono text-[10px] font-bold">
                        {rule}
                      </span>
                    ))}
                  </div>
                </div>
              )}

              {/* Threat Indicators */}
              {currentResult.threatIndicators && currentResult.threatIndicators.length > 0 && (
                <div className="command-card p-4 space-y-2">
                  <h4 className="text-xs font-bold font-mono uppercase tracking-wider text-slate-200">
                    Observed Threat Indicators
                  </h4>
                  <ul className="space-y-1 text-xs font-sans text-slate-300">
                    {currentResult.threatIndicators.map((ind, idx) => (
                      <li key={idx} className="flex items-center gap-2">
                        <span className="text-amber-400 font-bold">•</span>
                        <span>{ind}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              )}

              {/* Transparent Score Breakdown */}
              {currentResult.scoreBreakdown && currentResult.scoreBreakdown.length > 0 && (
                <div className="command-card p-4 space-y-2">
                  <h4 className="text-xs font-bold font-mono uppercase tracking-wider text-white">
                    Transparent Scoring Rubric
                  </h4>
                  <div className="space-y-1 font-mono text-[11px]">
                    {currentResult.scoreBreakdown.map((sb, idx) => (
                      <div key={idx} className="flex items-center justify-between p-1.5 rounded bg-[#111827] border border-[#1C273C]">
                        <span className="text-slate-300">{sb.rule}</span>
                        <span className="text-amber-400 font-bold">+{sb.points} pts</span>
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
