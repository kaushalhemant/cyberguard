import React, { useState } from 'react';
import { 
  Globe, Search, MapPin, Server, ShieldCheck, AlertTriangle, 
  RefreshCw, Lock, Terminal as TerminalIcon
} from 'lucide-react';
import { OsintResult } from '../../types';
import StatusBadge from '../common/StatusBadge';

interface OsintAnalysisViewProps {
  token: string;
  onAnalyzeOsint: (target: string) => Promise<OsintResult | null>;
  currentResult: OsintResult | null;
  loading: boolean;
  error: string | null;
}

export default function OsintAnalysisView({
  token,
  onAnalyzeOsint,
  currentResult,
  loading,
  error
}: OsintAnalysisViewProps) {
  const [targetInput, setTargetInput] = useState('');

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!targetInput.trim()) return;
    await onAnalyzeOsint(targetInput.trim());
  };

  const handleSample = async (sampleTarget: string) => {
    setTargetInput(sampleTarget);
    await onAnalyzeOsint(sampleTarget);
  };

  return (
    <div className="space-y-4">
      {/* Header Banner */}
      <div className="command-card p-4 sm:p-5 flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <div className="w-8 h-8 rounded bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center text-cyan-400">
              <Globe className="w-4 h-4" />
            </div>
            <h2 className="text-base font-bold font-display uppercase tracking-wider text-white">
              OSINT IP & Autonomous System Reconnaissance
            </h2>
            <span className="px-1.5 py-0.5 rounded text-[9px] font-mono font-bold bg-cyan-500/20 text-cyan-300 border border-cyan-500/40">
              NETWORK TOPOLOGY RADAR
            </span>
          </div>
          <p className="text-xs text-slate-400 font-sans mt-1 max-w-3xl">
            Autonomous IP address and domain asset reconnaissance: GeoIP telemetry, Autonomous System Number (ASN), DNS records, SSL/TLS certificates, and open port risk auditing.
          </p>
        </div>

        {/* 1-Click Samples */}
        <div className="flex flex-wrap items-center gap-2">
          <span className="text-[10px] font-mono text-slate-400 uppercase">Presets:</span>
          <button
            onClick={() => handleSample('185.220.101.5')}
            className="px-2 py-1 rounded bg-[#131C2E] hover:bg-[#1A263D] border border-red-500/30 text-red-300 text-[10px] font-mono transition-colors"
          >
            🚨 TOR Exit Node (185.220.101.5)
          </button>
          <button
            onClick={() => handleSample('1.1.1.1')}
            className="px-2 py-1 rounded bg-[#131C2E] hover:bg-[#1A263D] border border-emerald-500/30 text-emerald-300 text-[10px] font-mono transition-colors"
          >
            🟢 Cloudflare DNS (1.1.1.1)
          </button>
          <button
            onClick={() => handleSample('cloudflare.com')}
            className="px-2 py-1 rounded bg-[#131C2E] hover:bg-[#1A263D] border border-blue-500/30 text-blue-300 text-[10px] font-mono transition-colors"
          >
            🌐 Enterprise Host (cloudflare.com)
          </button>
        </div>
      </div>

      {/* Main Grid: Input Form (5 cols) & Results (7 cols) */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
        {/* Left Column: Target Input (5 cols) */}
        <div className="lg:col-span-5 space-y-4">
          <div className="command-card p-4 space-y-4">
            <h3 className="text-xs font-bold font-mono uppercase tracking-wider text-white">
              Target IP Address or Hostname
            </h3>

            <form onSubmit={handleSubmit} className="space-y-3">
              <div className="space-y-1">
                <label className="text-[11px] font-mono text-slate-400 uppercase">
                  IPv4 / IPv6 or FQDN
                </label>
                <div className="relative">
                  <Server className="w-4 h-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
                  <input
                    type="text"
                    value={targetInput}
                    onChange={(e) => setTargetInput(e.target.value)}
                    placeholder="e.g. 185.220.101.5 or domain.com"
                    className="w-full h-9 pl-9 pr-3 bg-[#111827] border border-[#1C273C] rounded text-xs text-slate-200 placeholder-slate-500 focus:border-cyan-500 font-mono"
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
                disabled={!targetInput.trim() || loading}
                className="w-full py-2.5 px-4 rounded-md bg-cyan-600 hover:bg-cyan-500 text-slate-950 font-bold font-sans text-xs uppercase tracking-wider transition-all shadow-[0_0_12px_rgba(6,182,212,0.3)] flex items-center justify-center gap-2 cursor-pointer disabled:opacity-40 disabled:cursor-not-allowed"
              >
                {loading ? (
                  <>
                    <RefreshCw className="w-4 h-4 animate-spin text-slate-950" />
                    <span>Resolving ASN, DNS & GeoIP...</span>
                  </>
                ) : (
                  <>
                    <Search className="w-4 h-4 text-slate-950" />
                    <span>Inspect Target Asset</span>
                  </>
                )}
              </button>
            </form>
          </div>
        </div>

        {/* Right Column: Recon Results (7 cols) */}
        <div className="lg:col-span-7 space-y-4">
          {!currentResult ? (
            <div className="command-card p-8 flex flex-col items-center justify-center text-center space-y-3 min-h-[360px]">
              <div className="w-14 h-14 rounded-full bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center text-cyan-400">
                <Globe className="w-7 h-7" />
              </div>
              <h4 className="text-sm font-bold font-sans text-white">
                No OSINT Reconnaissance Executed
              </h4>
              <p className="text-xs text-slate-400 max-w-md font-sans">
                Provide an IP address or domain to resolve geographic location, ASN provider, open port risk, and certificate parameters.
              </p>
            </div>
          ) : (
            <div className="space-y-4">
              {/* Verdict Summary Card */}
              <div className="command-card p-4 space-y-3 border-cyan-500/30">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-[#1C273C] pb-3">
                  <div>
                    <div className="flex items-center gap-2">
                      <span className="text-xs font-mono text-slate-400 uppercase">Target:</span>
                      <span className="font-mono text-xs font-bold text-white truncate max-w-xs" title={currentResult.target}>
                        {currentResult.target}
                      </span>
                    </div>
                    <span className="text-[10px] font-mono text-slate-400">
                      Resolved IP: {currentResult.resolvedIp} • {currentResult.hostname}
                    </span>
                  </div>

                  <StatusBadge 
                    severity={currentResult.reputationScore >= 70 ? 'critical' : (currentResult.reputationScore >= 30 ? 'high' : 'low')} 
                    label={currentResult.reputationScore >= 70 ? 'HIGH RISK ASSET' : (currentResult.reputationScore >= 30 ? 'SUSPICIOUS RECON' : 'CLEAN HOST')}
                    size="md"
                  />
                </div>

                {/* GeoIP & ASN Grid */}
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 font-mono text-[10px]">
                  <div className="bg-[#111827] border border-[#1C273C] p-2 rounded">
                    <span className="text-slate-400 block">Location</span>
                    <span className="font-bold text-xs text-white">
                      {currentResult.location.country} {currentResult.location.flag}
                    </span>
                  </div>
                  <div className="bg-[#111827] border border-[#1C273C] p-2 rounded">
                    <span className="text-slate-400 block">City</span>
                    <span className="font-bold text-xs text-cyan-300">
                      {currentResult.location.city || 'Undisclosed'}
                    </span>
                  </div>
                  <div className="bg-[#111827] border border-[#1C273C] p-2 rounded">
                    <span className="text-slate-400 block">Autonomous System</span>
                    <span className="font-bold text-xs text-purple-300 truncate block" title={currentResult.location.asn}>
                      {currentResult.location.asn}
                    </span>
                  </div>
                  <div className="bg-[#111827] border border-[#1C273C] p-2 rounded">
                    <span className="text-slate-400 block">ISP Provider</span>
                    <span className="font-bold text-xs text-slate-200 truncate block" title={currentResult.location.isp}>
                      {currentResult.location.isp}
                    </span>
                  </div>
                </div>

                {/* Score Bar */}
                <div className="space-y-1 pt-1">
                  <div className="flex justify-between items-center text-xs font-mono">
                    <span className="text-slate-300">Reputation Index:</span>
                    <span className={`font-bold ${currentResult.reputationScore >= 50 ? 'text-red-400' : 'text-emerald-400'}`}>
                      {currentResult.reputationScore} / 100
                    </span>
                  </div>
                  <div className="w-full h-2 bg-[#090D14] border border-[#1C273C] rounded-full overflow-hidden flex">
                    <div 
                      className={`h-full ${currentResult.reputationScore >= 50 ? 'bg-red-500' : 'bg-emerald-500'}`} 
                      style={{ width: `${Math.max(currentResult.reputationScore, 5)}%` }} 
                    />
                  </div>
                </div>
              </div>

              {/* Open Ports & Services Audit */}
              {currentResult.openPorts && currentResult.openPorts.length > 0 && (
                <div className="command-card p-4 space-y-2">
                  <h4 className="text-xs font-bold font-mono uppercase tracking-wider text-white">
                    Audited Port Services
                  </h4>
                  <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 font-mono text-[10px]">
                    {currentResult.openPorts.map((p, idx) => (
                      <div key={idx} className="bg-[#111827] border border-[#1C273C] p-2 rounded flex justify-between items-center">
                        <div>
                          <span className="font-bold text-slate-200 block">PORT {p.port}</span>
                          <span className="text-slate-400">{p.service}</span>
                        </div>
                        <StatusBadge severity={p.risk} />
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* DNS Records */}
              {currentResult.dnsRecords && currentResult.dnsRecords.length > 0 && (
                <div className="command-card p-4 space-y-2">
                  <h4 className="text-xs font-bold font-mono uppercase tracking-wider text-white">
                    DNS Asset Resolution
                  </h4>
                  <div className="space-y-1 font-mono text-[11px]">
                    {currentResult.dnsRecords.map((dns, idx) => (
                      <div key={idx} className="flex items-center justify-between p-2 rounded bg-[#111827] border border-[#1C273C]">
                        <span className="text-cyan-400 font-bold">{dns.type}</span>
                        <span className="text-slate-300 truncate max-w-sm">{dns.value}</span>
                        <StatusBadge status={dns.status} />
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
