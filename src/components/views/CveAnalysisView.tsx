import React, { useState } from 'react';
import { 
  Database, Search, Filter, AlertTriangle, ShieldCheck, 
  ExternalLink, ArrowUpRight, RefreshCw
} from 'lucide-react';
import { CveRecord } from '../../types';
import StatusBadge from '../common/StatusBadge';

interface CveAnalysisViewProps {
  token: string;
  onSearchCves: (query: string, severity?: string) => Promise<{ totalMatches: number; cves: CveRecord[] } | null>;
  currentResults: { totalMatches: number; cves: CveRecord[] } | null;
  loading: boolean;
}

export default function CveAnalysisView({
  token,
  onSearchCves,
  currentResults,
  loading
}: CveAnalysisViewProps) {
  const [query, setQuery] = useState('');
  const [severityFilter, setSeverityFilter] = useState('ALL');

  const handleSearch = async (e: React.FormEvent) => {
    e.preventDefault();
    await onSearchCves(query.trim(), severityFilter);
  };

  const handleQuickPreset = async (cveId: string) => {
    setQuery(cveId);
    await onSearchCves(cveId, 'ALL');
  };

  return (
    <div className="space-y-4">
      {/* Header Banner */}
      <div className="command-card p-4 sm:p-5 flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <div className="w-8 h-8 rounded bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center text-cyan-400">
              <Database className="w-4 h-4" />
            </div>
            <h2 className="text-base font-bold font-display uppercase tracking-wider text-white">
              NIST NVD CVE Vulnerability Intelligence
            </h2>
            <span className="px-1.5 py-0.5 rounded text-[9px] font-mono font-bold bg-cyan-500/20 text-cyan-300 border border-cyan-500/40">
              100,000+ INDEXED ADVISORIES
            </span>
          </div>
          <p className="text-xs text-slate-400 font-sans mt-1 max-w-3xl">
            Correlate Common Vulnerabilities and Exposures (CVE) directly with the National Vulnerability Database (NVD v2.0 feed), CVSS v3.1 severity scores, and CVSS vector metrics.
          </p>
        </div>

        {/* 1-Click Presets */}
        <div className="flex flex-wrap items-center gap-2">
          <span className="text-[10px] font-mono text-slate-400 uppercase">Presets:</span>
          <button
            onClick={() => handleQuickPreset('CVE-2023-4966')}
            className="px-2 py-1 rounded bg-[#131C2E] hover:bg-[#1A263D] border border-red-500/30 text-red-300 text-[10px] font-mono transition-colors"
          >
            🚨 CVE-2023-4966 (Citrix)
          </button>
          <button
            onClick={() => handleQuickPreset('CVE-2021-44228')}
            className="px-2 py-1 rounded bg-[#131C2E] hover:bg-[#1A263D] border border-red-500/30 text-red-300 text-[10px] font-mono transition-colors"
          >
            🚨 CVE-2021-44228 (Log4j)
          </button>
          <button
            onClick={() => handleQuickPreset('CVE-2024-3094')}
            className="px-2 py-1 rounded bg-[#131C2E] hover:bg-[#1A263D] border border-amber-500/30 text-amber-300 text-[10px] font-mono transition-colors"
          >
            ⚠️ CVE-2024-3094 (XZ Utils)
          </button>
        </div>
      </div>

      {/* Search & Filter Bar */}
      <div className="command-card p-4">
        <form onSubmit={handleSearch} className="flex flex-col sm:flex-row items-center gap-3">
          <div className="relative flex-1 w-full">
            <Search className="w-4 h-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="Search by CVE ID, software, or keyword (e.g. Citrix, OpenSSL, Windows)..."
              className="w-full h-9 pl-9 pr-3 bg-[#111827] border border-[#1C273C] rounded text-xs text-slate-200 placeholder-slate-500 focus:border-cyan-500 font-mono"
            />
          </div>

          <div className="flex items-center gap-2 w-full sm:w-auto">
            <select
              value={severityFilter}
              onChange={(e) => setSeverityFilter(e.target.value)}
              className="h-9 px-3 bg-[#111827] border border-[#1C273C] rounded text-xs text-slate-300 focus:border-cyan-500 cursor-pointer w-full sm:w-auto"
            >
              <option value="ALL">All Severities</option>
              <option value="CRITICAL">Critical Only (9.0 - 10.0)</option>
              <option value="HIGH">High Only (7.0 - 8.9)</option>
              <option value="MEDIUM">Medium Only (4.0 - 6.9)</option>
            </select>

            <button
              type="submit"
              disabled={loading}
              className="h-9 px-4 rounded bg-cyan-600 hover:bg-cyan-500 text-slate-950 font-bold font-sans text-xs uppercase tracking-wider transition-all flex items-center gap-2 shrink-0 cursor-pointer disabled:opacity-40"
            >
              {loading ? (
                <>
                  <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                  <span>Searching...</span>
                </>
              ) : (
                <>
                  <Search className="w-3.5 h-3.5" />
                  <span>Search Feed</span>
                </>
              )}
            </button>
          </div>
        </form>
      </div>

      {/* CVE Records Grid */}
      <div className="space-y-3">
        {currentResults && (
          <div className="flex items-center justify-between text-xs font-mono text-slate-400 px-1">
            <span>
              Found <strong className="text-white">{currentResults.totalMatches}</strong> matching vulnerabilities
            </span>
            <span>NIST NVD JSON v2.0 Sync</span>
          </div>
        )}

        <div className="grid grid-cols-1 md:grid-cols-2 gap-3.5">
          {(!currentResults || currentResults.cves.length === 0) ? (
            <div className="col-span-full command-card p-8 text-center text-slate-400 font-mono text-xs">
              No CVE vulnerabilities match the current query filter.
            </div>
          ) : (
            currentResults.cves.map((cve) => (
              <div
                key={cve.id}
                className="command-card p-4 space-y-2.5 hover:border-cyan-500/40 transition-all flex flex-col justify-between"
              >
                <div className="space-y-1.5">
                  <div className="flex items-start justify-between gap-2">
                    <span className="font-mono text-xs font-bold text-cyan-400">
                      {cve.id}
                    </span>
                    <div className="flex items-center gap-1.5">
                      <StatusBadge severity={cve.severity} />
                      <span className="font-mono text-xs font-bold text-white bg-[#101726] px-1.5 py-0.5 rounded border border-[#1C273C]">
                        {cve.score}
                      </span>
                    </div>
                  </div>

                  <p className="text-xs font-sans text-slate-300 line-clamp-3">
                    {cve.description}
                  </p>
                </div>

                <div className="pt-2 border-t border-[#1C273C] flex items-center justify-between font-mono text-[10px] text-slate-400">
                  <span>Modified: {new Date(cve.lastModified).toLocaleDateString()}</span>
                  <a
                    href={`https://nvd.nist.gov/vuln/detail/${cve.id}`}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-cyan-400 hover:text-cyan-300 flex items-center gap-1"
                  >
                    <span>NVD Detail</span>
                    <ExternalLink className="w-3 h-3" />
                  </a>
                </div>
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  );
}
