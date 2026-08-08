import React, { useState, useEffect } from 'react';
import { AlertTriangle, TrendingUp, RefreshCw, ShieldAlert, Bot, ChevronDown, ChevronUp, Globe, Activity, CheckCircle2, ShieldCheck } from 'lucide-react';
import { motion } from 'motion/react';
import { ThreatIntelligenceReport, ThreatIntelligenceAlert, PhishingTactic } from '../types';

import { safeJsonResponse } from '../lib/api';

interface ThreatIntelligenceProps {
  token: string;
}

export default function ThreatIntelligence({ token }: ThreatIntelligenceProps) {
  const [report, setReport] = useState<ThreatIntelligenceReport | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<'alerts' | 'tactics'>('alerts');
  const [expandedId, setExpandedId] = useState<string | null>(null);

  const fetchThreatIntelligence = async () => {
    setLoading(true);
    setError(null);
    try {
      const response = await fetch('/api/ai/threat-intelligence', {
        headers: {
          'Authorization': `Bearer ${token}`
        }
      });
      const data: ThreatIntelligenceReport = await safeJsonResponse(response, 'Failed to fetch threat intelligence');
      setReport(data);
    } catch (err: any) {
      console.error('Failed to load threat intelligence:', err);
      setError('Could not retrieve threat feeds. Click refresh to retry.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (token) {
      fetchThreatIntelligence();
    }
  }, [token]);

  const toggleExpand = (id: string) => {
    setExpandedId(expandedId === id ? null : id);
  };

  const getSeverityBadgeClass = (severity: string) => {
    switch (severity.toLowerCase()) {
      case 'critical':
        return 'text-rose-400 bg-rose-500/10 border-rose-500/20';
      case 'high':
        return 'text-amber-400 bg-amber-500/10 border-amber-500/20';
      case 'medium':
        return 'text-cyan-400 bg-cyan-500/10 border-cyan-500/20';
      default:
        return 'text-slate-400 bg-slate-500/10 border-slate-500/20';
    }
  };

  const getTrendBadgeClass = (trend: string) => {
    switch (trend.toLowerCase()) {
      case 'surging':
        return 'text-rose-400 bg-rose-500/10 border-rose-500/20';
      case 'stable':
        return 'text-cyan-400 bg-cyan-500/10 border-cyan-500/20';
      default:
        return 'text-slate-400 bg-slate-500/10 border-slate-500/20';
    }
  };

  return (
    <div className="bento-card p-5 space-y-4">
      {/* Header section with Refresh */}
      <div className="flex items-start justify-between border-b border-slate-800 pb-3">
        <div>
          <div className="flex items-center gap-1.5 text-cyan-400 font-mono text-[10px] font-bold tracking-wider">
            <Globe className="w-3.5 h-3.5 text-cyan-400 animate-pulse" />
            <span>GLOBAL THREAT RADAR</span>
            <span className="bg-cyan-500/15 text-[8px] text-cyan-300 px-1.5 py-0.5 rounded flex items-center gap-1 font-sans">
              <Bot className="w-2.5 h-2.5 text-cyan-400" />
              CyberGuard Core
            </span>
          </div>
          <h3 className="font-bold text-sm text-white font-display mt-1">AI Threat Intelligence</h3>
          <p className="text-[10px] text-slate-500 mt-0.5">Real-time global cybersecurity alerts & trending exploits.</p>
        </div>
        <button
          onClick={fetchThreatIntelligence}
          disabled={loading}
          className="text-slate-500 hover:text-cyan-400 transition-colors p-1.5 rounded-lg bg-slate-950/40 border border-slate-800 hover:border-cyan-500/20 disabled:opacity-50 cursor-pointer"
          title="Refresh threat intelligence"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin text-cyan-400' : ''}`} />
        </button>
      </div>

      {/* Tab Selectors */}
      <div className="grid grid-cols-2 gap-1 bg-slate-950/40 p-1 rounded-xl border border-slate-900 text-[10px] font-mono font-bold">
        <button
          onClick={() => { setActiveTab('alerts'); setExpandedId(null); }}
          className={`py-1.5 rounded-lg transition-all cursor-pointer ${activeTab === 'alerts' ? 'bg-cyan-500/10 text-cyan-400 border border-cyan-500/15' : 'text-slate-500 hover:text-slate-300 border border-transparent'}`}
        >
          ACTIVE ALERTS ({report?.alerts?.length || 0})
        </button>
        <button
          onClick={() => { setActiveTab('tactics'); setExpandedId(null); }}
          className={`py-1.5 rounded-lg transition-all cursor-pointer ${activeTab === 'tactics' ? 'bg-cyan-500/10 text-cyan-400 border border-cyan-500/15' : 'text-slate-500 hover:text-slate-300 border border-transparent'}`}
        >
          TRENDING EXPLOITS ({report?.phishingTactics?.length || 0})
        </button>
      </div>

      {/* Core Feed Container */}
      <div className="min-h-[220px] max-h-[350px] overflow-y-auto pr-1 space-y-3 scrollbar-thin">
        {loading ? (
          <div className="h-[220px] flex flex-col items-center justify-center space-y-3">
            <div className="relative w-8 h-8">
              <div className="absolute inset-0 rounded-full border-2 border-cyan-500/10"></div>
              <div className="absolute inset-0 rounded-full border-2 border-t-cyan-400 animate-spin"></div>
            </div>
            <div className="text-center">
              <span className="text-[10px] font-mono text-cyan-400/80 animate-pulse block uppercase tracking-wider">Syncing Neural Feeds...</span>
              <span className="text-[8px] text-slate-600 font-mono">Grounded query in progress</span>
            </div>
          </div>
        ) : error ? (
          <div className="h-[220px] flex flex-col items-center justify-center p-4 text-center space-y-2">
            <AlertTriangle className="w-8 h-8 text-rose-500/80" />
            <p className="text-[11px] text-slate-400">{error}</p>
            <button
              onClick={fetchThreatIntelligence}
              className="bg-cyan-500/10 hover:bg-cyan-500/20 text-cyan-400 border border-cyan-500/25 px-3 py-1.5 rounded-xl font-mono text-[10px] font-bold cursor-pointer transition-colors"
            >
              Force Retry Sync
            </button>
          </div>
        ) : activeTab === 'alerts' ? (
          /* ACTIVE ALERTS FEED */
          report?.alerts && report.alerts.length > 0 ? (
            report.alerts.map((alert, index) => {
              const isExpanded = expandedId === alert.id;
              return (
                <motion.div 
                  key={alert.id}
                  initial={{ opacity: 0, y: 12 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ duration: 0.35, ease: "easeOut", delay: index * 0.06 }}
                  className={`bg-slate-950/45 border rounded-2xl p-3.5 transition-all space-y-2.5 ${isExpanded ? 'border-cyan-500/25 bg-slate-950/70' : 'border-slate-850 hover:border-slate-800'}`}
                >
                  <div 
                    onClick={() => toggleExpand(alert.id)}
                    className="flex items-start justify-between gap-2.5 cursor-pointer select-none"
                  >
                    <div className="space-y-1.5">
                      <div className="flex flex-wrap items-center gap-1.5">
                        <span className={`px-1.5 py-0.5 rounded text-[8px] uppercase tracking-wider font-mono font-bold border ${getSeverityBadgeClass(alert.severity)}`}>
                          {alert.severity}
                        </span>
                        <span className="text-[9px] text-slate-500 font-mono font-medium">{alert.category}</span>
                      </div>
                      <h4 className="text-xs font-bold text-white leading-snug">{alert.title}</h4>
                    </div>
                    <span className="text-slate-500 hover:text-slate-300 p-0.5 shrink-0">
                      {isExpanded ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
                    </span>
                  </div>

                  {isExpanded && (
                    <div className="pt-2 border-t border-slate-900/60 text-[11px] leading-relaxed text-slate-400 space-y-2.5 animate-slide-down">
                      <p>{alert.description}</p>
                      
                      <div className="grid grid-cols-1 gap-2 bg-slate-900/55 p-2 rounded-xl border border-slate-950">
                        <div>
                          <strong className="text-slate-300 text-[10px] block font-mono uppercase tracking-wider">💥 Potential Impact</strong>
                          <span className="text-slate-400 text-[10px]">{alert.impact}</span>
                        </div>
                        <div className="pt-1.5 border-t border-slate-850/40">
                          <strong className="text-cyan-400 text-[10px] block font-mono uppercase tracking-wider">🛠️ Recommended Action</strong>
                          <span className="text-slate-300 text-[10px] font-medium">{alert.remediation}</span>
                        </div>
                      </div>

                      <div className="flex items-center gap-1 text-[9px] text-slate-500 font-mono">
                        <Activity className="w-3 h-3 text-cyan-500" />
                        <span>Status: {alert.timestamp}</span>
                      </div>
                    </div>
                  )}
                </motion.div>
              );
            })
          ) : (
            <div className="h-[220px] flex items-center justify-center text-slate-500 text-[11px] font-mono">No active global alerts.</div>
          )
        ) : (
          /* PHISHING TACTICS FEED */
          report?.phishingTactics && report.phishingTactics.length > 0 ? (
            report.phishingTactics.map((tactic, index) => {
              const isExpanded = expandedId === tactic.id;
              return (
                <motion.div 
                  key={tactic.id}
                  initial={{ opacity: 0, y: 12 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ duration: 0.35, ease: "easeOut", delay: index * 0.06 }}
                  className={`bg-slate-950/45 border rounded-2xl p-3.5 transition-all space-y-2.5 ${isExpanded ? 'border-cyan-500/25 bg-slate-950/70' : 'border-slate-850 hover:border-slate-800'}`}
                >
                  <div 
                    onClick={() => toggleExpand(tactic.id)}
                    className="flex items-start justify-between gap-2.5 cursor-pointer select-none"
                  >
                    <div className="space-y-1.5">
                      <div className="flex flex-wrap items-center gap-1.5">
                        <span className={`px-1.5 py-0.5 rounded text-[8px] uppercase tracking-wider font-mono font-bold border ${getTrendBadgeClass(tactic.trendLevel)}`}>
                          {tactic.trendLevel} Trend
                        </span>
                        <span className="text-[9px] text-slate-500 font-mono font-medium">Targets: {tactic.targetAudience}</span>
                      </div>
                      <h4 className="text-xs font-bold text-white leading-snug">{tactic.name}</h4>
                    </div>
                    <span className="text-slate-500 hover:text-slate-300 p-0.5 shrink-0">
                      {isExpanded ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
                    </span>
                  </div>

                  {isExpanded && (
                    <div className="pt-2 border-t border-slate-900/60 text-[11px] leading-relaxed text-slate-400 space-y-2.5 animate-slide-down">
                      <p>{tactic.description}</p>
                      
                      <div className="space-y-2 bg-slate-900/55 p-2.5 rounded-xl border border-slate-950">
                        <div>
                          <strong className="text-rose-400 text-[10px] block font-mono uppercase tracking-wider">⚠️ Critical Red Flags</strong>
                          <ul className="list-disc pl-4 space-y-0.5 text-slate-400 text-[10px] mt-1">
                            {tactic.redFlags.map((flag, index) => (
                              <li key={index}>{flag}</li>
                            ))}
                          </ul>
                        </div>
                        <div className="pt-2 border-t border-slate-850/40">
                          <strong className="text-emerald-400 text-[10px] block font-mono uppercase tracking-wider">🛡️ Defensive Strategy</strong>
                          <span className="text-slate-300 text-[10px] mt-1 block">{tactic.prevention}</span>
                        </div>
                      </div>
                    </div>
                  )}
                </motion.div>
              );
            })
          ) : (
            <div className="h-[220px] flex items-center justify-center text-slate-500 text-[11px] font-mono">No phishing metrics found.</div>
          )
        )}
      </div>

      {/* Footer / Status */}
      {report?.lastUpdated && !loading && (
        <div className="border-t border-slate-900/60 pt-2 flex items-center justify-between text-[8px] font-mono text-slate-500">
          <div className="flex items-center gap-1">
            <ShieldCheck className="w-3 h-3 text-emerald-500" />
            <span>Feed Secured</span>
          </div>
          <span>Updated: {new Date(report.lastUpdated).toLocaleTimeString()}</span>
        </div>
      )}
    </div>
  );
}
