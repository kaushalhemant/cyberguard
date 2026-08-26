import React, { useState, useEffect } from 'react';
import { AlertTriangle, RefreshCw, ChevronDown, ChevronUp, Globe, Activity, ShieldCheck } from 'lucide-react';
import { ThreatIntelligenceReport } from '../types';
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
      const response = await fetch('/api/threat-intelligence', {
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
        return 'status-chip-critical';
      case 'high':
        return 'status-chip-high';
      case 'medium':
        return 'status-chip-medium';
      default:
        return 'status-chip-low';
    }
  };

  return (
    <div className="soc-panel p-4 space-y-3 font-sans">
      {/* Header section with Refresh */}
      <div className="flex items-start justify-between border-b border-[#263147] pb-2">
        <div>
          <div className="flex items-center gap-1.5 text-[#00E5FF] font-mono text-[10px] font-bold tracking-wider">
            <Globe className="w-3.5 h-3.5 text-[#00E5FF]" />
            <span>GLOBAL THREAT RADAR</span>
          </div>
          <h3 className="font-bold text-xs uppercase font-display text-white mt-0.5">Threat Intelligence Feed</h3>
        </div>
        <button
          onClick={fetchThreatIntelligence}
          disabled={loading}
          className="btn-soc p-1.5 text-[10px]"
          title="Refresh threat intelligence"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin text-[#00E5FF]' : ''}`} />
        </button>
      </div>

      {/* Tab Selectors */}
      <div className="grid grid-cols-2 gap-1 bg-[#090D14] p-1 border border-[#263147] text-[10px] font-mono font-bold">
        <button
          onClick={() => { setActiveTab('alerts'); setExpandedId(null); }}
          className={`py-1 transition-colors cursor-pointer ${
            activeTab === 'alerts' ? 'bg-[#181F2E] text-[#00E5FF] border border-[#263147]' : 'text-[#7E8B9B] hover:text-[#ECEFF4]'
          }`}
        >
          ACTIVE ALERTS ({report?.alerts?.length || 0})
        </button>
        <button
          onClick={() => { setActiveTab('tactics'); setExpandedId(null); }}
          className={`py-1 transition-colors cursor-pointer ${
            activeTab === 'tactics' ? 'bg-[#181F2E] text-[#00E5FF] border border-[#263147]' : 'text-[#7E8B9B] hover:text-[#ECEFF4]'
          }`}
        >
          EXPLOIT TACTICS ({report?.phishingTactics?.length || 0})
        </button>
      </div>

      {/* Core Feed Container */}
      <div className="min-h-[220px] max-h-[350px] overflow-y-auto pr-1 space-y-2 font-mono">
        {loading ? (
          <div className="h-[220px] flex flex-col items-center justify-center space-y-2 text-xs text-[#00E5FF] animate-pulse">
            <span>SYNCING NEURAL FEEDS...</span>
          </div>
        ) : error ? (
          <div className="h-[220px] flex flex-col items-center justify-center p-4 text-center space-y-2">
            <AlertTriangle className="w-6 h-6 text-[#FF334B]" />
            <p className="text-[11px] text-[#7E8B9B]">{error}</p>
            <button
              onClick={fetchThreatIntelligence}
              className="btn-soc btn-soc-primary px-3 py-1 text-[10px]"
            >
              RETRY SYNC
            </button>
          </div>
        ) : activeTab === 'alerts' ? (
          /* ACTIVE ALERTS FEED */
          report?.alerts && report.alerts.length > 0 ? (
            report.alerts.map((alert) => {
              const isExpanded = expandedId === alert.id;
              return (
                <div 
                  key={alert.id}
                  className={`bg-[#090D14] border p-2.5 space-y-2 transition-colors ${
                    isExpanded ? 'border-[#00E5FF] bg-[#181F2E]' : 'border-[#263147] hover:border-[#7E8B9B]'
                  }`}
                >
                  <div 
                    onClick={() => toggleExpand(alert.id)}
                    className="flex items-start justify-between gap-2 cursor-pointer select-none"
                  >
                    <div className="space-y-1">
                      <div className="flex items-center gap-1.5">
                        <span className={`status-chip ${getSeverityBadgeClass(alert.severity)}`}>
                          {alert.severity}
                        </span>
                        <span className="text-[9px] text-[#7E8B9B]">{alert.category}</span>
                      </div>
                      <h4 className="text-xs font-bold text-white leading-snug">{alert.title}</h4>
                    </div>
                    <span className="text-[#7E8B9B]">
                      {isExpanded ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
                    </span>
                  </div>

                  {isExpanded && (
                    <div className="pt-2 border-t border-[#263147] text-[11px] text-[#ECEFF4] space-y-2">
                      <p>{alert.description}</p>
                      <div className="bg-[#090D14] p-2 border border-[#263147] space-y-1">
                        <div>
                          <strong className="text-[#7E8B9B] text-[9px] uppercase block">Impact Assessment</strong>
                          <span className="text-[#ECEFF4] text-[10px]">{alert.impact}</span>
                        </div>
                        <div className="pt-1 border-t border-[#263147]">
                          <strong className="text-[#00E5FF] text-[9px] uppercase block">Mitigation Action</strong>
                          <span className="text-[#ECEFF4] text-[10px]">{alert.remediation}</span>
                        </div>
                      </div>
                    </div>
                  )}
                </div>
              );
            })
          ) : (
            <div className="h-[220px] flex items-center justify-center text-[#7E8B9B] text-[11px]">No active global alerts.</div>
          )
        ) : (
          /* PHISHING TACTICS FEED */
          report?.phishingTactics && report.phishingTactics.length > 0 ? (
            report.phishingTactics.map((tactic) => {
              const isExpanded = expandedId === tactic.id;
              return (
                <div 
                  key={tactic.id}
                  className={`bg-[#090D14] border p-2.5 space-y-2 transition-colors ${
                    isExpanded ? 'border-[#00E5FF] bg-[#181F2E]' : 'border-[#263147] hover:border-[#7E8B9B]'
                  }`}
                >
                  <div 
                    onClick={() => toggleExpand(tactic.id)}
                    className="flex items-start justify-between gap-2 cursor-pointer select-none"
                  >
                    <div className="space-y-1">
                      <div className="flex items-center gap-1.5">
                        <span className="status-chip status-chip-high">
                          {tactic.trendLevel} TREND
                        </span>
                        <span className="text-[9px] text-[#7E8B9B]">TARGETS: {tactic.targetAudience}</span>
                      </div>
                      <h4 className="text-xs font-bold text-white leading-snug">{tactic.name}</h4>
                    </div>
                    <span className="text-[#7E8B9B]">
                      {isExpanded ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
                    </span>
                  </div>

                  {isExpanded && (
                    <div className="pt-2 border-t border-[#263147] text-[11px] text-[#ECEFF4] space-y-2">
                      <p>{tactic.description}</p>
                      <div className="bg-[#090D14] p-2 border border-[#263147] space-y-1">
                        <div>
                          <strong className="text-[#FF334B] text-[9px] uppercase block">Key Red Flags</strong>
                          <ul className="list-disc pl-3 text-[10px] text-[#ECEFF4]">
                            {tactic.redFlags.map((flag, idx) => (
                              <li key={idx}>{flag}</li>
                            ))}
                          </ul>
                        </div>
                        <div className="pt-1 border-t border-[#263147]">
                          <strong className="text-[#00E676] text-[9px] uppercase block">Defensive Strategy</strong>
                          <span className="text-[#ECEFF4] text-[10px]">{tactic.prevention}</span>
                        </div>
                      </div>
                    </div>
                  )}
                </div>
              );
            })
          ) : (
            <div className="h-[220px] flex items-center justify-center text-[#7E8B9B] text-[11px]">No exploit tactics recorded.</div>
          )
        )}
      </div>

      {report?.lastUpdated && !loading && (
        <div className="border-t border-[#263147] pt-2 flex items-center justify-between text-[9px] font-mono text-[#7E8B9B]">
          <span className="flex items-center gap-1">
            <ShieldCheck className="w-3 h-3 text-[#00E676]" />
            Feed Verified
          </span>
          <span>Updated: {new Date(report.lastUpdated).toLocaleTimeString()}</span>
        </div>
      )}
    </div>
  );
}
