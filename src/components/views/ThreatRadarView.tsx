import React, { useState } from 'react';
import { 
  Radio, AlertTriangle, ShieldAlert, TrendingUp, RefreshCw, 
  ExternalLink, ArrowUpRight, ShieldCheck, Zap
} from 'lucide-react';
import StatusBadge from '../common/StatusBadge';

export default function ThreatRadarView() {
  const [activeTab, setActiveTab] = useState<'alerts' | 'tactics'>('alerts');

  const alerts = [
    {
      id: 'ALT-2026-091',
      title: 'Active Phishing Campaign targeting Corporate Okta SSO',
      severity: 'critical',
      category: 'Credential Harvesting',
      impact: 'High risk of credential exfiltration across enterprise single-sign-on portals.',
      remediation: 'Enforce hardware FIDO2 keys and deploy edge DNS sinkholing on flagged lookalike domains.',
      timestamp: '15 mins ago'
    },
    {
      id: 'ALT-2026-088',
      title: 'Polymorphic PowerShell Droppers propagating via Malvertising',
      severity: 'high',
      category: 'Malware Dropper',
      impact: 'High entropy payloads executing in-memory DLL injection without writing to disk.',
      remediation: 'Enable PowerShell Constrained Language Mode and enforce AppLocker/WDAC policy.',
      timestamp: '1 hour ago'
    },
    {
      id: 'ALT-2026-072',
      title: 'Citrix Bleed (CVE-2023-4966) Buffer Over-Read Scanning',
      severity: 'critical',
      category: 'Zero-Day Exploitation',
      impact: 'Unauthenticated session hijacking bypassing multi-factor authentication.',
      remediation: 'Immediately terminate all active NetScaler sessions and apply vendor security updates.',
      timestamp: '3 hours ago'
    },
    {
      id: 'ALT-2026-061',
      title: 'DNS Tunneling & TXT Query Exfiltration observed on port 53',
      severity: 'medium',
      category: 'Command & Control',
      impact: 'Slow bandwidth data exfiltration bypassing corporate HTTP inspection proxies.',
      remediation: 'Deploy DNS response policy zones (RPZ) and inspect entropy of inbound subdomains.',
      timestamp: '6 hours ago'
    }
  ];

  const tactics = [
    {
      id: 'TAC-01',
      name: 'Adversary-in-the-Middle (AiTM) Proxy Phishing',
      trendLevel: 'surging',
      targetAudience: 'Enterprise IT & Executive Leaders',
      description: 'Attackers deploy reverse proxies (Evilginx) to capture session session cookies and bypass standard TOTP codes.',
      redFlags: ['Domain mismatch in browser address bar', 'Unexpected TLS issuer certificate', 'Unsolicited MFA push notification requests'],
      prevention: 'Mandate FIDO2 WebAuthn / Passkeys cryptographically bound to origin domain.'
    },
    {
      id: 'TAC-02',
      name: 'QR-Code Phishing (Quishing) in PDF Attachments',
      trendLevel: 'surging',
      targetAudience: 'Finance & Payroll Staff',
      description: 'Emails containing embedded high-resolution QR codes that redirect mobile browsers away from desktop email security sandboxes.',
      redFlags: ['Urgent payroll or benefits QR code prompt', 'Redirects to third-party shortener links', 'Requests login on mobile device'],
      prevention: 'Scan and decode all embedded QR codes inside email gateway sandbox before inbox delivery.'
    },
    {
      id: 'TAC-03',
      name: 'Executive Voice Clone Wire Authorization (Deepfake Audio)',
      trendLevel: 'increasing',
      targetAudience: 'Accounts Payable & CFO Office',
      description: 'Generative AI voice models cloning executive speech to verbally authorize emergency wire transfers via phone or conference audio.',
      redFlags: ['Unnatural vocal cadence / zero ambient breath sound', 'Emergency out-of-band wire transfer request', 'Refusal to confirm over video or authenticated Slack'],
      prevention: 'Strict dual-person verbal code verification protocol for all fund transfers > $10,000.'
    }
  ];

  return (
    <div className="space-y-4">
      {/* Header Banner */}
      <div className="command-card p-4 sm:p-5 flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <div className="w-8 h-8 rounded bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center text-cyan-400">
              <Radio className="w-4 h-4" />
            </div>
            <h2 className="text-base font-bold font-display uppercase tracking-wider text-white">
              Global Threat Radar & Intelligence Feeds
            </h2>
            <span className="px-1.5 py-0.5 rounded text-[9px] font-mono font-bold bg-cyan-500/20 text-cyan-300 border border-cyan-500/40">
              LIVE TELEMETRY FEED
            </span>
          </div>
          <p className="text-xs text-slate-400 font-sans mt-1 max-w-3xl">
            Real-time adversary tactics, trending phishing vectors, zero-day threat advisories, and defensive mitigation countermeasures.
          </p>
        </div>

        {/* Tab Switcher */}
        <div className="flex items-center gap-1.5 bg-[#101726] p-1 rounded-md border border-[#1C273C]">
          <button
            onClick={() => setActiveTab('alerts')}
            className={`px-3 py-1.5 rounded text-xs font-mono font-bold uppercase transition-colors ${
              activeTab === 'alerts' 
                ? 'bg-blue-600 text-white shadow-sm' 
                : 'text-slate-400 hover:text-white'
            }`}
          >
            Active Alerts ({alerts.length})
          </button>
          <button
            onClick={() => setActiveTab('tactics')}
            className={`px-3 py-1.5 rounded text-xs font-mono font-bold uppercase transition-colors ${
              activeTab === 'tactics' 
                ? 'bg-blue-600 text-white shadow-sm' 
                : 'text-slate-400 hover:text-white'
            }`}
          >
            Surging Tactics ({tactics.length})
          </button>
        </div>
      </div>

      {/* Main Content Area */}
      {activeTab === 'alerts' ? (
        <div className="space-y-3">
          {alerts.map((alt) => (
            <div key={alt.id} className="command-card p-4 space-y-2 hover:border-blue-500/40 transition-colors">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-[#1C273C] pb-2">
                <div className="flex items-center gap-2">
                  <span className="font-mono text-xs font-bold text-blue-400">{alt.id}</span>
                  <span className="text-slate-500">•</span>
                  <span className="font-mono text-xs text-slate-300 uppercase">{alt.category}</span>
                </div>
                <div className="flex items-center gap-2">
                  <span className="font-mono text-[10px] text-slate-400">{alt.timestamp}</span>
                  <StatusBadge severity={alt.severity} />
                </div>
              </div>

              <h3 className="font-sans text-sm font-bold text-white">
                {alt.title}
              </h3>

              <div className="space-y-1 text-xs font-sans">
                <div className="text-slate-300">
                  <strong className="text-amber-400 font-mono text-[11px] uppercase mr-1">Impact:</strong>
                  {alt.impact}
                </div>
                <div className="text-slate-300">
                  <strong className="text-emerald-400 font-mono text-[11px] uppercase mr-1">Remediation:</strong>
                  {alt.remediation}
                </div>
              </div>
            </div>
          ))}
        </div>
      ) : (
        <div className="space-y-3">
          {tactics.map((tac) => (
            <div key={tac.id} className="command-card p-4 space-y-3 hover:border-purple-500/40 transition-colors">
              <div className="flex items-center justify-between border-b border-[#1C273C] pb-2">
                <div className="flex items-center gap-2">
                  <span className="font-mono text-xs font-bold text-purple-400">{tac.id}</span>
                  <h3 className="font-sans text-sm font-bold text-white">{tac.name}</h3>
                </div>
                <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase bg-red-500/20 text-red-300 border border-red-500/30">
                  {tac.trendLevel}
                </span>
              </div>

              <p className="text-xs font-sans text-slate-300">
                {tac.description}
              </p>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs font-sans">
                <div className="bg-[#101726] p-3 rounded border border-[#1C273C] space-y-1">
                  <strong className="text-amber-400 font-mono text-[10px] uppercase block">Key Red Flags:</strong>
                  <ul className="space-y-0.5 text-slate-300 list-disc list-inside">
                    {tac.redFlags.map((rf, idx) => (
                      <li key={idx}>{rf}</li>
                    ))}
                  </ul>
                </div>
                <div className="bg-[#101726] p-3 rounded border border-[#1C273C] space-y-1">
                  <strong className="text-emerald-400 font-mono text-[10px] uppercase block">Defensive Prevention:</strong>
                  <p className="text-slate-300">{tac.prevention}</p>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
