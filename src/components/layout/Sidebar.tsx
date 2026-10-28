import React from 'react';
import { 
  ShieldCheck, LayoutDashboard, Radio, Globe, FileCode, Video, 
  Database, Mail, AlertOctagon, FileText, Bot, Satellite, ShieldAlert,
  ChevronLeft, ChevronRight, CheckCircle2, Lock, Sparkles, Sliders
} from 'lucide-react';
import { SocIncident } from '../../types';

export type NavigationTab = 
  | 'command-center'
  | 'threat-radar'
  | 'stix-bundler'
  | 'satellite-mesh'
  | 'url-scanner'
  | 'osint-inspector'
  | 'hash-forensics'
  | 'deepfake-detection'
  | 'cve-database'
  | 'email-breach'
  | 'siem-incidents'
  | 'forensic-reports'
  | 'ai-soc-swarm'
  | 'pqc-audit'
  | 'compliance-settings';

interface SidebarProps {
  activeTab: NavigationTab;
  onSelectTab: (tab: NavigationTab) => void;
  collapsed: boolean;
  onToggleCollapse: () => void;
  incidents: SocIncident[];
  isMobileOpen: boolean;
  onCloseMobile: () => void;
}

interface NavGroup {
  label: string;
  items: {
    id: NavigationTab;
    label: string;
    icon: React.ComponentType<{ className?: string }>;
    badge?: string | number;
    badgeColor?: string;
    isAi?: boolean;
  }[];
}

export default function Sidebar({
  activeTab,
  onSelectTab,
  collapsed,
  onToggleCollapse,
  incidents,
  isMobileOpen,
  onCloseMobile
}: SidebarProps) {
  const openIncidentsCount = incidents.filter(i => i.status === 'new' || i.status === 'investigating').length;

  const navGroups: NavGroup[] = [
    {
      label: 'Command',
      items: [
        { id: 'command-center', label: 'Command Center', icon: LayoutDashboard }
      ]
    },
    {
      label: 'Threat Intelligence',
      items: [
        { id: 'threat-radar', label: 'Global Threat Radar', icon: Radio },
        { id: 'stix-bundler', label: 'STIX 2.1/3.0 Bundler', icon: FileText },
        { id: 'satellite-mesh', label: 'LEO Satellite & QKD', icon: Satellite }
      ]
    },
    {
      label: 'Detection & Forensics',
      items: [
        { id: 'url-scanner', label: 'URL & Phishing Scanner', icon: Globe },
        { id: 'osint-inspector', label: 'OSINT IP & Domain', icon: Globe },
        { id: 'hash-forensics', label: 'Malware Hash & Binary', icon: FileCode },
        { id: 'deepfake-detection', label: 'Neural Deepfake Lab', icon: Video, isAi: true, badge: 'AI', badgeColor: 'bg-purple-500/20 text-purple-300 border-purple-500/40' }
      ]
    },
    {
      label: 'Vulnerability & Exposure',
      items: [
        { id: 'cve-database', label: 'NIST NVD CVE Database', icon: Database },
        { id: 'email-breach', label: 'Exposure & Breach Auditor', icon: Mail }
      ]
    },
    {
      label: 'Operations & Cases',
      items: [
        { 
          id: 'siem-incidents', 
          label: 'SIEM Incidents & Triage', 
          icon: AlertOctagon, 
          badge: openIncidentsCount > 0 ? openIncidentsCount : undefined,
          badgeColor: 'bg-red-500/20 text-red-400 border-red-500/40'
        },
        { id: 'ai-soc-swarm', label: 'Autonomous AI Swarm', icon: Bot, isAi: true, badge: '4/4', badgeColor: 'bg-purple-500/20 text-purple-300 border-purple-500/40' },
        { id: 'pqc-audit', label: 'Post-Quantum (PQC)', icon: Lock }
      ]
    },
    {
      label: 'Governance & Trust',
      items: [
        { id: 'compliance-settings', label: 'Compliance & Data Rights', icon: Sliders }
      ]
    }
  ];

  const handleNavClick = (tabId: NavigationTab) => {
    onSelectTab(tabId);
    if (isMobileOpen) {
      onCloseMobile();
    }
  };

  return (
    <>
      {/* Mobile Backdrop */}
      {isMobileOpen && (
        <div 
          onClick={onCloseMobile}
          className="fixed inset-0 bg-black/70 backdrop-blur-xs z-40 lg:hidden"
        />
      )}

      {/* Sidebar Container */}
      <aside 
        className={`fixed lg:sticky top-0 left-0 h-screen z-50 flex flex-col bg-[#0B0F19] border-r border-[#1C273C] transition-all duration-200 select-none ${
          collapsed ? 'w-[68px]' : 'w-[260px]'
        } ${
          isMobileOpen ? 'translate-x-0' : '-translate-x-full lg:translate-x-0'
        }`}
      >
        {/* Brand Header */}
        <div className="h-14 border-b border-[#1C273C] flex items-center justify-between px-3.5 bg-[#0B0F19]">
          <div 
            onClick={() => handleNavClick('command-center')}
            className="flex items-center gap-2.5 cursor-pointer overflow-hidden"
          >
            <div className="w-8 h-8 rounded-md bg-[#111A2E] border border-blue-500/30 flex items-center justify-center text-blue-400 shrink-0 shadow-[0_0_12px_rgba(59,130,246,0.2)]">
              <ShieldCheck className="w-5 h-5 text-blue-400" />
            </div>
            {!collapsed && (
              <div className="flex flex-col min-w-0">
                <div className="flex items-center gap-1.5">
                  <span className="font-bold text-sm tracking-wide text-white uppercase font-sans">
                    Cyber<span className="text-blue-400">Guard</span>
                  </span>
                  <span className="text-[9px] font-mono px-1 py-0.2 rounded bg-blue-500/10 text-blue-400 border border-blue-500/30 font-semibold">
                    SOC
                  </span>
                </div>
                <span className="text-[10px] text-slate-400 font-mono tracking-tight truncate">
                  Honest Security Hub
                </span>
              </div>
            )}
          </div>

          {/* Desktop Collapse Toggle */}
          <button
            onClick={onToggleCollapse}
            className="hidden lg:flex w-6 h-6 items-center justify-center rounded text-slate-400 hover:text-white hover:bg-slate-800/60 transition-colors"
            title={collapsed ? "Expand sidebar" : "Collapse sidebar"}
          >
            {collapsed ? <ChevronRight className="w-4 h-4" /> : <ChevronLeft className="w-4 h-4" />}
          </button>
        </div>

        {/* Navigation Items */}
        <div className="flex-1 overflow-y-auto px-2 py-3 space-y-4">
          {navGroups.map((group, groupIdx) => (
            <div key={groupIdx} className="space-y-1">
              {!collapsed && (
                <div className="px-2.5 py-1 text-[10px] font-mono uppercase tracking-wider text-slate-400 font-semibold">
                  {group.label}
                </div>
              )}
              {collapsed && groupIdx > 0 && (
                <div className="border-t border-[#1C273C] my-2" />
              )}
              {group.items.map((item) => {
                const Icon = item.icon;
                const isActive = activeTab === item.id;
                return (
                  <button
                    key={item.id}
                    onClick={() => handleNavClick(item.id)}
                    className={`w-full flex items-center gap-2.5 px-2.5 py-2 rounded-md text-xs font-medium transition-all group relative ${
                      isActive 
                        ? 'bg-blue-600/15 text-blue-300 border border-blue-500/40 shadow-[0_0_15px_rgba(59,130,246,0.15)] font-semibold' 
                        : 'text-slate-400 hover:text-slate-200 hover:bg-[#121A2D] border border-transparent'
                    }`}
                    title={collapsed ? item.label : undefined}
                  >
                    <Icon className={`w-4 h-4 shrink-0 transition-colors ${
                      isActive 
                        ? (item.isAi ? 'text-purple-400' : 'text-blue-400') 
                        : (item.isAi ? 'text-purple-400/80 group-hover:text-purple-300' : 'text-slate-400 group-hover:text-slate-300')
                    }`} />
                    
                    {!collapsed && (
                      <span className="truncate flex-1 text-left font-sans">
                        {item.label}
                      </span>
                    )}

                    {!collapsed && item.badge !== undefined && (
                      <span className={`text-[9px] font-mono px-1.5 py-0.5 rounded border font-semibold ${
                        item.badgeColor || 'bg-slate-800 text-slate-300 border-slate-700'
                      }`}>
                        {item.badge}
                      </span>
                    )}

                    {collapsed && isActive && (
                      <div className="absolute right-1 w-1.5 h-1.5 rounded-full bg-blue-400 shadow-[0_0_8px_#3B82F6]" />
                    )}
                  </button>
                );
              })}
            </div>
          ))}
        </div>

        {/* Sidebar Footer / Telemetry Status */}
        <div className="p-2.5 border-t border-[#1C273C] bg-[#090D15]">
          {!collapsed ? (
            <div className="bg-[#0E1524] border border-[#1C273C] rounded-md p-2.5 space-y-1.5 text-[10px] font-mono">
              <div className="flex items-center justify-between text-slate-400">
                <span className="flex items-center gap-1.5">
                  <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
                  Deterministic Engine
                </span>
                <span className="text-emerald-400 font-bold">ONLINE</span>
              </div>
              <div className="flex items-center justify-between text-slate-400">
                <span>NIST FIPS 203 PQC</span>
                <span className="text-purple-400 font-bold">READY</span>
              </div>
              <div className="flex items-center justify-between text-slate-400">
                <span>Zero-Retention</span>
                <span className="text-blue-400 font-bold">ACTIVE</span>
              </div>
            </div>
          ) : (
            <div className="flex justify-center" title="Deterministic Engine: ONLINE">
              <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse shadow-[0_0_8px_#10B981]" />
            </div>
          )}
        </div>
      </aside>
    </>
  );
}
