import React, { useState } from 'react';
import { 
  AlertOctagon, Plus, Check, Eye, Trash2, ShieldAlert, 
  FileText, Download, UserCheck, ShieldCheck, RefreshCw, Send
} from 'lucide-react';
import { SocIncident } from '../../types';
import StatusBadge from '../common/StatusBadge';
import { generateIncidentPdf } from '../../lib/pdfGenerator';

interface SiemIncidentsViewProps {
  token: string;
  incidents: SocIncident[];
  onNewIncident: () => void;
  onTriageIncident: (id: string, status: SocIncident['status'], containmentAction?: string, note?: string) => Promise<void>;
  loading: boolean;
}

export default function SiemIncidentsView({
  token,
  incidents,
  onNewIncident,
  onTriageIncident,
  loading
}: SiemIncidentsViewProps) {
  const [selectedIncident, setSelectedIncident] = useState<SocIncident | null>(incidents[0] || null);
  const [containmentInput, setContainmentInput] = useState('');
  const [noteInput, setNoteInput] = useState('');
  const [isUpdating, setIsUpdating] = useState(false);

  const activeIncident = selectedIncident || incidents[0] || null;

  const handleApplyTriage = async (newStatus: SocIncident['status']) => {
    if (!activeIncident) return;
    setIsUpdating(true);
    await onTriageIncident(activeIncident.id, newStatus, containmentInput || undefined, noteInput || undefined);
    setContainmentInput('');
    setNoteInput('');
    setIsUpdating(false);
  };

  const handleExportPdf = (inc: SocIncident) => {
    generateIncidentPdf(inc);
  };

  return (
    <div className="space-y-4">
      {/* Header Banner */}
      <div className="command-card p-4 sm:p-5 flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <div className="w-8 h-8 rounded bg-red-500/10 border border-red-500/30 flex items-center justify-center text-red-400">
              <AlertOctagon className="w-4 h-4" />
            </div>
            <h2 className="text-base font-bold font-display uppercase tracking-wider text-white">
              SIEM Incident Response & Case Management
            </h2>
            <span className="px-1.5 py-0.5 rounded text-[9px] font-mono font-bold bg-red-500/20 text-red-300 border border-red-500/40">
              ACTIVE CASE MATRIX
            </span>
          </div>
          <p className="text-xs text-slate-400 font-sans mt-1 max-w-3xl">
            Triage observed security events, assign containment playbooks, track MITRE ATT&CK techniques, and export official chain-of-custody PDF incident records.
          </p>
        </div>

        <button
          onClick={onNewIncident}
          className="btn-soc btn-soc-primary px-3.5 py-2 text-xs flex items-center gap-1.5 self-start md:self-auto cursor-pointer"
        >
          <Plus className="w-4 h-4" />
          <span>+ Create Incident Case</span>
        </button>
      </div>

      {/* Main Grid: Cases List (5 cols) & Active Triage Desk (7 cols) */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
        {/* Left Column: Incidents List (5 cols) */}
        <div className="lg:col-span-5 space-y-2.5">
          <div className="command-card p-3 flex items-center justify-between font-mono text-xs text-slate-400">
            <span>INCIDENTS IN QUEUE ({incidents.length})</span>
            <span>SORT: RECENT</span>
          </div>

          <div className="space-y-2">
            {incidents.map((inc) => {
              const isSelected = activeIncident?.id === inc.id;
              return (
                <div
                  key={inc.id}
                  onClick={() => setSelectedIncident(inc)}
                  className={`command-card p-3.5 space-y-2 cursor-pointer transition-all ${
                    isSelected 
                      ? 'border-blue-500 bg-[#121B2F] shadow-[0_0_15px_rgba(59,130,246,0.15)]' 
                      : 'hover:border-slate-700 hover:bg-[#101726]'
                  }`}
                >
                  <div className="flex items-center justify-between">
                    <span className="font-mono text-xs font-bold text-blue-400">{inc.id}</span>
                    <div className="flex items-center gap-1.5">
                      <StatusBadge severity={inc.severity} />
                      <StatusBadge status={inc.status} />
                    </div>
                  </div>

                  <h4 className="font-sans text-xs font-bold text-white line-clamp-1">
                    {inc.title}
                  </h4>

                  <div className="flex items-center justify-between text-[10px] font-mono text-slate-400 pt-1 border-t border-[#1C273C]/50">
                    <span className="truncate max-w-[160px]">{inc.target}</span>
                    <span>{new Date(inc.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}</span>
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* Right Column: Active Incident Details & Triage Actions (7 cols) */}
        <div className="lg:col-span-7 space-y-4">
          {!activeIncident ? (
            <div className="command-card p-8 text-center text-slate-400 font-mono text-xs">
              No incident selected for triage.
            </div>
          ) : (
            <div className="space-y-4">
              {/* Incident Header Card */}
              <div className="command-card p-4 space-y-3 border-blue-500/30">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-[#1C273C] pb-3">
                  <div>
                    <div className="flex items-center gap-2">
                      <span className="font-mono text-xs font-bold text-blue-400">{activeIncident.id}</span>
                      <span className="text-slate-400">•</span>
                      <span className="font-mono text-xs text-slate-300 uppercase">{activeIncident.category}</span>
                    </div>
                    <h3 className="font-sans text-sm font-bold text-white mt-0.5">
                      {activeIncident.title}
                    </h3>
                  </div>

                  <div className="flex items-center gap-2">
                    <button
                      onClick={() => handleExportPdf(activeIncident)}
                      className="px-2.5 py-1 rounded bg-blue-600/20 hover:bg-blue-600/40 text-blue-300 font-mono text-[10px] border border-blue-500/30 flex items-center gap-1.5 transition-colors cursor-pointer"
                    >
                      <Download className="w-3 h-3" />
                      <span>PDF Brief</span>
                    </button>
                    <StatusBadge status={activeIncident.status} size="md" />
                  </div>
                </div>

                {/* Metadata Grid */}
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 font-mono text-[10px]">
                  <div className="bg-[#111827] border border-[#1C273C] p-2 rounded">
                    <span className="text-slate-400 block">Target Asset</span>
                    <span className="font-bold text-xs text-cyan-300 truncate block" title={activeIncident.target}>
                      {activeIncident.target}
                    </span>
                  </div>
                  <div className="bg-[#111827] border border-[#1C273C] p-2 rounded">
                    <span className="text-slate-400 block">MITRE Tactic</span>
                    <span className="font-bold text-xs text-amber-300 truncate block" title={activeIncident.mitreTactic}>
                      {activeIncident.mitreTactic}
                    </span>
                  </div>
                  <div className="bg-[#111827] border border-[#1C273C] p-2 rounded">
                    <span className="text-slate-400 block">Technique ID</span>
                    <span className="font-bold text-xs text-purple-300 truncate block" title={activeIncident.mitreTechniqueId}>
                      {activeIncident.mitreTechniqueId}
                    </span>
                  </div>
                  <div className="bg-[#111827] border border-[#1C273C] p-2 rounded">
                    <span className="text-slate-400 block">Assigned Officer</span>
                    <span className="font-bold text-xs text-emerald-300 truncate block" title={activeIncident.assignedOfficer}>
                      {activeIncident.assignedOfficer}
                    </span>
                  </div>
                </div>

                {/* Description */}
                <div className="text-xs font-sans text-slate-300 bg-[#111827] p-3 rounded border border-[#1C273C]">
                  {activeIncident.description}
                </div>

                {/* Containment Action Taken */}
                {activeIncident.containmentActionTaken && (
                  <div className="p-2.5 rounded bg-emerald-500/10 border border-emerald-500/30 text-xs font-mono text-emerald-300 flex items-center gap-2">
                    <ShieldCheck className="w-4 h-4 text-emerald-400 shrink-0" />
                    <span>Containment: {activeIncident.containmentActionTaken}</span>
                  </div>
                )}
              </div>

              {/* Triage Actions Form */}
              <div className="command-card p-4 space-y-3">
                <h4 className="text-xs font-bold font-mono uppercase tracking-wider text-white">
                  Execute Case Triage & Containment
                </h4>

                <div className="space-y-3">
                  <div className="space-y-1">
                    <label className="text-[11px] font-mono text-slate-400 uppercase">
                      Add Containment Action (e.g. WAF Block, Endpoint Isolation)
                    </label>
                    <input
                      type="text"
                      value={containmentInput}
                      onChange={(e) => setContainmentInput(e.target.value)}
                      placeholder="e.g. Edge firewall IP rule deployed"
                      className="w-full h-8 px-3 bg-[#111827] border border-[#1C273C] rounded text-xs text-slate-200 placeholder-slate-500 focus:border-blue-500 font-mono"
                    />
                  </div>

                  <div className="space-y-1">
                    <label className="text-[11px] font-mono text-slate-400 uppercase">
                      Add Analyst Investigation Note
                    </label>
                    <textarea
                      value={noteInput}
                      onChange={(e) => setNoteInput(e.target.value)}
                      placeholder="e.g. Validated threat signature with security team..."
                      rows={2}
                      className="w-full p-2.5 bg-[#111827] border border-[#1C273C] rounded text-xs text-slate-200 placeholder-slate-500 focus:border-blue-500 font-mono"
                    />
                  </div>

                  <div className="flex flex-wrap items-center gap-2 pt-1">
                    <button
                      onClick={() => handleApplyTriage('investigating')}
                      disabled={isUpdating}
                      className="px-3 py-1.5 rounded bg-blue-600/20 hover:bg-blue-600/40 text-blue-300 font-mono text-xs border border-blue-500/30 transition-colors cursor-pointer"
                    >
                      Set Status: Investigating
                    </button>
                    <button
                      onClick={() => handleApplyTriage('mitigated')}
                      disabled={isUpdating}
                      className="px-3 py-1.5 rounded bg-emerald-600/20 hover:bg-emerald-600/40 text-emerald-300 font-mono text-xs border border-emerald-500/30 transition-colors cursor-pointer"
                    >
                      Set Status: Mitigated
                    </button>
                    <button
                      onClick={() => handleApplyTriage('escalated')}
                      disabled={isUpdating}
                      className="px-3 py-1.5 rounded bg-purple-600/20 hover:bg-purple-600/40 text-purple-300 font-mono text-xs border border-purple-500/30 transition-colors cursor-pointer"
                    >
                      Set Status: Escalated
                    </button>
                  </div>
                </div>
              </div>

              {/* Investigation Notes Ledger */}
              {activeIncident.notes && activeIncident.notes.length > 0 && (
                <div className="command-card p-4 space-y-2">
                  <h4 className="text-xs font-bold font-mono uppercase tracking-wider text-slate-200">
                    Investigation Log & Notes
                  </h4>
                  <div className="space-y-1.5">
                    {activeIncident.notes.map((note, idx) => (
                      <div key={idx} className="p-2 rounded bg-[#101726] border border-[#1C273C] text-xs font-sans text-slate-300 flex items-start gap-2">
                        <span className="text-blue-400 font-mono font-bold">•</span>
                        <span>{note}</span>
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
