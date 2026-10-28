import React, { useState } from 'react';
import { X, AlertOctagon, ShieldAlert, Plus, Check } from 'lucide-react';
import { SocIncident } from '../../types';

interface NewIncidentModalProps {
  isOpen: boolean;
  onClose: () => void;
  onSubmit: (incidentData: Partial<SocIncident>) => Promise<void>;
  officerName: string;
}

export default function NewIncidentModal({
  isOpen,
  onClose,
  onSubmit,
  officerName
}: NewIncidentModalProps) {
  const [title, setTitle] = useState('');
  const [target, setTarget] = useState('');
  const [severity, setSeverity] = useState<SocIncident['severity']>('high');
  const [priority, setPriority] = useState<'P1' | 'P2' | 'P3' | 'P4'>('P2');
  const [category, setCategory] = useState<SocIncident['category']>('Phishing');
  const [mitreTactic, setMitreTactic] = useState('Initial Access');
  const [mitreTechniqueId, setMitreTechniqueId] = useState('T1566.002');
  const [description, setDescription] = useState('');
  const [note, setNote] = useState('');
  const [isSubmitting, setIsSubmitting] = useState(false);

  if (!isOpen) return null;

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!title.trim() || !target.trim()) return;

    setIsSubmitting(true);
    await onSubmit({
      title: title.trim(),
      target: target.trim(),
      severity,
      category,
      mitreTactic,
      mitreTechniqueId,
      description: description.trim() || `Security incident case regarding ${target.trim()}`,
      assignedOfficer: officerName,
      notes: note.trim() ? [note.trim()] : ['Initial case triage opened']
    });
    setIsSubmitting(false);
    onClose();
  };

  return (
    <div className="fixed inset-0 z-50 bg-black/75 backdrop-blur-xs flex items-center justify-center p-4">
      <div className="bg-[#0D1424] border border-[#1C273C] rounded-lg max-w-lg w-full p-5 space-y-4 shadow-2xl relative">
        <div className="flex items-center justify-between border-b border-[#1C273C] pb-3">
          <div className="flex items-center gap-2">
            <div className="w-7 h-7 rounded bg-red-500/10 border border-red-500/30 flex items-center justify-center text-red-400">
              <AlertOctagon className="w-4 h-4" />
            </div>
            <h3 className="font-display font-bold text-sm uppercase tracking-wider text-white">
              Create New SIEM Incident Case
            </h3>
          </div>

          <button
            onClick={onClose}
            className="p-1 text-slate-400 hover:text-white rounded"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        <form onSubmit={handleSubmit} className="space-y-3 font-mono text-xs">
          <div className="space-y-1">
            <label className="text-[10px] text-slate-400 uppercase">Incident Title *</label>
            <input
              type="text"
              required
              value={title}
              onChange={(e) => setTitle(e.target.value)}
              placeholder="e.g. Spearphishing campaign targeting finance execs"
              className="w-full h-8 px-2.5 bg-[#111827] border border-[#1C273C] rounded text-slate-200 placeholder-slate-500 focus:border-blue-500 font-sans"
            />
          </div>

          <div className="space-y-1">
            <label className="text-[10px] text-slate-400 uppercase">Target Indicator / Asset *</label>
            <input
              type="text"
              required
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              placeholder="e.g. secure-login-portal.org or 185.220.101.5"
              className="w-full h-8 px-2.5 bg-[#111827] border border-[#1C273C] rounded text-slate-200 placeholder-slate-500 focus:border-blue-500"
            />
          </div>

          <div className="grid grid-cols-2 gap-2.5">
            <div className="space-y-1">
              <label className="text-[10px] text-slate-400 uppercase">Severity</label>
              <select
                value={severity}
                onChange={(e) => setSeverity(e.target.value as any)}
                className="w-full h-8 px-2 bg-[#111827] border border-[#1C273C] rounded text-slate-300"
              >
                <option value="critical">Critical</option>
                <option value="high">High</option>
                <option value="medium">Medium</option>
                <option value="low">Low</option>
              </select>
            </div>

            <div className="space-y-1">
              <label className="text-[10px] text-slate-400 uppercase">Category</label>
              <select
                value={category}
                onChange={(e) => setCategory(e.target.value as any)}
                className="w-full h-8 px-2 bg-[#111827] border border-[#1C273C] rounded text-slate-300"
              >
                <option value="Phishing">Phishing</option>
                <option value="Malware Payload">Malware Payload</option>
                <option value="Zero-Day">Zero-Day</option>
                <option value="Credential Abuse">Credential Abuse</option>
                <option value="Ransomware">Ransomware</option>
                <option value="DDoS">DDoS</option>
              </select>
            </div>
          </div>

          <div className="grid grid-cols-2 gap-2.5">
            <div className="space-y-1">
              <label className="text-[10px] text-slate-400 uppercase">MITRE Tactic</label>
              <input
                type="text"
                value={mitreTactic}
                onChange={(e) => setMitreTactic(e.target.value)}
                placeholder="e.g. Initial Access"
                className="w-full h-8 px-2.5 bg-[#111827] border border-[#1C273C] rounded text-slate-200"
              />
            </div>

            <div className="space-y-1">
              <label className="text-[10px] text-slate-400 uppercase">MITRE Technique ID</label>
              <input
                type="text"
                value={mitreTechniqueId}
                onChange={(e) => setMitreTechniqueId(e.target.value)}
                placeholder="e.g. T1566.002"
                className="w-full h-8 px-2.5 bg-[#111827] border border-[#1C273C] rounded text-slate-200"
              />
            </div>
          </div>

          <div className="space-y-1">
            <label className="text-[10px] text-slate-400 uppercase">Incident Description</label>
            <textarea
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              placeholder="Observed threat context..."
              rows={2}
              className="w-full p-2 bg-[#111827] border border-[#1C273C] rounded text-slate-200 font-sans"
            />
          </div>

          <div className="flex justify-end gap-2 pt-2 border-t border-[#1C273C]">
            <button
              type="button"
              onClick={onClose}
              className="px-3 py-1.5 rounded bg-[#162136] hover:bg-[#1E2D48] text-slate-300 text-xs font-mono transition-colors"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={isSubmitting}
              className="px-4 py-1.5 rounded bg-blue-600 hover:bg-blue-500 text-white font-sans text-xs font-bold uppercase tracking-wider transition-colors"
            >
              {isSubmitting ? 'Creating Case...' : 'Create Case'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
