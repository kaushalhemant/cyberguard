import React, { useState } from 'react';
import { 
  X, Search, Globe, FileCode, Database, Mail, Video, ArrowRight 
} from 'lucide-react';
import { NavigationTab } from '../layout/Sidebar';

interface QuickInvestigationModalProps {
  isOpen: boolean;
  onClose: () => void;
  onLaunchInvestigation: (type: 'url' | 'hash' | 'cve' | 'email' | 'deepfake', target: string) => void;
}

export default function QuickInvestigationModal({
  isOpen,
  onClose,
  onLaunchInvestigation
}: QuickInvestigationModalProps) {
  const [targetType, setTargetType] = useState<'url' | 'hash' | 'cve' | 'email' | 'deepfake'>('url');
  const [targetValue, setTargetValue] = useState('');

  if (!isOpen) return null;

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!targetValue.trim()) return;
    onLaunchInvestigation(targetType, targetValue.trim());
    onClose();
  };

  const handleSelectPreset = (type: 'url' | 'hash' | 'cve' | 'email' | 'deepfake', val: string) => {
    onLaunchInvestigation(type, val);
    onClose();
  };

  return (
    <div className="fixed inset-0 z-50 bg-black/75 backdrop-blur-xs flex items-center justify-center p-4">
      <div className="bg-[#0D1424] border border-[#1C273C] rounded-lg max-w-lg w-full p-5 space-y-4 shadow-2xl relative">
        <div className="flex items-center justify-between border-b border-[#1C273C] pb-3">
          <div className="flex items-center gap-2">
            <div className="w-7 h-7 rounded bg-blue-500/10 border border-blue-500/30 flex items-center justify-center text-blue-400">
              <Search className="w-4 h-4" />
            </div>
            <h3 className="font-display font-bold text-sm uppercase tracking-wider text-white">
              Launch Security Investigation
            </h3>
          </div>

          <button
            onClick={onClose}
            className="p-1 text-slate-400 hover:text-white rounded"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Vector Tabs */}
        <div className="grid grid-cols-5 gap-1.5 p-1 bg-[#090D14] rounded-md border border-[#1C273C] text-[10px] font-mono">
          <button
            type="button"
            onClick={() => setTargetType('url')}
            className={`py-1.5 rounded text-center transition-colors ${
              targetType === 'url' ? 'bg-blue-600 text-white font-bold' : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            URL
          </button>
          <button
            type="button"
            onClick={() => setTargetType('hash')}
            className={`py-1.5 rounded text-center transition-colors ${
              targetType === 'hash' ? 'bg-amber-600 text-slate-950 font-bold' : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            Hash
          </button>
          <button
            type="button"
            onClick={() => setTargetType('cve')}
            className={`py-1.5 rounded text-center transition-colors ${
              targetType === 'cve' ? 'bg-cyan-600 text-slate-950 font-bold' : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            CVE
          </button>
          <button
            type="button"
            onClick={() => setTargetType('email')}
            className={`py-1.5 rounded text-center transition-colors ${
              targetType === 'email' ? 'bg-emerald-600 text-slate-950 font-bold' : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            Email
          </button>
          <button
            type="button"
            onClick={() => setTargetType('deepfake')}
            className={`py-1.5 rounded text-center transition-colors ${
              targetType === 'deepfake' ? 'bg-purple-600 text-white font-bold' : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            Media
          </button>
        </div>

        <form onSubmit={handleSubmit} className="space-y-3 font-mono text-xs">
          <div className="space-y-1">
            <label className="text-[10px] text-slate-400 uppercase">
              Target Indicator
            </label>
            <input
              type="text"
              required
              value={targetValue}
              onChange={(e) => setTargetValue(e.target.value)}
              placeholder={
                targetType === 'url' ? 'https://example.com' :
                targetType === 'hash' ? 'MD5 or SHA-256 hash' :
                targetType === 'cve' ? 'e.g. CVE-2023-4966' :
                targetType === 'email' ? 'target@domain.com' : 'filename or media artifact'
              }
              className="w-full h-9 px-3 bg-[#111827] border border-[#1C273C] rounded text-slate-200 placeholder-slate-500 focus:border-blue-500"
            />
          </div>

          <button
            type="submit"
            disabled={!targetValue.trim()}
            className="w-full py-2 px-3 rounded bg-blue-600 hover:bg-blue-500 text-white font-sans text-xs font-bold uppercase tracking-wider transition-colors disabled:opacity-40"
          >
            Execute Investigation
          </button>
        </form>

        {/* 1-Click Fast Track Presets */}
        <div className="pt-2 border-t border-[#1C273C] space-y-1.5">
          <span className="text-[10px] font-mono text-slate-400 uppercase block">Instant Benchmarks:</span>
          <div className="grid grid-cols-2 gap-1.5 text-[10px] font-mono">
            <button
              onClick={() => handleSelectPreset('url', 'https://secure-update-portal.org')}
              className="p-1.5 rounded bg-[#111827] hover:bg-[#162136] border border-[#1C273C] text-slate-300 text-left truncate"
            >
              🚨 Phishing URL
            </button>
            <button
              onClick={() => handleSelectPreset('hash', '44d88612fea8a8f36de82e1278abb02f')}
              className="p-1.5 rounded bg-[#111827] hover:bg-[#162136] border border-[#1C273C] text-slate-300 text-left truncate"
            >
              ⚠️ AsyncRAT Hash
            </button>
            <button
              onClick={() => handleSelectPreset('cve', 'CVE-2023-4966')}
              className="p-1.5 rounded bg-[#111827] hover:bg-[#162136] border border-[#1C273C] text-slate-300 text-left truncate"
            >
              🚨 CVE-2023-4966
            </button>
            <button
              onClick={() => handleSelectPreset('email', 'usxr@yahoo.com')}
              className="p-1.5 rounded bg-[#111827] hover:bg-[#162136] border border-[#1C273C] text-slate-300 text-left truncate"
            >
              🟢 Leaked Email Target
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
