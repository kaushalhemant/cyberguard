import React from 'react';

export type BadgeSeverity = 'critical' | 'high' | 'medium' | 'low' | 'quantum' | 'info';
export type BadgeStatus = 'new' | 'investigating' | 'mitigated' | 'escalated' | 'false_positive' | 'active' | 'clean' | 'verified';

interface StatusBadgeProps {
  severity?: BadgeSeverity | string;
  status?: BadgeStatus | string;
  label?: string;
  size?: 'sm' | 'md';
}

export default function StatusBadge({
  severity,
  status,
  label,
  size = 'sm'
}: StatusBadgeProps) {
  const sizeClasses = size === 'sm' ? 'px-2 py-0.5 text-[9px]' : 'px-2.5 py-1 text-[10px]';

  if (severity) {
    const sev = severity.toLowerCase();
    let bg = 'bg-slate-500/15 text-slate-300 border-slate-600/40';
    let dot = 'bg-slate-400';
    let displayLabel = label || severity.toUpperCase();

    if (sev.includes('crit')) {
      bg = 'bg-red-500/15 text-red-400 border-red-500/40';
      dot = 'bg-red-500 animate-pulse';
    } else if (sev.includes('high')) {
      bg = 'bg-amber-500/15 text-amber-400 border-amber-500/40';
      dot = 'bg-amber-500';
    } else if (sev.includes('med')) {
      bg = 'bg-yellow-500/15 text-yellow-300 border-yellow-500/40';
      dot = 'bg-yellow-400';
    } else if (sev.includes('low') || sev.includes('clean') || sev.includes('safe')) {
      bg = 'bg-emerald-500/15 text-emerald-400 border-emerald-500/40';
      dot = 'bg-emerald-400';
    } else if (sev.includes('quant') || sev.includes('pqc')) {
      bg = 'bg-purple-500/15 text-purple-300 border-purple-500/40';
      dot = 'bg-purple-400 animate-pulse';
    }

    return (
      <span className={`inline-flex items-center gap-1.5 font-mono font-bold uppercase tracking-wider rounded border ${sizeClasses} ${bg}`}>
        <span className={`w-1.5 h-1.5 rounded-full ${dot}`} />
        <span>{displayLabel}</span>
      </span>
    );
  }

  if (status) {
    const stat = status.toLowerCase();
    let bg = 'bg-slate-500/15 text-slate-300 border-slate-600/40';
    let dot = 'bg-slate-400';
    let displayLabel = label || status.replace('_', ' ').toUpperCase();

    if (stat === 'new' || stat === 'active') {
      bg = 'bg-red-500/15 text-red-400 border-red-500/40';
      dot = 'bg-red-500 animate-pulse';
    } else if (stat === 'investigating') {
      bg = 'bg-blue-500/15 text-blue-400 border-blue-500/40';
      dot = 'bg-blue-400';
    } else if (stat === 'mitigated' || stat === 'clean' || stat === 'verified') {
      bg = 'bg-emerald-500/15 text-emerald-400 border-emerald-500/40';
      dot = 'bg-emerald-400';
    } else if (stat === 'escalated') {
      bg = 'bg-purple-500/15 text-purple-300 border-purple-500/40';
      dot = 'bg-purple-400';
    } else if (stat === 'false_positive') {
      bg = 'bg-slate-500/15 text-slate-400 border-slate-600/40';
      dot = 'bg-slate-400';
    }

    return (
      <span className={`inline-flex items-center gap-1.5 font-mono font-bold uppercase tracking-wider rounded border ${sizeClasses} ${bg}`}>
        <span className={`w-1.5 h-1.5 rounded-full ${dot}`} />
        <span>{displayLabel}</span>
      </span>
    );
  }

  return (
    <span className={`inline-flex items-center gap-1.5 font-mono font-bold uppercase tracking-wider rounded border bg-slate-500/15 text-slate-300 border-slate-600/40 ${sizeClasses}`}>
      <span className="w-1.5 h-1.5 rounded-full bg-slate-400" />
      <span>{label || 'UNKNOWN'}</span>
    </span>
  );
}
