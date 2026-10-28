import React from 'react';
import { LucideIcon } from 'lucide-react';

interface MetricCardProps {
  label: string;
  value: string | number;
  subValue?: string;
  trend?: string;
  trendType?: 'positive' | 'negative' | 'neutral' | 'warning';
  icon: LucideIcon;
  accentColor?: 'blue' | 'purple' | 'cyan' | 'red' | 'amber' | 'emerald';
  onClick?: () => void;
}

export default function MetricCard({
  label,
  value,
  subValue,
  trend,
  trendType = 'neutral',
  icon: Icon,
  accentColor = 'blue',
  onClick
}: MetricCardProps) {
  const colorMap = {
    blue: {
      border: 'border-blue-500/20 hover:border-blue-500/40',
      iconBg: 'bg-blue-500/10 text-blue-400 border-blue-500/30',
      glow: 'shadow-[0_0_15px_rgba(59,130,246,0.06)]'
    },
    purple: {
      border: 'border-purple-500/20 hover:border-purple-500/40',
      iconBg: 'bg-purple-500/10 text-purple-400 border-purple-500/30',
      glow: 'shadow-[0_0_15px_rgba(168,85,247,0.06)]'
    },
    cyan: {
      border: 'border-cyan-500/20 hover:border-cyan-500/40',
      iconBg: 'bg-cyan-500/10 text-cyan-400 border-cyan-500/30',
      glow: 'shadow-[0_0_15px_rgba(6,182,212,0.06)]'
    },
    red: {
      border: 'border-red-500/20 hover:border-red-500/40',
      iconBg: 'bg-red-500/10 text-red-400 border-red-500/30',
      glow: 'shadow-[0_0_15px_rgba(239,68,68,0.06)]'
    },
    amber: {
      border: 'border-amber-500/20 hover:border-amber-500/40',
      iconBg: 'bg-amber-500/10 text-amber-400 border-amber-500/30',
      glow: 'shadow-[0_0_15px_rgba(245,158,11,0.06)]'
    },
    emerald: {
      border: 'border-emerald-500/20 hover:border-emerald-500/40',
      iconBg: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30',
      glow: 'shadow-[0_0_15px_rgba(16,185,129,0.06)]'
    }
  };

  const trendStyles = {
    positive: 'text-emerald-400 bg-emerald-500/10 border-emerald-500/20',
    negative: 'text-red-400 bg-red-500/10 border-red-500/20',
    warning: 'text-amber-400 bg-amber-500/10 border-amber-500/20',
    neutral: 'text-slate-400 bg-slate-500/10 border-slate-500/20'
  };

  const scheme = colorMap[accentColor] || colorMap.blue;

  return (
    <div
      onClick={onClick}
      className={`bg-[#0D1322] border rounded-lg p-3.5 transition-all relative overflow-hidden ${
        scheme.border
      } ${scheme.glow} ${onClick ? 'cursor-pointer hover:bg-[#111A2E]' : ''}`}
    >
      <div className="flex items-start justify-between gap-2">
        <div className="space-y-1 min-w-0">
          <span className="text-[11px] font-mono uppercase tracking-wider text-slate-400 block truncate">
            {label}
          </span>
          <div className="flex items-baseline gap-2">
            <span className="text-xl sm:text-2xl font-bold font-sans tracking-tight text-white">
              {value}
            </span>
            {subValue && (
              <span className="text-xs font-mono text-slate-400">
                {subValue}
              </span>
            )}
          </div>
        </div>

        <div className={`w-8 h-8 rounded-md border flex items-center justify-center shrink-0 ${scheme.iconBg}`}>
          <Icon className="w-4 h-4" />
        </div>
      </div>

      {trend && (
        <div className="mt-2.5 pt-2 border-t border-[#1C273C]/60 flex items-center justify-between text-[10px] font-mono">
          <span className={`px-1.5 py-0.5 rounded border font-semibold ${trendStyles[trendType]}`}>
            {trend}
          </span>
          <span className="text-slate-500 text-[9px]">REAL-TIME TELEMETRY</span>
        </div>
      )}
    </div>
  );
}
