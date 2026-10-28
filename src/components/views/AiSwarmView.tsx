import React, { useState } from 'react';
import { 
  Bot, Activity, ShieldCheck, Play, RefreshCw, 
  CheckCircle2, AlertOctagon, Terminal as TerminalIcon
} from 'lucide-react';
import { AiAgent, AiSwarmEvent } from '../../types';
import StatusBadge from '../common/StatusBadge';

interface AiSwarmViewProps {
  token: string;
  agents: AiAgent[];
  events: AiSwarmEvent[];
  onDispatchPlaybook: (agentId: string, playbook: string, target: string) => Promise<any>;
  loading: boolean;
}

export default function AiSwarmView({
  token,
  agents,
  events,
  onDispatchPlaybook,
  loading
}: AiSwarmViewProps) {
  const [selectedAgentId, setSelectedAgentId] = useState(agents[0]?.id || 'agent_sentinel_alpha');
  const [playbookInput, setPlaybookInput] = useState('Micro-Isolation Ephemeral Honeyswarm');
  const [targetInput, setTargetInput] = useState('Kernel WASM Sandbox WS-092');
  const [isDispatching, setIsDispatching] = useState(false);

  const handleDispatch = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsDispatching(true);
    await onDispatchPlaybook(selectedAgentId, playbookInput, targetInput);
    setIsDispatching(false);
  };

  return (
    <div className="space-y-4">
      {/* Header Banner */}
      <div className="command-card p-4 sm:p-5 flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <div className="w-8 h-8 rounded bg-purple-500/10 border border-purple-500/30 flex items-center justify-center text-purple-400">
              <Bot className="w-4 h-4" />
            </div>
            <h2 className="text-base font-bold font-display uppercase tracking-wider text-white">
              Autonomous AI SOC Defense Swarm
            </h2>
            <span className="px-1.5 py-0.5 rounded text-[9px] font-mono font-bold bg-purple-500/20 text-purple-300 border border-purple-500/40">
              4/4 AGENTS SYNCHRONIZED
            </span>
          </div>
          <p className="text-xs text-slate-400 font-sans mt-1 max-w-3xl">
            Autonomous multi-agent defense swarm executing real-time sub-millisecond memory page relocation, zero-day interception, and Byzantine fault-tolerant consensus voting.
          </p>
        </div>
      </div>

      {/* Agents Status Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
        {agents.map((agent) => (
          <div 
            key={agent.id}
            className="command-card p-3.5 space-y-2.5 border-purple-500/20 hover:border-purple-500/40 transition-colors"
          >
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <div className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
                <span className="font-mono text-xs font-bold text-white">{agent.name}</span>
              </div>
              <span className="text-[10px] font-mono text-purple-400 font-bold">{agent.codename}</span>
            </div>

            <div className="text-[11px] font-sans text-slate-300">
              {agent.role}
            </div>

            <div className="grid grid-cols-2 gap-1.5 font-mono text-[10px] bg-[#111827] p-2 rounded border border-[#1C273C]">
              <div>
                <span className="text-slate-400 block">Neutralized</span>
                <span className="font-bold text-emerald-400">{agent.threatsNeutralized}</span>
              </div>
              <div>
                <span className="text-slate-400 block">Confidence</span>
                <span className="font-bold text-purple-300">{agent.confidenceScore}%</span>
              </div>
            </div>

            <div className="text-[10px] font-mono text-slate-400 truncate" title={agent.activePlaybook}>
              Playbook: <strong className="text-slate-200">{agent.activePlaybook}</strong>
            </div>
          </div>
        ))}
      </div>

      {/* Main Grid: Playbook Dispatcher (5 cols) & Live Telemetry Feed (7 cols) */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
        {/* Left Column: Manual Playbook Override (5 cols) */}
        <div className="lg:col-span-5 space-y-4">
          <div className="command-card p-4 space-y-4">
            <h3 className="text-xs font-bold font-mono uppercase tracking-wider text-white">
              Dispatch Autonomous Swarm Action
            </h3>

            <form onSubmit={handleDispatch} className="space-y-3 font-mono text-xs">
              <div className="space-y-1">
                <label className="text-[10px] text-slate-400 uppercase">Assigned Agent Node</label>
                <select
                  value={selectedAgentId}
                  onChange={(e) => setSelectedAgentId(e.target.value)}
                  className="w-full h-8 px-2 bg-[#111827] border border-[#1C273C] rounded text-slate-200"
                >
                  {agents.map(a => (
                    <option key={a.id} value={a.id}>{a.name} ({a.role})</option>
                  ))}
                </select>
              </div>

              <div className="space-y-1">
                <label className="text-[10px] text-slate-400 uppercase">Playbook Template</label>
                <input
                  type="text"
                  value={playbookInput}
                  onChange={(e) => setPlaybookInput(e.target.value)}
                  className="w-full h-8 px-2.5 bg-[#111827] border border-[#1C273C] rounded text-slate-200"
                />
              </div>

              <div className="space-y-1">
                <label className="text-[10px] text-slate-400 uppercase">Target Sandbox / Asset</label>
                <input
                  type="text"
                  value={targetInput}
                  onChange={(e) => setTargetInput(e.target.value)}
                  className="w-full h-8 px-2.5 bg-[#111827] border border-[#1C273C] rounded text-slate-200"
                />
              </div>

              <button
                type="submit"
                disabled={isDispatching}
                className="w-full py-2 px-3 rounded bg-purple-600 hover:bg-purple-500 text-white font-bold font-sans text-xs uppercase tracking-wider transition-colors flex items-center justify-center gap-1.5 cursor-pointer"
              >
                <Play className="w-3.5 h-3.5" />
                <span>Execute Playbook Override</span>
              </button>
            </form>
          </div>
        </div>

        {/* Right Column: Live Swarm Telemetry Stream (7 cols) */}
        <div className="lg:col-span-7 space-y-4">
          <div className="command-card p-4 space-y-3">
            <h3 className="text-xs font-bold font-mono uppercase tracking-wider text-white">
              Autonomous Swarm Event Stream
            </h3>

            <div className="space-y-2 max-h-[380px] overflow-y-auto">
              {events.map((evt) => (
                <div key={evt.id} className="p-3 rounded bg-[#101726] border border-[#1C273C] space-y-1 font-mono text-xs">
                  <div className="flex items-center justify-between text-[10px]">
                    <span className="font-bold text-purple-400">{evt.agentCodename}</span>
                    <span className="text-slate-400">{new Date(evt.timestamp).toLocaleTimeString()}</span>
                  </div>
                  <div className="font-bold text-white text-[11px] font-sans">
                    {evt.autonomousAction}
                  </div>
                  <p className="text-[11px] font-sans text-slate-300">
                    {evt.details}
                  </p>
                  <div className="flex items-center justify-between text-[10px] text-slate-400 pt-1 border-t border-[#1C273C]/50">
                    <span className="truncate max-w-[200px]">Target: {evt.target}</span>
                    <span className="text-emerald-400 font-bold">Consensus: {evt.consensusScore}%</span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
