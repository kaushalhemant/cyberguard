import React, { useState } from 'react';
import { 
  Bot, Activity, ShieldAlert, Play, RefreshCw, 
  CheckCircle2, AlertOctagon, Terminal as TerminalIcon, Info, Cpu, Server, Network
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
  const [isPinging, setIsPinging] = useState(false);
  const [pingResult, setPingResult] = useState<string | null>(null);

  const handleTestConnection = async () => {
    setIsPinging(true);
    setPingResult(null);
    try {
      const res = await fetch('/api/ai-swarm/telemetry', {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      const data = await res.json();
      if (data.swarmStatus === 'INFRASTRUCTURE_NOT_CONFIGURED') {
        setPingResult('Diagnostic completed: No active worker daemon registered on host cluster RPC. Synthetic executions remain disabled.');
      } else {
        setPingResult(`Swarm status: ${data.swarmStatus}`);
      }
    } catch (err: any) {
      setPingResult('Connection probe timed out. No local or remote worker daemon reachable.');
    } finally {
      setIsPinging(false);
    }
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
            <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-amber-500/10 text-amber-400 border border-amber-500/30">
              INFRASTRUCTURE NOT CONFIGURED
            </span>
          </div>
          <p className="text-xs text-slate-400 font-sans mt-1 max-w-3xl">
            Autonomous multi-agent defense architecture blueprint. Requires host eBPF daemon and sovereign LLM worker nodes for live automated execution.
          </p>
        </div>

        <button
          onClick={handleTestConnection}
          disabled={isPinging}
          className="px-3 py-1.5 rounded bg-[#131C2E] hover:bg-[#1A263D] border border-purple-500/30 text-purple-300 text-xs font-mono flex items-center gap-2 transition-colors cursor-pointer disabled:opacity-50"
        >
          {isPinging ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <Activity className="w-3.5 h-3.5" />}
          <span>Test Worker RPC Node</span>
        </button>
      </div>

      {/* Ping Result Notification */}
      {pingResult && (
        <div className="p-3 rounded bg-blue-500/10 border border-blue-500/30 text-blue-300 text-xs font-mono flex items-start gap-2">
          <Info className="w-4 h-4 shrink-0 text-blue-400 mt-0.5" />
          <span>{pingResult}</span>
        </div>
      )}

      {/* Infrastructure Prerequisites Card */}
      <div className="command-card p-4 border-amber-500/30 bg-[#0E1422] space-y-3">
        <div className="flex items-center gap-2 text-amber-400 text-xs font-bold font-mono uppercase tracking-wider">
          <AlertOctagon className="w-4 h-4" />
          <span>Missing Prerequisites for Autonomous Execution</span>
        </div>
        <p className="text-xs text-slate-300 font-sans">
          To prevent misleading or simulated security assertions, autonomous remediation is strictly locked until genuine worker daemons are registered.
        </p>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-3 font-mono text-[11px] pt-1">
          <div className="p-3 rounded bg-[#0A0E18] border border-[#1C273C] space-y-1.5">
            <div className="flex items-center justify-between">
              <span className="text-slate-300 font-bold flex items-center gap-1.5">
                <Cpu className="w-3.5 h-3.5 text-purple-400" />
                eBPF Kernel Probe
              </span>
              <span className="text-[9px] px-1.5 py-0.5 rounded bg-red-500/10 text-red-400 border border-red-500/30 font-bold">
                UNCONNECTED
              </span>
            </div>
            <p className="text-[10px] text-slate-400 font-sans">
              Requires Cilium / Tetragon or Falco runtime daemon for ring-0 memory traps.
            </p>
          </div>

          <div className="p-3 rounded bg-[#0A0E18] border border-[#1C273C] space-y-1.5">
            <div className="flex items-center justify-between">
              <span className="text-slate-300 font-bold flex items-center gap-1.5">
                <Server className="w-3.5 h-3.5 text-cyan-400" />
                Sovereign LLM Worker
              </span>
              <span className="text-[9px] px-1.5 py-0.5 rounded bg-red-500/10 text-red-400 border border-red-500/30 font-bold">
                UNCONNECTED
              </span>
            </div>
            <p className="text-[10px] text-slate-400 font-sans">
              Requires Ollama, vLLM, or Anthropic API credentials in environment variables.
            </p>
          </div>

          <div className="p-3 rounded bg-[#0A0E18] border border-[#1C273C] space-y-1.5">
            <div className="flex items-center justify-between">
              <span className="text-slate-300 font-bold flex items-center gap-1.5">
                <Network className="w-3.5 h-3.5 text-emerald-400" />
                SOAR Webhook Gateway
              </span>
              <span className="text-[9px] px-1.5 py-0.5 rounded bg-red-500/10 text-red-400 border border-red-500/30 font-bold">
                UNCONNECTED
              </span>
            </div>
            <p className="text-[10px] text-slate-400 font-sans">
              Requires Tines, Shuffle, or Cortex XSOAR webhook to enforce edge ACL blocks.
            </p>
          </div>
        </div>
      </div>

      {/* Agents Status Cards (Truthful Blueprints) */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
        {agents.map((agent) => (
          <div 
            key={agent.id}
            className="command-card p-3.5 space-y-2.5 border-purple-500/20 hover:border-purple-500/40 transition-colors"
          >
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <div className="w-2 h-2 rounded-full bg-slate-500" />
                <span className="font-mono text-xs font-bold text-white">{agent.name}</span>
              </div>
              <span className="text-[10px] font-mono text-purple-400 font-bold">{agent.codename}</span>
            </div>

            <div className="text-[11px] font-sans text-slate-300">
              {agent.role}
            </div>

            <div className="grid grid-cols-2 gap-1.5 font-mono text-[10px] bg-[#111827] p-2 rounded border border-[#1C273C]">
              <div>
                <span className="text-slate-400 block">Status</span>
                <span className="font-bold text-amber-400">OFFLINE</span>
              </div>
              <div>
                <span className="text-slate-400 block">Neutralized</span>
                <span className="font-bold text-slate-400">0 (Honest)</span>
              </div>
            </div>

            <div className="text-[10px] font-mono text-slate-400 truncate" title={agent.activePlaybook}>
              Role: <strong className="text-slate-200">{agent.activePlaybook}</strong>
            </div>
          </div>
        ))}
      </div>

      {/* Main Grid: Playbook Dispatcher (5 cols) & Live Telemetry Feed (7 cols) */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
        {/* Left Column: Manual Playbook Override (Disabled honestly) */}
        <div className="lg:col-span-5 space-y-4">
          <div className="command-card p-4 space-y-4">
            <div className="flex items-center justify-between">
              <h3 className="text-xs font-bold font-mono uppercase tracking-wider text-white">
                Dispatch Playbook Action
              </h3>
              <span className="text-[9px] font-mono px-1.5 py-0.5 rounded bg-slate-800 text-slate-400 border border-slate-700">
                LOCKED
              </span>
            </div>

            <div className="space-y-3 font-mono text-xs opacity-60 pointer-events-none">
              <div className="space-y-1">
                <label className="text-[10px] text-slate-400 uppercase">Assigned Agent Node</label>
                <select
                  value={selectedAgentId}
                  disabled
                  className="w-full h-8 px-2 bg-[#111827] border border-[#1C273C] rounded text-slate-400 cursor-not-allowed"
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
                  disabled
                  className="w-full h-8 px-2.5 bg-[#111827] border border-[#1C273C] rounded text-slate-400 cursor-not-allowed"
                />
              </div>

              <div className="space-y-1">
                <label className="text-[10px] text-slate-400 uppercase">Target Sandbox / Asset</label>
                <input
                  type="text"
                  value={targetInput}
                  disabled
                  className="w-full h-8 px-2.5 bg-[#111827] border border-[#1C273C] rounded text-slate-400 cursor-not-allowed"
                />
              </div>
            </div>

            <div className="pt-2">
              <button
                type="button"
                disabled
                className="w-full py-2.5 px-3 rounded bg-slate-800 text-slate-500 font-bold font-sans text-xs uppercase tracking-wider border border-slate-700 cursor-not-allowed flex items-center justify-center gap-2"
                title="Playbook execution disabled until an autonomous SOAR worker node is registered"
              >
                <AlertOctagon className="w-3.5 h-3.5" />
                <span>Execution Disabled (No Worker Daemon)</span>
              </button>
              <p className="text-[10px] text-slate-400 font-sans mt-2 text-center">
                Action execution is disabled to prevent simulated remediation. Register a live worker daemon to unlock playbooks.
              </p>
            </div>
          </div>
        </div>

        {/* Right Column: Live Swarm Telemetry Stream */}
        <div className="lg:col-span-7 space-y-4">
          <div className="command-card p-4 space-y-3 min-h-[340px] flex flex-col justify-between">
            <div>
              <div className="flex items-center justify-between border-b border-[#1C273C] pb-2.5 mb-3">
                <h3 className="text-xs font-bold font-mono uppercase tracking-wider text-white">
                  Autonomous Swarm Audit Log
                </h3>
                <span className="text-[10px] font-mono text-slate-400">
                  REAL-TIME TELEMETRY STREAM
                </span>
              </div>

              {events.length === 0 ? (
                <div className="py-12 flex flex-col items-center justify-center text-center space-y-2.5 text-slate-400">
                  <div className="w-10 h-10 rounded-full bg-purple-500/10 border border-purple-500/20 flex items-center justify-center text-purple-400">
                    <Bot className="w-5 h-5" />
                  </div>
                  <h4 className="text-xs font-bold text-white font-sans">
                    Zero Simulated Events Logged
                  </h4>
                  <p className="text-[11px] max-w-sm font-sans text-slate-400">
                    In compliance with CyberGuard data integrity standards, synthetic events are not generated. Genuine consensus events will appear once worker nodes are connected.
                  </p>
                </div>
              ) : (
                <div className="space-y-2 max-h-[320px] overflow-y-auto">
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
                    </div>
                  ))}
                </div>
              )}
            </div>

            <div className="text-[10px] font-mono text-slate-400 pt-3 border-t border-[#1C273C] flex items-center justify-between">
              <span>Swarm Consensus Engine: BFT Mesh</span>
              <span className="text-slate-500">Zero Simulated Telemetry</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
