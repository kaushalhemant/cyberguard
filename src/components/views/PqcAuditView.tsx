import React, { useState } from 'react';
import { 
  Lock, Atom, ShieldCheck, AlertTriangle, RefreshCw, 
  ExternalLink, ArrowUpRight, Cpu, Zap
} from 'lucide-react';
import { PqcAnalysisResult, QuantumSimResult } from '../../types';
import StatusBadge from '../common/StatusBadge';

interface PqcAuditViewProps {
  token: string;
  onAnalyzePqc: (target: string) => Promise<PqcAnalysisResult | null>;
  onSimulateQuantum: (cipher: 'RSA' | 'ECC' | 'ML-KEM', keySize: number) => Promise<QuantumSimResult | null>;
  pqcResult: PqcAnalysisResult | null;
  simResult: QuantumSimResult | null;
  loading: boolean;
}

export default function PqcAuditView({
  token,
  onAnalyzePqc,
  onSimulateQuantum,
  pqcResult,
  simResult,
  loading
}: PqcAuditViewProps) {
  const [targetDomain, setTargetDomain] = useState('quantum-defense.gov');
  const [simCipher, setSimCipher] = useState<'RSA' | 'ECC' | 'ML-KEM'>('RSA');
  const [simKeySize, setSimKeySize] = useState<number>(2048);

  const handleAudit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!targetDomain.trim()) return;
    await onAnalyzePqc(targetDomain.trim());
  };

  const handleSimulate = async (e: React.FormEvent) => {
    e.preventDefault();
    await onSimulateQuantum(simCipher, simKeySize);
  };

  return (
    <div className="space-y-4">
      {/* Header Banner */}
      <div className="command-card p-4 sm:p-5 flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <div className="w-8 h-8 rounded bg-purple-500/10 border border-purple-500/30 flex items-center justify-center text-purple-400">
              <Atom className="w-4 h-4" />
            </div>
            <h2 className="text-base font-bold font-display uppercase tracking-wider text-white">
              NIST Post-Quantum Cryptography (PQC) & Shor Simulator
            </h2>
            <span className="px-1.5 py-0.5 rounded text-[9px] font-mono font-bold bg-purple-500/20 text-purple-300 border border-purple-500/40">
              FIPS 203 / 204 / 205
            </span>
          </div>
          <p className="text-xs text-slate-400 font-sans mt-1 max-w-3xl">
            Audit endpoint cipher suites against Harvest-Now-Decrypt-Later (HNDL) quantum threats, verify Module-Lattice Key Encapsulation (ML-KEM / Kyber), and simulate Shor's polynomial-time factoring against classical RSA and ECC keys.
          </p>
        </div>

        {/* 1-Click Samples */}
        <div className="flex flex-wrap items-center gap-2">
          <span className="text-[10px] font-mono text-slate-400 uppercase">Presets:</span>
          <button
            onClick={() => {
              setTargetDomain('quantum-defense.gov');
              onAnalyzePqc('quantum-defense.gov');
            }}
            className="px-2 py-1 rounded bg-[#131C2E] hover:bg-[#1A263D] border border-purple-500/30 text-purple-300 text-[10px] font-mono transition-colors"
          >
            🛡️ PQC Mesh (quantum-defense.gov)
          </button>
          <button
            onClick={() => {
              setTargetDomain('legacy-bank.org');
              onAnalyzePqc('legacy-bank.org');
            }}
            className="px-2 py-1 rounded bg-[#131C2E] hover:bg-[#1A263D] border border-red-500/30 text-red-300 text-[10px] font-mono transition-colors"
          >
            🚨 Legacy RSA (legacy-bank.org)
          </button>
        </div>
      </div>

      {/* Main Grid: PQC Audit (6 cols) & Shor Simulator (6 cols) */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
        {/* Left Column: PQC Endpoint Audit (6 cols) */}
        <div className="lg:col-span-6 space-y-4">
          <div className="command-card p-4 space-y-4">
            <h3 className="text-xs font-bold font-mono uppercase tracking-wider text-white">
              PQC Endpoint Migration Readiness Audit
            </h3>

            <form onSubmit={handleAudit} className="flex gap-2">
              <input
                type="text"
                value={targetDomain}
                onChange={(e) => setTargetDomain(e.target.value)}
                placeholder="e.g. enterprise-domain.com"
                className="flex-1 h-8.5 px-3 bg-[#111827] border border-[#1C273C] rounded text-xs text-slate-200 placeholder-slate-500 focus:border-purple-500 font-mono"
              />
              <button
                type="submit"
                disabled={loading}
                className="px-3.5 h-8.5 rounded bg-purple-600 hover:bg-purple-500 text-white font-bold font-sans text-xs uppercase tracking-wider transition-colors shrink-0"
              >
                Audit Endpoint
              </button>
            </form>

            {pqcResult && (
              <div className="space-y-3 pt-2 border-t border-[#1C273C]">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-mono text-slate-300 truncate max-w-[200px]">
                    {pqcResult.target}
                  </span>
                  <StatusBadge 
                    severity={pqcResult.quantumReadinessScore >= 80 ? 'low' : (pqcResult.quantumReadinessScore >= 40 ? 'high' : 'critical')} 
                    label={pqcResult.complianceStatus}
                  />
                </div>

                {/* Score Bar */}
                <div className="space-y-1">
                  <div className="flex justify-between items-center text-xs font-mono">
                    <span className="text-slate-400">Quantum Readiness Index:</span>
                    <span className="text-purple-400 font-bold">{pqcResult.quantumReadinessScore} / 100</span>
                  </div>
                  <div className="w-full h-2 bg-[#090D14] rounded-full overflow-hidden flex">
                    <div 
                      className="bg-purple-500 h-full transition-all" 
                      style={{ width: `${pqcResult.quantumReadinessScore}%` }} 
                    />
                  </div>
                </div>

                {/* Ciphers Evaluation */}
                <div className="space-y-1.5">
                  <span className="text-[10px] font-mono text-slate-400 uppercase block">Audited Cryptographic Algorithms:</span>
                  {pqcResult.ciphers.map((c, idx) => (
                    <div key={idx} className="p-2 rounded bg-[#101726] border border-[#1C273C] flex items-center justify-between text-xs font-mono">
                      <div>
                        <span className="font-bold text-white block">{c.name}</span>
                        <span className="text-[10px] text-slate-400">{c.nistStandard}</span>
                      </div>
                      <StatusBadge severity={c.quantumResistant ? 'low' : 'critical'} label={c.quantumResistant ? 'RESISTANT' : 'BROKEN'} />
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        </div>

        {/* Right Column: Quantum Shor Cryptanalysis Simulator (6 cols) */}
        <div className="lg:col-span-6 space-y-4">
          <div className="command-card p-4 space-y-4">
            <h3 className="text-xs font-bold font-mono uppercase tracking-wider text-white">
              Shor's Algorithm Quantum Cracking Simulator
            </h3>

            <form onSubmit={handleSimulate} className="grid grid-cols-2 gap-2.5">
              <div className="space-y-1">
                <label className="text-[10px] font-mono text-slate-400 uppercase">Algorithm</label>
                <select
                  value={simCipher}
                  onChange={(e) => setSimCipher(e.target.value as any)}
                  className="w-full h-8 px-2 bg-[#111827] border border-[#1C273C] rounded text-xs text-slate-300"
                >
                  <option value="RSA">RSA (Factoring)</option>
                  <option value="ECC">ECC (Discrete Log)</option>
                  <option value="ML-KEM">ML-KEM / Kyber (Lattice)</option>
                </select>
              </div>

              <div className="space-y-1">
                <label className="text-[10px] font-mono text-slate-400 uppercase">Key Size (Bits)</label>
                <select
                  value={simKeySize}
                  onChange={(e) => setSimKeySize(parseInt(e.target.value, 10))}
                  className="w-full h-8 px-2 bg-[#111827] border border-[#1C273C] rounded text-xs text-slate-300"
                >
                  <option value={1024}>1024 bits</option>
                  <option value={2048}>2048 bits</option>
                  <option value={4096}>4096 bits</option>
                </select>
              </div>

              <button
                type="submit"
                className="col-span-2 h-8 rounded bg-gradient-to-r from-purple-600 to-indigo-600 hover:from-purple-500 hover:to-indigo-500 text-white font-bold font-sans text-xs uppercase tracking-wider transition-colors"
              >
                Simulate Shor Execution
              </button>
            </form>

            {simResult && (
              <div className="space-y-2.5 pt-2 border-t border-[#1C273C] font-mono text-xs">
                <div className="grid grid-cols-2 gap-2 text-[10px]">
                  <div className="bg-[#111827] border border-[#1C273C] p-2 rounded">
                    <span className="text-slate-400 block">Est. Logical Qubits</span>
                    <span className="font-bold text-xs text-cyan-300">{simResult.estimatedLogicalQubits.toLocaleString()}</span>
                  </div>
                  <div className="bg-[#111827] border border-[#1C273C] p-2 rounded">
                    <span className="text-slate-400 block">Shor Execution Time</span>
                    <span className={`font-bold text-xs ${simResult.shorExecutionSeconds < 60 ? 'text-red-400' : 'text-emerald-400'}`}>
                      {simResult.shorExecutionSeconds < 60 ? `${simResult.shorExecutionSeconds}s (Instant)` : '> 10^12 yrs'}
                    </span>
                  </div>
                </div>

                <div className="bg-[#101726] p-2.5 rounded border border-[#1C273C] space-y-1">
                  <span className="text-[10px] text-amber-400 uppercase font-bold block">Security Assessment:</span>
                  <p className="text-xs text-slate-300 font-sans">{simResult.securityAssessment}</p>
                </div>

                <div className="bg-[#101726] p-2.5 rounded border border-[#1C273C] space-y-1">
                  <span className="text-[10px] text-purple-300 uppercase font-bold block">PQC Recommendation:</span>
                  <p className="text-xs text-slate-300 font-sans">{simResult.recommendedPqcAlternative}</p>
                </div>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
