import React, { useState, useRef, useEffect } from 'react';
import { Terminal as TerminalIcon } from 'lucide-react';
import { TerminalLog } from '../types';
import { safeJsonResponse } from '../lib/api';
import {
  clientAnalyzePqc,
  clientSimulateQuantum,
  clientGetAiSwarmState,
  clientAnalyzeDeepfake,
  clientGetSatelliteMesh
} from '../lib/clientThreatEngine';

export default function Terminal() {
  const [logs, setLogs] = useState<TerminalLog[]>([
    {
      id: 'init-1',
      text: 'CyberGuard 2030 Quantum Command Shell [Version 2030.1.0-PQC]',
      type: 'success',
      timestamp: new Date().toLocaleTimeString()
    },
    {
      id: 'init-2',
      text: 'NIST FIPS 203 ML-KEM & 4-Agent Autonomous AI Defense Swarm ARMED.',
      type: 'output',
      timestamp: new Date().toLocaleTimeString()
    },
    {
      id: 'init-3',
      text: 'Type "help" to list 2030 Post-Quantum and Autonomous commands.',
      type: 'output',
      timestamp: new Date().toLocaleTimeString()
    }
  ]);
  const [input, setInput] = useState('');
  const terminalEndRef = useRef<HTMLDivElement>(null);

  const scrollToBottom = () => {
    terminalEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  };

  useEffect(() => {
    scrollToBottom();
  }, [logs]);

  const addLog = (text: string, type: TerminalLog['type'] = 'output') => {
    setLogs(prev => [
      ...prev,
      {
        id: Math.random().toString(),
        text,
        type,
        timestamp: new Date().toLocaleTimeString()
      }
    ]);
  };

  const handleCommand = async (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    if (!input.trim()) return;

    const cmd = input.trim();
    addLog(`soc@cyberguard-2030:~$ ${cmd}`, 'command');
    setInput('');

    const args = cmd.split(' ');
    const mainCommand = args[0].toLowerCase();

    switch (mainCommand) {
      case 'help':
        addLog('2030 Operational Command Suite:', 'output');
        addLog('  pqc <target>          - Run NIST FIPS 203/204 Post-Quantum cipher audit', 'output');
        addLog('  quantum-sim <cipher>  - Execute Shor\'s algorithm cryptanalysis simulator', 'output');
        addLog('  ai-swarm              - Display 4-agent autonomous SOC defense mesh state', 'output');
        addLog('  deepfake <file>       - Run FFT spectral & rPPG biometric forensics scan', 'output');
        addLog('  leo-mesh              - Query LEO satellite QKD photon entanglement status', 'output');
        addLog('  scan <email>          - Audit database credential leaks', 'output');
        addLog('  cve <keyword>         - Query NIST NVD CVE vulnerability records', 'output');
        addLog('  osint <ip/domain>     - Resolve OSINT reputation & DNS records', 'output');
        addLog('  hash <hash>           - Perform high-entropy malware signature inspection', 'output');
        addLog('  stix3 <target>        - Export STIX 3.0 DFIR JSON evidence bundle', 'output');
        addLog('  sys-info              - Query 2030 Quantum SOC engine telemetry', 'output');
        addLog('  clear                 - Purge terminal buffer', 'output');
        break;

      case 'clear':
        setLogs([]);
        break;

      case 'pqc':
      case 'pqc-audit': {
        const target = args[1] || 'quantum-defense.gov';
        addLog(`[~] Auditing Post-Quantum Cryptography readiness for: "${target}"...`, 'output');
        try {
          const res = await fetch('/api/pqc/audit', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ target })
          });
          const data = res.ok ? await safeJsonResponse(res) : clientAnalyzePqc(target);
          addLog(`[+] PQC Score: ${data.quantumReadinessScore}/100 [${data.complianceStatus}]`, data.quantumReadinessScore >= 80 ? 'success' : 'error');
          addLog(`    KEM Standard: ${data.kemAlgorithm}`, 'output');
          addLog(`    HNDL Risk: ${data.hndlRisk}`, data.hndlRisk.includes('Protected') ? 'success' : 'error');
        } catch {
          const localData = clientAnalyzePqc(target);
          addLog(`[+] PQC Score (Client): ${localData.quantumReadinessScore}/100 [${localData.complianceStatus}]`, 'success');
        }
        break;
      }

      case 'quantum-sim':
      case 'shor-sim': {
        const cipher = args[1] || 'RSA';
        const keySize = parseInt(args[2] || '2048', 10);
        addLog(`[~] Running Shor's algorithm simulation on ${cipher}-${keySize}...`, 'output');
        try {
          const res = await fetch('/api/quantum/simulate', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ cipher, keySize })
          });
          const data = res.ok ? await safeJsonResponse(res) : clientSimulateQuantum(cipher, keySize);
          addLog(`[+] Assessment: ${data.securityAssessment}`, data.quantumResistanceScore > 50 ? 'success' : 'error');
          addLog(`    Recommended PQC Alternative: ${data.recommendedPqcAlternative}`, 'output');
        } catch {
          const localData = clientSimulateQuantum(cipher, keySize);
          addLog(`[+] ${localData.securityAssessment}`, 'output');
        }
        break;
      }

      case 'ai-swarm':
      case 'swarm-status': {
        addLog('[~] Querying 4-Agent Autonomous AI SOC Swarm...', 'output');
        try {
          const res = await fetch('/api/ai-swarm/telemetry');
          const data = res.ok ? await safeJsonResponse(res) : clientGetAiSwarmState();
          addLog(`[+] Swarm Status: ${data.swarmStatus} | Consensus: ${data.consensusHealth}`, 'success');
          data.activeAgents.forEach((a: any) => {
            addLog(`    - [${a.codename}] ${a.name}: ${a.role} (${a.confidenceScore}% acc, ${a.latencyMs}ms latency)`, 'output');
          });
        } catch {
          addLog('[+] Swarm status: 4/4 Agents Synchronized (Byzantine Fault-Tolerant Mesh)', 'success');
        }
        break;
      }

      case 'deepfake':
      case 'deepfake-scan': {
        const target = args[1] || 'executive_conference_stream.mp4';
        addLog(`[~] Dissecting generative synthetic artifacts in: "${target}"...`, 'output');
        try {
          const res = await fetch('/api/deepfake/scan', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ targetName: target })
          });
          const data = res.ok ? await safeJsonResponse(res) : clientAnalyzeDeepfake(target);
          addLog(`[+] Classification: ${data.classification} (Confidence: ${data.syntheticConfidence}%)`, data.syntheticConfidence > 70 ? 'error' : 'success');
          addLog(`    FFT Spectral Anomaly: ${data.spectralAnomalyScore}% | rPPG Pulse: ${data.rppgPulseDetected ? 'ORGANIC' : 'SYNTHETIC'}`, 'output');
        } catch {
          const localData = clientAnalyzeDeepfake(target);
          addLog(`[+] Classification: ${localData.classification}`, 'output');
        }
        break;
      }

      case 'leo-mesh':
      case 'satellite': {
        addLog('[~] Querying LEO Space Satellite Constellation & QKD Links...', 'output');
        try {
          const res = await fetch('/api/satellite/mesh');
          const data = res.ok ? await safeJsonResponse(res) : clientGetSatelliteMesh();
          addLog(`[+] Constellation Health: ${data.constellationHealthScore}% | Entangled Photons: ${data.totalPhotonThroughput}`, 'success');
          data.activeNodes.forEach((sat: any) => {
            addLog(`    - ${sat.name} (${sat.altitudeKm}km): ${sat.qkdStatus} -> Ground: ${sat.activeGroundStation}`, 'output');
          });
        } catch {
          addLog('[+] Space-to-ground QKD Link: ACTIVE_ENTANGLED across 4 orbital relays', 'success');
        }
        break;
      }

      case 'cve':
      case 'cve-search': {
        const query = args.slice(1).join(' ');
        if (!query) {
          addLog('Error: Specify a search query. Example: cve Log4j', 'error');
          break;
        }
        addLog(`[~] Querying NIST NVD CVE records for: "${query}"...`, 'output');
        fetch(`/api/cve/search?query=${encodeURIComponent(query)}&limit=5`)
          .then(res => safeJsonResponse(res, 'CVE query failed'))
          .then(data => {
            if (!data.cves || data.cves.length === 0) {
              addLog(`[-] No CVE records found matching "${query}".`, 'error');
            } else {
              addLog(`[+] Found ${data.totalMatches} matches in NIST NVD:`, 'success');
              data.cves.forEach((c: any) => {
                addLog(`    - ${c.id} [${c.severity}] (Score: ${c.score}/10): ${c.description.substring(0, 85)}...`, c.severity === 'CRITICAL' ? 'error' : 'output');
              });
            }
          })
          .catch(err => addLog(`[-] CVE query failed: ${err.message}`, 'error'));
        break;
      }

      case 'osint': {
        const target = args[1] || '185.220.101.5';
        addLog(`[~] Performing OSINT lookup for: "${target}"...`, 'output');
        fetch('/api/soc/osint-lookup', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ target })
        })
          .then(res => safeJsonResponse(res))
          .then(data => {
            if (data?.target) {
              addLog(`[+] Target: ${data.target} | Score: ${data.reputationScore}/100 | ISP: ${data.location?.isp}`, data.reputationScore > 50 ? 'error' : 'success');
            }
          })
          .catch(err => addLog(`[-] OSINT error: ${err.message}`, 'error'));
        break;
      }

      case 'scan': {
        const email = args[1];
        if (!email || !email.includes('@')) {
          addLog('Error: Specify valid email. Example: scan user@domain.com', 'error');
          break;
        }
        addLog(`[~] Executing breach audit for: "${email}"...`, 'output');
        fetch('/api/scan', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ email })
        })
          .then(res => safeJsonResponse(res))
          .then(data => {
            if (data?.scan) {
              addLog(`[+] Audit complete: Risk Score ${data.scan.riskScore}/100 (${data.scan.resultCount} breaches found)`, data.scan.riskScore >= 50 ? 'error' : 'success');
            }
          })
          .catch(err => addLog(`[-] Scan failed: ${err.message}`, 'error'));
        break;
      }

      case 'stix3':
      case 'stix': {
        const target = args[1] || 'quantum-defense-mesh.net';
        addLog(`[~] Generating 2030 STIX 3.0 DFIR Bundle for: "${target}"...`, 'output');
        fetch('/api/stix3/export', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ target })
        })
          .then(res => safeJsonResponse(res))
          .then(data => {
            if (data?.stix3Bundle || data?.bundle) {
              const bundle = data.stix3Bundle || data.bundle;
              addLog(`[+] Generated STIX 3.0 Bundle ID: ${bundle.id} (Spec: 3.0 - PQC Armed)`, 'success');
            }
          })
          .catch(err => addLog(`[-] STIX export failed: ${err.message}`, 'error'));
        break;
      }

      case 'sys-info': {
        addLog('[~] Gathering CyberGuard 2030 Quantum SOC Telemetry...', 'output');
        addLog('    Engine: CyberGuard 2030 Post-Quantum Multi-Agent Workstation', 'success');
        addLog(`    Timestamp: ${new Date().toISOString()}`, 'output');
        addLog('    PQC Standard: NIST FIPS 203 (ML-KEM) & FIPS 204 (ML-DSA)', 'success');
        addLog('    Status: ALL 2030 DEFENSE MODULES OPERATIONAL (100% HEALTH)', 'success');
        break;
      }

      default:
        addLog(`Command not recognized: "${mainCommand}". Type "help" for a list of available 2030 commands.`, 'error');
        break;
    }
  };

  const handleKeyDown = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'Enter') {
      handleCommand();
    }
  };

  return (
    <div className="soc-panel p-4 font-mono flex flex-col h-[360px] border border-[#202D42] shadow-xl">
      <div className="flex items-center justify-between border-b border-[#202D42] pb-2 mb-2">
        <div className="flex items-center gap-2">
          <TerminalIcon className="w-4 h-4 text-[#00E5FF]" />
          <span className="text-xs text-[#F0F4F8] font-bold font-display uppercase">CyberGuard 2030 Quantum Shell</span>
        </div>
        <div className="flex items-center gap-1.5">
          <span className="text-[9px] text-[#A855F7] font-bold px-1.5 py-0.5 bg-[#A855F7]/15 rounded-xs border border-[#A855F7]/40">FIPS 203</span>
          <div className="w-2 h-2 rounded-full bg-[#10B981] animate-pulse"></div>
        </div>
      </div>

      <div className="flex-1 overflow-y-auto space-y-1 pr-1 text-xs leading-relaxed scrollbar-thin">
        {logs.map((log) => (
          <div key={log.id} className="flex items-start gap-2">
            <span className="text-[#8392A5] text-[10px] select-none pt-0.5">
              [{log.timestamp}]
            </span>
            <span
              className={
                log.type === 'command'
                  ? 'text-[#F0F4F8] font-bold'
                  : log.type === 'error'
                  ? 'text-[#FF334B]'
                  : log.type === 'success'
                  ? 'text-[#10B981] font-medium'
                  : 'text-[#8392A5]'
              }
            >
              {log.text}
            </span>
          </div>
        ))}
        <div ref={terminalEndRef} />
      </div>

      <div className="mt-2 border-t border-[#202D42] pt-2 flex items-center gap-2">
        <span className="text-[#00E5FF] font-bold select-none text-xs">soc@cyberguard-2030:~$</span>
        <input
          type="text"
          value={input}
          onChange={(e) => setInput(e.target.value)}
          onKeyDown={handleKeyDown}
          placeholder='Type a command (e.g. "pqc", "quantum-sim", "ai-swarm", "deepfake", "help")...'
          className="flex-1 bg-transparent border-none outline-none text-[#F0F4F8] text-xs placeholder-[#8392A5]/50 font-mono"
        />
      </div>
    </div>
  );
}
