import React, { useState, useRef, useEffect } from 'react';
import { Terminal as TerminalIcon, ShieldAlert, Check, RefreshCw } from 'lucide-react';
import { TerminalLog } from '../types';

export default function Terminal() {
  const [logs, setLogs] = useState<TerminalLog[]>([
    {
      id: 'init-1',
      text: 'CyberGuard Interactive Kali Shell [Version 4.2.14-CG]',
      type: 'success',
      timestamp: new Date().toLocaleTimeString()
    },
    {
      id: 'init-2',
      text: 'Type "help" to list available security commands.',
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
    const newLog: TerminalLog = {
      id: Math.random().toString(36).substring(7),
      text,
      type,
      timestamp: new Date().toLocaleTimeString()
    };
    setLogs(prev => [...prev, newLog]);
  };

  const handleCommand = (cmdStr: string) => {
    const trimmed = cmdStr.trim();
    if (!trimmed) return;

    addLog(`$ ${trimmed}`, 'command');

    const args = trimmed.split(' ');
    const command = args[0].toLowerCase();

    switch (command) {
      case 'help':
        addLog('CyberGuard Official SOC Security Commands:', 'success');
        addLog('  cve-search <query>        - Search NIST NVD CVE vulnerability records by keyword', 'output');
        addLog('  sys-info                  - Display SOC system telemetry & runtime stats', 'output');
        addLog('  soc-osint <ip/domain>     - Perform deep OSINT IP forensic inspection & port audit', 'output');
        addLog('  soc-hash <sha256/md5>     - Analyze malware binary hash, entropy & YARA matches', 'output');
        addLog('  soc-triage <incident-id>  - Update SIEM incident status & containment playbook', 'output');
        addLog('  stix-export <target>      - Generate STIX 2.1 evidence bundle JSON', 'output');
        addLog('  cyberguard-scan <email>   - Run deep breach search on target email', 'output');
        addLog('  nmap <host/IP>           - Stealth port scan on target host', 'output');
        addLog('  whois <domain>           - Retrieve registrar WHOIS records', 'output');
        addLog('  clear                    - Clear the terminal screen buffer', 'output');
        break;

      case 'cve-search': {
        const query = args.slice(1).join(' ');
        if (!query) {
          addLog('Error: Specify a search query. Example: cve-search Log4j', 'error');
          break;
        }
        addLog(`[~] Querying NIST NVD CVE vulnerability records for: "${query}"...`, 'output');
        fetch(`/api/cve/search?query=${encodeURIComponent(query)}&limit=5`)
          .then(res => res.json())
          .then(data => {
            if (!data.cves || data.cves.length === 0) {
              addLog(`[-] No CVE records found matching "${query}".`, 'error');
            } else {
              addLog(`[+] Found ${data.totalMatches} matches in NIST NVD database (showing top ${data.cves.length}):`, 'success');
              data.cves.forEach((cve: any) => {
                addLog(`    - ${cve.id} [${cve.severity}] (Score: ${cve.score}/10): ${cve.description.substring(0, 100)}...`, cve.severity === 'CRITICAL' ? 'error' : 'output');
              });
            }
          })
          .catch(err => addLog(`[-] CVE search failed: ${err.message}`, 'error'));
        break;
      }

      case 'sys-info': {
        addLog('[~] Gathering CyberGuard SOC Core System Telemetry...', 'output');
        addLog('    Engine: CyberGuard Security Operations Engine v4.0', 'success');
        addLog(`    Browser Agent: ${navigator.userAgent.substring(0, 50)}...`, 'output');
        addLog(`    Timestamp: ${new Date().toISOString()}`, 'output');
        addLog('    Status: ALL 7 THREAT SCANNERS OPERATIONAL (0 ERRORS)', 'success');
        break;
      }

      case 'soc-osint': {
        const target = args[1];
        if (!target) {
          addLog('Error: Specify IP or domain. Example: soc-osint 185.220.101.5', 'error');
          break;
        }
        addLog(`[~] Dispatching OSINT Forensic Query for target: ${target}...`, 'output');
        fetch('/api/soc/osint-lookup', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ target })
        })
          .then(res => res.json())
          .then(data => {
            if (data.error) {
              addLog(`[-] OSINT Error: ${data.error}`, 'error');
            } else {
              addLog(`[+] OSINT Target: ${data.target} -> Resolved IP: ${data.resolvedIp}`, 'success');
              addLog(`    Geo: ${data.location.city}, ${data.location.country} (${data.location.flag}) | ISP: ${data.location.isp}`, 'output');
              addLog(`    Threat Score: ${data.reputationScore}/100 | Blacklists Listed: ${data.blacklists.filter((b: any) => b.listed).length}`, 'error');
              addLog(`    Open Ports: ${data.openPorts.filter((p: any) => p.state === 'open').map((p: any) => `${p.port}/${p.service}`).join(', ') || 'None'}`, 'output');
            }
          })
          .catch(err => addLog(`[-] Failed to query OSINT API: ${err.message}`, 'error'));
        break;
      }

      case 'soc-hash': {
        const hashVal = args[1];
        if (!hashVal) {
          addLog('Error: Specify binary hash string. Example: soc-hash e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', 'error');
          break;
        }
        addLog(`[~] Analyzing Cryptographic Hash Forensics: ${hashVal}...`, 'output');
        fetch('/api/soc/hash-lookup', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ hash: hashVal })
        })
          .then(res => res.json())
          .then(data => {
            if (data.error) {
              addLog(`[-] Hash Forensics Error: ${data.error}`, 'error');
            } else {
              addLog(`[+] Hash Type: ${data.hashType} | Format: ${data.detectedFormat}`, 'success');
              addLog(`    Entropy Score: ${data.entropyScore}/8.00 (Packed/Obfuscated: ${data.isPackedOrEncrypted ? 'YES' : 'NO'})`, 'output');
              addLog(`    Classification: ${data.malwareClassification.toUpperCase()} | Threat Family: ${data.threatFamily || 'None'}`, data.malwareClassification === 'malicious' ? 'error' : 'success');
              addLog(`    YARA Rules Matched: ${data.matchedYaraRules.join(', ')}`, 'output');
            }
          })
          .catch(err => addLog(`[-] Hash lookup failed: ${err.message}`, 'error'));
        break;
      }

      case 'stix-export': {
        const target = args[1] || '185.220.101.5';
        addLog(`[~] Generating STIX 2.1 Threat Evidence Bundle for: ${target}...`, 'output');
        fetch('/api/soc/stix-export', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ target, notes: 'Terminal CLI STIX Export' })
        })
          .then(res => res.json())
          .then(data => {
            addLog(`[+] STIX Bundle Created: ${data.stixBundle.id}`, 'success');
            addLog(`    Digital Signature Seal: ${data.stixBundle.chainOfCustody.digitalSignatureSeal.substring(0, 32)}...`, 'output');
            addLog('    Official DFIR Evidence Bundle ready for agency reporting.', 'success');
          })
          .catch(err => addLog(`[-] STIX export error: ${err.message}`, 'error'));
        break;
      }

      case 'clear':
        setLogs([]);
        break;

      case 'cyberguard-scan': {
        const targetEmail = args[1];
        if (!targetEmail || !targetEmail.includes('@')) {
          addLog('Error: Please provide a valid email format. Example: cyberguard-scan target@test.com', 'error');
        } else {
          addLog(`[~] Initializing cyberguard-scan core engine against ${targetEmail}...`, 'output');
          addLog('[*] Resolving HIBP database credentials...', 'output');
          
          setTimeout(() => {
            if (targetEmail === 'secure@cyberguard.com') {
              addLog('[+] CyberGuard scan completed. No active breaches found! Status: SECURE.', 'success');
            } else {
              addLog(`[!] VULNERABILITY ALERT: Found 2 credential leaks associated with ${targetEmail}!`, 'error');
              addLog('    - Leaked in Canva Design Hub (Domain: canva.com)', 'error');
              addLog('    - Leaked in Adobe Inc (Domain: adobe.com)', 'error');
              addLog('[~] Launch PDF Threat Report Generator on the Dashboard to mitigate.', 'success');
            }
          }, 1200);
        }
        break;
      }

      case 'nmap': {
        const host = args[1];
        if (!host) {
          addLog('Error: Please provide a target host. Example: nmap google.com', 'error');
          break;
        }
        addLog(`Starting Nmap 7.92 ( https://nmap.org ) at ${new Date().toISOString()}`, 'output');
        addLog(`Initiating SYN Stealth Scan against ${host}...`, 'output');
        
        setTimeout(() => {
          addLog(`Nmap scan report for ${host} (${Math.floor(Math.random() * 254) + 1}.8.14.92)`, 'success');
          addLog('Host is up (0.012s latency).', 'output');
          addLog('Not shown: 997 closed ports', 'output');
          addLog('PORT     STATE    SERVICE', 'success');
          addLog('22/tcp   open     ssh', 'output');
          addLog('80/tcp   open     http', 'output');
          addLog('443/tcp  open     https', 'output');
          addLog('Nmap done: 1 IP address scanned in 1.45 seconds', 'success');
        }, 1500);
        break;
      }

      case 'whois': {
        const domain = args[1];
        if (!domain) {
          addLog('Error: Please specify a domain. Example: whois cyberguard.org', 'error');
          break;
        }
        addLog(`[~] Fetching WHOIS data for: ${domain}...`, 'output');
        
        setTimeout(() => {
          addLog(`Domain Name: ${domain.toUpperCase()}`, 'success');
          addLog('Registry Domain ID: CG-9871239841_DOMAIN-OR', 'output');
          addLog('Registrar WHOIS Server: whois.iana.org', 'output');
          addLog('Registrar: CyberGuard Security Registrar, LLC', 'output');
          addLog('Creation Date: 2018-04-14T11:22:00Z', 'output');
          addLog('Registrant State/Province: Security Ops', 'output');
          addLog('DNSSEC: signedDelegation', 'success');
        }, 1000);
        break;
      }

      default:
        addLog(`bash: command not found: ${command}. Type "help" for a list of valid controls.`, 'error');
    }
  };

  const handleKeyDown = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'Enter') {
      handleCommand(input);
      setInput('');
    }
  };

  return (
    <div className="bento-card p-4 font-mono flex flex-col h-[400px]">
      {/* Terminal Title Bar */}
      <div className="flex items-center justify-between border-b border-slate-800 pb-2 mb-3">
        <div className="flex items-center gap-2">
          <TerminalIcon className="w-4 h-4 text-emerald-500" />
          <span className="text-xs text-slate-400 font-semibold font-display">Kali Linux Interactive Terminal (Simulation)</span>
        </div>
        <div className="flex gap-1.5">
          <div className="w-2.5 h-2.5 rounded-full bg-rose-500/80"></div>
          <div className="w-2.5 h-2.5 rounded-full bg-amber-500/80"></div>
          <div className="w-2.5 h-2.5 rounded-full bg-emerald-500/80"></div>
        </div>
      </div>

      {/* Terminal Display Screen */}
      <div className="flex-1 overflow-y-auto space-y-1.5 pr-2 text-sm leading-relaxed scrollbar-thin">
        {logs.map((log) => (
          <div key={log.id} className="flex items-start gap-2">
            <span className="text-slate-600 text-[10px] select-none pt-0.5 font-sans">
              [{log.timestamp}]
            </span>
            <span
              className={
                log.type === 'command'
                  ? 'text-slate-300 font-bold'
                  : log.type === 'error'
                  ? 'text-rose-400'
                  : log.type === 'success'
                  ? 'text-emerald-400 font-medium'
                  : 'text-slate-400'
              }
            >
              {log.text}
            </span>
          </div>
        ))}
        <div ref={terminalEndRef} />
      </div>

      {/* Terminal Input Line */}
      <div className="mt-3 border-t border-slate-800 pt-2 flex items-center gap-2">
        <span className="text-emerald-400 font-bold select-none text-sm">kali@cyberguard:~$</span>
        <input
          type="text"
          value={input}
          onChange={(e) => setInput(e.target.value)}
          onKeyDown={handleKeyDown}
          placeholder='Type a command (e.g., "help", "nmap", "clear")...'
          className="flex-1 bg-transparent border-none outline-none text-slate-100 text-sm placeholder-slate-600 caret-emerald-500 font-mono"
        />
      </div>
    </div>
  );
}
