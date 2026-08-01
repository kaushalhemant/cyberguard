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
        addLog('Available commands:', 'success');
        addLog('  cyberguard-scan <email>  - Run deep AI breach search on target email', 'output');
        addLog('  nmap <host/IP>          - Simulate a stealth port scan on target domain', 'output');
        addLog('  whois <domain>          - Retrieve registrar registry records', 'output');
        addLog('  clear                   - Clear the screen buffer logs', 'output');
        break;

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
              addLog('[~] Launch AI PDF Threat Report Generator on the Dashboard to mitigate.', 'success');
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
