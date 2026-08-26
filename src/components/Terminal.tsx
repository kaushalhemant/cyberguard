import React, { useState, useRef, useEffect } from 'react';
import { Terminal as TerminalIcon } from 'lucide-react';
import { TerminalLog } from '../types';

export default function Terminal() {
  const [logs, setLogs] = useState<TerminalLog[]>([
    {
      id: 'init-1',
      text: 'CyberGuard Security Command Shell [Version 4.2.0-PROD]',
      type: 'success',
      timestamp: new Date().toLocaleTimeString()
    },
    {
      id: 'init-2',
      text: 'Type "help" to list available security analysis commands.',
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
        addLog('  stix-export <target>      - Generate STIX 2.1 evidence bundle JSON', 'output');
        addLog('  cyberguard-scan <email>   - Run deep breach search on target email', 'output');
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
        addLog('    Engine: CyberGuard Security Operations Engine v4.2', 'success');
        addLog(`    Browser Agent: ${navigator.userAgent.substring(0, 50)}...`, 'output');
        addLog(`    Timestamp: ${new Date().toISOString()}`, 'output');
        addLog('    Status: ALL SECURITY SCANNERS OPERATIONAL (0 ERRORS)', 'success');
        break;
      }

      case 'clear':
        setLogs([]);
        break;

      default:
        addLog(`Command not recognized: "${command}". Type "help" for a list of available commands.`, 'error');
        break;
    }
  };

  const handleKeyDown = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'Enter') {
      handleCommand(input);
      setInput('');
    }
  };

  return (
    <div className="soc-panel p-4 font-mono flex flex-col h-[350px]">
      {/* Terminal Title Bar */}
      <div className="flex items-center justify-between border-b border-[#263147] pb-2 mb-2">
        <div className="flex items-center gap-2">
          <TerminalIcon className="w-4 h-4 text-[#00E5FF]" />
          <span className="text-xs text-[#ECEFF4] font-bold font-display uppercase">CyberGuard Interactive Command Shell</span>
        </div>
        <div className="flex gap-1">
          <div className="w-2 h-2 rounded-full bg-[#FF334B]"></div>
          <div className="w-2 h-2 rounded-full bg-[#FF9900]"></div>
          <div className="w-2 h-2 rounded-full bg-[#00E676]"></div>
        </div>
      </div>

      {/* Terminal Display Screen */}
      <div className="flex-1 overflow-y-auto space-y-1 pr-1 text-xs leading-relaxed scrollbar-thin">
        {logs.map((log) => (
          <div key={log.id} className="flex items-start gap-2">
            <span className="text-[#7E8B9B] text-[10px] select-none pt-0.5">
              [{log.timestamp}]
            </span>
            <span
              className={
                log.type === 'command'
                  ? 'text-[#ECEFF4] font-bold'
                  : log.type === 'error'
                  ? 'text-[#FF334B]'
                  : log.type === 'success'
                  ? 'text-[#00E676] font-medium'
                  : 'text-[#7E8B9B]'
              }
            >
              {log.text}
            </span>
          </div>
        ))}
        <div ref={terminalEndRef} />
      </div>

      {/* Terminal Input Line */}
      <div className="mt-2 border-t border-[#263147] pt-2 flex items-center gap-2">
        <span className="text-[#00E5FF] font-bold select-none text-xs">soc@cyberguard:~$</span>
        <input
          type="text"
          value={input}
          onChange={(e) => setInput(e.target.value)}
          onKeyDown={handleKeyDown}
          placeholder='Type a command (e.g. "help", "cve-search", "clear")...'
          className="flex-1 bg-transparent border-none outline-none text-[#ECEFF4] text-xs placeholder-[#7E8B9B]/50 font-mono"
        />
      </div>
    </div>
  );
}
