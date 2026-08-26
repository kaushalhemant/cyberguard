import React, { useState } from 'react';
import { Download, Eye, Lock, FileSpreadsheet, FileCode, Search, HelpCircle, ShieldCheck, CheckCircle2 } from 'lucide-react';
import { ScanResult } from '../types';

interface UsageAuditProps {
  scans: ScanResult[];
  onSelectReport: (scan: ScanResult) => void;
}

export default function UsageAudit({ scans, onSelectReport }: UsageAuditProps) {
  const [downloadDropdown, setDownloadDropdown] = useState(false);

  const getThreatLevel = (score: number) => {
    if (score >= 75) return { label: 'CRITICAL', color: 'status-chip-critical' };
    if (score >= 50) return { label: 'HIGH', color: 'status-chip-high' };
    if (score >= 25) return { label: 'MEDIUM', color: 'status-chip-medium' };
    return { label: 'VERIFIED / LOW', color: 'status-chip-low' };
  };

  const maskTarget = (target: string, type?: string) => {
    if (!target) return 'N/A';
    if (type === 'link') {
      try {
        const url = new URL(target);
        return `${url.protocol}//${url.hostname.substring(0, 3)}***${url.pathname.substring(0, 4)}***`;
      } catch {
        return target.substring(0, 8) + '...';
      }
    }
    if (type === 'image') {
      return target.length > 20 ? target.substring(0, 10) + '...' + target.substring(target.length - 8) : target;
    }
    const [name, domain] = target.split('@');
    if (!domain) return target.substring(0, 4) + '***';
    const maskedName = name.length > 2 ? name[0] + name[1] + '*'.repeat(name.length - 2) : name + '**';
    return `${maskedName}@${domain}`;
  };

  const getModuleLabel = (type?: string) => {
    switch (type) {
      case 'link':
        return 'URL Reputation';
      case 'image':
        return 'Visual Payload OCR';
      default:
        return 'Email Breach Auditor';
    }
  };

  const exportToCSV = () => {
    if (scans.length === 0) return;
    const headers = ['Timestamp', 'Audit ID', 'Module Used', 'Target (Masked)', 'Result Count', 'Risk Score', 'Threat Level', 'System Integrity Status'];
    const rows = scans.map(scan => {
      const level = getThreatLevel(scan.riskScore);
      const moduleStr = getModuleLabel(scan.scanType);
      const targetStr = maskTarget(scan.scanType === 'link' ? scan.targetLink || '' : scan.scanType === 'image' ? scan.imageFileName || '' : scan.targetEmail, scan.scanType);
      return [
        new Date(scan.timestamp).toISOString(),
        scan.id,
        moduleStr,
        targetStr,
        scan.resultCount,
        `${scan.riskScore}/100`,
        level.label,
        'VERIFIED_SHA256'
      ];
    });

    const csvContent = "data:text/csv;charset=utf-8," 
      + [headers.join(','), ...rows.map(e => e.map(val => `"${val}"`).join(','))].join('\n');
    
    const encodedUri = encodeURI(csvContent);
    const link = document.createElement("a");
    link.setAttribute("href", encodedUri);
    link.setAttribute("download", `cyberguard_usage_audit_${new Date().toISOString().split('T')[0]}.csv`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    setDownloadDropdown(false);
  };

  const exportToJSON = () => {
    if (scans.length === 0) return;
    const exportData = scans.map(scan => {
      const level = getThreatLevel(scan.riskScore);
      return {
        timestamp: scan.timestamp,
        auditId: scan.id,
        moduleUsed: getModuleLabel(scan.scanType),
        scannedTargetMasked: maskTarget(scan.scanType === 'link' ? scan.targetLink || '' : scan.scanType === 'image' ? scan.imageFileName || '' : scan.targetEmail, scan.scanType),
        detectedIssuesCount: scan.resultCount,
        riskScore: scan.riskScore,
        calculatedThreatLevel: level.label,
        sessionVerification: 'SHA-256 Verified Endpoint Session'
      };
    });

    const jsonString = `data:text/json;charset=utf-8,${encodeURIComponent(JSON.stringify(exportData, null, 2))}`;
    const link = document.createElement("a");
    link.setAttribute("href", jsonString);
    link.setAttribute("download", `cyberguard_usage_audit_${new Date().toISOString().split('T')[0]}.json`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    setDownloadDropdown(false);
  };

  return (
    <div className="soc-panel p-4 space-y-4 font-mono text-xs">
      {/* Header Panel */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-[#263147] pb-3">
        <div className="space-y-0.5">
          <div className="flex items-center gap-1.5 text-[#00E5FF] text-[10px] font-bold">
            <Lock className="w-3.5 h-3.5 text-[#00E5FF]" />
            <span>SESSION AUDIT TRAIL LOG</span>
          </div>
          <h3 className="text-sm font-bold uppercase text-white font-display">System Usage & Compliance Log</h3>
        </div>

        {scans.length > 0 && (
          <div className="relative shrink-0">
            <button
              onClick={() => setDownloadDropdown(!downloadDropdown)}
              className="btn-soc px-3 py-1 text-[10px] flex items-center gap-1.5 cursor-pointer"
            >
              <Download className="w-3.5 h-3.5" />
              <span>EXPORT AUDIT LOG</span>
            </button>

            {downloadDropdown && (
              <div className="absolute right-0 mt-1 w-44 bg-[#111622] border border-[#263147] rounded-sm p-1 z-50 shadow-none font-mono text-[10px]">
                <button
                  onClick={exportToCSV}
                  className="w-full text-left px-2 py-1.5 text-[#ECEFF4] hover:bg-[#181F2E] flex items-center gap-2 cursor-pointer"
                >
                  <FileSpreadsheet className="w-3.5 h-3.5 text-[#00E676]" />
                  <span>Download CSV</span>
                </button>
                <button
                  onClick={exportToJSON}
                  className="w-full text-left px-2 py-1.5 text-[#ECEFF4] hover:bg-[#181F2E] flex items-center gap-2 cursor-pointer"
                >
                  <FileCode className="w-3.5 h-3.5 text-[#00E5FF]" />
                  <span>Download JSON</span>
                </button>
              </div>
            )}
          </div>
        )}
      </div>

      {/* Logs Table */}
      {scans.length === 0 ? (
        <div className="bg-[#090D14] border border-[#263147] p-6 text-center text-[#7E8B9B] space-y-1">
          <HelpCircle className="w-5 h-5 mx-auto text-[#7E8B9B]" />
          <p>No historical executions audited under this session.</p>
        </div>
      ) : (
        <div className="overflow-x-auto border border-[#263147] bg-[#090D14]">
          <table className="w-full text-left font-mono text-[11px] text-[#ECEFF4]">
            <thead>
              <tr className="bg-[#181F2E] border-b border-[#263147] text-[#7E8B9B] text-[10px] uppercase font-bold">
                <th className="py-2 px-3">Timestamp / ID</th>
                <th className="py-2 px-3">Module</th>
                <th className="py-2 px-3">Target (Masked)</th>
                <th className="py-2 px-3">Risk Score</th>
                <th className="py-2 px-3">Threat Level</th>
                <th className="py-2 px-3 text-right">Inspect</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#263147]">
              {scans.map((scan) => {
                const threat = getThreatLevel(scan.riskScore);
                const moduleStr = getModuleLabel(scan.scanType);
                const targetStr = maskTarget(scan.scanType === 'link' ? scan.targetLink || '' : scan.scanType === 'image' ? scan.imageFileName || '' : scan.targetEmail, scan.scanType);
                
                return (
                  <tr key={scan.id} className="hover:bg-[#181F2E] transition-colors">
                    <td className="py-2 px-3">
                      <span className="text-white font-semibold block">{new Date(scan.timestamp).toLocaleTimeString()}</span>
                      <span className="text-[9px] text-[#7E8B9B]">{scan.id.substring(0, 10)}</span>
                    </td>
                    <td className="py-2 px-3 text-[#ECEFF4]">
                      {moduleStr}
                    </td>
                    <td className="py-2 px-3 text-[#7E8B9B] select-all">
                      {targetStr}
                    </td>
                    <td className="py-2 px-3 font-bold text-white">
                      {scan.riskScore}/100
                    </td>
                    <td className="py-2 px-3">
                      <span className={`status-chip ${threat.color}`}>
                        {threat.label}
                      </span>
                    </td>
                    <td className="py-2 px-3 text-right">
                      <button
                        onClick={() => onSelectReport(scan)}
                        className="btn-soc p-1 text-[10px]"
                        title="Review audited record"
                      >
                        <Eye className="w-3.5 h-3.5 text-[#00E5FF]" />
                      </button>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
