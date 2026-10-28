import React, { useState, useMemo } from 'react';
import { 
  Globe, Mail, FileCode, Database, Video, AlertOctagon, 
  Search, Filter, ChevronLeft, ChevronRight, FileText, Download,
  ExternalLink, Trash2, Eye, ShieldCheck, ArrowUpDown
} from 'lucide-react';
import { ScanResult, SocIncident } from '../../types';
import StatusBadge from './StatusBadge';

export interface InvestigationItem {
  id: string;
  name: string;
  type: 'url' | 'hash' | 'email' | 'cve' | 'media' | 'incident';
  severity: 'critical' | 'high' | 'medium' | 'low';
  status: 'active' | 'investigating' | 'mitigated' | 'clean' | 'new';
  timestamp: string;
  source: string;
  rawScan?: ScanResult;
  rawIncident?: SocIncident;
}

interface InvestigationTableProps {
  scans: ScanResult[];
  incidents: SocIncident[];
  onSelectScanReport: (scan: ScanResult) => void;
  onSelectIncident?: (incident: SocIncident) => void;
  onInspectItem?: (item: InvestigationItem) => void;
}

export default function InvestigationTable({
  scans,
  incidents,
  onSelectScanReport,
  onSelectIncident,
  onInspectItem
}: InvestigationTableProps) {
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedType, setSelectedType] = useState<string>('all');
  const [selectedSeverity, setSelectedSeverity] = useState<string>('all');
  const [currentPage, setCurrentPage] = useState(1);
  const pageSize = 8;

  // Normalize scans and incidents into unified investigation assets list
  const allItems: InvestigationItem[] = useMemo(() => {
    const list: InvestigationItem[] = [];

    // 1. Incidents
    incidents.forEach(inc => {
      list.push({
        id: inc.id,
        name: inc.target || inc.title,
        type: 'incident',
        severity: inc.severity,
        status: inc.status === 'investigating' ? 'investigating' : (inc.status === 'mitigated' ? 'mitigated' : 'active'),
        timestamp: inc.timestamp,
        source: 'SIEM Core',
        rawIncident: inc
      });
    });

    // 2. Scans
    scans.forEach(scan => {
      let type: InvestigationItem['type'] = 'email';
      let name = scan.targetEmail;
      let source = 'Breach Ledger';

      if (scan.scanType === 'link') {
        type = 'url';
        name = scan.targetLink || 'inspected-link.org';
        source = 'URL Scanner';
      } else if (scan.scanType === 'image') {
        type = 'media';
        name = scan.targetImage || 'media_payload.png';
        source = 'Visual Forensics';
      }

      let severity: InvestigationItem['severity'] = 'low';
      let status: InvestigationItem['status'] = 'clean';
      if (scan.riskScore >= 70) {
        severity = 'critical';
        status = 'active';
      } else if (scan.riskScore >= 40) {
        severity = 'high';
        status = 'investigating';
      } else if (scan.riskScore >= 20) {
        severity = 'medium';
        status = 'investigating';
      }

      list.push({
        id: scan.id,
        name,
        type,
        severity,
        status,
        timestamp: scan.timestamp,
        source,
        rawScan: scan
      });
    });

    // Add baseline demonstration assets if table is sparse
    if (list.length < 5) {
      list.push(
        {
          id: 'AST-NVD-4966',
          name: 'CVE-2023-4966 (Citrix Bleed)',
          type: 'cve',
          severity: 'critical',
          status: 'active',
          timestamp: new Date(Date.now() - 45 * 60 * 1000).toISOString(),
          source: 'NIST NVD v2.0'
        },
        {
          id: 'AST-HASH-092',
          name: '44d88612fea8a8f36de82e1278abb02f (AsyncRAT)',
          type: 'hash',
          severity: 'high',
          status: 'investigating',
          timestamp: new Date(Date.now() - 95 * 60 * 1000).toISOString(),
          source: 'Hash Forensics'
        },
        {
          id: 'AST-DEEP-STREAM',
          name: 'executive_conference_stream.mp4',
          type: 'media',
          severity: 'critical',
          status: 'active',
          timestamp: new Date(Date.now() - 140 * 60 * 1000).toISOString(),
          source: 'Deepfake Lab'
        }
      );
    }

    // Sort by timestamp descending
    return list.sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime());
  }, [scans, incidents]);

  // Filtering
  const filteredItems = useMemo(() => {
    return allItems.filter(item => {
      const matchSearch = item.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
        item.source.toLowerCase().includes(searchTerm.toLowerCase()) ||
        item.type.toLowerCase().includes(searchTerm.toLowerCase());
      
      const matchType = selectedType === 'all' || item.type === selectedType;
      const matchSeverity = selectedSeverity === 'all' || item.severity === selectedSeverity;

      return matchSearch && matchType && matchSeverity;
    });
  }, [allItems, searchTerm, selectedType, selectedSeverity]);

  // Pagination
  const totalPages = Math.ceil(filteredItems.length / pageSize) || 1;
  const paginatedItems = useMemo(() => {
    const start = (currentPage - 1) * pageSize;
    return filteredItems.slice(start, start + pageSize);
  }, [filteredItems, currentPage, pageSize]);

  // Format relative timestamp
  const formatTime = (ts: string) => {
    try {
      const date = new Date(ts);
      const diffMs = Date.now() - date.getTime();
      const diffMins = Math.floor(diffMs / 60000);
      if (diffMins < 1) return 'Just now';
      if (diffMins < 60) return `${diffMins}m ago`;
      const diffHours = Math.floor(diffMins / 60);
      if (diffHours < 24) return `${diffHours}h ago`;
      return date.toLocaleDateString(undefined, { month: 'short', day: 'numeric' });
    } catch {
      return 'Recent';
    }
  };

  const getTypeIcon = (type: InvestigationItem['type']) => {
    switch (type) {
      case 'url': return <Globe className="w-3.5 h-3.5 text-blue-400" />;
      case 'hash': return <FileCode className="w-3.5 h-3.5 text-amber-400" />;
      case 'cve': return <Database className="w-3.5 h-3.5 text-cyan-400" />;
      case 'email': return <Mail className="w-3.5 h-3.5 text-emerald-400" />;
      case 'media': return <Video className="w-3.5 h-3.5 text-purple-400" />;
      case 'incident': return <AlertOctagon className="w-3.5 h-3.5 text-red-400" />;
      default: return <ShieldCheck className="w-3.5 h-3.5 text-slate-400" />;
    }
  };

  return (
    <div className="command-card p-4 space-y-3.5">
      {/* Table Header with Search & Filters */}
      <div className="flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-3">
        <div className="flex items-center gap-2">
          <h3 className="text-xs font-bold font-mono uppercase tracking-wider text-white flex items-center gap-2">
            <span>Investigated Assets & Indicators</span>
            <span className="text-[10px] px-1.5 py-0.2 rounded bg-blue-500/10 text-blue-400 border border-blue-500/30">
              {filteredItems.length}
            </span>
          </h3>
        </div>

        {/* Filter Controls */}
        <div className="flex flex-wrap items-center gap-2">
          <div className="relative min-w-[160px]">
            <Search className="w-3.5 h-3.5 text-slate-400 absolute left-2.5 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              value={searchTerm}
              onChange={(e) => {
                setSearchTerm(e.target.value);
                setCurrentPage(1);
              }}
              placeholder="Filter assets..."
              className="w-full h-7.5 pl-8 pr-2.5 bg-[#121B2D] border border-[#1C273C] rounded text-xs text-slate-200 placeholder-slate-400 focus:border-blue-500"
            />
          </div>

          <select
            value={selectedType}
            onChange={(e) => {
              setSelectedType(e.target.value);
              setCurrentPage(1);
            }}
            className="h-7.5 px-2 bg-[#121B2D] border border-[#1C273C] rounded text-xs text-slate-300 focus:border-blue-500 cursor-pointer"
          >
            <option value="all">All Types</option>
            <option value="url">URLs & Links</option>
            <option value="hash">Malware Hashes</option>
            <option value="cve">CVE Advisories</option>
            <option value="email">Email Breaches</option>
            <option value="media">Media / Deepfakes</option>
            <option value="incident">SIEM Incidents</option>
          </select>

          <select
            value={selectedSeverity}
            onChange={(e) => {
              setSelectedSeverity(e.target.value);
              setCurrentPage(1);
            }}
            className="h-7.5 px-2 bg-[#121B2D] border border-[#1C273C] rounded text-xs text-slate-300 focus:border-blue-500 cursor-pointer"
          >
            <option value="all">All Severities</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low / Clean</option>
          </select>
        </div>
      </div>

      {/* Responsive Table Container */}
      <div className="overflow-x-auto rounded border border-[#1C273C]">
        <table className="w-full text-left border-collapse">
          <thead>
            <tr className="bg-[#101728] border-b border-[#1C273C] text-[10px] font-mono uppercase tracking-wider text-slate-400">
              <th className="py-2.5 px-3 font-semibold">Asset / Indicator</th>
              <th className="py-2.5 px-3 font-semibold">Type</th>
              <th className="py-2.5 px-3 font-semibold">Severity</th>
              <th className="py-2.5 px-3 font-semibold">Status</th>
              <th className="py-2.5 px-3 font-semibold">Audited</th>
              <th className="py-2.5 px-3 font-semibold">Source Engine</th>
              <th className="py-2.5 px-3 font-semibold text-right">Actions</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-[#1C273C]/60 text-xs font-sans">
            {paginatedItems.length === 0 ? (
              <tr>
                <td colSpan={7} className="py-8 text-center text-slate-400 font-mono text-xs">
                  No investigation assets found matching your active filters.
                </td>
              </tr>
            ) : (
              paginatedItems.map((item) => (
                <tr 
                  key={item.id} 
                  className="hover:bg-[#131D31] transition-colors group"
                >
                  {/* Indicator / Asset Name */}
                  <td className="py-2.5 px-3 font-medium text-slate-200">
                    <div className="flex items-center gap-2 max-w-[280px]">
                      <div className="p-1 rounded bg-[#162136] border border-[#202E48] shrink-0">
                        {getTypeIcon(item.type)}
                      </div>
                      <span className="font-mono text-[11px] truncate text-slate-200" title={item.name}>
                        {item.name}
                      </span>
                    </div>
                  </td>

                  {/* Type */}
                  <td className="py-2.5 px-3 font-mono text-[11px] text-slate-400 uppercase">
                    {item.type}
                  </td>

                  {/* Severity */}
                  <td className="py-2.5 px-3">
                    <StatusBadge severity={item.severity} />
                  </td>

                  {/* Status */}
                  <td className="py-2.5 px-3">
                    <StatusBadge status={item.status} />
                  </td>

                  {/* Last Checked */}
                  <td className="py-2.5 px-3 font-mono text-[11px] text-slate-400 whitespace-nowrap">
                    {formatTime(item.timestamp)}
                  </td>

                  {/* Source */}
                  <td className="py-2.5 px-3 font-mono text-[11px] text-slate-400 whitespace-nowrap">
                    {item.source}
                  </td>

                  {/* Actions */}
                  <td className="py-2.5 px-3 text-right whitespace-nowrap">
                    <div className="flex items-center justify-end gap-1.5">
                      {item.rawScan && (
                        <button
                          onClick={() => onSelectScanReport(item.rawScan!)}
                          className="px-2 py-1 rounded bg-blue-600/20 hover:bg-blue-600/40 text-blue-300 font-mono text-[10px] border border-blue-500/30 flex items-center gap-1 transition-colors"
                          title="View Forensic PDF Briefing"
                        >
                          <FileText className="w-3 h-3" />
                          <span>Briefing</span>
                        </button>
                      )}
                      {item.rawIncident && onSelectIncident && (
                        <button
                          onClick={() => onSelectIncident(item.rawIncident!)}
                          className="px-2 py-1 rounded bg-amber-600/20 hover:bg-amber-600/40 text-amber-300 font-mono text-[10px] border border-amber-500/30 flex items-center gap-1 transition-colors"
                          title="Triage SIEM Case"
                        >
                          <Eye className="w-3 h-3" />
                          <span>Triage</span>
                        </button>
                      )}
                    </div>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      {/* Pagination Footer */}
      <div className="flex items-center justify-between text-[11px] font-mono text-slate-400 pt-1">
        <span>
          Showing {paginatedItems.length > 0 ? (currentPage - 1) * pageSize + 1 : 0} - {Math.min(currentPage * pageSize, filteredItems.length)} of {filteredItems.length} records
        </span>

        <div className="flex items-center gap-1.5">
          <button
            onClick={() => setCurrentPage(p => Math.max(p - 1, 1))}
            disabled={currentPage <= 1}
            className="p-1 rounded bg-[#121B2D] border border-[#1C273C] text-slate-300 hover:text-white disabled:opacity-40 disabled:cursor-not-allowed"
          >
            <ChevronLeft className="w-3.5 h-3.5" />
          </button>
          <span className="px-2 font-bold text-slate-200">
            {currentPage} / {totalPages}
          </span>
          <button
            onClick={() => setCurrentPage(p => Math.min(p + 1, totalPages))}
            disabled={currentPage >= totalPages}
            className="p-1 rounded bg-[#121B2D] border border-[#1C273C] text-slate-300 hover:text-white disabled:opacity-40 disabled:cursor-not-allowed"
          >
            <ChevronRight className="w-3.5 h-3.5" />
          </button>
        </div>
      </div>
    </div>
  );
}
