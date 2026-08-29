import React, { useState, useEffect, useRef } from 'react';
import { 
  Shield, ShieldAlert, ShieldCheck, Mail, Search, History, Terminal as TerminalIcon, 
  Zap, Lock, Bell, Users, Cpu, FileText, CheckCircle2, RefreshCw, Link2, 
  UploadCloud, Globe, Eye, Trash2, Server, Activity, FileCode, AlertTriangle, 
  Download, Database, Key, Layers, Crosshair, Code, Filter, Check, X, ChevronRight,
  ArrowUpRight, Sparkles, Copy, FileJson
} from 'lucide-react';
import { User, ScanResult, OsintResult, HashAnalysisResult, SocIncident, CveRecord } from '../types';
import Terminal from './Terminal';
import PrivacyStatementModal from './PrivacyStatementModal';
import UsageAudit from './UsageAudit';
import { safeJsonResponse } from '../lib/api';

interface DashboardProps {
  user: User;
  token: string;
  gmailToken: string | null;
  setGmailToken: (token: string | null) => void;
  onSelectReport: (scan: ScanResult) => void;
  onUserUpdate: (updatedUser: User) => void;
}

export default function Dashboard({
  user,
  token,
  gmailToken,
  setGmailToken,
  onSelectReport,
  onUserUpdate
}: DashboardProps) {
  const [activeTab, setActiveTab] = useState<'email' | 'link' | 'image' | 'cve' | 'osint' | 'hash' | 'siem' | 'stix'>('email');
  const [rawViewMode, setRawViewMode] = useState<boolean>(false);
  const [scanEmail, setScanEmail] = useState('');
  const [scanUrl, setScanUrl] = useState('');

  // CVE Vulnerability Database States
  const [cveQuery, setCveQuery] = useState('');
  const [cveSeverity, setCveSeverity] = useState<string>('ALL');
  const [cveLoading, setCveLoading] = useState(false);
  const [cveResults, setCveResults] = useState<{ totalMatches: number; cves: CveRecord[] } | null>(null);

  // OSINT IP & Domain Inspector States
  const [osintTarget, setOsintTarget] = useState('');
  const [osintLoading, setOsintLoading] = useState(false);
  const [osintResult, setOsintResult] = useState<OsintResult | null>(null);

  // Malware Payload Hash Forensics States
  const [hashInput, setHashInput] = useState('');
  const [hashFileName, setHashFileName] = useState('');
  const [hashLoading, setHashLoading] = useState(false);
  const [hashResult, setHashResult] = useState<HashAnalysisResult | null>(null);

  // SIEM Incident Response Matrix States
  const [incidentsList, setIncidentsList] = useState<SocIncident[]>([]);
  const [incidentsLoading, setIncidentsLoading] = useState(false);
  const [selectedIncident, setSelectedIncident] = useState<SocIncident | null>(null);
  const [triageNote, setTriageNote] = useState('');
  const [triageStatus, setTriageStatus] = useState<SocIncident['status']>('investigating');
  const [containmentActionInput, setContainmentActionInput] = useState('');

  // STIX 2.1 DFIR Evidence Bundle States
  const [stixTarget, setStixTarget] = useState('');
  const [stixHash, setStixHash] = useState('');
  const [stixNotes, setStixNotes] = useState('');
  const [stixBundleResult, setStixBundleResult] = useState<any | null>(null);
  const [stixLoading, setStixLoading] = useState(false);

  const [imageFile, setImageFile] = useState<File | null>(null);
  const [imagePreview, setImagePreview] = useState<string | null>(null);
  const [isDragging, setIsDragging] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [copiedNotification, setCopiedNotification] = useState<string | null>(null);

  // General State
  const [scans, setScans] = useState<ScanResult[]>([]);
  const [currentScan, setCurrentScan] = useState<ScanResult | null>(null);
  const [showTerminal, setShowTerminal] = useState(false);

  // Trust & Privacy States
  const [showPrivacyModal, setShowPrivacyModal] = useState(false);
  const [complianceTab, setComplianceTab] = useState<'gmail' | 'sourcing' | 'soc2' | 'bounty' | 'erasure'>('gmail');
  const [confirmWipe, setConfirmWipe] = useState(false);
  const [isClearingScans, setIsClearingScans] = useState(false);
  const [clearScansSuccess, setClearScansSuccess] = useState(false);

  const notifyCopy = (msg: string) => {
    setCopiedNotification(msg);
    setTimeout(() => setCopiedNotification(null), 2500);
  };

  // Load Scan History & Data on Mount
  const loadHistory = async () => {
    try {
      const response = await fetch('/api/scans', {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      if (response.ok) {
        const data = await safeJsonResponse(response);
        if (data?.scans) {
          setScans(data.scans);
          if (data.scans.length > 0 && !currentScan) {
            setCurrentScan(data.scans[0]);
          }
        }
      }
    } catch (err) {
      console.warn('Failed to load scan history:', err);
    }
  };

  const loadLatestCves = async () => {
    setCveLoading(true);
    try {
      const res = await fetch('/api/cve/latest?limit=12', {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      if (res.ok) {
        const data = await safeJsonResponse(res);
        if (data?.cves) {
          setCveResults({ totalMatches: data.cves.length, cves: data.cves });
        }
      }
    } catch (err) {
      console.warn('Failed to load CVE feed:', err);
    } finally {
      setCveLoading(false);
    }
  };

  const fetchIncidents = async () => {
    setIncidentsLoading(true);
    try {
      const res = await fetch('/api/soc/incidents', {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      if (res.ok) {
        const data = await safeJsonResponse(res);
        if (data?.incidents) {
          setIncidentsList(data.incidents);
          if (data.incidents.length > 0 && !selectedIncident) {
            setSelectedIncident(data.incidents[0]);
          }
        }
      }
    } catch (err) {
      console.warn('Failed to fetch SIEM incidents:', err);
    } finally {
      setIncidentsLoading(false);
    }
  };

  useEffect(() => {
    loadHistory();
    loadLatestCves();
    fetchIncidents();
  }, [token]);

  // Handle Keybindings for SOC Terminal (Ctrl + ~)
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.ctrlKey && e.key === '`') {
        e.preventDefault();
        setShowTerminal(prev => !prev);
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, []);

  // Handlers for Scanners
  const executeEmailScan = async (targetEmail: string) => {
    if (!targetEmail || !targetEmail.includes('@')) {
      setError('Please provide a valid target email address.');
      return;
    }
    setLoading(true);
    setError(null);
    try {
      const res = await fetch('/api/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${token}` },
        body: JSON.stringify({ email: targetEmail })
      });
      const data = await safeJsonResponse(res, 'Email breach assessment failed');
      if (data?.scan) {
        setCurrentScan(data.scan);
        setScans(prev => [data.scan, ...prev]);
        if (data.user) onUserUpdate(data.user);
      }
    } catch (err: any) {
      setError(err.message || 'Email breach scan execution error.');
    } finally {
      setLoading(false);
    }
  };

  const handleScanEmail = async (e: React.FormEvent) => {
    e.preventDefault();
    executeEmailScan(scanEmail);
  };

  const executeUrlScan = async (targetUrl: string) => {
    if (!targetUrl) {
      setError('Target URL is required.');
      return;
    }
    setLoading(true);
    setError(null);
    try {
      const res = await fetch('/api/scan-link', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${token}` },
        body: JSON.stringify({ url: targetUrl })
      });
      const data = await safeJsonResponse(res, 'Link reputation inspection failed');
      if (data?.scan) {
        setCurrentScan(data.scan);
        setScans(prev => [data.scan, ...prev]);
        if (data.user) onUserUpdate(data.user);
      }
    } catch (err: any) {
      setError(err.message || 'URL threat inspection failed.');
    } finally {
      setLoading(false);
    }
  };

  const handleScanUrl = async (e: React.FormEvent) => {
    e.preventDefault();
    executeUrlScan(scanUrl);
  };

  const handleImageFileChange = (file: File) => {
    if (!file.type.startsWith('image/')) {
      setError('Selected artifact file must be a valid image format (PNG, JPG, WEBP).');
      return;
    }
    setImageFile(file);
    setError(null);
    const reader = new FileReader();
    reader.onload = () => setImagePreview(reader.result as string);
    reader.readAsDataURL(file);
  };

  const handleLoadSampleInvoice = () => {
    // Generate a simple synthetic sample canvas image for instant testing
    const canvas = document.createElement('canvas');
    canvas.width = 400;
    canvas.height = 200;
    const ctx = canvas.getContext('2d');
    if (ctx) {
      ctx.fillStyle = '#0f172a';
      ctx.fillRect(0, 0, 400, 200);
      ctx.fillStyle = '#ef4444';
      ctx.font = 'bold 16px sans-serif';
      ctx.fillText('URGENT: INVOICE PAYMENT DUE', 20, 40);
      ctx.fillStyle = '#94a3b8';
      ctx.font = '13px monospace';
      ctx.fillText('Amount: $4,850.00 USD', 20, 80);
      ctx.fillText('Action: Verify wire transfer credentials', 20, 110);
      ctx.fillText('Metamask Wallet seed phrase required', 20, 140);
      ctx.fillStyle = '#00E5FF';
      ctx.fillText('Target: CyberGuard Threat Lab Sample', 20, 175);
    }
    const sampleDataUrl = canvas.toDataURL('image/png');
    setImagePreview(sampleDataUrl);
    // Create a mock File object
    const blobBin = atob(sampleDataUrl.split(',')[1]);
    const array = [];
    for (let i = 0; i < blobBin.length; i++) array.push(blobBin.charCodeAt(i));
    const sampleFile = new File([new Uint8Array(array)], 'urgent_wire_invoice_sample.png', { type: 'image/png' });
    setImageFile(sampleFile);
    setError(null);
  };

  const handleScanImage = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!imageFile || !imagePreview) {
      setError('Please attach or drop an image payload artifact for inspection.');
      return;
    }
    setLoading(true);
    setError(null);
    try {
      const base64Data = imagePreview.split(',')[1];
      const res = await fetch('/api/scan-image', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${token}` },
        body: JSON.stringify({
          base64Image: base64Data,
          mimeType: imageFile.type,
          filename: imageFile.name
        })
      });
      const data = await safeJsonResponse(res, 'Visual threat inspection failed');
      if (data?.scan) {
        setCurrentScan(data.scan);
        setScans(prev => [data.scan, ...prev]);
        if (data.user) onUserUpdate(data.user);
      }
    } catch (err: any) {
      setError(err.message || 'Visual payload inspection error.');
    } finally {
      setLoading(false);
    }
  };

  const executeCveSearch = async (query: string, severity: string = 'ALL') => {
    setCveLoading(true);
    try {
      const res = await fetch(`/api/cve/search?query=${encodeURIComponent(query)}&severity=${severity}&limit=20`, {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      const data = await safeJsonResponse(res, 'CVE query failed');
      if (data) {
        setCveResults(data);
      }
    } catch (err: any) {
      console.warn('CVE search error:', err);
      setError(err.message || 'CVE vulnerability query failed.');
    } finally {
      setCveLoading(false);
    }
  };

  const handleCveSearch = async (e: React.FormEvent) => {
    e.preventDefault();
    executeCveSearch(cveQuery, cveSeverity);
  };

  const executeOsintLookup = async (target: string) => {
    if (!target) return;
    setOsintLoading(true);
    setError(null);
    try {
      const res = await fetch('/api/soc/osint-lookup', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${token}` },
        body: JSON.stringify({ target })
      });
      const data = await safeJsonResponse(res, 'OSINT inspection failed');
      if (data) setOsintResult(data);
    } catch (err: any) {
      console.warn('OSINT lookup error:', err);
      setError(err.message || 'OSINT lookup failed.');
    } finally {
      setOsintLoading(false);
    }
  };

  const handleOsintLookup = async (e: React.FormEvent) => {
    e.preventDefault();
    executeOsintLookup(osintTarget);
  };

  const executeHashLookup = async (hash: string, fileName?: string) => {
    if (!hash) return;
    setHashLoading(true);
    setError(null);
    try {
      const res = await fetch('/api/soc/hash-lookup', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${token}` },
        body: JSON.stringify({ hash, fileName: fileName || hashFileName })
      });
      const data = await safeJsonResponse(res, 'Malware hash forensics failed');
      if (data) setHashResult(data);
    } catch (err: any) {
      console.warn('Hash lookup error:', err);
      setError(err.message || 'Malware hash forensics failed.');
    } finally {
      setHashLoading(false);
    }
  };

  const handleHashLookup = async (e: React.FormEvent) => {
    e.preventDefault();
    executeHashLookup(hashInput, hashFileName);
  };

  const handleTriageSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedIncident) return;
    try {
      const res = await fetch(`/api/soc/incidents/${selectedIncident.id}/triage`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${token}` },
        body: JSON.stringify({
          status: triageStatus,
          containmentAction: containmentActionInput,
          note: triageNote
        })
      });
      const data = await safeJsonResponse(res, 'SIEM triage update failed');
      if (data?.incident) {
        setSelectedIncident(data.incident);
        setIncidentsList(prev => prev.map(inc => inc.id === data.incident.id ? data.incident : inc));
        setTriageNote('');
        notifyCopy('Incident status updated');
      }
    } catch (err: any) {
      console.warn('SIEM triage error:', err);
      setError(err.message || 'Failed to update SIEM incident.');
    }
  };

  const handleStixExport = async (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    setStixLoading(true);
    setError(null);
    try {
      const res = await fetch('/api/soc/stix-export', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${token}` },
        body: JSON.stringify({
          target: stixTarget || 'malicious-c2-node.org',
          hash: stixHash || '44d88612fea8a8f36de82e1278abb02f',
          notes: stixNotes || 'Forensic threat indicator extracted via CyberGuard Workstation'
        })
      });
      const data = await safeJsonResponse(res, 'STIX 2.1 generation failed');
      if (data?.stixBundle || data?.bundle) {
        setStixBundleResult(data.stixBundle || data.bundle);
        notifyCopy('STIX 2.1 JSON Generated');
      }
    } catch (err: any) {
      console.warn('STIX export error:', err);
      setError(err.message || 'STIX 2.1 generation error.');
    } finally {
      setStixLoading(false);
    }
  };

  const handleDownloadStixJson = () => {
    if (!stixBundleResult) return;
    const blob = new Blob([JSON.stringify(stixBundleResult, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `cyberguard_stix21_bundle_${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const handleWipeScans = async () => {
    setIsClearingScans(true);
    try {
      await fetch('/api/scans/clear', {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${token}` }
      });
      setScans([]);
      setCurrentScan(null);
      setClearScansSuccess(true);
      setTimeout(() => {
        setClearScansSuccess(false);
        setConfirmWipe(false);
      }, 3000);
    } catch (err) {
      console.warn('Failed to wipe scans:', err);
    } finally {
      setIsClearingScans(false);
    }
  };

  // Helper for Bit-Density Risk Segment Meter
  const renderBitDensityMeter = (score: number) => {
    const totalBlocks = 20;
    const filledBlocks = Math.round((score / 100) * totalBlocks);
    const emptyBlocks = totalBlocks - filledBlocks;
    const filledStr = '█'.repeat(filledBlocks);
    const emptyStr = '░'.repeat(emptyBlocks);

    let colorClass = 'text-[#00E676]';
    let label = 'VERIFIED / LOW';
    if (score >= 75) {
      colorClass = 'text-[#FF334B]';
      label = 'CRITICAL THREAT';
    } else if (score >= 50) {
      colorClass = 'text-[#FF9900]';
      label = 'HIGH RISK';
    } else if (score >= 25) {
      colorClass = 'text-[#E0C000]';
      label = 'MEDIUM HAZARD';
    }

    return (
      <div className="font-mono text-xs flex flex-wrap items-center justify-between gap-3 bg-[#090D14] p-2.5 border border-[#263147] rounded-sm">
        <span className={colorClass}>[{filledStr}{emptyStr}]</span>
        <span className={`font-bold uppercase tracking-wider ${colorClass}`}>
          RISK INDEX: {score}/100 • {label}
        </span>
      </div>
    );
  };

  return (
    <div className="space-y-4 font-sans text-[#ECEFF4]">
      
      {/* SIEM COMMAND SUMMARY STRIP */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-2 text-xs font-mono">
        <div className="soc-panel p-2.5 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Activity className="w-4 h-4 text-[#00E5FF]" />
            <span className="text-[#7E8B9B] uppercase font-semibold text-[10px]">Session Scans</span>
          </div>
          <span className="font-bold text-white text-sm">{scans.length}</span>
        </div>

        <div className="soc-panel p-2.5 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <ShieldAlert className="w-4 h-4 text-[#FF334B]" />
            <span className="text-[#7E8B9B] uppercase font-semibold text-[10px]">High Severity</span>
          </div>
          <span className="font-bold text-[#FF334B] text-sm">
            {scans.filter(s => s.riskScore >= 50).length}
          </span>
        </div>

        <div className="soc-panel p-2.5 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Database className="w-4 h-4 text-[#FF9900]" />
            <span className="text-[#7E8B9B] uppercase font-semibold text-[10px]">CVE Index</span>
          </div>
          <span className="font-bold text-[#FF9900] text-sm">
            {cveResults?.totalMatches || 0} RECORDS
          </span>
        </div>

        <div className="soc-panel p-2.5 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <ShieldCheck className="w-4 h-4 text-[#00E676]" />
            <span className="text-[#7E8B9B] uppercase font-semibold text-[10px]">STIX 2.1 Engine</span>
          </div>
          <span className="font-bold text-[#00E676] text-sm flex items-center gap-1">
            <span className="w-2 h-2 rounded-full bg-[#00E676] animate-pulse"></span>
            ACTIVE
          </span>
        </div>
      </div>

      {/* VECTOR TAB MODULE SELECTOR */}
      <div className="soc-panel p-1.5 flex flex-wrap gap-1 border border-[#263147] text-[11px] font-mono font-bold">
        {[
          { id: 'email', label: 'EMAIL BREACH', icon: Mail },
          { id: 'link', label: 'URL REPUTATION', icon: Link2 },
          { id: 'image', label: 'VISUAL OCR', icon: FileText },
          { id: 'cve', label: 'NIST CVE DB', icon: Database },
          { id: 'osint', label: 'OSINT INSPECTOR', icon: Crosshair },
          { id: 'hash', label: 'MALWARE HASH', icon: FileCode },
          { id: 'siem', label: 'SIEM INCIDENTS', icon: ShieldAlert },
          { id: 'stix', label: 'STIX 2.1 BUNDLE', icon: Layers },
        ].map(tab => {
          const IconComp = tab.icon;
          const isActive = activeTab === tab.id;
          return (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id as any)}
              className={`px-3 py-1.5 flex items-center gap-1.5 rounded-sm transition-colors cursor-pointer ${
                isActive 
                  ? 'bg-[#181F2E] text-[#00E5FF] border border-[#00E5FF]' 
                  : 'text-[#7E8B9B] hover:text-[#ECEFF4] border border-transparent hover:border-[#263147]'
              }`}
            >
              <IconComp className={`w-3.5 h-3.5 ${isActive ? 'text-[#00E5FF]' : ''}`} />
              <span>{tab.label}</span>
            </button>
          );
        })}
      </div>

      {/* MAIN 3-COLUMN WORKSTATION LAYOUT */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
        
        {/* LEFT COLUMN: COMMAND FORM INPUTS & EXECUTORS (4 cols) */}
        <div className="lg:col-span-4 space-y-4">
          
          {/* TAB 1: EMAIL BREACH AUDITOR */}
          {activeTab === 'email' && (
            <div className="soc-panel p-4 space-y-3">
              <div className="border-b border-[#263147] pb-2 flex items-center justify-between">
                <h2 className="font-display font-bold text-sm uppercase text-white flex items-center gap-2">
                  <Mail className="w-4 h-4 text-[#00E5FF]" />
                  <span>Email Breach Auditor</span>
                </h2>
                <span className="status-chip status-chip-low">ACTIVE</span>
              </div>
              <p className="text-[11px] text-[#7E8B9B] font-mono leading-relaxed">
                Queries deterministic leak records and analyzes compromised account exposures, leaked credential types, and mitigation steps.
              </p>
              
              <form onSubmit={handleScanEmail} className="space-y-3 pt-1">
                <div className="space-y-1">
                  <label className="text-[10px] font-mono uppercase text-[#7E8B9B] font-bold block">
                    Target Email Address
                  </label>
                  <input
                    type="email"
                    value={scanEmail}
                    onChange={(e) => setScanEmail(e.target.value)}
                    placeholder="analyst@enterprise-domain.com"
                    className="w-full bg-[#090D14] border border-[#263147] px-3 py-2 text-xs text-[#ECEFF4] placeholder-[#7E8B9B]/50 rounded-sm font-mono focus:border-[#00E5FF] focus:outline-none"
                    required
                  />
                </div>

                {/* 1-Click Quick Test Presets */}
                <div className="space-y-1.5">
                  <span className="text-[10px] font-mono uppercase text-[#7E8B9B] font-bold flex items-center gap-1">
                    <Sparkles className="w-3 h-3 text-[#00E5FF]" />
                    <span>Quick Test Presets (1-Click)</span>
                  </span>
                  <div className="grid grid-cols-2 gap-1.5">
                    <button
                      type="button"
                      onClick={() => {
                        const email = 'user@yahoo.com';
                        setScanEmail(email);
                        executeEmailScan(email);
                      }}
                      className="text-left bg-[#181F2E] border border-[#263147] hover:border-[#FF334B] hover:text-white px-2 py-1.5 rounded-sm font-mono text-[10px] text-[#ECEFF4] transition-colors cursor-pointer"
                    >
                      <span className="text-[#FF334B] font-bold block">🚨 Leaked Target</span>
                      <span className="text-[#7E8B9B] text-[9px]">user@yahoo.com</span>
                    </button>
                    <button
                      type="button"
                      onClick={() => {
                        const email = 'secure@cyberguard.com';
                        setScanEmail(email);
                        executeEmailScan(email);
                      }}
                      className="text-left bg-[#181F2E] border border-[#263147] hover:border-[#00E676] hover:text-white px-2 py-1.5 rounded-sm font-mono text-[10px] text-[#ECEFF4] transition-colors cursor-pointer"
                    >
                      <span className="text-[#00E676] font-bold block">🟢 Clean Target</span>
                      <span className="text-[#7E8B9B] text-[9px]">secure@cyberguard.com</span>
                    </button>
                  </div>
                </div>

                {error && (
                  <div className="p-2 bg-[#FF334B]/10 border border-[#FF334B]/30 text-[#FF334B] text-[11px] font-mono flex items-center gap-2">
                    <AlertTriangle className="w-3.5 h-3.5 shrink-0" />
                    <span>{error}</span>
                  </div>
                )}

                <button
                  type="submit"
                  disabled={loading}
                  className="w-full btn-soc btn-soc-primary py-2 flex items-center justify-center gap-2 cursor-pointer disabled:opacity-50"
                >
                  <Search className="w-3.5 h-3.5" />
                  <span>{loading ? 'AUDITING BREACH LOGS...' : 'EXECUTE BREACH AUDIT'}</span>
                </button>
              </form>
            </div>
          )}

          {/* TAB 2: URL REPUTATION SCANNER */}
          {activeTab === 'link' && (
            <div className="soc-panel p-4 space-y-3">
              <div className="border-b border-[#263147] pb-2 flex items-center justify-between">
                <h2 className="font-display font-bold text-sm uppercase text-white flex items-center gap-2">
                  <Link2 className="w-4 h-4 text-[#00E5FF]" />
                  <span>URL Phishing Scanner</span>
                </h2>
                <span className="status-chip status-chip-low">ACTIVE</span>
              </div>
              <p className="text-[11px] text-[#7E8B9B] font-mono leading-relaxed">
                Deterministic rule engine inspecting target URL structures, domain age, typosquatting indicators, redirect hops, and SSL certificates.
              </p>

              <form onSubmit={handleScanUrl} className="space-y-3 pt-1">
                <div className="space-y-1">
                  <label className="text-[10px] font-mono uppercase text-[#7E8B9B] font-bold block">
                    Target URL / Host Domain
                  </label>
                  <input
                    type="text"
                    value={scanUrl}
                    onChange={(e) => setScanUrl(e.target.value)}
                    placeholder="https://suspicious-verify-auth.com"
                    className="w-full bg-[#090D14] border border-[#263147] px-3 py-2 text-xs text-[#ECEFF4] placeholder-[#7E8B9B]/50 rounded-sm font-mono focus:border-[#00E5FF] focus:outline-none"
                    required
                  />
                </div>

                {/* 1-Click Quick Test Presets */}
                <div className="space-y-1.5">
                  <span className="text-[10px] font-mono uppercase text-[#7E8B9B] font-bold flex items-center gap-1">
                    <Sparkles className="w-3 h-3 text-[#00E5FF]" />
                    <span>Quick Test Presets (1-Click)</span>
                  </span>
                  <div className="grid grid-cols-2 gap-1.5">
                    <button
                      type="button"
                      onClick={() => {
                        const url = 'https://paypa1-secure-login.xyz/verify';
                        setScanUrl(url);
                        executeUrlScan(url);
                      }}
                      className="text-left bg-[#181F2E] border border-[#263147] hover:border-[#FF334B] hover:text-white px-2 py-1.5 rounded-sm font-mono text-[10px] text-[#ECEFF4] transition-colors cursor-pointer"
                    >
                      <span className="text-[#FF334B] font-bold block">🚨 Phishing Typosquat</span>
                      <span className="text-[#7E8B9B] text-[9px] truncate block">paypa1-login.xyz</span>
                    </button>
                    <button
                      type="button"
                      onClick={() => {
                        const url = 'https://google.com';
                        setScanUrl(url);
                        executeUrlScan(url);
                      }}
                      className="text-left bg-[#181F2E] border border-[#263147] hover:border-[#00E676] hover:text-white px-2 py-1.5 rounded-sm font-mono text-[10px] text-[#ECEFF4] transition-colors cursor-pointer"
                    >
                      <span className="text-[#00E676] font-bold block">🟢 Legitimate Portal</span>
                      <span className="text-[#7E8B9B] text-[9px] truncate block">https://google.com</span>
                    </button>
                  </div>
                </div>

                {error && (
                  <div className="p-2 bg-[#FF334B]/10 border border-[#FF334B]/30 text-[#FF334B] text-[11px] font-mono flex items-center gap-2">
                    <AlertTriangle className="w-3.5 h-3.5 shrink-0" />
                    <span>{error}</span>
                  </div>
                )}

                <button
                  type="submit"
                  disabled={loading}
                  className="w-full btn-soc btn-soc-primary py-2 flex items-center justify-center gap-2 cursor-pointer disabled:opacity-50"
                >
                  <Crosshair className="w-3.5 h-3.5" />
                  <span>{loading ? 'INSPECTING URL STRUCTURE...' : 'RUN URL REPUTATION CHECK'}</span>
                </button>
              </form>
            </div>
          )}

          {/* TAB 3: VISUAL OCR & FILE SCANNER */}
          {activeTab === 'image' && (
            <div className="soc-panel p-4 space-y-3">
              <div className="border-b border-[#263147] pb-2 flex items-center justify-between">
                <h2 className="font-display font-bold text-sm uppercase text-white flex items-center gap-2">
                  <FileText className="w-4 h-4 text-[#00E5FF]" />
                  <span>Visual Payload Inspector</span>
                </h2>
                <span className="status-chip status-chip-low">OCR & HASH</span>
              </div>
              <p className="text-[11px] text-[#7E8B9B] font-mono leading-relaxed">
                Computes cryptographic image signatures (SHA-256 / MD5), inspects metadata, and evaluates OCR heuristic lures.
              </p>

              <form onSubmit={handleScanImage} className="space-y-3">
                <div
                  onDragOver={(e) => { e.preventDefault(); setIsDragging(true); }}
                  onDragLeave={() => setIsDragging(false)}
                  onDrop={(e) => {
                    e.preventDefault();
                    setIsDragging(false);
                    if (e.dataTransfer.files?.[0]) handleImageFileChange(e.dataTransfer.files[0]);
                  }}
                  onClick={() => fileInputRef.current?.click()}
                  className={`border border-dashed p-4 text-center cursor-pointer transition-colors ${
                    isDragging ? 'border-[#00E5FF] bg-[#181F2E]' : 'border-[#263147] bg-[#090D14] hover:border-[#7E8B9B]'
                  }`}
                >
                  <input
                    ref={fileInputRef}
                    type="file"
                    accept="image/*"
                    onChange={(e) => e.target.files?.[0] && handleImageFileChange(e.target.files[0])}
                    className="hidden"
                  />
                  <UploadCloud className="w-6 h-6 text-[#00E5FF] mx-auto mb-1" />
                  <span className="text-[11px] font-mono text-[#ECEFF4] block font-bold">
                    {imageFile ? imageFile.name : 'DROP ARTIFACT IMAGE OR CLICK TO BROWSE'}
                  </span>
                  <span className="text-[9px] font-mono text-[#7E8B9B] block mt-0.5">
                    PNG, JPG, WEBP • Max 10MB payload size
                  </span>
                </div>

                {/* 1-Click Synthetic Sample Button */}
                <div className="flex items-center justify-between">
                  <button
                    type="button"
                    onClick={handleLoadSampleInvoice}
                    className="btn-soc px-2.5 py-1 text-[10px] flex items-center gap-1 text-[#00E5FF] border-[#00E5FF]/40 cursor-pointer"
                  >
                    <Sparkles className="w-3 h-3" />
                    <span>LOAD SAMPLE INVOICE PAYLOAD</span>
                  </button>
                  {imageFile && (
                    <span className="text-[10px] font-mono text-[#00E676]">Payload Ready</span>
                  )}
                </div>

                {imagePreview && (
                  <div className="border border-[#263147] bg-[#090D14] p-1 text-center">
                    <img src={imagePreview} alt="Artifact preview" className="max-h-28 mx-auto object-contain rounded-xs" />
                  </div>
                )}

                <button
                  type="submit"
                  disabled={loading || !imageFile}
                  className="w-full btn-soc btn-soc-primary py-2 flex items-center justify-center gap-2 cursor-pointer disabled:opacity-50"
                >
                  <Eye className="w-3.5 h-3.5" />
                  <span>{loading ? 'ANALYZING VISUAL PAYLOAD...' : 'EXECUTE VISUAL INSPECTION'}</span>
                </button>
              </form>
            </div>
          )}

          {/* TAB 4: NIST CVE DATABASE SEARCH */}
          {activeTab === 'cve' && (
            <div className="soc-panel p-4 space-y-3">
              <div className="border-b border-[#263147] pb-2 flex items-center justify-between">
                <h2 className="font-display font-bold text-sm uppercase text-white flex items-center gap-2">
                  <Database className="w-4 h-4 text-[#00E5FF]" />
                  <span>NIST NVD CVE Query</span>
                </h2>
                <span className="status-chip status-chip-medium">LIVE NVD FEED</span>
              </div>
              <p className="text-[11px] text-[#7E8B9B] font-mono leading-relaxed">
                Query official CVE vulnerability records, CVSS scores, vector strings, and technical descriptions.
              </p>

              <form onSubmit={handleCveSearch} className="space-y-3">
                <div className="space-y-1">
                  <label className="text-[10px] font-mono uppercase text-[#7E8B9B] font-bold block">
                    Vulnerability Query / Tech Stack
                  </label>
                  <input
                    type="text"
                    value={cveQuery}
                    onChange={(e) => setCveQuery(e.target.value)}
                    placeholder="Log4j, OpenSSL, Apache, CVE-2024-..."
                    className="w-full bg-[#090D14] border border-[#263147] px-3 py-2 text-xs text-[#ECEFF4] placeholder-[#7E8B9B]/50 rounded-sm font-mono focus:border-[#00E5FF] focus:outline-none"
                  />
                </div>

                {/* 1-Click Quick CVE Preset Chips */}
                <div className="space-y-1.5">
                  <span className="text-[10px] font-mono uppercase text-[#7E8B9B] font-bold block">
                    Quick Attack Vectors:
                  </span>
                  <div className="flex flex-wrap gap-1 font-mono text-[10px]">
                    {[
                      { name: 'Log4j (CVSS 10.0)', query: 'Log4j' },
                      { name: 'OpenSSL (Buffer Overflow)', query: 'OpenSSL' },
                      { name: 'XZ Utils (SSH Backdoor)', query: 'CVE-2024-3094' },
                      { name: 'Fortinet (FortiOS)', query: 'Fortinet' },
                      { name: 'Citrix Bleed', query: 'Citrix' },
                      { name: 'Apache HTTP', query: 'Apache' },
                    ].map((item, idx) => (
                      <button
                        key={idx}
                        type="button"
                        onClick={() => {
                          setCveQuery(item.query);
                          executeCveSearch(item.query, cveSeverity);
                        }}
                        className="bg-[#181F2E] border border-[#263147] hover:border-[#00E5FF] hover:text-[#00E5FF] px-2 py-0.5 rounded-sm text-[#ECEFF4] transition-colors cursor-pointer"
                      >
                        {item.name}
                      </button>
                    ))}
                  </div>
                </div>

                <div className="space-y-1">
                  <label className="text-[10px] font-mono uppercase text-[#7E8B9B] font-bold block">
                    CVSS Severity Threshold
                  </label>
                  <select
                    value={cveSeverity}
                    onChange={(e) => {
                      setCveSeverity(e.target.value);
                      executeCveSearch(cveQuery, e.target.value);
                    }}
                    className="w-full bg-[#090D14] border border-[#263147] px-3 py-2 text-xs text-[#ECEFF4] rounded-sm font-mono focus:border-[#00E5FF] focus:outline-none"
                  >
                    <option value="ALL">ALL SEVERITIES</option>
                    <option value="CRITICAL">CRITICAL ONLY (9.0+)</option>
                    <option value="HIGH">HIGH (7.0 - 8.9)</option>
                    <option value="MEDIUM">MEDIUM (4.0 - 6.9)</option>
                  </select>
                </div>

                <button
                  type="submit"
                  disabled={cveLoading}
                  className="w-full btn-soc btn-soc-primary py-2 flex items-center justify-center gap-2 cursor-pointer disabled:opacity-50"
                >
                  <Search className="w-3.5 h-3.5" />
                  <span>{cveLoading ? 'QUERYING NVD DATABASE...' : 'SEARCH NIST CVE DB'}</span>
                </button>
              </form>
            </div>
          )}

          {/* TAB 5: OSINT IP & DOMAIN INSPECTOR */}
          {activeTab === 'osint' && (
            <div className="soc-panel p-4 space-y-3">
              <div className="border-b border-[#263147] pb-2 flex items-center justify-between">
                <h2 className="font-display font-bold text-sm uppercase text-white flex items-center gap-2">
                  <Crosshair className="w-4 h-4 text-[#00E5FF]" />
                  <span>OSINT Domain / IP Inspector</span>
                </h2>
                <span className="status-chip status-chip-low">DNS & REPUTATION</span>
              </div>
              <p className="text-[11px] text-[#7E8B9B] font-mono leading-relaxed">
                Resolves DNS records, blacklist status, open service ports, and autonomous system numbers (ASN).
              </p>

              <form onSubmit={handleOsintLookup} className="space-y-3">
                <div className="space-y-1">
                  <label className="text-[10px] font-mono uppercase text-[#7E8B9B] font-bold block">
                    Target IP Address or Hostname
                  </label>
                  <input
                    type="text"
                    value={osintTarget}
                    onChange={(e) => setOsintTarget(e.target.value)}
                    placeholder="185.220.101.5 or domain.com"
                    className="w-full bg-[#090D14] border border-[#263147] px-3 py-2 text-xs text-[#ECEFF4] placeholder-[#7E8B9B]/50 rounded-sm font-mono focus:border-[#00E5FF] focus:outline-none"
                    required
                  />
                </div>

                {/* 1-Click Quick Presets */}
                <div className="space-y-1.5">
                  <span className="text-[10px] font-mono uppercase text-[#7E8B9B] font-bold block">
                    Sample Targets:
                  </span>
                  <div className="flex flex-wrap gap-1 font-mono text-[10px]">
                    {[
                      { name: '185.220.101.5 (Tor Exit)', target: '185.220.101.5' },
                      { name: '8.8.8.8 (Google DNS)', target: '8.8.8.8' },
                      { name: 'github.com', target: 'github.com' }
                    ].map((item, idx) => (
                      <button
                        key={idx}
                        type="button"
                        onClick={() => {
                          setOsintTarget(item.target);
                          executeOsintLookup(item.target);
                        }}
                        className="bg-[#181F2E] border border-[#263147] hover:border-[#00E5FF] hover:text-[#00E5FF] px-2 py-0.5 rounded-sm text-[#ECEFF4] transition-colors cursor-pointer"
                      >
                        {item.name}
                      </button>
                    ))}
                  </div>
                </div>

                <button
                  type="submit"
                  disabled={osintLoading}
                  className="w-full btn-soc btn-soc-primary py-2 flex items-center justify-center gap-2 cursor-pointer disabled:opacity-50"
                >
                  <Globe className="w-3.5 h-3.5" />
                  <span>{osintLoading ? 'RESOLVING OSINT METRICS...' : 'RUN OSINT FORENSIC LOOKUP'}</span>
                </button>
              </form>
            </div>
          )}

          {/* TAB 6: MALWARE PAYLOAD HASH FORENSICS */}
          {activeTab === 'hash' && (
            <div className="soc-panel p-4 space-y-3">
              <div className="border-b border-[#263147] pb-2 flex items-center justify-between">
                <h2 className="font-display font-bold text-sm uppercase text-white flex items-center gap-2">
                  <FileCode className="w-4 h-4 text-[#00E5FF]" />
                  <span>Malware Hash Forensics</span>
                </h2>
                <span className="status-chip status-chip-high">SHA256 / YARA</span>
              </div>
              <p className="text-[11px] text-[#7E8B9B] font-mono leading-relaxed">
                Calculates Shannon entropy, inspects PE header magic bytes, evaluates YARA detection rules, and outputs quarantine guidance.
              </p>

              <form onSubmit={handleHashLookup} className="space-y-3">
                <div className="space-y-1">
                  <label className="text-[10px] font-mono uppercase text-[#7E8B9B] font-bold block">
                    Binary Payload Hash (MD5, SHA1, SHA256)
                  </label>
                  <input
                    type="text"
                    value={hashInput}
                    onChange={(e) => setHashInput(e.target.value)}
                    placeholder="44d88612fea8a8f36de82e1278abb02f"
                    className="w-full bg-[#090D14] border border-[#263147] px-3 py-2 text-xs text-[#ECEFF4] placeholder-[#7E8B9B]/50 rounded-sm font-mono focus:border-[#00E5FF] focus:outline-none"
                    required
                  />
                </div>

                {/* 1-Click Quick Presets */}
                <div className="space-y-1.5">
                  <span className="text-[10px] font-mono uppercase text-[#7E8B9B] font-bold block">
                    Sample Hashes:
                  </span>
                  <div className="flex flex-wrap gap-1 font-mono text-[10px]">
                    <button
                      type="button"
                      onClick={() => {
                        const h = '44d88612fea8a8f36de82e1278abb02f';
                        setHashInput(h);
                        setHashFileName('AsyncRAT_Trojan_dropper.exe');
                        executeHashLookup(h, 'AsyncRAT_Trojan_dropper.exe');
                      }}
                      className="bg-[#181F2E] border border-[#FF334B]/50 hover:border-[#FF334B] px-2 py-0.5 rounded-sm text-[#FF334B] transition-colors cursor-pointer"
                    >
                      🚨 AsyncRAT Dropper MD5
                    </button>
                    <button
                      type="button"
                      onClick={() => {
                        const h = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
                        setHashInput(h);
                        setHashFileName('clean_specification.pdf');
                        executeHashLookup(h, 'clean_specification.pdf');
                      }}
                      className="bg-[#181F2E] border border-[#00E676]/50 hover:border-[#00E676] px-2 py-0.5 rounded-sm text-[#00E676] transition-colors cursor-pointer"
                    >
                      🟢 Clean File SHA-256
                    </button>
                  </div>
                </div>

                <div className="space-y-1">
                  <label className="text-[10px] font-mono uppercase text-[#7E8B9B] font-bold block">
                    Artifact Filename (Optional)
                  </label>
                  <input
                    type="text"
                    value={hashFileName}
                    onChange={(e) => setHashFileName(e.target.value)}
                    placeholder="payload_dropper.exe"
                    className="w-full bg-[#090D14] border border-[#263147] px-3 py-2 text-xs text-[#ECEFF4] placeholder-[#7E8B9B]/50 rounded-sm font-mono focus:border-[#00E5FF] focus:outline-none"
                  />
                </div>

                <button
                  type="submit"
                  disabled={hashLoading}
                  className="w-full btn-soc btn-soc-primary py-2 flex items-center justify-center gap-2 cursor-pointer disabled:opacity-50"
                >
                  <Cpu className="w-3.5 h-3.5" />
                  <span>{hashLoading ? 'INSPECTING HASH MATCHES...' : 'ANALYZE BINARY HASH'}</span>
                </button>
              </form>
            </div>
          )}

          {/* TAB 7: SIEM INCIDENT TRIAGE */}
          {activeTab === 'siem' && (
            <div className="soc-panel p-4 space-y-3">
              <div className="border-b border-[#263147] pb-2 flex items-center justify-between">
                <h2 className="font-display font-bold text-sm uppercase text-white flex items-center gap-2">
                  <ShieldAlert className="w-4 h-4 text-[#FF334B]" />
                  <span>SIEM Incident Response</span>
                </h2>
                <span className="status-chip status-chip-critical">INCIDENT MATRIX</span>
              </div>
              <p className="text-[11px] text-[#7E8B9B] font-mono leading-relaxed">
                Active security incident triage queue with MITRE ATT&CK tactical tagging and automated containment controls.
              </p>

              <button
                onClick={fetchIncidents}
                disabled={incidentsLoading}
                className="w-full btn-soc py-2 flex items-center justify-center gap-2 cursor-pointer"
              >
                <RefreshCw className={`w-3.5 h-3.5 ${incidentsLoading ? 'animate-spin' : ''}`} />
                <span>REFRESH SIEM QUEUE</span>
              </button>
            </div>
          )}

          {/* TAB 8: STIX 2.1 DFIR BUNDLE EXPORT */}
          {activeTab === 'stix' && (
            <div className="soc-panel p-4 space-y-3">
              <div className="border-b border-[#263147] pb-2 flex items-center justify-between">
                <h2 className="font-display font-bold text-sm uppercase text-white flex items-center gap-2">
                  <Layers className="w-4 h-4 text-[#00E5FF]" />
                  <span>STIX 2.1 DFIR Bundler</span>
                </h2>
                <span className="status-chip status-chip-low">STIX SPEC v2.1</span>
              </div>
              <p className="text-[11px] text-[#7E8B9B] font-mono leading-relaxed">
                Export standard Structured Threat Information Expression (STIX 2.1) JSON bundles for interoperability with SIEMs.
              </p>

              <form onSubmit={handleStixExport} className="space-y-3">
                <div className="space-y-1">
                  <label className="text-[10px] font-mono uppercase text-[#7E8B9B] font-bold block">
                    Target Domain / Indicator
                  </label>
                  <input
                    type="text"
                    value={stixTarget}
                    onChange={(e) => setStixTarget(e.target.value)}
                    placeholder="malicious-c2-node.org"
                    className="w-full bg-[#090D14] border border-[#263147] px-3 py-2 text-xs text-[#ECEFF4] placeholder-[#7E8B9B]/50 rounded-sm font-mono focus:border-[#00E5FF] focus:outline-none"
                  />
                </div>

                <div className="space-y-1">
                  <label className="text-[10px] font-mono uppercase text-[#7E8B9B] font-bold block">
                    Malware Payload Hash (SHA-256)
                  </label>
                  <input
                    type="text"
                    value={stixHash}
                    onChange={(e) => setStixHash(e.target.value)}
                    placeholder="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
                    className="w-full bg-[#090D14] border border-[#263147] px-3 py-2 text-xs text-[#ECEFF4] placeholder-[#7E8B9B]/50 rounded-sm font-mono focus:border-[#00E5FF] focus:outline-none"
                  />
                </div>

                <button
                  type="submit"
                  disabled={stixLoading}
                  className="w-full btn-soc btn-soc-primary py-2 flex items-center justify-center gap-2 cursor-pointer disabled:opacity-50"
                >
                  <Code className="w-3.5 h-3.5" />
                  <span>{stixLoading ? 'GENERATING BUNDLE...' : 'GENERATE STIX 2.1 BUNDLE'}</span>
                </button>
              </form>
            </div>
          )}

          {/* Quick Terminal Drawer Toggle */}
          <div className="soc-panel p-3 flex items-center justify-between">
            <div className="flex items-center gap-2 text-xs font-mono">
              <TerminalIcon className="w-4 h-4 text-[#00E5FF]" />
              <span>Interactive SOC Shell</span>
            </div>
            <button
              onClick={() => setShowTerminal(!showTerminal)}
              className="btn-soc px-2.5 py-1 text-[10px] cursor-pointer"
            >
              {showTerminal ? 'HIDE SHELL' : 'LAUNCH SHELL (Ctrl+~)'}
            </button>
          </div>

          {showTerminal && <Terminal />}

        </div>

        {/* CENTER COLUMN: TELEMETRY FINDINGS & FORENSICS INSPECTOR (5 cols) */}
        <div className="lg:col-span-5 space-y-4">
          
          {/* DISPLAY SCAN RESULTS FOR BREACH / LINK / IMAGE SCANS */}
          {['email', 'link', 'image'].includes(activeTab) && currentScan && (
            <div className="soc-panel p-4 space-y-4">
              <div className="border-b border-[#263147] pb-2 flex items-center justify-between">
                <div>
                  <span className="text-[10px] font-mono uppercase text-[#7E8B9B] block font-bold">
                    AUDITED TARGET: {currentScan.targetEmail || currentScan.targetLink || currentScan.imageFileName}
                  </span>
                  <h3 className="font-display font-bold text-base uppercase text-white mt-0.5">
                    Threat Audit Summary
                  </h3>
                </div>

                {/* Raw JSON vs Annotated Switcher */}
                <button
                  onClick={() => setRawViewMode(!rawViewMode)}
                  className={`btn-soc px-2 py-1 text-[10px] flex items-center gap-1 cursor-pointer ${rawViewMode ? 'border-[#00E5FF] text-[#00E5FF]' : ''}`}
                >
                  <Code className="w-3 h-3" />
                  <span>{rawViewMode ? 'ANNOTATED VIEW' : 'RAW JSON'}</span>
                </button>
              </div>

              {/* Bit-Density Segment Risk Meter */}
              {renderBitDensityMeter(currentScan.riskScore)}

              {/* RAW JSON VIEW */}
              {rawViewMode ? (
                <div className="bg-[#090D14] border border-[#263147] p-3 rounded-sm font-mono text-[11px] overflow-x-auto text-[#00E5FF] max-h-96">
                  <pre>{JSON.stringify(currentScan, null, 2)}</pre>
                </div>
              ) : (
                /* ANNOTATED FINDINGS VIEW */
                <div className="space-y-3">
                  <div className="bg-[#090D14] border border-[#263147] p-3 text-xs leading-relaxed text-[#ECEFF4] font-mono whitespace-pre-wrap">
                    {currentScan.forensicSummary || currentScan.aiSummary}
                  </div>

                  {currentScan.breaches && currentScan.breaches.length > 0 && (
                    <div className="space-y-2">
                      <span className="text-[10px] font-mono uppercase text-[#7E8B9B] font-bold block">
                        Exposed Database Leak Records ({currentScan.breaches.length})
                      </span>
                      <div className="space-y-2">
                        {currentScan.breaches.map(breach => (
                          <div key={breach.id} className="border border-[#263147] bg-[#090D14] p-2.5 rounded-sm space-y-1 text-xs">
                            <div className="flex items-center justify-between font-mono">
                              <strong className="text-white">{breach.Title} ({breach.Domain})</strong>
                              <span className={`status-chip ${breach.severity === 'critical' ? 'status-chip-critical' : breach.severity === 'high' ? 'status-chip-high' : 'status-chip-medium'}`}>
                                {breach.severity}
                              </span>
                            </div>
                            <p className="text-[11px] text-[#7E8B9B] leading-snug">{breach.Description}</p>
                            <div className="text-[10px] font-mono text-[#00E5FF] pt-1">
                              EXPOSED DATA: {breach.DataClasses.join(', ')}
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  <div className="flex items-center justify-between pt-2 border-t border-[#263147]">
                    <span className="text-[10px] font-mono text-[#7E8B9B]">
                      TIMESTAMP: {new Date(currentScan.timestamp).toLocaleString()}
                    </span>
                    <button
                      onClick={() => onSelectReport(currentScan)}
                      className="btn-soc px-3 py-1 text-[10px] flex items-center gap-1 text-[#00E5FF] border-[#00E5FF]/40 cursor-pointer"
                    >
                      <Eye className="w-3 h-3" />
                      <span>FULL FORENSIC REPORT & PDF</span>
                    </button>
                  </div>
                </div>
              )}
            </div>
          )}

          {/* DISPLAY NIST CVE RESULTS */}
          {activeTab === 'cve' && (
            <div className="soc-panel p-4 space-y-3">
              <div className="border-b border-[#263147] pb-2 flex items-center justify-between">
                <h3 className="font-display font-bold text-sm uppercase text-white">
                  NVD CVE Records ({cveResults?.totalMatches || 0})
                </h3>
                <span className="text-[10px] font-mono text-[#7E8B9B]">NIST NVD API v2.0</span>
              </div>

              {cveLoading ? (
                <div className="py-12 text-center font-mono text-xs text-[#00E5FF] animate-pulse">
                  Querying NIST National Vulnerability Database...
                </div>
              ) : cveResults?.cves && cveResults.cves.length > 0 ? (
                <div className="space-y-2 max-h-[500px] overflow-y-auto pr-1">
                  {cveResults.cves.map(cve => (
                    <div key={cve.id} className="border border-[#263147] bg-[#090D14] p-3 rounded-sm space-y-1.5 font-mono text-xs">
                      <div className="flex items-center justify-between">
                        <strong className="text-[#00E5FF] font-bold">{cve.id}</strong>
                        <span className={`status-chip ${cve.score >= 9.0 ? 'status-chip-critical' : cve.score >= 7.0 ? 'status-chip-high' : 'status-chip-medium'}`}>
                          CVSS {cve.score.toFixed(1)} [{cve.severity}]
                        </span>
                      </div>
                      <p className="text-[11px] text-[#ECEFF4] leading-relaxed">{cve.description}</p>
                      {cve.vectorString && (
                        <div className="text-[9px] text-[#7E8B9B] truncate">
                          VECTOR: {cve.vectorString}
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              ) : (
                <div className="py-8 text-center font-mono text-xs text-[#7E8B9B]">
                  No CVE records found. Select a quick preset above to search NVD.
                </div>
              )}
            </div>
          )}

          {/* DISPLAY OSINT INSPECTION RESULTS */}
          {activeTab === 'osint' && osintResult && (
            <div className="soc-panel p-4 space-y-3 font-mono text-xs">
              <div className="border-b border-[#263147] pb-2 flex items-center justify-between">
                <h3 className="font-display font-bold text-sm uppercase text-white">
                  OSINT Analysis: {osintResult.target}
                </h3>
                <span className="status-chip status-chip-medium">
                  SCORE: {osintResult.reputationScore}/100
                </span>
              </div>

              <div className="grid grid-cols-2 gap-2 text-[11px]">
                <div className="bg-[#090D14] p-2 border border-[#263147]">
                  <span className="text-[#7E8B9B] block text-[9px] uppercase">Resolved IP</span>
                  <span className="font-bold text-[#00E5FF]">{osintResult.resolvedIp}</span>
                </div>
                <div className="bg-[#090D14] p-2 border border-[#263147]">
                  <span className="text-[#7E8B9B] block text-[9px] uppercase">Location / ISP</span>
                  <span className="font-bold text-[#ECEFF4]">{osintResult.location.country} • {osintResult.location.isp}</span>
                </div>
              </div>

              <div className="space-y-1">
                <span className="text-[10px] uppercase text-[#7E8B9B] font-bold block">Blacklist DB Checks</span>
                <div className="space-y-1">
                  {osintResult.blacklists.map((bl, idx) => (
                    <div key={idx} className="flex items-center justify-between bg-[#090D14] px-2 py-1 border border-[#263147] text-[11px]">
                      <span>{bl.name}</span>
                      <span className={bl.listed ? 'text-[#FF334B] font-bold' : 'text-[#00E676]'}>
                        {bl.listed ? 'LISTED / THREAT' : 'CLEAN'}
                      </span>
                    </div>
                  ))}
                </div>
              </div>

              <div className="text-[10px] text-[#7E8B9B] bg-[#090D14] p-2 border border-[#263147]">
                {osintResult.investigatorNotes}
              </div>
            </div>
          )}

          {/* DISPLAY MALWARE HASH RESULTS */}
          {activeTab === 'hash' && hashResult && (
            <div className="soc-panel p-4 space-y-3 font-mono text-xs">
              <div className="border-b border-[#263147] pb-2 flex items-center justify-between">
                <h3 className="font-display font-bold text-sm uppercase text-white">
                  Hash Forensics: {hashResult.fileName}
                </h3>
                <span className={`status-chip ${hashResult.malwareClassification === 'malicious' ? 'status-chip-critical' : 'status-chip-low'}`}>
                  {hashResult.malwareClassification.toUpperCase()}
                </span>
              </div>

              <div className="space-y-1 bg-[#090D14] p-2.5 border border-[#263147] text-[11px]">
                <div><span className="text-[#7E8B9B]">HASH ({hashResult.hashType}):</span> <span className="text-[#00E5FF] select-all">{hashResult.hash}</span></div>
                <div><span className="text-[#7E8B9B]">FORMAT:</span> {hashResult.detectedFormat}</div>
                <div><span className="text-[#7E8B9B]">ENTROPY SCORE:</span> {hashResult.entropyScore}/8.00</div>
                <div><span className="text-[#7E8B9B]">MAGIC BYTES:</span> {hashResult.magicBytes}</div>
              </div>

              {hashResult.matchedYaraRules.length > 0 && (
                <div className="space-y-1">
                  <span className="text-[10px] uppercase text-[#7E8B9B] font-bold block">Matched YARA Signatures</span>
                  <div className="flex flex-wrap gap-1">
                    {hashResult.matchedYaraRules.map((rule, i) => (
                      <span key={i} className="bg-[#FF334B]/15 text-[#FF334B] border border-[#FF334B]/30 px-1.5 py-0.5 text-[10px]">
                        {rule}
                      </span>
                    ))}
                  </div>
                </div>
              )}

              <div className="p-2.5 bg-[#181F2E] border border-[#263147] text-[11px] leading-relaxed">
                <strong className="text-[#00E5FF] block text-[10px] uppercase">SOC Actionable Recommendation:</strong>
                <p className="mt-0.5">{hashResult.recommendation}</p>
              </div>
            </div>
          )}

          {/* DISPLAY SIEM INCIDENT LIST & TRIAGE */}
          {activeTab === 'siem' && (
            <div className="soc-panel p-4 space-y-3">
              <div className="border-b border-[#263147] pb-2 flex items-center justify-between">
                <h3 className="font-display font-bold text-sm uppercase text-white">
                  Active SIEM Incidents ({incidentsList.length})
                </h3>
                <span className="text-[10px] font-mono text-[#7E8B9B]">REALTIME INCIDENT MATRIX</span>
              </div>

              <div className="space-y-2">
                {incidentsList.map(inc => (
                  <div 
                    key={inc.id}
                    onClick={() => setSelectedIncident(inc)}
                    className={`border p-3 rounded-sm font-mono text-xs cursor-pointer transition-colors ${
                      selectedIncident?.id === inc.id 
                        ? 'border-[#00E5FF] bg-[#181F2E]' 
                        : 'border-[#263147] bg-[#090D14] hover:border-[#7E8B9B]'
                    }`}
                  >
                    <div className="flex items-center justify-between mb-1">
                      <strong className="text-white">{inc.id}: {inc.title}</strong>
                      <span className={`status-chip ${inc.severity === 'critical' ? 'status-chip-critical' : 'status-chip-high'}`}>
                        {inc.severity}
                      </span>
                    </div>
                    <p className="text-[11px] text-[#7E8B9B] leading-snug">{inc.description}</p>
                    <div className="flex items-center justify-between text-[10px] text-[#00E5FF] mt-2 pt-1 border-t border-[#263147]">
                      <span>TACTIC: {inc.mitreTactic} ({inc.mitreTechniqueId})</span>
                      <span className="uppercase text-white font-bold">{inc.status}</span>
                    </div>
                  </div>
                ))}
              </div>

              {selectedIncident && (
                <form onSubmit={handleTriageSubmit} className="border-t border-[#263147] pt-3 space-y-2">
                  <span className="text-[10px] font-mono uppercase text-[#7E8B9B] font-bold block">
                    Execute Triage Action for {selectedIncident.id}
                  </span>
                  
                  <div className="grid grid-cols-2 gap-2">
                    <select
                      value={triageStatus}
                      onChange={(e) => setTriageStatus(e.target.value as any)}
                      className="bg-[#090D14] border border-[#263147] p-1.5 text-xs text-[#ECEFF4] font-mono focus:border-[#00E5FF] focus:outline-none"
                    >
                      <option value="investigating">INVESTIGATING</option>
                      <option value="mitigated">MITIGATED / CONTAINED</option>
                      <option value="false_positive">FALSE POSITIVE</option>
                      <option value="new">NEW ALERT</option>
                    </select>

                    <input
                      type="text"
                      value={containmentActionInput}
                      onChange={(e) => setContainmentActionInput(e.target.value)}
                      placeholder="Containment action (e.g. Block IP)"
                      className="bg-[#090D14] border border-[#263147] p-1.5 text-xs text-[#ECEFF4] font-mono focus:border-[#00E5FF] focus:outline-none"
                    />
                  </div>

                  <input
                    type="text"
                    value={triageNote}
                    onChange={(e) => setTriageNote(e.target.value)}
                    placeholder="Analyst triage note..."
                    className="w-full bg-[#090D14] border border-[#263147] p-1.5 text-xs text-[#ECEFF4] font-mono focus:border-[#00E5FF] focus:outline-none"
                  />

                  <button type="submit" className="w-full btn-soc btn-soc-primary py-1.5 text-xs cursor-pointer">
                    UPDATE INCIDENT STATUS
                  </button>
                </form>
              )}
            </div>
          )}

          {/* DISPLAY STIX BUNDLE RESULT */}
          {activeTab === 'stix' && (
            <div className="soc-panel p-4 space-y-3">
              <div className="border-b border-[#263147] pb-2 flex items-center justify-between">
                <h3 className="font-display font-bold text-sm uppercase text-white">
                  STIX 2.1 JSON Evidence Bundle
                </h3>
                {stixBundleResult && (
                  <button
                    onClick={handleDownloadStixJson}
                    className="btn-soc px-2.5 py-1 text-[10px] flex items-center gap-1 text-[#00E676] border-[#00E676]/40 cursor-pointer"
                  >
                    <Download className="w-3 h-3" />
                    <span>DOWNLOAD JSON</span>
                  </button>
                )}
              </div>

              {stixBundleResult ? (
                <div className="bg-[#090D14] border border-[#263147] p-3 rounded-sm font-mono text-[11px] overflow-x-auto text-[#00E5FF] max-h-96">
                  <pre>{JSON.stringify(stixBundleResult, null, 2)}</pre>
                </div>
              ) : (
                <div className="py-8 text-center font-mono text-xs text-[#7E8B9B]">
                  Click "Generate STIX 2.1 Bundle" on the left panel to produce a standardized DFIR evidence bundle.
                </div>
              )}
            </div>
          )}

          {/* SYSTEM USAGE AUDIT TRAIL LOG */}
          <UsageAudit scans={scans} onSelectReport={onSelectReport} />

        </div>

        {/* RIGHT COLUMN: TRUST COMPLIANCE & RECENT THREAT LOGS (3 cols) */}
        <div className="lg:col-span-3 space-y-4">
          
          {/* Quick Scan History Feed */}
          <div className="soc-panel p-4 space-y-3">
            <div className="border-b border-[#263147] pb-2 flex items-center justify-between">
              <div className="flex items-center gap-1.5 text-[#00E5FF] font-mono text-[10px] font-bold">
                <History className="w-3.5 h-3.5" />
                <span>RECENT SESSIONS</span>
              </div>
              <span className="text-[10px] font-mono text-[#7E8B9B]">{scans.length} Total</span>
            </div>

            <div className="space-y-1.5 max-h-56 overflow-y-auto pr-1">
              {scans.length > 0 ? (
                scans.slice(0, 6).map(s => (
                  <div
                    key={s.id}
                    onClick={() => {
                      setCurrentScan(s);
                      if (s.scanType === 'link') setActiveTab('link');
                      else if (s.scanType === 'image') setActiveTab('image');
                      else setActiveTab('email');
                    }}
                    className="p-2 border border-[#263147] bg-[#090D14] hover:border-[#00E5FF] rounded-sm cursor-pointer transition-colors font-mono text-[11px]"
                  >
                    <div className="flex items-center justify-between">
                      <span className="text-white font-bold truncate max-w-[140px]">
                        {s.targetEmail || s.targetLink || s.imageFileName || 'Assessment'}
                      </span>
                      <span className={`text-[10px] font-bold ${s.riskScore >= 70 ? 'text-[#FF334B]' : s.riskScore >= 40 ? 'text-[#FF9900]' : 'text-[#00E676]'}`}>
                        {s.riskScore}/100
                      </span>
                    </div>
                    <span className="text-[9px] text-[#7E8B9B] block mt-0.5">
                      {new Date(s.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })} • {s.scanType?.toUpperCase() || 'EMAIL'}
                    </span>
                  </div>
                ))
              ) : (
                <div className="text-center py-4 text-[10px] font-mono text-[#7E8B9B]">
                  No scans recorded yet.
                </div>
              )}
            </div>
          </div>

          {/* Trust, Privacy & Compliance Center */}
          <div className="soc-panel p-4 space-y-3">
            <div className="border-b border-[#263147] pb-2">
              <div className="flex items-center gap-1 text-[#00E5FF] font-mono text-[10px] font-bold">
                <ShieldCheck className="w-3.5 h-3.5" />
                <span>COMPLIANCE & DATA RIGHTS</span>
              </div>
              <h3 className="font-display font-bold text-xs uppercase text-white mt-1">
                Trust & Security Center
              </h3>
            </div>

            {/* Compliance Selector Tabs */}
            <div className="grid grid-cols-5 gap-0.5 border-b border-[#263147] pb-2 text-[9px] font-mono font-bold text-center">
              {[
                { id: 'gmail', label: 'GMAIL' },
                { id: 'sourcing', label: 'LEGAL' },
                { id: 'soc2', label: 'SOC2' },
                { id: 'bounty', label: 'BOUNTY' },
                { id: 'erasure', label: 'ERASE' },
              ].map(item => (
                <button
                  key={item.id}
                  onClick={() => setComplianceTab(item.id as any)}
                  className={`pb-1 transition-colors cursor-pointer border-b ${
                    complianceTab === item.id 
                      ? 'border-[#00E5FF] text-[#00E5FF]' 
                      : 'border-transparent text-[#7E8B9B] hover:text-[#ECEFF4]'
                  }`}
                >
                  {item.label}
                </button>
              ))}
            </div>

            <div className="text-[11px] font-mono leading-relaxed text-[#7E8B9B]">
              {complianceTab === 'gmail' && (
                <div className="space-y-1.5">
                  <span className="font-bold text-[#00E5FF] text-[10px] uppercase block">Transient Inbox Audit</span>
                  <p>Zero retention: email bodies are audited transiently in-memory and purged immediately after scan.</p>
                </div>
              )}

              {complianceTab === 'sourcing' && (
                <div className="space-y-1.5">
                  <span className="font-bold text-[#00E5FF] text-[10px] uppercase block">Certified Sourcing</span>
                  <p>Leak matching queries leverage audited static academic leak databases without active forum scraping.</p>
                </div>
              )}

              {complianceTab === 'soc2' && (
                <div className="space-y-1.5">
                  <span className="font-bold text-[#00E5FF] text-[10px] uppercase block">SOC2 & GDPR Roadmap</span>
                  <p>Fully compliant with GDPR Art. 17 right-to-erasure and enforced 256-bit TLS in-transit encryption.</p>
                </div>
              )}

              {complianceTab === 'bounty' && (
                <div className="space-y-1.5">
                  <span className="font-bold text-[#00E5FF] text-[10px] uppercase block">Bug Bounty Program</span>
                  <p>Submit vulnerability reports to <span className="text-[#00E5FF] select-all">hemantkaushal72@gmail.com</span> for 48h response validation.</p>
                </div>
              )}

              {complianceTab === 'erasure' && (
                <div className="space-y-2">
                  <span className="font-bold text-[#00E5FF] text-[10px] uppercase block">GDPR Data Erasure</span>
                  <p>Instantly purge all historical scan logs under this session.</p>

                  {clearScansSuccess ? (
                    <div className="p-2 bg-[#00E676]/10 border border-[#00E676]/30 text-[#00E676] text-[10px]">
                      All threat scan logs purged successfully.
                    </div>
                  ) : confirmWipe ? (
                    <div className="space-y-1.5 bg-[#FF334B]/10 border border-[#FF334B]/30 p-2">
                      <span className="text-[9px] text-[#FF334B] font-bold block uppercase text-center">CONFIRM PERMANENT ERASURE?</span>
                      <div className="flex gap-2">
                        <button
                          type="button"
                          disabled={isClearingScans}
                          onClick={handleWipeScans}
                          className="flex-1 bg-[#FF334B] text-white font-bold text-[10px] py-1 cursor-pointer"
                        >
                          {isClearingScans ? 'PURGING...' : 'YES, PURGE'}
                        </button>
                        <button
                          type="button"
                          onClick={() => setConfirmWipe(false)}
                          className="btn-soc px-2 py-1 text-[10px]"
                        >
                          CANCEL
                        </button>
                      </div>
                    </div>
                  ) : (
                    <button
                      type="button"
                      onClick={() => setConfirmWipe(true)}
                      className="w-full btn-soc border-[#FF334B]/40 text-[#FF334B] hover:bg-[#FF334B]/10 py-1.5 text-[10px] flex items-center justify-center gap-1.5 cursor-pointer"
                    >
                      <Trash2 className="w-3.5 h-3.5" />
                      <span>PURGE ALL SCAN LOGS</span>
                    </button>
                  )}
                </div>
              )}
            </div>
          </div>

        </div>

      </div>

      {/* Brand Privacy Modal Overlay */}
      <PrivacyStatementModal 
        isOpen={showPrivacyModal} 
        onClose={() => setShowPrivacyModal(false)} 
        isLoggedIn={true} 
        userEmail={user.email} 
        onWipeData={handleWipeScans} 
      />

    </div>
  );
}
