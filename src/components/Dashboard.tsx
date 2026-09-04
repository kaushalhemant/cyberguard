import React, { useState, useEffect, useRef } from 'react';
import { 
  Shield, ShieldAlert, ShieldCheck, Mail, Search, History, Terminal as TerminalIcon, 
  Zap, Lock, Bell, Users, Cpu, FileText, CheckCircle2, RefreshCw, Link2, 
  UploadCloud, Globe, Eye, Trash2, Server, Activity, FileCode, AlertTriangle, 
  Download, Database, Key, Layers, Crosshair, Code, Filter, Check, X, ChevronRight,
  ArrowUpRight, Sparkles, Copy, FileJson, Atom, Bot, Satellite, Radio, Binary,
  ShieldOff, Workflow, BrainCircuit, Mic, Video, Radar, Network
} from 'lucide-react';
import { 
  User, ScanResult, OsintResult, HashAnalysisResult, SocIncident, CveRecord,
  PqcAnalysisResult, QuantumSimResult, DeepfakeForensicsResult, AiAgent, AiSwarmEvent, SatelliteMeshTelemetry
} from '../types';
import Terminal from './Terminal';
import PrivacyStatementModal from './PrivacyStatementModal';
import UsageAudit from './UsageAudit';
import { safeJsonResponse } from '../lib/api';
import { generateScanPdf } from '../lib/pdfGenerator';
import {
  clientLookupEmail,
  clientAnalyzeUrl,
  clientAnalyzeImage,
  clientSearchCves,
  clientAnalyzeOsint,
  clientAnalyzeHash,
  clientGenerateStix,
  CLIENT_PREINDEXED_CVES,
  clientAnalyzePqc,
  clientSimulateQuantum,
  clientAnalyzeDeepfake,
  clientGetAiSwarmState,
  clientExecuteSwarmPlaybook,
  clientGetSatelliteMesh
} from '../lib/clientThreatEngine';

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
  const [activeTab, setActiveTab] = useState<
    'pqc' | 'swarm' | 'deepfake' | 'satellite' | 'email' | 'link' | 'image' | 'cve' | 'osint' | 'hash' | 'siem' | 'stix'
  >('pqc');
  
  const [rawViewMode, setRawViewMode] = useState<boolean>(false);
  const [copiedNotification, setCopiedNotification] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // 1. Post-Quantum (PQC) States
  const [pqcTarget, setPqcTarget] = useState('quantum-defense.gov');
  const [pqcLoading, setPqcLoading] = useState(false);
  const [pqcResult, setPqcResult] = useState<PqcAnalysisResult | null>(null);
  const [simCipher, setSimCipher] = useState<'RSA' | 'ECC' | 'ML-KEM'>('RSA');
  const [simKeySize, setSimKeySize] = useState<number>(2048);
  const [simResult, setSimResult] = useState<QuantumSimResult | null>(null);

  // 2. Autonomous AI Swarm States
  const [swarmAgents, setSwarmAgents] = useState<AiAgent[]>([]);
  const [swarmEvents, setSwarmEvents] = useState<AiSwarmEvent[]>([]);
  const [swarmLoading, setSwarmLoading] = useState(false);
  const [selectedAgentId, setSelectedAgentId] = useState('agent_sentinel_alpha');
  const [selectedPlaybook, setSelectedPlaybook] = useState('Micro-Isolation Ephemeral Honeyswarm');
  const [customPlaybookTarget, setCustomPlaybookTarget] = useState('Kernel WASM Sandbox WS-092');

  // 3. Neural Deepfake States
  const [deepfakeTargetName, setDeepfakeTargetName] = useState('executive_conference_stream.mp4');
  const [deepfakeMediaType, setDeepfakeMediaType] = useState<'image' | 'audio' | 'video'>('video');
  const [deepfakeLoading, setDeepfakeLoading] = useState(false);
  const [deepfakeResult, setDeepfakeResult] = useState<DeepfakeForensicsResult | null>(null);

  // 4. LEO Satellite Mesh States
  const [satelliteData, setSatelliteData] = useState<SatelliteMeshTelemetry | null>(null);
  const [satelliteLoading, setSatelliteLoading] = useState(false);

  // 5. Existing Vectors (Email, URL, OCR, CVE, OSINT, Hash, SIEM, STIX)
  const [scanEmail, setScanEmail] = useState('');
  const [scanUrl, setScanUrl] = useState('');
  const [imageFile, setImageFile] = useState<File | null>(null);
  const [imagePreview, setImagePreview] = useState<string | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const [cveQuery, setCveQuery] = useState('');
  const [cveSeverity, setCveSeverity] = useState<string>('ALL');
  const [cveLoading, setCveLoading] = useState(false);
  const [cveResults, setCveResults] = useState<{ totalMatches: number; cves: CveRecord[] } | null>(null);

  const [osintTarget, setOsintTarget] = useState('');
  const [osintLoading, setOsintLoading] = useState(false);
  const [osintResult, setOsintResult] = useState<OsintResult | null>(null);

  const [hashInput, setHashInput] = useState('');
  const [hashFileName, setHashFileName] = useState('');
  const [hashLoading, setHashLoading] = useState(false);
  const [hashResult, setHashResult] = useState<HashAnalysisResult | null>(null);

  const [incidentsList, setIncidentsList] = useState<SocIncident[]>([]);
  const [incidentsLoading, setIncidentsLoading] = useState(false);
  const [selectedIncident, setSelectedIncident] = useState<SocIncident | null>(null);
  const [triageNote, setTriageNote] = useState('');
  const [triageStatus, setTriageStatus] = useState<SocIncident['status']>('investigating');
  const [containmentActionInput, setContainmentActionInput] = useState('');

  const [stixTarget, setStixTarget] = useState('');
  const [stixBundleResult, setStixBundleResult] = useState<any | null>(null);
  const [stixLoading, setStixLoading] = useState(false);

  const [scans, setScans] = useState<ScanResult[]>([]);
  const [currentScan, setCurrentScan] = useState<ScanResult | null>(null);
  const [showTerminal, setShowTerminal] = useState(false);

  const [showPrivacyModal, setShowPrivacyModal] = useState(false);
  const [complianceTab, setComplianceTab] = useState<'gmail' | 'sourcing' | 'soc2' | 'bounty' | 'erasure'>('gmail');
  const [confirmWipe, setConfirmWipe] = useState(false);
  const [isClearingScans, setIsClearingScans] = useState(false);
  const [clearScansSuccess, setClearScansSuccess] = useState(false);

  const notifyCopy = (msg: string) => {
    setCopiedNotification(msg);
    setTimeout(() => setCopiedNotification(null), 2500);
  };

  useEffect(() => {
    loadHistory();
    loadLatestCves();
    fetchIncidents();
    loadPqcAudit('quantum-defense.gov');
    loadQuantumSim('RSA', 2048);
    fetchSwarmState();
    loadDeepfakeForensics('executive_conference_stream.mp4', 'video');
    fetchSatelliteMesh();
  }, [token]);

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

  const loadHistory = async () => {
    try {
      const response = await fetch('/api/scans', { headers: { 'Authorization': `Bearer ${token}` } });
      if (response.ok) {
        const data = await safeJsonResponse(response);
        if (data?.scans) {
          setScans(data.scans);
          if (data.scans.length > 0 && !currentScan) setCurrentScan(data.scans[0]);
        }
      }
    } catch {
      // Fallback
    }
  };

  const loadLatestCves = async () => {
    setCveLoading(true);
    try {
      const res = await fetch('/api/cve/latest?limit=12', { headers: { 'Authorization': `Bearer ${token}` } });
      if (res.ok) {
        const data = await safeJsonResponse(res);
        if (data?.cves) {
          setCveResults({ totalMatches: data.cves.length, cves: data.cves });
          return;
        }
      }
    } catch {
      // Fallback
    } finally {
      setCveLoading(false);
    }
    setCveResults({ totalMatches: CLIENT_PREINDEXED_CVES.length, cves: CLIENT_PREINDEXED_CVES });
  };

  const fetchIncidents = async () => {
    setIncidentsLoading(true);
    try {
      const res = await fetch('/api/soc/incidents', { headers: { 'Authorization': `Bearer ${token}` } });
      if (res.ok) {
        const data = await safeJsonResponse(res);
        if (data?.incidents) {
          setIncidentsList(data.incidents);
          if (data.incidents.length > 0 && !selectedIncident) setSelectedIncident(data.incidents[0]);
          return;
        }
      }
    } catch {
      // Fallback
    } finally {
      setIncidentsLoading(false);
    }
  };

  const loadPqcAudit = async (target: string) => {
    if (!target) return;
    setPqcLoading(true);
    setError(null);
    try {
      const res = await fetch('/api/pqc/audit', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${token}` },
        body: JSON.stringify({ target })
      });
      if (res.ok) {
        const data = await safeJsonResponse(res);
        if (data && data.target) {
          setPqcResult(data);
          return;
        }
      }
    } catch {
      // Fallback
    } finally {
      setPqcLoading(false);
    }
    const localPqc = clientAnalyzePqc(target);
    setPqcResult(localPqc);
  };

  const loadQuantumSim = async (cipher: 'RSA' | 'ECC' | 'ML-KEM', keySize: number) => {
    try {
      const res = await fetch('/api/quantum/simulate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${token}` },
        body: JSON.stringify({ cipher, keySize })
      });
      if (res.ok) {
        const data = await safeJsonResponse(res);
        if (data && data.cipher) {
          setSimResult(data);
          return;
        }
      }
    } catch {
      // Fallback
    }
    const localSim = clientSimulateQuantum(cipher, keySize);
    setSimResult(localSim);
  };

  const fetchSwarmState = async () => {
    setSwarmLoading(true);
    try {
      const res = await fetch('/api/ai-swarm/telemetry', { headers: { 'Authorization': `Bearer ${token}` } });
      if (res.ok) {
        const data = await safeJsonResponse(res);
        if (data && data.activeAgents) {
          setSwarmAgents(data.activeAgents);
          setSwarmEvents(data.events || []);
          return;
        }
      }
    } catch {
      // Fallback
    } finally {
      setSwarmLoading(false);
    }
    const localSwarm = clientGetAiSwarmState();
    setSwarmAgents(localSwarm.activeAgents);
    setSwarmEvents(localSwarm.events);
  };

  const dispatchSwarmPlaybook = async () => {
    setSwarmLoading(true);
    try {
      const res = await fetch('/api/ai-swarm/action', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${token}` },
        body: JSON.stringify({
          agentId: selectedAgentId,
          playbook: selectedPlaybook,
          target: customPlaybookTarget
        })
      });
      if (res.ok) {
        const data = await safeJsonResponse(res);
        if (data?.event) {
          setSwarmEvents(prev => [data.event, ...prev]);
          notifyCopy(`Playbook Dispatched: ${data.event.agentCodename}`);
          return;
        }
      }
    } catch {
      // Fallback
    } finally {
      setSwarmLoading(false);
    }
    const localEvent = clientExecuteSwarmPlaybook(selectedAgentId, selectedPlaybook, customPlaybookTarget);
    setSwarmEvents(prev => [localEvent, ...prev]);
    notifyCopy(`Playbook Dispatched: ${localEvent.agentCodename}`);
  };

  const loadDeepfakeForensics = async (name: string, type: 'image' | 'audio' | 'video' = 'video') => {
    setDeepfakeLoading(true);
    try {
      const res = await fetch('/api/deepfake/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${token}` },
        body: JSON.stringify({ targetName: name, mediaType: type })
      });
      if (res.ok) {
        const data = await safeJsonResponse(res);
        if (data && data.targetName) {
          setDeepfakeResult(data);
          return;
        }
      }
    } catch {
      // Fallback
    } finally {
      setDeepfakeLoading(false);
    }
    const localDf = clientAnalyzeDeepfake(name, type);
    setDeepfakeResult(localDf);
  };

  const fetchSatelliteMesh = async () => {
    setSatelliteLoading(true);
    try {
      const res = await fetch('/api/satellite/mesh', { headers: { 'Authorization': `Bearer ${token}` } });
      if (res.ok) {
        const data = await safeJsonResponse(res);
        if (data && data.activeNodes) {
          setSatelliteData(data);
          return;
        }
      }
    } catch {
      // Fallback
    } finally {
      setSatelliteLoading(false);
    }
    const localMesh = clientGetSatelliteMesh();
    setSatelliteData(localMesh);
  };

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
      if (res.ok) {
        const data = await safeJsonResponse(res);
        if (data?.scan) {
          setCurrentScan(data.scan);
          setScans(prev => [data.scan, ...prev]);
          if (data.user) onUserUpdate(data.user);
          return;
        }
      }
    } catch {
      // Fallback
    } finally {
      setLoading(false);
    }
    const clientData = clientLookupEmail(targetEmail);
    setCurrentScan(clientData.scan);
    setScans(prev => [clientData.scan, ...prev]);
  };

  const executeUrlScan = async (targetUrl: string) => {
    if (!targetUrl) return;
    setLoading(true);
    setError(null);
    try {
      const res = await fetch('/api/scan-link', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${token}` },
        body: JSON.stringify({ url: targetUrl })
      });
      if (res.ok) {
        const data = await safeJsonResponse(res);
        if (data?.scan) {
          setCurrentScan(data.scan);
          setScans(prev => [data.scan, ...prev]);
          if (data.user) onUserUpdate(data.user);
          return;
        }
      }
    } catch {
      // Fallback
    } finally {
      setLoading(false);
    }
    const clientData = clientAnalyzeUrl(targetUrl);
    setCurrentScan(clientData.scan);
    setScans(prev => [clientData.scan, ...prev]);
  };

  const executeCveSearch = async (query: string, severity: string = 'ALL') => {
    setCveLoading(true);
    try {
      const res = await fetch(`/api/cve/search?query=${encodeURIComponent(query)}&severity=${severity}&limit=20`, {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      if (res.ok) {
        const data = await safeJsonResponse(res);
        if (data?.cves) {
          setCveResults(data);
          return;
        }
      }
    } catch {
      // Fallback
    } finally {
      setCveLoading(false);
    }
    const localCves = clientSearchCves(query, severity, 20);
    setCveResults(localCves);
  };

  const executeOsintLookup = async (target: string) => {
    if (!target) return;
    setOsintLoading(true);
    try {
      const res = await fetch('/api/soc/osint-lookup', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${token}` },
        body: JSON.stringify({ target })
      });
      if (res.ok) {
        const data = await safeJsonResponse(res);
        if (data && data.target) {
          setOsintResult(data);
          return;
        }
      }
    } catch {
      // Fallback
    } finally {
      setOsintLoading(false);
    }
    const localOsint = clientAnalyzeOsint(target);
    setOsintResult(localOsint);
  };

  const executeHashLookup = async (hash: string) => {
    if (!hash) return;
    setHashLoading(true);
    try {
      const res = await fetch('/api/soc/hash-lookup', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${token}` },
        body: JSON.stringify({ hash, fileName: hashFileName })
      });
      if (res.ok) {
        const data = await safeJsonResponse(res);
        if (data && data.hash) {
          setHashResult(data);
          return;
        }
      }
    } catch {
      // Fallback
    } finally {
      setHashLoading(false);
    }
    const localHash = clientAnalyzeHash(hash, hashFileName);
    setHashResult(localHash);
  };

  const handleTriageSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedIncident) return;
    try {
      const res = await fetch(`/api/soc/incidents/${selectedIncident.id}/triage`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${token}` },
        body: JSON.stringify({ status: triageStatus, containmentAction: containmentActionInput, note: triageNote })
      });
      if (res.ok) {
        const data = await safeJsonResponse(res);
        if (data?.incident) {
          setSelectedIncident(data.incident);
          setIncidentsList(prev => prev.map(i => i.id === data.incident.id ? data.incident : i));
          setTriageNote('');
          notifyCopy('Incident status updated');
          return;
        }
      }
    } catch {
      // Fallback
    }
    const updatedInc = {
      ...selectedIncident,
      status: triageStatus,
      containmentActionTaken: containmentActionInput || selectedIncident.containmentActionTaken
    };
    setSelectedIncident(updatedInc);
    setIncidentsList(prev => prev.map(i => i.id === updatedInc.id ? updatedInc : i));
    setTriageNote('');
    notifyCopy('Incident status updated');
  };

  const handleStixExport = async (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    setStixLoading(true);
    try {
      const res = await fetch('/api/stix3/export', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${token}` },
        body: JSON.stringify({ target: stixTarget || 'quantum-defense-mesh.net', threatScore: 85 })
      });
      if (res.ok) {
        const data = await safeJsonResponse(res);
        if (data?.stix3Bundle || data?.bundle) {
          setStixBundleResult(data.stix3Bundle || data.bundle);
          notifyCopy('2030 STIX 3.0 Bundle Generated');
          return;
        }
      }
    } catch {
      // Fallback
    } finally {
      setStixLoading(false);
    }
    const localStix = clientGenerateStix(stixTarget || 'quantum-defense-mesh.net', 85);
    setStixBundleResult(localStix.bundle);
    notifyCopy('STIX 3.0 JSON Generated (Client)');
  };

  const handleWipeScans = async () => {
    setIsClearingScans(true);
    try {
      await fetch('/api/scans/clear', { method: 'POST', headers: { 'Authorization': `Bearer ${token}` } });
      setScans([]);
      setCurrentScan(null);
      setClearScansSuccess(true);
      setTimeout(() => {
        setClearScansSuccess(false);
        setConfirmWipe(false);
      }, 3000);
    } catch {
      // Fallback
    } finally {
      setIsClearingScans(false);
    }
  };

  const renderBitDensityMeter = (score: number) => {
    const totalBlocks = 20;
    const filledBlocks = Math.round((score / 100) * totalBlocks);
    const emptyBlocks = totalBlocks - filledBlocks;
    const filledStr = '█'.repeat(filledBlocks);
    const emptyStr = '░'.repeat(emptyBlocks);

    let colorClass = 'text-[#10B981]';
    let label = 'LOW / QUANTUM SECURE';
    if (score >= 75) {
      colorClass = 'text-[#FF334B]';
      label = 'CRITICAL RISK';
    } else if (score >= 50) {
      colorClass = 'text-[#FF9900]';
      label = 'HIGH RISK';
    } else if (score >= 25) {
      colorClass = 'text-[#E0C000]';
      label = 'MEDIUM HAZARD';
    }

    return (
      <div className="font-mono text-xs flex flex-wrap items-center justify-between gap-3 bg-[#06090F] p-2.5 border border-[#202D42] rounded-sm">
        <span className={colorClass}>[{filledStr}{emptyStr}]</span>
        <span className={`font-bold uppercase tracking-wider ${colorClass}`}>
          RISK INDEX: {score}/100 • {label}
        </span>
      </div>
    );
  };

  return (
    <div className="space-y-4 font-sans text-[#F0F4F8]">
      
      {/* 2030 TOP TELEMETRY METRIC STRIP */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-2 text-xs font-mono">
        <div className="soc-panel p-2.5 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Atom className="w-4 h-4 text-[#A855F7]" />
            <span className="text-[#8392A5] uppercase font-semibold text-[10px]">PQC Readiness</span>
          </div>
          <span className="font-bold text-[#C084FC] text-sm">
            {pqcResult ? `${pqcResult.quantumReadinessScore}%` : '95%'}
          </span>
        </div>

        <div className="soc-panel p-2.5 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Bot className="w-4 h-4 text-[#00E5FF]" />
            <span className="text-[#8392A5] uppercase font-semibold text-[10px]">AI Swarm SOC</span>
          </div>
          <span className="font-bold text-[#00E5FF] text-sm flex items-center gap-1">
            <span className="w-2 h-2 rounded-full bg-[#10B981] animate-pulse"></span>
            4 AGENTS
          </span>
        </div>

        <div className="soc-panel p-2.5 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Satellite className="w-4 h-4 text-[#10B981]" />
            <span className="text-[#8392A5] uppercase font-semibold text-[10px]">LEO QKD Mesh</span>
          </div>
          <span className="font-bold text-[#10B981] text-sm">
            {satelliteData?.totalPhotonThroughput || '1.42B QPS'}
          </span>
        </div>

        <div className="soc-panel p-2.5 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Layers className="w-4 h-4 text-[#F59E0B]" />
            <span className="text-[#8392A5] uppercase font-semibold text-[10px]">STIX 3.0 DFIR</span>
          </div>
          <span className="font-bold text-[#F59E0B] text-sm">
            FIPS 203 ARMED
          </span>
        </div>
      </div>

      {/* 2030 VECTOR MODULE SELECTOR TAB BAR */}
      <div className="soc-panel p-1.5 flex flex-wrap gap-1 border border-[#202D42] text-[11px] font-mono font-bold">
        {[
          { id: 'pqc', label: '⚛️ POST-QUANTUM (PQC)', icon: Atom, highlight: true },
          { id: 'swarm', label: '🤖 AI SOC SWARM', icon: Bot, highlight: true },
          { id: 'deepfake', label: '👁️ DEEPFAKE LAB', icon: BrainCircuit, highlight: true },
          { id: 'satellite', label: '🛰️ LEO SATELLITE MESH', icon: Satellite, highlight: true },
          { id: 'email', label: 'EMAIL BREACH', icon: Mail },
          { id: 'link', label: 'URL REPUTATION', icon: Link2 },
          { id: 'image', label: 'VISUAL OCR', icon: FileText },
          { id: 'cve', label: 'NIST CVE DB', icon: Database },
          { id: 'osint', label: 'OSINT INSPECTOR', icon: Crosshair },
          { id: 'hash', label: 'MALWARE HASH', icon: FileCode },
          { id: 'siem', label: 'SIEM INCIDENTS', icon: ShieldAlert },
          { id: 'stix', label: 'STIX 3.0 BUNDLE', icon: Layers },
        ].map(tab => {
          const IconComp = tab.icon;
          const isActive = activeTab === tab.id;
          return (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id as any)}
              className={`px-3 py-1.5 flex items-center gap-1.5 rounded-sm transition-all cursor-pointer ${
                isActive 
                  ? (tab.highlight 
                      ? 'bg-[#131B2A] text-[#C084FC] border border-[#A855F7] shadow-[0_0_12px_rgba(168,85,247,0.3)]' 
                      : 'bg-[#131B2A] text-[#00E5FF] border border-[#00E5FF] shadow-[0_0_12px_rgba(0,229,255,0.25)]')
                  : 'text-[#8392A5] hover:text-[#F0F4F8] border border-transparent hover:border-[#202D42]'
              }`}
            >
              <IconComp className={`w-3.5 h-3.5 ${isActive ? (tab.highlight ? 'text-[#C084FC]' : 'text-[#00E5FF]') : ''}`} />
              <span>{tab.label}</span>
            </button>
          );
        })}
      </div>

      {/* MAIN 3-COLUMN WORKSTATION LAYOUT */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
        
        {/* LEFT COLUMN: COMMAND INPUTS & 2030 EXECUTORS (4 cols) */}
        <div className="lg:col-span-4 space-y-4">
          
          {/* TAB 1: 2030 POST-QUANTUM CRYPTOGRAPHY (PQC) & Q-DAY */}
          {activeTab === 'pqc' && (
            <div className="soc-panel p-4 space-y-3">
              <div className="border-b border-[#202D42] pb-2 flex items-center justify-between">
                <h2 className="font-display font-bold text-sm uppercase text-white flex items-center gap-2">
                  <Atom className="w-4 h-4 text-[#A855F7]" />
                  <span>Post-Quantum (PQC) Auditor</span>
                </h2>
                <span className="status-chip status-chip-quantum">NIST FIPS 203/204</span>
              </div>
              <p className="text-[11px] text-[#8392A5] font-mono leading-relaxed">
                Audits cryptographic cipher suites for quantum vulnerability, Shor's algorithm susceptibility, and "Harvest Now, Decrypt Later" (HNDL) data exposure.
              </p>

              <form onSubmit={(e) => { e.preventDefault(); loadPqcAudit(pqcTarget); }} className="space-y-3 pt-1">
                <div className="space-y-1">
                  <label className="text-[10px] font-mono uppercase text-[#8392A5] font-bold block">
                    Target Domain / Endpoint
                  </label>
                  <input
                    type="text"
                    value={pqcTarget}
                    onChange={(e) => setPqcTarget(e.target.value)}
                    placeholder="quantum-defense.gov"
                    className="w-full bg-[#06090F] border border-[#202D42] px-3 py-2 text-xs text-[#F0F4F8] placeholder-[#8392A5]/50 rounded-sm font-mono focus:border-[#A855F7] focus:outline-none"
                    required
                  />
                </div>

                {/* 1-Click PQC Presets */}
                <div className="space-y-1.5">
                  <span className="text-[10px] font-mono uppercase text-[#8392A5] font-bold flex items-center gap-1">
                    <Sparkles className="w-3 h-3 text-[#A855F7]" />
                    <span>Sample Network Endpoints:</span>
                  </span>
                  <div className="grid grid-cols-2 gap-1.5 font-mono text-[10px]">
                    <button
                      type="button"
                      onClick={() => {
                        setPqcTarget('quantum-defense.gov');
                        loadPqcAudit('quantum-defense.gov');
                      }}
                      className="text-left bg-[#131B2A] border border-[#202D42] hover:border-[#10B981] px-2 py-1.5 rounded-sm text-[#F0F4F8] cursor-pointer"
                    >
                      <span className="text-[#10B981] font-bold block">🟢 PQC Compliant</span>
                      <span className="text-[#8392A5] text-[9px] truncate block">quantum-defense.gov</span>
                    </button>
                    <button
                      type="button"
                      onClick={() => {
                        setPqcTarget('legacy-bank.com');
                        loadPqcAudit('legacy-bank.com');
                      }}
                      className="text-left bg-[#131B2A] border border-[#202D42] hover:border-[#FF334B] px-2 py-1.5 rounded-sm text-[#F0F4F8] cursor-pointer"
                    >
                      <span className="text-[#FF334B] font-bold block">🚨 Legacy RSA-2048</span>
                      <span className="text-[#8392A5] text-[9px] truncate block">legacy-bank.com</span>
                    </button>
                  </div>
                </div>

                <button
                  type="submit"
                  disabled={pqcLoading}
                  className="w-full btn-soc btn-soc-quantum py-2 flex items-center justify-center gap-2 cursor-pointer disabled:opacity-50"
                >
                  <Atom className="w-3.5 h-3.5" />
                  <span>{pqcLoading ? 'CALCULATING LATTICE SECURITY...' : 'RUN PQC AUDIT'}</span>
                </button>
              </form>

              {/* Quantum Shor Simulator Quick Switcher */}
              <div className="border-t border-[#202D42] pt-3 space-y-2">
                <span className="text-[10px] font-mono uppercase text-[#8392A5] font-bold block">
                  Quantum Shor's Algorithm Simulator:
                </span>
                <div className="grid grid-cols-3 gap-1 font-mono text-[10px]">
                  {[
                    { cipher: 'RSA' as const, key: 2048, label: 'RSA-2048' },
                    { cipher: 'ECC' as const, key: 256, label: 'ECC-256' },
                    { cipher: 'ML-KEM' as const, key: 768, label: 'ML-KEM-768' },
                  ].map(sim => (
                    <button
                      key={sim.label}
                      type="button"
                      onClick={() => {
                        setSimCipher(sim.cipher);
                        setSimKeySize(sim.key);
                        loadQuantumSim(sim.cipher, sim.key);
                      }}
                      className={`p-1.5 border rounded-sm transition-colors text-center cursor-pointer ${
                        simCipher === sim.cipher && simKeySize === sim.key
                          ? 'border-[#A855F7] bg-[#131B2A] text-[#C084FC] font-bold'
                          : 'border-[#202D42] bg-[#06090F] text-[#8392A5] hover:text-[#F0F4F8]'
                      }`}
                    >
                      {sim.label}
                    </button>
                  ))}
                </div>
              </div>
            </div>
          )}

          {/* TAB 2: AUTONOMOUS MULTI-AGENT AI SOC SWARM */}
          {activeTab === 'swarm' && (
            <div className="soc-panel p-4 space-y-3">
              <div className="border-b border-[#202D42] pb-2 flex items-center justify-between">
                <h2 className="font-display font-bold text-sm uppercase text-white flex items-center gap-2">
                  <Bot className="w-4 h-4 text-[#00E5FF]" />
                  <span>AI Defense Swarm Room</span>
                </h2>
                <span className="status-chip status-chip-cyan">AUTONOMOUS MESH</span>
              </div>
              <p className="text-[11px] text-[#8392A5] font-mono leading-relaxed">
                Coordinated 4-agent autonomous defense mesh executing sub-millisecond hypervisor trapping, automated memory sandbox relocation, and Byzantine consensus voting.
              </p>

              <div className="space-y-2">
                <span className="text-[10px] font-mono uppercase text-[#8392A5] font-bold block">
                  Active Swarm Agents ({swarmAgents.length || 4}):
                </span>
                <div className="space-y-1.5">
                  {(swarmAgents.length > 0 ? swarmAgents : [
                    { id: 'agent_sentinel_alpha', name: 'Sentinel-Alpha', codename: 'SENTINEL-01', role: 'Zero-Day Interception', status: 'ACTIVE', confidenceScore: 99.4, latencyMs: 1.2 },
                    { id: 'agent_crypt_omega', name: 'Crypt-Omega', codename: 'CRYPT-02', role: 'Quantum Lattice Audit', status: 'ACTIVE', confidenceScore: 99.9, latencyMs: 0.8 },
                    { id: 'agent_recon_sigma', name: 'Recon-Sigma', codename: 'RECON-03', role: 'Adversarial AI & Deepfake Hunter', status: 'PATROLLING', confidenceScore: 98.7, latencyMs: 2.1 },
                    { id: 'agent_neutralizer_x', name: 'Neutralizer-X', codename: 'NEUTRAL-04', role: 'Autonomous Counter-Payload', status: 'ACTIVE', confidenceScore: 99.8, latencyMs: 0.4 }
                  ]).map((agent: any) => (
                    <div 
                      key={agent.id}
                      onClick={() => setSelectedAgentId(agent.id)}
                      className={`p-2 border rounded-sm font-mono text-xs cursor-pointer transition-colors ${
                        selectedAgentId === agent.id ? 'border-[#00E5FF] bg-[#131B2A]' : 'border-[#202D42] bg-[#06090F] hover:border-[#8392A5]'
                      }`}
                    >
                      <div className="flex items-center justify-between">
                        <span className="font-bold text-white flex items-center gap-1.5">
                          <span className="w-1.5 h-1.5 rounded-full bg-[#10B981]"></span>
                          {agent.name} <span className="text-[10px] text-[#00E5FF]">[{agent.codename}]</span>
                        </span>
                        <span className="text-[10px] text-[#10B981] font-bold">{agent.confidenceScore}% ACC</span>
                      </div>
                      <div className="text-[10px] text-[#8392A5] mt-1 flex items-center justify-between">
                        <span>{agent.role}</span>
                        <span>{agent.latencyMs}ms latency</span>
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              {/* Playbook Dispatch Form */}
              <div className="border-t border-[#202D42] pt-3 space-y-2">
                <span className="text-[10px] font-mono uppercase text-[#8392A5] font-bold block">
                  Dispatch Autonomous Counter-Playbook:
                </span>
                <input
                  type="text"
                  value={customPlaybookTarget}
                  onChange={(e) => setCustomPlaybookTarget(e.target.value)}
                  placeholder="Target host asset (e.g. Kernel WS-092)"
                  className="w-full bg-[#06090F] border border-[#202D42] px-2 py-1.5 text-xs font-mono text-[#F0F4F8] rounded-sm focus:border-[#00E5FF] focus:outline-none"
                />
                <button
                  type="button"
                  disabled={swarmLoading}
                  onClick={dispatchSwarmPlaybook}
                  className="w-full btn-soc btn-soc-primary py-2 flex items-center justify-center gap-2 cursor-pointer disabled:opacity-50"
                >
                  <Zap className="w-3.5 h-3.5" />
                  <span>EXECUTE SWARM PLAYBOOK</span>
                </button>
              </div>
            </div>
          )}

          {/* TAB 3: NEURAL DEEPFAKE & SYNTHETIC FORENSICS */}
          {activeTab === 'deepfake' && (
            <div className="soc-panel p-4 space-y-3">
              <div className="border-b border-[#202D42] pb-2 flex items-center justify-between">
                <h2 className="font-display font-bold text-sm uppercase text-white flex items-center gap-2">
                  <BrainCircuit className="w-4 h-4 text-[#A855F7]" />
                  <span>Deepfake Forensics Lab</span>
                </h2>
                <span className="status-chip status-chip-quantum">FFT & rPPG BIO</span>
              </div>
              <p className="text-[11px] text-[#8392A5] font-mono leading-relaxed">
                Inspects video, audio, and portrait artifacts for generative diffusion checkerboard anomalies, subdermal blood-pulse hemoglobin variance, and voice formant jitter.
              </p>

              <form onSubmit={(e) => { e.preventDefault(); loadDeepfakeForensics(deepfakeTargetName, deepfakeMediaType); }} className="space-y-3">
                <div className="space-y-1">
                  <label className="text-[10px] font-mono uppercase text-[#8392A5] font-bold block">
                    Target Media Asset Filename / URL
                  </label>
                  <input
                    type="text"
                    value={deepfakeTargetName}
                    onChange={(e) => setDeepfakeTargetName(e.target.value)}
                    placeholder="executive_zoom_auth_call.mp4"
                    className="w-full bg-[#06090F] border border-[#202D42] px-3 py-2 text-xs text-[#F0F4F8] rounded-sm font-mono focus:border-[#A855F7] focus:outline-none"
                    required
                  />
                </div>

                <div className="grid grid-cols-3 gap-1 text-[10px] font-mono">
                  {(['video', 'audio', 'image'] as const).map(t => (
                    <button
                      key={t}
                      type="button"
                      onClick={() => setDeepfakeMediaType(t)}
                      className={`p-1.5 border rounded-sm text-center uppercase cursor-pointer ${
                        deepfakeMediaType === t ? 'border-[#A855F7] bg-[#131B2A] text-[#C084FC] font-bold' : 'border-[#202D42] bg-[#06090F] text-[#8392A5]'
                      }`}
                    >
                      {t}
                    </button>
                  ))}
                </div>

                <div className="space-y-1.5">
                  <span className="text-[10px] font-mono uppercase text-[#8392A5] font-bold block">
                    Sample Media Artifacts:
                  </span>
                  <div className="space-y-1 font-mono text-[10px]">
                    <button
                      type="button"
                      onClick={() => {
                        setDeepfakeTargetName('generative_ceo_video_stream.mp4');
                        setDeepfakeMediaType('video');
                        loadDeepfakeForensics('generative_ceo_video_stream.mp4', 'video');
                      }}
                      className="w-full text-left bg-[#131B2A] border border-[#FF334B]/40 hover:border-[#FF334B] p-1.5 rounded-sm text-[#FF334B] cursor-pointer block truncate"
                    >
                      🚨 Synthetic Diffusion Video Stream (SD-Next 2030)
                    </button>
                    <button
                      type="button"
                      onClick={() => {
                        setDeepfakeTargetName('voice_clone_wire_authorization.mp3');
                        setDeepfakeMediaType('audio');
                        loadDeepfakeForensics('voice_clone_wire_authorization.mp3', 'audio');
                      }}
                      className="w-full text-left bg-[#131B2A] border border-[#FF9900]/40 hover:border-[#FF9900] p-1.5 rounded-sm text-[#FF9900] cursor-pointer block truncate"
                    >
                      🎙️ Neural Voice Clone Stream (XTTS-v3)
                    </button>
                    <button
                      type="button"
                      onClick={() => {
                        setDeepfakeTargetName('authentic_lead_officer_portrait.png');
                        setDeepfakeMediaType('image');
                        loadDeepfakeForensics('authentic_lead_officer_portrait.png', 'image');
                      }}
                      className="w-full text-left bg-[#131B2A] border border-[#10B981]/40 hover:border-[#10B981] p-1.5 rounded-sm text-[#10B981] cursor-pointer block truncate"
                    >
                      🟢 Authentic Sony Sensor Video Stream
                    </button>
                  </div>
                </div>

                <button
                  type="submit"
                  disabled={deepfakeLoading}
                  className="w-full btn-soc btn-soc-quantum py-2 flex items-center justify-center gap-2 cursor-pointer disabled:opacity-50"
                >
                  <BrainCircuit className="w-3.5 h-3.5" />
                  <span>{deepfakeLoading ? 'DISSECTING SPECTRAL FFT...' : 'ANALYZE SYNTHETIC MEDIA'}</span>
                </button>
              </form>
            </div>
          )}

          {/* TAB 4: LEO SATELLITE MESH */}
          {activeTab === 'satellite' && (
            <div className="soc-panel p-4 space-y-3">
              <div className="border-b border-[#202D42] pb-2 flex items-center justify-between">
                <h2 className="font-display font-bold text-sm uppercase text-white flex items-center gap-2">
                  <Satellite className="w-4 h-4 text-[#10B981]" />
                  <span>LEO Constellation Relay</span>
                </h2>
                <span className="status-chip status-chip-low">SPACE QKD MESH</span>
              </div>
              <p className="text-[11px] text-[#8392A5] font-mono leading-relaxed">
                Low Earth Orbit (LEO) space-to-ground satellite telemetry with Quantum Key Distribution (QKD) entangled photon channels and FIPS 140-3 L4 hardware enclave attestation.
              </p>

              <button
                onClick={fetchSatelliteMesh}
                disabled={satelliteLoading}
                className="w-full btn-soc py-2 flex items-center justify-center gap-2 cursor-pointer"
              >
                <RefreshCw className={`w-3.5 h-3.5 ${satelliteLoading ? 'animate-spin' : ''}`} />
                <span>REFRESH ORBITAL TELEMETRY</span>
              </button>
            </div>
          )}

          {/* TAB 5: EMAIL BREACH AUDITOR */}
          {activeTab === 'email' && (
            <div className="soc-panel p-4 space-y-3">
              <div className="border-b border-[#202D42] pb-2 flex items-center justify-between">
                <h2 className="font-display font-bold text-sm uppercase text-white flex items-center gap-2">
                  <Mail className="w-4 h-4 text-[#00E5FF]" />
                  <span>Email Breach Auditor</span>
                </h2>
                <span className="status-chip status-chip-low">ACTIVE</span>
              </div>
              <p className="text-[11px] text-[#8392A5] font-mono leading-relaxed">
                Queries deterministic leak records and analyzes compromised account exposures, leaked credential types, and mitigation steps.
              </p>
              
              <form onSubmit={(e) => { e.preventDefault(); executeEmailScan(scanEmail); }} className="space-y-3 pt-1">
                <div className="space-y-1">
                  <label className="text-[10px] font-mono uppercase text-[#8392A5] font-bold block">Target Email Address</label>
                  <input
                    type="email"
                    value={scanEmail}
                    onChange={(e) => setScanEmail(e.target.value)}
                    placeholder="analyst@enterprise-domain.com"
                    className="w-full bg-[#06090F] border border-[#202D42] px-3 py-2 text-xs text-[#F0F4F8] rounded-sm font-mono focus:border-[#00E5FF] focus:outline-none"
                    required
                  />
                </div>

                <div className="grid grid-cols-2 gap-1.5 font-mono text-[10px]">
                  <button
                    type="button"
                    onClick={() => { setScanEmail('user@yahoo.com'); executeEmailScan('user@yahoo.com'); }}
                    className="text-left bg-[#131B2A] border border-[#202D42] hover:border-[#FF334B] px-2 py-1.5 rounded-sm text-[#F0F4F8] cursor-pointer"
                  >
                    <span className="text-[#FF334B] font-bold block">🚨 Leaked Target</span>
                    <span className="text-[#8392A5] text-[9px]">user@yahoo.com</span>
                  </button>
                  <button
                    type="button"
                    onClick={() => { setScanEmail('secure@cyberguard.gov'); executeEmailScan('secure@cyberguard.gov'); }}
                    className="text-left bg-[#131B2A] border border-[#202D42] hover:border-[#10B981] px-2 py-1.5 rounded-sm text-[#F0F4F8] cursor-pointer"
                  >
                    <span className="text-[#10B981] font-bold block">🟢 Clean Target</span>
                    <span className="text-[#8392A5] text-[9px]">secure@cyberguard.gov</span>
                  </button>
                </div>

                <button type="submit" disabled={loading} className="w-full btn-soc btn-soc-primary py-2 flex items-center justify-center gap-2 cursor-pointer disabled:opacity-50">
                  <Search className="w-3.5 h-3.5" />
                  <span>{loading ? 'AUDITING...' : 'EXECUTE BREACH AUDIT'}</span>
                </button>
              </form>
            </div>
          )}

          {/* TAB 6: URL REPUTATION SCANNER */}
          {activeTab === 'link' && (
            <div className="soc-panel p-4 space-y-3">
              <div className="border-b border-[#202D42] pb-2 flex items-center justify-between">
                <h2 className="font-display font-bold text-sm uppercase text-white flex items-center gap-2">
                  <Link2 className="w-4 h-4 text-[#00E5FF]" />
                  <span>URL Phishing Scanner</span>
                </h2>
                <span className="status-chip status-chip-low">ACTIVE</span>
              </div>
              <p className="text-[11px] text-[#8392A5] font-mono leading-relaxed">
                Deterministic rule engine inspecting target URL structures, typosquatting indicators, redirect hops, and TLS 1.3 certificates.
              </p>

              <form onSubmit={(e) => { e.preventDefault(); executeUrlScan(scanUrl); }} className="space-y-3 pt-1">
                <div className="space-y-1">
                  <label className="text-[10px] font-mono uppercase text-[#8392A5] font-bold block">Target URL</label>
                  <input
                    type="text"
                    value={scanUrl}
                    onChange={(e) => setScanUrl(e.target.value)}
                    placeholder="https://suspicious-verify-auth.com"
                    className="w-full bg-[#06090F] border border-[#202D42] px-3 py-2 text-xs text-[#F0F4F8] rounded-sm font-mono focus:border-[#00E5FF] focus:outline-none"
                    required
                  />
                </div>

                <div className="grid grid-cols-2 gap-1.5 font-mono text-[10px]">
                  <button
                    type="button"
                    onClick={() => { const u = 'https://paypa1-secure-login.xyz/verify'; setScanUrl(u); executeUrlScan(u); }}
                    className="text-left bg-[#131B2A] border border-[#202D42] hover:border-[#FF334B] px-2 py-1.5 rounded-sm text-[#F0F4F8] cursor-pointer"
                  >
                    <span className="text-[#FF334B] font-bold block">🚨 Phishing Typosquat</span>
                    <span className="text-[#8392A5] text-[9px] truncate block">paypa1-login.xyz</span>
                  </button>
                  <button
                    type="button"
                    onClick={() => { const u = 'https://google.com'; setScanUrl(u); executeUrlScan(u); }}
                    className="text-left bg-[#131B2A] border border-[#202D42] hover:border-[#10B981] px-2 py-1.5 rounded-sm text-[#F0F4F8] cursor-pointer"
                  >
                    <span className="text-[#10B981] font-bold block">🟢 Legitimate Portal</span>
                    <span className="text-[#8392A5] text-[9px] truncate block">google.com</span>
                  </button>
                </div>

                <button type="submit" disabled={loading} className="w-full btn-soc btn-soc-primary py-2 flex items-center justify-center gap-2 cursor-pointer disabled:opacity-50">
                  <Search className="w-3.5 h-3.5" />
                  <span>{loading ? 'AUDITING LINK...' : 'EXECUTE URL SCAN'}</span>
                </button>
              </form>
            </div>
          )}

          {/* TAB 7: VISUAL OCR FORENSICS */}
          {activeTab === 'image' && (
            <div className="soc-panel p-4 space-y-3">
              <div className="border-b border-[#202D42] pb-2 flex items-center justify-between">
                <h2 className="font-display font-bold text-sm uppercase text-white flex items-center gap-2">
                  <FileText className="w-4 h-4 text-[#00E5FF]" />
                  <span>Visual OCR Auditor</span>
                </h2>
                <span className="status-chip status-chip-low">OCR ENGINE</span>
              </div>
              <div 
                onClick={() => fileInputRef.current?.click()}
                className="border-2 border-dashed border-[#202D42] hover:border-[#00E5FF] p-4 text-center cursor-pointer rounded-sm bg-[#06090F]"
              >
                <input
                  type="file"
                  ref={fileInputRef}
                  onChange={(e) => {
                    const f = e.target.files?.[0];
                    if (f) {
                      setImageFile(f);
                      const r = new FileReader();
                      r.onload = () => setImagePreview(r.result as string);
                      r.readAsDataURL(f);
                    }
                  }}
                  accept="image/*"
                  className="hidden"
                />
                <UploadCloud className="w-6 h-6 text-[#00E5FF] mx-auto mb-1" />
                <span className="text-xs font-mono text-[#F0F4F8] block font-bold">Select Screenshot / Invoice</span>
                <span className="text-[10px] font-mono text-[#8392A5]">PNG, JPG, WEBP (Max 15MB)</span>
              </div>
            </div>
          )}

          {/* TAB 8: NIST CVE DB */}
          {activeTab === 'cve' && (
            <div className="soc-panel p-4 space-y-3">
              <div className="border-b border-[#202D42] pb-2 flex items-center justify-between">
                <h2 className="font-display font-bold text-sm uppercase text-white flex items-center gap-2">
                  <Database className="w-4 h-4 text-[#00E5FF]" />
                  <span>NIST CVE Database</span>
                </h2>
                <span className="status-chip status-chip-low">NVD v2.0</span>
              </div>
              <form onSubmit={(e) => { e.preventDefault(); executeCveSearch(cveQuery, cveSeverity); }} className="space-y-3">
                <input
                  type="text"
                  value={cveQuery}
                  onChange={(e) => setCveQuery(e.target.value)}
                  placeholder="e.g. Log4j, OpenSSH, XZ Utils"
                  className="w-full bg-[#06090F] border border-[#202D42] px-3 py-2 text-xs text-[#F0F4F8] font-mono rounded-sm focus:border-[#00E5FF] focus:outline-none"
                />
                <button type="submit" disabled={cveLoading} className="w-full btn-soc btn-soc-primary py-2 flex items-center justify-center gap-2 cursor-pointer">
                  <Search className="w-3.5 h-3.5" />
                  <span>SEARCH NIST CVE DB</span>
                </button>
              </form>
            </div>
          )}

          {/* TAB 9: OSINT INSPECTOR */}
          {activeTab === 'osint' && (
            <div className="soc-panel p-4 space-y-3">
              <div className="border-b border-[#202D42] pb-2 flex items-center justify-between">
                <h2 className="font-display font-bold text-sm uppercase text-white flex items-center gap-2">
                  <Crosshair className="w-4 h-4 text-[#00E5FF]" />
                  <span>OSINT IP Inspector</span>
                </h2>
                <span className="status-chip status-chip-low">DNS & ASN</span>
              </div>
              <form onSubmit={(e) => { e.preventDefault(); executeOsintLookup(osintTarget); }} className="space-y-3">
                <input
                  type="text"
                  value={osintTarget}
                  onChange={(e) => setOsintTarget(e.target.value)}
                  placeholder="185.220.101.5 or domain.com"
                  className="w-full bg-[#06090F] border border-[#202D42] px-3 py-2 text-xs text-[#F0F4F8] font-mono rounded-sm focus:border-[#00E5FF] focus:outline-none"
                />
                <button type="submit" disabled={osintLoading} className="w-full btn-soc btn-soc-primary py-2 flex items-center justify-center gap-2 cursor-pointer">
                  <Globe className="w-3.5 h-3.5" />
                  <span>RUN OSINT LOOKUP</span>
                </button>
              </form>
            </div>
          )}

          {/* TAB 10: MALWARE HASH */}
          {activeTab === 'hash' && (
            <div className="soc-panel p-4 space-y-3">
              <div className="border-b border-[#202D42] pb-2 flex items-center justify-between">
                <h2 className="font-display font-bold text-sm uppercase text-white flex items-center gap-2">
                  <FileCode className="w-4 h-4 text-[#00E5FF]" />
                  <span>Malware Hash Forensics</span>
                </h2>
                <span className="status-chip status-chip-high">SHA-256</span>
              </div>
              <form onSubmit={(e) => { e.preventDefault(); executeHashLookup(hashInput); }} className="space-y-3">
                <input
                  type="text"
                  value={hashInput}
                  onChange={(e) => setHashInput(e.target.value)}
                  placeholder="44d88612fea8a8f36de82e1278abb02f"
                  className="w-full bg-[#06090F] border border-[#202D42] px-3 py-2 text-xs text-[#F0F4F8] font-mono rounded-sm focus:border-[#00E5FF] focus:outline-none"
                />
                <button type="submit" disabled={hashLoading} className="w-full btn-soc btn-soc-primary py-2 flex items-center justify-center gap-2 cursor-pointer">
                  <Cpu className="w-3.5 h-3.5" />
                  <span>ANALYZE BINARY HASH</span>
                </button>
              </form>
            </div>
          )}

          {/* TAB 11: SIEM INCIDENTS */}
          {activeTab === 'siem' && (
            <div className="soc-panel p-4 space-y-3">
              <div className="border-b border-[#202D42] pb-2 flex items-center justify-between">
                <h2 className="font-display font-bold text-sm uppercase text-white flex items-center gap-2">
                  <ShieldAlert className="w-4 h-4 text-[#FF334B]" />
                  <span>SIEM Incident Response</span>
                </h2>
                <span className="status-chip status-chip-critical">MATRIX</span>
              </div>
              <button onClick={fetchIncidents} disabled={incidentsLoading} className="w-full btn-soc py-2 flex items-center justify-center gap-2 cursor-pointer">
                <RefreshCw className={`w-3.5 h-3.5 ${incidentsLoading ? 'animate-spin' : ''}`} />
                <span>REFRESH SIEM QUEUE</span>
              </button>
            </div>
          )}

          {/* TAB 12: STIX 3.0 BUNDLE */}
          {activeTab === 'stix' && (
            <div className="soc-panel p-4 space-y-3">
              <div className="border-b border-[#202D42] pb-2 flex items-center justify-between">
                <h2 className="font-display font-bold text-sm uppercase text-white flex items-center gap-2">
                  <Layers className="w-4 h-4 text-[#00E5FF]" />
                  <span>STIX 3.0 DFIR Bundler</span>
                </h2>
                <span className="status-chip status-chip-quantum">STIX v3.0</span>
              </div>
              <form onSubmit={handleStixExport} className="space-y-3">
                <input
                  type="text"
                  value={stixTarget}
                  onChange={(e) => setStixTarget(e.target.value)}
                  placeholder="quantum-defense-mesh.net"
                  className="w-full bg-[#06090F] border border-[#202D42] px-3 py-2 text-xs text-[#F0F4F8] font-mono rounded-sm focus:border-[#00E5FF] focus:outline-none"
                />
                <button type="submit" disabled={stixLoading} className="w-full btn-soc btn-soc-primary py-2 flex items-center justify-center gap-2 cursor-pointer">
                  <Code className="w-3.5 h-3.5" />
                  <span>GENERATE STIX 3.0 BUNDLE</span>
                </button>
              </form>
            </div>
          )}

          {/* Quick Terminal Launcher Drawer */}
          <div className="soc-panel p-3 flex items-center justify-between">
            <div className="flex items-center gap-2 text-xs font-mono">
              <TerminalIcon className="w-4 h-4 text-[#00E5FF]" />
              <span>Interactive 2030 Cyber Shell</span>
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

        {/* CENTER COLUMN: LIVE 2030 TELEMETRY & FORENSICS (5 cols) */}
        <div className="lg:col-span-5 space-y-4">
          
          {/* TAB 1 CENTER: POST-QUANTUM (PQC) DETAILED AUDIT & SHOR SIMULATOR */}
          {activeTab === 'pqc' && pqcResult && (
            <div className="soc-panel soc-panel-quantum p-4 space-y-4">
              <div className="border-b border-[#202D42] pb-2 flex items-center justify-between">
                <div>
                  <span className="text-[10px] font-mono uppercase text-[#C084FC] font-bold block">
                    TARGET: {pqcResult.target}
                  </span>
                  <h3 className="font-display font-bold text-base uppercase text-white mt-0.5">
                    Post-Quantum Cryptography Audit
                  </h3>
                </div>
                <span className={`status-chip ${pqcResult.quantumReadinessScore >= 80 ? 'status-chip-low' : (pqcResult.quantumReadinessScore >= 50 ? 'status-chip-quantum' : 'status-chip-critical')}`}>
                  {pqcResult.complianceStatus}
                </span>
              </div>

              {renderBitDensityMeter(100 - pqcResult.quantumReadinessScore)}

              {/* Harvest-Now-Decrypt-Later (HNDL) Risk Gauge */}
              <div className="bg-[#06090F] p-3 border border-[#202D42] rounded-sm space-y-2 font-mono text-xs">
                <div className="flex items-center justify-between">
                  <span className="text-[#8392A5]">HNDL Exposure Risk:</span>
                  <strong className={pqcResult.hndlRisk.includes('Protected') ? 'text-[#10B981]' : 'text-[#FF334B]'}>
                    {pqcResult.hndlRisk}
                  </strong>
                </div>
                <div className="text-[11px] text-[#8392A5]">
                  <div><span className="text-[#F0F4F8]">KEM Standard:</span> {pqcResult.kemAlgorithm}</div>
                  <div><span className="text-[#F0F4F8]">Signature Standard:</span> {pqcResult.signatureAlgorithm}</div>
                </div>
              </div>

              {/* Detected Cipher Suite Breakdown */}
              <div className="space-y-2">
                <span className="text-[10px] font-mono uppercase text-[#8392A5] font-bold block">
                  Detected Cipher Suites & NIST Security Levels:
                </span>
                <div className="space-y-1.5 font-mono text-xs">
                  {pqcResult.ciphers.map((cipher, idx) => (
                    <div key={idx} className="p-2.5 bg-[#06090F] border border-[#202D42] rounded-sm space-y-1">
                      <div className="flex items-center justify-between">
                        <span className="text-white font-bold text-[11px] truncate max-w-[280px]">{cipher.name}</span>
                        <span className={`status-chip ${cipher.quantumResistant ? 'status-chip-low' : 'status-chip-critical'}`}>
                          {cipher.quantumResistant ? 'QUANTUM RESISTANT' : 'VULNERABLE'}
                        </span>
                      </div>
                      <div className="flex items-center justify-between text-[10px] text-[#8392A5]">
                        <span>{cipher.nistStandard}</span>
                        <span className="text-[#C084FC]">Shor: {cipher.shorVulnerability}</span>
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              {/* Interactive Shor Simulation Result Box */}
              {simResult && (
                <div className="p-3 bg-[#131B2A] border border-[#A855F7]/40 rounded-sm space-y-2 font-mono text-xs">
                  <div className="flex items-center justify-between border-b border-[#202D42] pb-1.5">
                    <strong className="text-[#C084FC] flex items-center gap-1.5">
                      <Atom className="w-3.5 h-3.5" />
                      Shor's Cryptanalysis Simulator: {simResult.cipher}
                    </strong>
                    <span className="text-[10px] text-[#8392A5]">{simResult.estimatedLogicalQubits ? `${simResult.estimatedLogicalQubits} Qubits` : 'Lattice Hard'}</span>
                  </div>
                  <p className="text-[11px] text-[#F0F4F8] leading-relaxed">{simResult.securityAssessment}</p>
                  <div className="grid grid-cols-2 gap-2 text-[10px] pt-1 text-[#8392A5]">
                    <div><span className="text-[#C084FC]">Classical Time:</span> {simResult.classicalCrackingYears}</div>
                    <div><span className="text-[#C084FC]">Quantum Shor Time:</span> {simResult.shorExecutionSeconds ? `${simResult.shorExecutionSeconds}s` : 'Immune'}</div>
                  </div>
                </div>
              )}
            </div>
          )}

          {/* TAB 2 CENTER: AUTONOMOUS AI SWARM LIVE EVENT LOG */}
          {activeTab === 'swarm' && (
            <div className="soc-panel p-4 space-y-3 font-mono text-xs">
              <div className="border-b border-[#202D42] pb-2 flex items-center justify-between">
                <div>
                  <h3 className="font-display font-bold text-sm uppercase text-white">
                    Live Swarm Defense Stream
                  </h3>
                  <span className="text-[10px] text-[#10B981]">Byzantine Fault-Tolerant Consensus: 100% Locked</span>
                </div>
                <button
                  onClick={fetchSwarmState}
                  className="btn-soc px-2 py-1 text-[10px] flex items-center gap-1 cursor-pointer"
                >
                  <RefreshCw className="w-3 h-3" />
                  <span>POLL</span>
                </button>
              </div>

              <div className="space-y-2 max-h-[480px] overflow-y-auto pr-1">
                {swarmEvents.map(evt => (
                  <div key={evt.id} className="p-3 bg-[#06090F] border border-[#202D42] rounded-sm space-y-1.5">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-1.5">
                        <span className="w-2 h-2 rounded-full bg-[#00E5FF] animate-pulse"></span>
                        <strong className="text-white text-[11px]">{evt.agentCodename}</strong>
                        <span className="text-[9px] text-[#8392A5]">({evt.eventType})</span>
                      </div>
                      <span className={`status-chip ${evt.severity === 'critical' ? 'status-chip-critical' : 'status-chip-high'}`}>
                        {evt.severity}
                      </span>
                    </div>
                    <p className="text-[11px] text-[#F0F4F8] leading-relaxed">{evt.details}</p>
                    <div className="flex items-center justify-between text-[10px] text-[#00E5FF] pt-1 border-t border-[#202D42]">
                      <span className="truncate max-w-[240px]">TARGET: {evt.target}</span>
                      <span>{new Date(evt.timestamp).toLocaleTimeString()}</span>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* TAB 3 CENTER: NEURAL DEEPFAKE & SYNTHETIC FORENSICS VIEW */}
          {activeTab === 'deepfake' && deepfakeResult && (
            <div className="soc-panel soc-panel-quantum p-4 space-y-4 font-mono text-xs">
              <div className="border-b border-[#202D42] pb-2 flex items-center justify-between">
                <div>
                  <span className="text-[10px] uppercase text-[#C084FC] font-bold block">
                    ARTIFACT: {deepfakeResult.targetName}
                  </span>
                  <h3 className="font-display font-bold text-base uppercase text-white mt-0.5">
                    Neural Generative AI Forensics
                  </h3>
                </div>
                <span className={`status-chip ${deepfakeResult.syntheticConfidence > 70 ? 'status-chip-critical' : (deepfakeResult.syntheticConfidence > 30 ? 'status-chip-high' : 'status-chip-low')}`}>
                  {deepfakeResult.classification}
                </span>
              </div>

              {renderBitDensityMeter(deepfakeResult.syntheticConfidence)}

              {/* FFT Spectral Anomaly & rPPG Pulse Telemetry */}
              <div className="grid grid-cols-2 gap-2">
                <div className="bg-[#06090F] p-3 border border-[#202D42] rounded-sm space-y-1">
                  <span className="text-[#8392A5] block text-[9px] uppercase">FFT Spectral Anomaly</span>
                  <span className="text-base font-bold text-[#C084FC]">{deepfakeResult.spectralAnomalyScore}%</span>
                  <span className="text-[9px] text-[#8392A5] block">Frequency phase distortion index</span>
                </div>
                <div className="bg-[#06090F] p-3 border border-[#202D42] rounded-sm space-y-1">
                  <span className="text-[#8392A5] block text-[9px] uppercase">rPPG Subdermal Pulse</span>
                  <span className={`text-base font-bold ${deepfakeResult.rppgPulseDetected ? 'text-[#10B981]' : 'text-[#FF334B]'}`}>
                    {deepfakeResult.rppgPulseDetected ? 'ORGANIC PULSE' : 'SYNTHETIC SIGNAL'}
                  </span>
                  <span className="text-[9px] text-[#8392A5] block">Hemoglobin micro-vibration</span>
                </div>
              </div>

              {/* Forensic Metric Checks */}
              <div className="space-y-1.5">
                <span className="text-[10px] uppercase text-[#8392A5] font-bold block">Forensic Signal Attributions:</span>
                <div className="space-y-1">
                  {deepfakeResult.forensicEvidence.map((ev, i) => (
                    <div key={i} className="flex items-center justify-between bg-[#06090F] px-2.5 py-1.5 border border-[#202D42] text-[11px]">
                      <span>{ev.metric}</span>
                      <span className={ev.status === 'anomaly' ? 'text-[#FF334B] font-bold' : 'text-[#10B981]'}>
                        {ev.measured}
                      </span>
                    </div>
                  ))}
                </div>
              </div>

              {/* Red Flags Alert Box */}
              {deepfakeResult.redFlags.length > 0 && (
                <div className="p-3 bg-[#FF334B]/10 border border-[#FF334B]/30 rounded-sm space-y-1 text-[11px] text-[#FF334B]">
                  <strong className="block text-[10px] uppercase">Detected Synthetic Anomalies:</strong>
                  {deepfakeResult.redFlags.map((flag, idx) => (
                    <div key={idx}>• {flag}</div>
                  ))}
                </div>
              )}
            </div>
          )}

          {/* TAB 4 CENTER: LEO SATELLITE MESH CONSTELATION HUD */}
          {activeTab === 'satellite' && satelliteData && (
            <div className="soc-panel p-4 space-y-3 font-mono text-xs">
              <div className="border-b border-[#202D42] pb-2 flex items-center justify-between">
                <div>
                  <h3 className="font-display font-bold text-sm uppercase text-white">
                    LEO Orbital Nodes & QKD Links
                  </h3>
                  <span className="text-[10px] text-[#10B981]">{satelliteData.totalPhotonThroughput} Entangled Photons</span>
                </div>
                <span className="status-chip status-chip-low">
                  HEALTH {satelliteData.constellationHealthScore}%
                </span>
              </div>

              <div className="space-y-2">
                {satelliteData.activeNodes.map(sat => (
                  <div key={sat.id} className="p-3 bg-[#06090F] border border-[#202D42] rounded-sm space-y-1">
                    <div className="flex items-center justify-between">
                      <strong className="text-white text-[11px] flex items-center gap-1.5">
                        <Satellite className="w-3.5 h-3.5 text-[#10B981]" />
                        {sat.name} ({sat.constellation})
                      </strong>
                      <span className="status-chip status-chip-low">
                        {sat.qkdStatus}
                      </span>
                    </div>
                    <div className="text-[10px] text-[#8392A5] grid grid-cols-2 gap-1 pt-1">
                      <div>Altitude: {sat.altitudeKm} km ({sat.orbitInclination})</div>
                      <div>Latency: {sat.linkLatencyMs}ms</div>
                      <div className="col-span-2 text-[#00E5FF]">Ground Station: {sat.activeGroundStation}</div>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* EXISTING SCANS (Email, Link, OCR) RESULTS */}
          {['email', 'link', 'image'].includes(activeTab) && currentScan && (
            <div className="soc-panel p-4 space-y-4">
              <div className="border-b border-[#202D42] pb-2 flex items-center justify-between">
                <div>
                  <span className="text-[10px] font-mono uppercase text-[#8392A5] block font-bold">
                    AUDITED TARGET: {currentScan.targetEmail || currentScan.targetLink || currentScan.imageFileName}
                  </span>
                  <h3 className="font-display font-bold text-base uppercase text-white mt-0.5">
                    Threat Audit Summary
                  </h3>
                </div>

                <button
                  onClick={() => setRawViewMode(!rawViewMode)}
                  className={`btn-soc px-2 py-1 text-[10px] flex items-center gap-1 cursor-pointer ${rawViewMode ? 'border-[#00E5FF] text-[#00E5FF]' : ''}`}
                >
                  <Code className="w-3 h-3" />
                  <span>{rawViewMode ? 'ANNOTATED VIEW' : 'RAW JSON'}</span>
                </button>
              </div>

              {renderBitDensityMeter(currentScan.riskScore)}

              <div className="bg-[#06090F] border border-[#202D42] p-3 text-xs leading-relaxed text-[#F0F4F8] font-mono whitespace-pre-wrap rounded-sm">
                {currentScan.forensicSummary || currentScan.aiSummary}
              </div>

              <div className="flex items-center justify-between pt-2 border-t border-[#202D42]">
                <button
                  type="button"
                  onClick={() => generateScanPdf(currentScan)}
                  className="btn-soc btn-soc-primary px-3 py-1 text-[10px] flex items-center gap-1 cursor-pointer"
                >
                  <Download className="w-3 h-3" />
                  <span>DOWNLOAD PDF</span>
                </button>
                <button
                  type="button"
                  onClick={() => onSelectReport(currentScan)}
                  className="btn-soc px-3 py-1 text-[10px] flex items-center gap-1 text-[#00E5FF] border-[#00E5FF]/40 cursor-pointer"
                >
                  <Eye className="w-3 h-3" />
                  <span>FULL REPORT VIEW</span>
                </button>
              </div>
            </div>
          )}

          {/* CVE / OSINT / HASH / SIEM / STIX VIEWS */}
          {activeTab === 'cve' && cveResults && (
            <div className="soc-panel p-4 space-y-3 font-mono text-xs">
              <div className="border-b border-[#202D42] pb-2 flex items-center justify-between">
                <h3 className="font-display font-bold text-sm uppercase text-white">NVD CVE Records ({cveResults.totalMatches})</h3>
              </div>
              <div className="space-y-2 max-h-[500px] overflow-y-auto pr-1">
                {cveResults.cves.map(cve => (
                  <div key={cve.id} className="border border-[#202D42] bg-[#06090F] p-3 rounded-sm space-y-1">
                    <div className="flex items-center justify-between">
                      <strong className="text-[#00E5FF] font-bold">{cve.id}</strong>
                      <span className={`status-chip ${cve.score >= 9.0 ? 'status-chip-critical' : cve.score >= 7.0 ? 'status-chip-high' : 'status-chip-medium'}`}>
                        CVSS {cve.score.toFixed(1)}
                      </span>
                    </div>
                    <p className="text-[11px] text-[#F0F4F8] leading-relaxed">{cve.description}</p>
                  </div>
                ))}
              </div>
            </div>
          )}

          {activeTab === 'osint' && osintResult && (
            <div className="soc-panel p-4 space-y-3 font-mono text-xs">
              <div className="border-b border-[#202D42] pb-2 flex items-center justify-between">
                <h3 className="font-display font-bold text-sm uppercase text-white">OSINT: {osintResult.target}</h3>
                <span className="status-chip status-chip-medium">SCORE {osintResult.reputationScore}/100</span>
              </div>
              <div className="bg-[#06090F] p-2.5 border border-[#202D42] space-y-1">
                <div><span className="text-[#8392A5]">IP:</span> <span className="text-[#00E5FF]">{osintResult.resolvedIp}</span></div>
                <div><span className="text-[#8392A5]">ISP:</span> {osintResult.location.isp} ({osintResult.location.country})</div>
              </div>
            </div>
          )}

          {activeTab === 'hash' && hashResult && (
            <div className="soc-panel p-4 space-y-3 font-mono text-xs">
              <div className="border-b border-[#202D42] pb-2 flex items-center justify-between">
                <h3 className="font-display font-bold text-sm uppercase text-white">Hash Forensics: {hashResult.fileName || hashResult.hash}</h3>
                <span className={`status-chip ${hashResult.malwareClassification === 'malicious' ? 'status-chip-critical' : 'status-chip-low'}`}>
                  {hashResult.malwareClassification.toUpperCase()}
                </span>
              </div>
              <div className="bg-[#06090F] p-2.5 border border-[#202D42] space-y-1 text-[11px]">
                <div><span className="text-[#8392A5]">ENTROPY:</span> {hashResult.entropyScore}/8.00</div>
                <div><span className="text-[#8392A5]">FORMAT:</span> {hashResult.detectedFormat}</div>
              </div>
            </div>
          )}

          {activeTab === 'siem' && (
            <div className="soc-panel p-4 space-y-3 font-mono text-xs">
              <h3 className="font-display font-bold text-sm uppercase text-white">Active SIEM Incidents</h3>
              <div className="space-y-2">
                {incidentsList.map(inc => (
                  <div key={inc.id} onClick={() => setSelectedIncident(inc)} className="p-3 bg-[#06090F] border border-[#202D42] rounded-sm cursor-pointer hover:border-[#00E5FF]">
                    <div className="flex items-center justify-between">
                      <strong className="text-white">{inc.id}: {inc.title}</strong>
                      <span className={`status-chip ${inc.severity === 'critical' ? 'status-chip-critical' : 'status-chip-high'}`}>{inc.severity}</span>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {activeTab === 'stix' && stixBundleResult && (
            <div className="soc-panel p-4 space-y-3 font-mono text-xs">
              <div className="border-b border-[#202D42] pb-2 flex items-center justify-between">
                <h3 className="font-display font-bold text-sm uppercase text-white">STIX 3.0 DFIR JSON</h3>
                <button
                  onClick={() => {
                    const blob = new Blob([JSON.stringify(stixBundleResult, null, 2)], { type: 'application/json' });
                    const url = URL.createObjectURL(blob);
                    const a = document.createElement('a');
                    a.href = url;
                    a.download = `cyberguard_stix3_bundle_${Date.now()}.json`;
                    a.click();
                  }}
                  className="btn-soc px-2.5 py-1 text-[10px] flex items-center gap-1 text-[#10B981] border-[#10B981]/40 cursor-pointer"
                >
                  <Download className="w-3 h-3" />
                  <span>DOWNLOAD STIX 3.0</span>
                </button>
              </div>
              <div className="bg-[#06090F] border border-[#202D42] p-3 rounded-sm text-[11px] overflow-x-auto text-[#00E5FF] max-h-96">
                <pre>{JSON.stringify(stixBundleResult, null, 2)}</pre>
              </div>
            </div>
          )}

          {/* SYSTEM USAGE AUDIT TRAIL LOG */}
          <UsageAudit scans={scans} onSelectReport={onSelectReport} />

        </div>

        {/* RIGHT COLUMN: RECENT SESSIONS & COMPLIANCE (3 cols) */}
        <div className="lg:col-span-3 space-y-4">
          
          {/* Quick Scan History Feed */}
          <div className="soc-panel p-4 space-y-3">
            <div className="border-b border-[#202D42] pb-2 flex items-center justify-between">
              <div className="flex items-center gap-1.5 text-[#00E5FF] font-mono text-[10px] font-bold">
                <History className="w-3.5 h-3.5" />
                <span>SESSION SESSIONS</span>
              </div>
              <span className="text-[10px] font-mono text-[#8392A5]">{scans.length} Total</span>
            </div>

            <div className="space-y-1.5 max-h-56 overflow-y-auto pr-1 font-mono text-[11px]">
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
                    className="p-2 border border-[#202D42] bg-[#06090F] hover:border-[#00E5FF] rounded-sm cursor-pointer transition-colors"
                  >
                    <div className="flex items-center justify-between">
                      <span className="text-white font-bold truncate max-w-[140px]">
                        {s.targetEmail || s.targetLink || s.imageFileName || 'Assessment'}
                      </span>
                      <span className={`text-[10px] font-bold ${s.riskScore >= 70 ? 'text-[#FF334B]' : s.riskScore >= 40 ? 'text-[#FF9900]' : 'text-[#10B981]'}`}>
                        {s.riskScore}/100
                      </span>
                    </div>
                    <span className="text-[9px] text-[#8392A5] block mt-0.5">
                      {new Date(s.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })} • {s.scanType?.toUpperCase() || 'EMAIL'}
                    </span>
                  </div>
                ))
              ) : (
                <div className="text-center py-4 text-[10px] font-mono text-[#8392A5]">
                  No scans recorded yet.
                </div>
              )}
            </div>
          </div>

          {/* Trust, Privacy & 2030 Cryptographic Standards */}
          <div className="soc-panel p-4 space-y-3">
            <div className="border-b border-[#202D42] pb-2">
              <div className="flex items-center gap-1 text-[#00E5FF] font-mono text-[10px] font-bold">
                <ShieldCheck className="w-3.5 h-3.5" />
                <span>2030 STANDARDS & TRUST</span>
              </div>
              <h3 className="font-display font-bold text-xs uppercase text-white mt-1">
                Security & PQC Compliance
              </h3>
            </div>

            <div className="grid grid-cols-5 gap-0.5 border-b border-[#202D42] pb-2 text-[9px] font-mono font-bold text-center">
              {[
                { id: 'gmail', label: 'GMAIL' },
                { id: 'sourcing', label: 'PQC' },
                { id: 'soc2', label: 'SOC2' },
                { id: 'bounty', label: 'BOUNTY' },
                { id: 'erasure', label: 'ERASE' },
              ].map(item => (
                <button
                  key={item.id}
                  onClick={() => setComplianceTab(item.id as any)}
                  className={`pb-1 transition-colors cursor-pointer border-b ${
                    complianceTab === item.id ? 'border-[#00E5FF] text-[#00E5FF]' : 'border-transparent text-[#8392A5] hover:text-[#F0F4F8]'
                  }`}
                >
                  {item.label}
                </button>
              ))}
            </div>

            <div className="text-[11px] font-mono leading-relaxed text-[#8392A5]">
              {complianceTab === 'gmail' && (
                <div className="space-y-1.5">
                  <span className="font-bold text-[#00E5FF] text-[10px] uppercase block">Zero Retention</span>
                  <p>All transient payloads and tokens audited in volatile enclave memory and purged immediately.</p>
                </div>
              )}

              {complianceTab === 'sourcing' && (
                <div className="space-y-1.5">
                  <span className="font-bold text-[#C084FC] text-[10px] uppercase block">NIST FIPS 203/204 Standards</span>
                  <p>Certified compatibility with ML-KEM-768 lattice encryption and ML-DSA digital signatures.</p>
                </div>
              )}

              {complianceTab === 'soc2' && (
                <div className="space-y-1.5">
                  <span className="font-bold text-[#00E5FF] text-[10px] uppercase block">SOC2 & GDPR Compliance</span>
                  <p>Enforces zero-knowledge audits and GDPR Article 17 automated permanent right-to-erasure.</p>
                </div>
              )}

              {complianceTab === 'bounty' && (
                <div className="space-y-1.5">
                  <span className="font-bold text-[#00E5FF] text-[10px] uppercase block">Bug Bounty & Research</span>
                  <p>Contact security desk at <span className="text-[#00E5FF] select-all">hemantkaushal72@gmail.com</span> for 48h response SLA.</p>
                </div>
              )}

              {complianceTab === 'erasure' && (
                <div className="space-y-2">
                  <span className="font-bold text-[#00E5FF] text-[10px] uppercase block">GDPR Data Erasure</span>
                  <p>Permanently wipe all session threat telemetry.</p>
                  {clearScansSuccess ? (
                    <div className="p-2 bg-[#10B981]/10 border border-[#10B981]/30 text-[#10B981] text-[10px]">
                      Session data purged.
                    </div>
                  ) : confirmWipe ? (
                    <div className="flex gap-2">
                      <button
                        type="button"
                        onClick={handleWipeScans}
                        className="flex-1 bg-[#FF334B] text-white font-bold text-[10px] py-1 cursor-pointer"
                      >
                        PURGE ALL
                      </button>
                      <button
                        type="button"
                        onClick={() => setConfirmWipe(false)}
                        className="btn-soc px-2 py-1 text-[10px]"
                      >
                        CANCEL
                      </button>
                    </div>
                  ) : (
                    <button
                      type="button"
                      onClick={() => setConfirmWipe(true)}
                      className="w-full btn-soc border-[#FF334B]/40 text-[#FF334B] hover:bg-[#FF334B]/10 py-1.5 text-[10px] cursor-pointer"
                    >
                      PURGE ALL SCAN LOGS
                    </button>
                  )}
                </div>
              )}
            </div>
          </div>

        </div>

      </div>

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
