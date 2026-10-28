import React, { useState, useEffect, useRef } from 'react';
import { 
  User, ScanResult, OsintResult, HashAnalysisResult, SocIncident, CveRecord,
  PqcAnalysisResult, QuantumSimResult, DeepfakeForensicsResult, AiAgent, AiSwarmEvent, SatelliteMeshTelemetry
} from '../types';
import Sidebar, { NavigationTab } from './layout/Sidebar';
import Header from './layout/Header';
import { ShieldCheck } from 'lucide-react';
import Terminal from './Terminal';
import CommandCenterView from './views/CommandCenterView';
import DeepfakeDetectionView from './views/DeepfakeDetectionView';
import HashAnalysisView from './views/HashAnalysisView';
import UrlAnalysisView from './views/UrlAnalysisView';
import OsintAnalysisView from './views/OsintAnalysisView';
import CveAnalysisView from './views/CveAnalysisView';
import EmailBreachView from './views/EmailBreachView';
import SiemIncidentsView from './views/SiemIncidentsView';
import StixBundlerView from './views/StixBundlerView';
import ThreatRadarView from './views/ThreatRadarView';
import PqcAuditView from './views/PqcAuditView';
import AiSwarmView from './views/AiSwarmView';
import SatelliteMeshView from './views/SatelliteMeshView';
import ComplianceView from './views/ComplianceView';
import NewIncidentModal from './modals/NewIncidentModal';
import QuickInvestigationModal from './modals/QuickInvestigationModal';
import { safeJsonResponse } from '../lib/api';
import {
  clientLookupEmail,
  clientAnalyzeUrl,
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
  // Navigation State
  const [activeTab, setActiveTab] = useState<NavigationTab>('command-center');
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);
  const [mobileSidebarOpen, setMobileSidebarOpen] = useState(false);

  // Modals & Terminal
  const [showNewIncidentModal, setShowNewIncidentModal] = useState(false);
  const [showQuickInvestigationModal, setShowQuickInvestigationModal] = useState(false);
  const [showTerminal, setShowTerminal] = useState(false);

  // Global Loading & Error State
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Data States
  const [scans, setScans] = useState<ScanResult[]>([]);
  const [currentScan, setCurrentScan] = useState<ScanResult | null>(null);
  
  const [incidents, setIncidents] = useState<SocIncident[]>([]);
  const [incidentsLoading, setIncidentsLoading] = useState(false);

  // 1. Deepfake State
  const [deepfakeResult, setDeepfakeResult] = useState<DeepfakeForensicsResult | null>(null);
  const [deepfakeLoading, setDeepfakeLoading] = useState(false);
  const [deepfakeError, setDeepfakeError] = useState<string | null>(null);

  // 2. Hash State
  const [hashResult, setHashResult] = useState<HashAnalysisResult | null>(null);
  const [hashLoading, setHashLoading] = useState(false);
  const [hashError, setHashError] = useState<string | null>(null);

  // 3. URL State
  const [urlLoading, setUrlLoading] = useState(false);
  const [urlError, setUrlError] = useState<string | null>(null);

  // 4. OSINT State
  const [osintResult, setOsintResult] = useState<OsintResult | null>(null);
  const [osintLoading, setOsintLoading] = useState(false);
  const [osintError, setOsintError] = useState<string | null>(null);

  // 5. CVE State
  const [cveResults, setCveResults] = useState<{ totalMatches: number; cves: CveRecord[] } | null>(null);
  const [cveLoading, setCveLoading] = useState(false);

  // 6. PQC & Quantum State
  const [pqcResult, setPqcResult] = useState<PqcAnalysisResult | null>(null);
  const [simResult, setSimResult] = useState<QuantumSimResult | null>(null);
  const [pqcLoading, setPqcLoading] = useState(false);

  // 7. Swarm State
  const [swarmAgents, setSwarmAgents] = useState<AiAgent[]>([]);
  const [swarmEvents, setSwarmEvents] = useState<AiSwarmEvent[]>([]);
  const [swarmLoading, setSwarmLoading] = useState(false);

  // 8. Satellite State
  const [satelliteData, setSatelliteData] = useState<SatelliteMeshTelemetry | null>(null);
  const [satelliteLoading, setSatelliteLoading] = useState(false);

  // 9. Compliance / Erasure State
  const [isClearingScans, setIsClearingScans] = useState(false);

  // Initial Data Fetching
  useEffect(() => {
    loadScanHistory();
    fetchIncidents();
    loadLatestCves();
    loadPqcAudit('quantum-defense.gov');
    loadQuantumSim('RSA', 2048);
    fetchSwarmState();
    loadSampleDeepfake('executive_conference_stream.mp4', 'video');
    fetchSatelliteMesh();
  }, [token]);

  // Keyboard shortcut Ctrl+` for terminal
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

  // -------------------------------------------------------------
  // Data Fetchers
  // -------------------------------------------------------------
  const loadScanHistory = async () => {
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

  const fetchIncidents = async () => {
    setIncidentsLoading(true);
    try {
      const res = await fetch('/api/soc/incidents', { headers: { 'Authorization': `Bearer ${token}` } });
      if (res.ok) {
        const data = await safeJsonResponse(res);
        if (data?.incidents) {
          setIncidents(data.incidents);
          return;
        }
      }
    } catch {
      // Fallback
    } finally {
      setIncidentsLoading(false);
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

  const loadPqcAudit = async (target: string): Promise<PqcAnalysisResult | null> => {
    setPqcLoading(true);
    try {
      const res = await fetch('/api/pqc/audit', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${token}` },
        body: JSON.stringify({ target })
      });
      if (res.ok) {
        const data = await safeJsonResponse(res);
        if (data?.target) {
          setPqcResult(data);
          return data;
        }
      }
    } catch {
      // Fallback
    } finally {
      setPqcLoading(false);
    }
    const local = clientAnalyzePqc(target);
    setPqcResult(local);
    return local;
  };

  const loadQuantumSim = async (cipher: 'RSA' | 'ECC' | 'ML-KEM', keySize: number): Promise<QuantumSimResult | null> => {
    try {
      const res = await fetch('/api/quantum/simulate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${token}` },
        body: JSON.stringify({ cipher, keySize })
      });
      if (res.ok) {
        const data = await safeJsonResponse(res);
        if (data?.cipher) {
          setSimResult(data);
          return data;
        }
      }
    } catch {
      // Fallback
    }
    const local = clientSimulateQuantum(cipher, keySize);
    setSimResult(local);
    return local;
  };

  const fetchSwarmState = async () => {
    setSwarmLoading(true);
    try {
      const res = await fetch('/api/ai-swarm/telemetry', { headers: { 'Authorization': `Bearer ${token}` } });
      if (res.ok) {
        const data = await safeJsonResponse(res);
        if (data?.activeAgents) {
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
    const local = clientGetAiSwarmState();
    setSwarmAgents(local.activeAgents);
    setSwarmEvents(local.events);
  };

  const fetchSatelliteMesh = async () => {
    setSatelliteLoading(true);
    try {
      const res = await fetch('/api/satellite/mesh', { headers: { 'Authorization': `Bearer ${token}` } });
      if (res.ok) {
        const data = await safeJsonResponse(res);
        if (data?.activeNodes) {
          setSatelliteData(data);
          return;
        }
      }
    } catch {
      // Fallback
    } finally {
      setSatelliteLoading(false);
    }
    const local = clientGetSatelliteMesh();
    setSatelliteData(local);
  };

  // -------------------------------------------------------------
  // Investigation Handlers
  // -------------------------------------------------------------
  const handleAnalyzeMedia = async (file: File): Promise<DeepfakeForensicsResult | null> => {
    setDeepfakeLoading(true);
    setDeepfakeError(null);

    let mediaType: 'image' | 'video' | 'audio' = 'image';
    if (file.type.startsWith('video/')) mediaType = 'video';
    else if (file.type.startsWith('audio/')) mediaType = 'audio';

    try {
      // Read file as base64
      const base64: string = await new Promise((resolve, reject) => {
        const reader = new FileReader();
        reader.onload = () => resolve((reader.result as string).replace(/^data:.*?;base64,/, ''));
        reader.onerror = reject;
        reader.readAsDataURL(file);
      });

      const res = await fetch('/api/deepfake/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${token}` },
        body: JSON.stringify({
          targetName: file.name,
          mediaType,
          fileBase64: base64,
          fileSize: file.size
        })
      });

      if (res.ok) {
        const data = await safeJsonResponse(res);
        if (data?.targetName) {
          setDeepfakeResult(data);
          return data;
        }
      }
    } catch (err: any) {
      setDeepfakeError(err.message || 'Failed to analyze uploaded media file.');
    } finally {
      setDeepfakeLoading(false);
    }

    // Local client fallback
    const local = clientAnalyzeDeepfake(file.name, mediaType);
    setDeepfakeResult(local);
    return local;
  };

  const loadSampleDeepfake = async (sampleName: string, mediaType: 'image' | 'audio' | 'video'): Promise<DeepfakeForensicsResult | null> => {
    setDeepfakeLoading(true);
    try {
      const res = await fetch('/api/deepfake/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${token}` },
        body: JSON.stringify({ targetName: sampleName, mediaType })
      });
      if (res.ok) {
        const data = await safeJsonResponse(res);
        if (data?.targetName) {
          setDeepfakeResult(data);
          return data;
        }
      }
    } catch {
      // Fallback
    } finally {
      setDeepfakeLoading(false);
    }
    const local = clientAnalyzeDeepfake(sampleName, mediaType);
    setDeepfakeResult(local);
    return local;
  };

  const handleAnalyzeUrl = async (url: string): Promise<ScanResult | null> => {
    setUrlLoading(true);
    setUrlError(null);
    try {
      const res = await fetch('/api/scan-link', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${token}` },
        body: JSON.stringify({ url })
      });
      if (res.ok) {
        const data = await safeJsonResponse(res);
        if (data?.scan) {
          setCurrentScan(data.scan);
          setScans(prev => [data.scan, ...prev.filter(s => s.id !== data.scan.id)]);
          if (data.user) onUserUpdate(data.user);
          return data.scan;
        }
      } else {
        const errJson = await safeJsonResponse(res);
        setUrlError(errJson?.error || `URL scan failed with HTTP ${res.status}`);
        return null;
      }
    } catch (err: any) {
      setUrlError(err.message || 'URL inspection request failed. Check server connectivity.');
      return null;
    } finally {
      setUrlLoading(false);
    }
    return null;
  };

  const handleAnalyzeHash = async (hash: string, fileName?: string, filePayload?: string): Promise<HashAnalysisResult | null> => {
    setHashLoading(true);
    setHashError(null);
    try {
      const res = await fetch('/api/soc/hash-lookup', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${token}` },
        body: JSON.stringify({ hash, fileName, fileBase64: filePayload })
      });
      if (res.ok) {
        const data = await safeJsonResponse(res);
        if (data?.hash || data?.entropyScore !== undefined) {
          setHashResult(data);
          return data;
        }
      } else {
        const errJson = await safeJsonResponse(res);
        setHashError(errJson?.error || `Hash analysis failed with HTTP ${res.status}`);
        return null;
      }
    } catch (err: any) {
      setHashError(err.message || 'Hash lookup request failed. Check server connectivity.');
      return null;
    } finally {
      setHashLoading(false);
    }
    return null;
  };

  const handleSearchCves = async (query: string, severity?: string) => {
    setCveLoading(true);
    try {
      const res = await fetch(`/api/cve/search?query=${encodeURIComponent(query)}&severity=${encodeURIComponent(severity || 'ALL')}`, {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      if (res.ok) {
        const data = await safeJsonResponse(res);
        if (data?.cves) {
          setCveResults(data);
          return data;
        }
      }
    } catch {
      // Fallback
    } finally {
      setCveLoading(false);
    }

    const local = clientSearchCves(query, severity || 'ALL');
    setCveResults(local);
    return local;
  };

  const handleAnalyzeOsint = async (target: string): Promise<OsintResult | null> => {
    setOsintLoading(true);
    setOsintError(null);
    try {
      const res = await fetch('/api/soc/osint-lookup', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${token}` },
        body: JSON.stringify({ target })
      });
      if (res.ok) {
        const data = await safeJsonResponse(res);
        if (data?.target) {
          setOsintResult(data);
          return data;
        }
      } else {
        const errJson = await safeJsonResponse(res);
        setOsintError(errJson?.error || `OSINT lookup failed with HTTP ${res.status}`);
        return null;
      }
    } catch (err: any) {
      setOsintError(err.message || 'OSINT lookup request failed. Check server connectivity.');
      return null;
    } finally {
      setOsintLoading(false);
    }
    return null;
  };

  const handleScanEmail = async (email: string): Promise<ScanResult | null> => {
    setLoading(true);
    setError(null);
    try {
      const res = await fetch('/api/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${token}` },
        body: JSON.stringify({ email })
      });
      if (res.ok) {
        const data = await safeJsonResponse(res);
        if (data?.scan) {
          setCurrentScan(data.scan);
          setScans(prev => [data.scan, ...prev.filter(s => s.id !== data.scan.id)]);
          if (data.user) onUserUpdate(data.user);
          return data.scan;
        }
      } else {
        const errJson = await safeJsonResponse(res);
        setError(errJson?.error || `Email breach audit failed with HTTP ${res.status}`);
        return null;
      }
    } catch (err: any) {
      setError(err.message || 'Email breach scan request failed. Check server connectivity.');
      return null;
    } finally {
      setLoading(false);
    }
    return null;
  };

  const handleCreateIncident = async (incidentData: Partial<SocIncident>) => {
    try {
      const res = await fetch('/api/soc/incidents', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${token}` },
        body: JSON.stringify(incidentData)
      });
      if (res.ok) {
        const data = await safeJsonResponse(res);
        if (data?.incident) {
          setIncidents(prev => [data.incident, ...prev]);
          return;
        }
      }
    } catch {
      // Fallback
    }

    const newInc: SocIncident = {
      id: `INC-2026-${Math.floor(1000 + Math.random() * 9000)}`,
      title: incidentData.title || 'Security Incident Assessment',
      target: incidentData.target || 'target-asset.local',
      severity: incidentData.severity || 'high',
      status: 'new',
      category: incidentData.category || 'Phishing',
      mitreTactic: incidentData.mitreTactic || 'Initial Access',
      mitreTechniqueId: incidentData.mitreTechniqueId || 'T1566',
      description: incidentData.description || 'Case opened from console',
      affectedAsset: 'Enterprise Asset',
      assignedOfficer: incidentData.assignedOfficer || user.fullName || 'SOC Lead',
      notes: incidentData.notes || ['Case triage initialized'],
      timestamp: new Date().toISOString()
    };
    setIncidents(prev => [newInc, ...prev]);
  };

  const handleTriageIncident = async (id: string, status: SocIncident['status'], containmentAction?: string, note?: string) => {
    try {
      const res = await fetch(`/api/soc/incidents/${id}/triage`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${token}` },
        body: JSON.stringify({ status, containmentAction, note })
      });
      if (res.ok) {
        const data = await safeJsonResponse(res);
        if (data?.incident) {
          setIncidents(prev => prev.map(i => i.id === id ? data.incident : i));
          return;
        }
      }
    } catch {
      // Fallback
    }

    setIncidents(prev => prev.map(i => {
      if (i.id === id) {
        return {
          ...i,
          status,
          containmentActionTaken: containmentAction || i.containmentActionTaken,
          notes: note ? [...i.notes, note] : i.notes
        };
      }
      return i;
    }));
  };

  const handleGenerateStix = async (target: string, indicatorType?: string) => {
    try {
      const res = await fetch('/api/soc/stix-export', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${token}` },
        body: JSON.stringify({ target, indicatorType })
      });
      if (res.ok) {
        return await safeJsonResponse(res);
      }
    } catch {
      // Fallback
    }
    return clientGenerateStix(target, 75);
  };

  const handleDispatchPlaybook = async (agentId: string, playbook: string, target: string) => {
    try {
      const res = await fetch('/api/ai-swarm/action', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${token}` },
        body: JSON.stringify({ agentId, playbook, target })
      });
      if (res.ok) {
        const data = await safeJsonResponse(res);
        if (data?.event) {
          setSwarmEvents(prev => [data.event, ...prev]);
          return data.event;
        }
      }
    } catch {
      // Fallback
    }

    const localEvt = clientExecuteSwarmPlaybook(agentId, playbook, target);
    setSwarmEvents(prev => [localEvt, ...prev]);
    return localEvt;
  };

  const handleClearAllScans = async () => {
    setIsClearingScans(true);
    try {
      await fetch('/api/scans/clear', { headers: { 'Authorization': `Bearer ${token}` } });
    } catch {
      // Fallback
    } finally {
      setIsClearingScans(false);
      setScans([]);
      setCurrentScan(null);
    }
  };

  // Global Search Router
  const handleGlobalSearch = (query: string) => {
    const q = query.trim();
    if (q.includes('@')) {
      setActiveTab('email-breach');
      handleScanEmail(q);
    } else if (q.startsWith('http://') || q.startsWith('https://')) {
      setActiveTab('url-scanner');
      handleAnalyzeUrl(q);
    } else if (/^cve-\d+/i.test(q)) {
      setActiveTab('cve-database');
      handleSearchCves(q);
    } else if (/^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$/.test(q)) {
      setActiveTab('hash-forensics');
      handleAnalyzeHash(q);
    } else if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(q)) {
      setActiveTab('osint-inspector');
      handleAnalyzeOsint(q);
    } else if (q.endsWith('.png') || q.endsWith('.jpg') || q.endsWith('.mp4') || q.endsWith('.mp3')) {
      setActiveTab('deepfake-detection');
      loadSampleDeepfake(q, q.endsWith('.mp3') ? 'audio' : 'video');
    } else {
      setActiveTab('url-scanner');
      handleAnalyzeUrl(`https://${q}`);
    }
  };

  // Launch from Quick Investigation Modal
  const handleLaunchModalInvestigation = (type: 'url' | 'hash' | 'cve' | 'email' | 'deepfake', target: string) => {
    switch (type) {
      case 'url':
        setActiveTab('url-scanner');
        handleAnalyzeUrl(target);
        break;
      case 'hash':
        setActiveTab('hash-forensics');
        handleAnalyzeHash(target);
        break;
      case 'cve':
        setActiveTab('cve-database');
        handleSearchCves(target);
        break;
      case 'email':
        setActiveTab('email-breach');
        handleScanEmail(target);
        break;
      case 'deepfake':
        setActiveTab('deepfake-detection');
        loadSampleDeepfake(target, target.endsWith('.mp3') ? 'audio' : 'video');
        break;
    }
  };

  // Map active tab to human-readable title
  const getTabTitle = (tab: NavigationTab) => {
    switch (tab) {
      case 'command-center': return 'COMMAND CENTER';
      case 'threat-radar': return 'GLOBAL THREAT RADAR';
      case 'stix-bundler': return 'STIX EVIDENCE BUNDLER';
      case 'satellite-mesh': return 'LEO SATELLITE MESH';
      case 'url-scanner': return 'URL & PHISHING REPUTATION';
      case 'osint-inspector': return 'OSINT IP & ASN RECON';
      case 'hash-forensics': return 'MALWARE HASH & BINARY FORENSICS';
      case 'deepfake-detection': return 'NEURAL DEEPFAKE FORENSICS LAB';
      case 'cve-database': return 'NIST NVD CVE DATABASE';
      case 'email-breach': return 'EXPOSURE & EMAIL BREACH AUDITOR';
      case 'siem-incidents': return 'SIEM INCIDENT RESPONSE MATRIX';
      case 'ai-soc-swarm': return 'AUTONOMOUS AI SOC DEFENSE SWARM';
      case 'pqc-audit': return 'POST-QUANTUM CRYPTOGRAPHY AUDIT';
      case 'compliance-settings': return 'COMPLIANCE & ZERO-RETENTION TRUST';
      default: return 'SECURITY WORKSTATION';
    }
  };

  return (
    <div className="h-screen bg-[#080C14] text-[#F1F5F9] flex flex-row overflow-hidden">
      {/* 1. Persistent Sidebar Navigation */}
      <Sidebar
        activeTab={activeTab}
        onSelectTab={setActiveTab}
        collapsed={sidebarCollapsed}
        onToggleCollapse={() => setSidebarCollapsed(prev => !prev)}
        incidents={incidents}
        isMobileOpen={mobileSidebarOpen}
        onCloseMobile={() => setMobileSidebarOpen(false)}
      />

      {/* 2. Main Content Canvas */}
      <div className="flex-1 flex flex-col min-w-0 h-screen overflow-hidden">
        {/* Top Header Bar */}
        <Header
          user={user}
          onOpenMobileSidebar={() => setMobileSidebarOpen(true)}
          onToggleTerminal={() => setShowTerminal(prev => !prev)}
          onQuickSearch={handleGlobalSearch}
          onStartInvestigation={() => setShowQuickInvestigationModal(true)}
          onNewIncident={() => setShowNewIncidentModal(true)}
          currentTitle={getTabTitle(activeTab)}
        />

        {/* Dynamic View Body */}
        <main className="flex-1 overflow-y-auto p-3 sm:p-4 lg:p-5 max-w-[1680px] w-full mx-auto space-y-4 pb-20">
          {activeTab === 'command-center' && (
            <CommandCenterView
              scans={scans}
              incidents={incidents}
              onNavigateTab={setActiveTab}
              onSelectScanReport={onSelectReport}
              onSelectIncident={(inc) => {
                setActiveTab('siem-incidents');
              }}
              onNewIncident={() => setShowNewIncidentModal(true)}
              onQuickSample={(type) => {
                if (type === 'url') {
                  setActiveTab('url-scanner');
                  handleAnalyzeUrl('https://secure-update-portal.org');
                } else if (type === 'hash') {
                  setActiveTab('hash-forensics');
                  handleAnalyzeHash('44d88612fea8a8f36de82e1278abb02f', 'dropper.exe');
                } else if (type === 'cve') {
                  setActiveTab('cve-database');
                  handleSearchCves('CVE-2023-4966');
                } else if (type === 'email') {
                  setActiveTab('email-breach');
                  handleScanEmail('usxr@yahoo.com');
                } else if (type === 'deepfake') {
                  setActiveTab('deepfake-detection');
                  loadSampleDeepfake('executive_conference_stream.mp4', 'video');
                }
              }}
            />
          )}

          {activeTab === 'deepfake-detection' && (
            <DeepfakeDetectionView
              token={token}
              onAnalyzeMedia={handleAnalyzeMedia}
              onAnalyzeSample={loadSampleDeepfake}
              currentResult={deepfakeResult}
              loading={deepfakeLoading}
              error={deepfakeError}
            />
          )}

          {activeTab === 'hash-forensics' && (
            <HashAnalysisView
              token={token}
              onAnalyzeHash={handleAnalyzeHash}
              currentResult={hashResult}
              loading={hashLoading}
              error={hashError}
            />
          )}

          {activeTab === 'url-scanner' && (
            <UrlAnalysisView
              token={token}
              onAnalyzeUrl={handleAnalyzeUrl}
              currentScan={currentScan}
              loading={urlLoading}
              error={urlError}
              onSelectReport={onSelectReport}
            />
          )}

          {activeTab === 'osint-inspector' && (
            <OsintAnalysisView
              token={token}
              onAnalyzeOsint={handleAnalyzeOsint}
              currentResult={osintResult}
              loading={osintLoading}
              error={osintError}
            />
          )}

          {activeTab === 'cve-database' && (
            <CveAnalysisView
              token={token}
              onSearchCves={handleSearchCves}
              currentResults={cveResults}
              loading={cveLoading}
            />
          )}

          {activeTab === 'email-breach' && (
            <EmailBreachView
              token={token}
              onScanEmail={handleScanEmail}
              currentScan={currentScan}
              loading={loading}
              error={error}
              onSelectReport={onSelectReport}
            />
          )}

          {activeTab === 'siem-incidents' && (
            <SiemIncidentsView
              token={token}
              incidents={incidents}
              onNewIncident={() => setShowNewIncidentModal(true)}
              onTriageIncident={handleTriageIncident}
              loading={incidentsLoading}
            />
          )}

          {activeTab === 'stix-bundler' && (
            <StixBundlerView
              token={token}
              onGenerateStix={handleGenerateStix}
              loading={loading}
            />
          )}

          {activeTab === 'threat-radar' && (
            <ThreatRadarView />
          )}

          {activeTab === 'pqc-audit' && (
            <PqcAuditView
              token={token}
              onAnalyzePqc={loadPqcAudit}
              onSimulateQuantum={loadQuantumSim}
              pqcResult={pqcResult}
              simResult={simResult}
              loading={pqcLoading}
            />
          )}

          {(activeTab === 'ai-soc-swarm' || activeTab === 'ai-swarm') && (
            <AiSwarmView
              token={token}
              agents={swarmAgents}
              events={swarmEvents}
              onDispatchPlaybook={handleDispatchPlaybook}
              loading={swarmLoading}
            />
          )}

          {activeTab === 'satellite-mesh' && (
            <SatelliteMeshView
              telemetry={satelliteData}
              loading={satelliteLoading}
            />
          )}

          {activeTab === 'compliance-settings' && (
            <ComplianceView
              token={token}
              user={user}
              onClearAllScans={handleClearAllScans}
              isClearing={isClearingScans}
            />
          )}

          {![
            'command-center', 'url-scanner', 'osint-inspector', 'hash-forensics',
            'deepfake-detection', 'cve-database', 'email-breach', 'siem-incidents',
            'stix-bundler', 'threat-radar', 'pqc-audit', 'ai-soc-swarm', 'ai-swarm',
            'satellite-mesh', 'compliance-settings'
          ].includes(activeTab) && (
            <div className="command-card p-10 text-center space-y-4 border-blue-500/30">
              <div className="w-12 h-12 rounded-full bg-blue-500/10 border border-blue-500/30 flex items-center justify-center mx-auto text-blue-400">
                <ShieldCheck className="w-6 h-6" />
              </div>
              <h3 className="text-sm font-bold text-white uppercase font-mono tracking-wider">Module Route Initialized</h3>
              <p className="text-xs text-slate-400 max-w-md mx-auto font-sans">
                This workstation module is active. Return to the Command Center to browse active investigations.
              </p>
              <button
                onClick={() => setActiveTab('command-center')}
                className="px-4 py-2 rounded-md bg-blue-600 hover:bg-blue-500 text-white font-sans text-xs font-semibold uppercase tracking-wider transition-colors shadow-[0_0_12px_rgba(59,130,246,0.3)]"
              >
                Return to Command Center
              </button>
            </div>
          )}
        </main>
      </div>

      {/* 3. New Incident Creation Modal */}
      <NewIncidentModal
        isOpen={showNewIncidentModal}
        onClose={() => setShowNewIncidentModal(false)}
        onSubmit={handleCreateIncident}
        officerName={user.fullName || 'SOC Lead'}
      />

      {/* 4. Quick Investigation Launchpad Modal */}
      <QuickInvestigationModal
        isOpen={showQuickInvestigationModal}
        onClose={() => setShowQuickInvestigationModal(false)}
        onLaunchInvestigation={handleLaunchModalInvestigation}
      />

      {/* 5. SOC Terminal Shell Drawer */}
      {showTerminal && (
        <div className="fixed inset-0 z-50 flex flex-col justify-end bg-black/60 backdrop-blur-xs">
          <div className="w-full max-w-5xl mx-auto mb-3 px-3">
            <div className="flex justify-end mb-1">
              <button
                onClick={() => setShowTerminal(false)}
                className="px-2.5 py-1 rounded bg-[#111A2E] hover:bg-[#1E2D48] text-slate-300 border border-[#202E48] text-xs font-mono transition-colors"
              >
                ✕ Close Shell
              </button>
            </div>
            <Terminal
              user={user}
              token={token}
              onClose={() => setShowTerminal(false)}
            />
          </div>
        </div>
      )}
    </div>
  );
}
