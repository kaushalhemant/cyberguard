import React, { useState, useEffect, useRef } from 'react';
import { Shield, ShieldAlert, ShieldCheck, Mail, Search, History, LogOut, Terminal as TerminalIcon, Bot, Zap, Brain, Plus, ChevronRight, Lock, Bell, Users, Cpu, FileText, CheckCircle2, UserCheck, RefreshCw, Link2, Image, UploadCloud, Globe, Eye, FileImage, Trash2 } from 'lucide-react';
import { User, ScanResult } from '../types';
import Terminal from './Terminal';
import PrivacyStatementModal from './PrivacyStatementModal';
import ThreatIntelligence from './ThreatIntelligence';
import UsageAudit from './UsageAudit';
import { signInWithPopup, GoogleAuthProvider } from 'firebase/auth';
import { auth, googleProvider } from '../lib/firebase';

interface DashboardProps {
  user: User;
  token: string;
  gmailToken: string | null;
  setGmailToken: (token: string | null) => void;
  onLogout: () => void;
  onSelectReport: (scan: ScanResult) => void;
  onUserUpdate: (updatedUser: User) => void;
  onNavigateAdmin: () => void;
}

export default function Dashboard({
  user,
  token,
  gmailToken,
  setGmailToken,
  onLogout,
  onSelectReport,
  onUserUpdate,
  onNavigateAdmin
}: DashboardProps) {
  const [activeTab, setActiveTab] = useState<'email' | 'link' | 'image' | 'grounding' | 'intelligence'>('email');
  const [scanEmail, setScanEmail] = useState('');
  const [scanUrl, setScanUrl] = useState('');
  
  const [imageFile, setImageFile] = useState<File | null>(null);
  const [imagePreview, setImagePreview] = useState<string | null>(null);
  const [isDragging, setIsDragging] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [isQuotaExceeded, setIsQuotaExceeded] = useState(false);

  // --- NEW AI ADVANCED STATES ---
  // Search Grounding States
  const [groundingQuery, setGroundingQuery] = useState('');
  const [groundingResult, setGroundingResult] = useState<{ text: string; sources: { title: string; url: string }[] } | null>(null);
  const [groundingLoading, setGroundingLoading] = useState(false);

  // CyberGuard Assistant Chat States
  const [intelMessage, setIntelMessage] = useState('');
  const [intelTaskType, setIntelTaskType] = useState<'complex' | 'general' | 'fast'>('general');
  const [intelChatHistory, setIntelChatHistory] = useState<{ sender: 'user' | 'assistant'; text: string; timestamp: string }[]>([
    { sender: 'assistant', text: 'Greetings! I am CyberGuard Assistant, your personal AI security helper. How can I help protect your digital accounts, analyze potential threat vectors, or answer your cybersecurity questions today?', timestamp: new Date().toLocaleTimeString() }
  ]);
  const [intelLoading, setIntelLoading] = useState(false);

  // Gmail Live Inbox Integration states
  const [gmailMode, setGmailMode] = useState<'breach' | 'gmail'>('breach');
  const [gmailMessages, setGmailMessages] = useState<any[]>([]);
  const [gmailLoading, setGmailLoading] = useState(false);
  const [gmailError, setGmailError] = useState<string | null>(null);
  const [activeScanningId, setActiveScanningId] = useState<string | null>(null);

  const fetchGmailEmails = async (tokenToUse: string) => {
    setGmailLoading(true);
    setGmailError(null);
    try {
      const response = await fetch('https://gmail.googleapis.com/gmail/v1/users/me/messages?maxResults=10&q=category:primary', {
        headers: {
          'Authorization': `Bearer ${tokenToUse}`
        }
      });
      
      if (!response.ok) {
        if (response.status === 401) {
          setGmailToken(null);
          throw new Error('Your Google session has expired. Please re-connect.');
        }
        throw new Error('Failed to retrieve your Gmail message list.');
      }
      
      const listData = await response.json();
      if (!listData.messages || listData.messages.length === 0) {
        setGmailMessages([]);
        return;
      }
      
      const details = await Promise.all(listData.messages.map(async (msg: any) => {
        try {
          const detailResponse = await fetch(`https://gmail.googleapis.com/gmail/v1/users/me/messages/${msg.id}?format=full`, {
            headers: {
              'Authorization': `Bearer ${tokenToUse}`
            }
          });
          if (!detailResponse.ok) return null;
          return await detailResponse.json();
        } catch (e) {
          return null;
        }
      }));
      
      const parsed = details.filter(Boolean).map((message: any) => {
        const headers = message.payload?.headers || [];
        const getHeader = (name: string) => headers.find((h: any) => h.name.toLowerCase() === name.toLowerCase())?.value || '';
        
        const fromHeader = getHeader('from');
        const subjectHeader = getHeader('subject');
        const dateHeader = getHeader('date');
        
        const decodeBase64Url = (str: string) => {
          if (!str) return '';
          try {
            const base64 = str.replace(/-/g, '+').replace(/_/g, '/');
            return decodeURIComponent(escape(window.atob(base64)));
          } catch (e) {
            return '';
          }
        };
        
        let body = '';
        const parts = message.payload?.parts;
        
        if (message.payload?.body?.data) {
          body = decodeBase64Url(message.payload.body.data);
        } else if (parts) {
          const findTextPart = (partsArray: any[]): string => {
            for (const part of partsArray) {
              if (part.mimeType === 'text/plain' && part.body?.data) {
                return decodeBase64Url(part.body.data);
              } else if (part.mimeType === 'text/html' && part.body?.data) {
                return decodeBase64Url(part.body.data);
              } else if (part.parts) {
                const subText = findTextPart(part.parts);
                if (subText) return subText;
              }
            }
            return '';
          };
          body = findTextPart(parts);
        }
        
        return {
          id: message.id,
          from: fromHeader,
          subject: subjectHeader,
          date: dateHeader,
          snippet: message.snippet || '',
          body: body || message.snippet || '',
        };
      });
      
      setGmailMessages(parsed);
    } catch (err: any) {
      console.error('Gmail retrieval failed:', err);
      setGmailError(err.message || 'Failed to sync your Gmail messages.');
    } finally {
      setGmailLoading(false);
    }
  };

  const handleConnectGmail = async () => {
    setGmailError(null);
    try {
      const result = await signInWithPopup(auth, googleProvider);
      const credential = GoogleAuthProvider.credentialFromResult(result);
      const accessToken = credential?.accessToken;
      if (!accessToken) {
        throw new Error('Could not retrieve access token from Google.');
      }
      setGmailToken(accessToken);
    } catch (err: any) {
      console.error('Google link failed:', err);
      let errMsg = 'Google account linking aborted.';
      if (err.code === 'auth/popup-closed-by-user' || (err.message && err.message.includes('popup-closed-by-user'))) {
        errMsg = 'The Google authorization window was closed before completion. If you are using the app inside the AI Studio iframe, please open the app in a new tab, allow popups, and try again.';
      } else if (err.code === 'auth/popup-blocked' || (err.message && err.message.includes('popup-blocked'))) {
        errMsg = 'The authorization popup was blocked by your browser. Please allow popups for this site and try again.';
      } else if (err.message) {
        errMsg = err.message;
      }
      setGmailError(errMsg);
    }
  };

  const handleScanGmailMessage = async (msg: any) => {
    setError(null);
    setIsQuotaExceeded(false);
    setActiveScanningId(msg.id);
    
    try {
      const response = await fetch('/api/scan-gmail-message', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify({
          from: msg.from,
          subject: msg.subject,
          snippet: msg.snippet,
          body: msg.body
        })
      });

      let data: any = {};
      const contentType = response.headers.get('content-type');
      if (contentType && contentType.includes('application/json')) {
        data = await response.json();
      } else {
        if (response.status === 402 || response.status === 403) {
          setIsQuotaExceeded(true);
          return;
        }
        throw new Error('Server returned unexpected non-JSON response.');
      }

      if (!response.ok) {
        if (data.code === 'QUOTA_EXCEEDED' || response.status === 402 || response.status === 403) {
          setIsQuotaExceeded(true);
          return;
        }
        throw new Error(data.error || 'Failed to scan the Gmail message.');
      }

      setScans(prev => [data.scan, ...prev]);
      onUserUpdate(data.user);
      onSelectReport(data.scan);
    } catch (err: any) {
      console.error('Scan Gmail Message error:', err);
      const msgLower = (err.message || '').toLowerCase();
      if (msgLower.includes('quota') || msgLower.includes('limit')) {
        setIsQuotaExceeded(true);
      } else {
        setError(err.message || 'Error executing Gmail message threat scan.');
      }
    } finally {
      setActiveScanningId(null);
    }
  };

  useEffect(() => {
    if (gmailToken && gmailMode === 'gmail') {
      fetchGmailEmails(gmailToken);
    }
  }, [gmailToken, gmailMode]);

  const [scans, setScans] = useState<ScanResult[]>([]);
  const [showTerminal, setShowTerminal] = useState(false);

  // --- COMPLIANCE, TRUST & DATA SUBJECT ERASURE STATES ---
  const [complianceTab, setComplianceTab] = useState<'gmail' | 'sourcing' | 'soc2' | 'bounty' | 'erasure'>('gmail');
  const [isClearingScans, setIsClearingScans] = useState(false);
  const [clearScansSuccess, setClearScansSuccess] = useState(false);
  const [confirmWipe, setConfirmWipe] = useState(false);
  const [showPrivacyModal, setShowPrivacyModal] = useState(false);

  const handleWipeScans = async () => {
    setIsClearingScans(true);
    setClearScansSuccess(false);
    try {
      const response = await fetch('/api/scans/clear', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        }
      });
      if (response.ok) {
        setScans([]);
        setClearScansSuccess(true);
        setConfirmWipe(false);
        setTimeout(() => setClearScansSuccess(false), 5000);
      }
    } catch (err) {
      console.error("Wipe scans error:", err);
    } finally {
      setIsClearingScans(false);
    }
  };

  const fetchScansHistory = async () => {
    try {
      const response = await fetch('/api/scans', {
        headers: {
          'Authorization': `Bearer ${token}`
        }
      });
      if (response.ok) {
        const data = await response.json();
        setScans(data.scans);
      }
    } catch (err) {
      console.error('Failed to load history:', err);
    }
  };

  useEffect(() => {
    fetchScansHistory();
  }, [token]);



  const handleGroundingSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!groundingQuery.trim()) return;

    setGroundingLoading(true);
    setError(null);
    try {
      const response = await fetch('/api/ai/search-grounding', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify({ query: groundingQuery.trim() })
      });
      const data = await response.json();
      if (!response.ok) {
        throw new Error(data.error || 'Failed to perform grounded web search.');
      }
      setGroundingResult({
        text: data.text,
        sources: data.sources || []
      });
    } catch (err: any) {
      setError(err.message || 'Error occurred during grounded security search.');
    } finally {
      setGroundingLoading(false);
    }
  };

  const handleIntelSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!intelMessage.trim() || intelLoading) return;

    const userMsg = intelMessage.trim();
    setIntelMessage('');
    setIntelChatHistory(prev => [...prev, { sender: 'user', text: userMsg, timestamp: new Date().toLocaleTimeString() }]);
    setIntelLoading(true);
    setError(null);

    try {
      const response = await fetch('/api/ai/intelligence', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify({ message: userMsg, taskType: intelTaskType })
      });
      const data = await response.json();
      if (!response.ok) {
        throw new Error(data.error || 'Failed to process intelligence request.');
      }
      setIntelChatHistory(prev => [...prev, { sender: 'assistant', text: data.response, timestamp: new Date().toLocaleTimeString() }]);
    } catch (err: any) {
      setIntelChatHistory(prev => [...prev, { sender: 'assistant', text: `⚠️ Error: ${err.message || 'Unable to retrieve advice.'}`, timestamp: new Date().toLocaleTimeString() }]);
    } finally {
      setIntelLoading(false);
    }
  };



  const handleScanSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setIsQuotaExceeded(false);
    
    const emailToScan = scanEmail.trim();
    if (!emailToScan || !emailToScan.includes('@')) {
      setError('Please provide a valid email address to audit.');
      return;
    }

    setLoading(true);
    try {
      const response = await fetch('/api/scan', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify({ email: emailToScan })
      });

      let data: any = {};
      const contentType = response.headers.get('content-type');
      if (contentType && contentType.includes('application/json')) {
        data = await response.json();
      } else {
        const textText = await response.text();
        if (response.status === 402 || response.status === 403) {
          setIsQuotaExceeded(true);
          setLoading(false);
          return;
        }
        throw new Error(`Server returned unexpected response (Status: ${response.status}). ${textText.substring(0, 100)}`);
      }

      if (!response.ok) {
        if (data.code === 'QUOTA_EXCEEDED' || response.status === 402 || response.status === 403) {
          setIsQuotaExceeded(true);
          setLoading(false);
          return;
        }
        throw new Error(data.error || 'Vulnerability scanning failed.');
      }

      setScanEmail('');
      // Update scans list
      setScans(prev => [data.scan, ...prev]);
      // Update user scans quota count
      onUserUpdate(data.user);
      // Directly load this new report
      onSelectReport(data.scan);
    } catch (err: any) {
      const msg = (err.message || '').toLowerCase();
      if (msg.includes('quota') || msg.includes('limit') || msg.includes('status: 403') || msg.includes('status: 402') || msg.includes('forbidden')) {
        setIsQuotaExceeded(true);
      } else {
        setError(err.message || 'Error executing secure breach audit.');
      }
    } finally {
      setLoading(false);
    }
  };

  const handleLinkScanSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setIsQuotaExceeded(false);

    const urlToScan = scanUrl.trim();
    if (!urlToScan) {
      setError('Please provide a valid URL to scan.');
      return;
    }

    setLoading(true);
    try {
      const response = await fetch('/api/scan-link', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify({ url: urlToScan })
      });

      let data: any = {};
      const contentType = response.headers.get('content-type');
      if (contentType && contentType.includes('application/json')) {
        data = await response.json();
      } else {
        const textText = await response.text();
        if (response.status === 402 || response.status === 403) {
          setIsQuotaExceeded(true);
          setLoading(false);
          return;
        }
        throw new Error(`Server returned unexpected response (Status: ${response.status}). ${textText.substring(0, 100)}`);
      }

      if (!response.ok) {
        if (data.code === 'QUOTA_EXCEEDED' || response.status === 402 || response.status === 403) {
          setIsQuotaExceeded(true);
          setLoading(false);
          return;
        }
        throw new Error(data.error || 'Malicious link analysis failed.');
      }

      setScanUrl('');
      setScans(prev => [data.scan, ...prev]);
      onUserUpdate(data.user);
      onSelectReport(data.scan);
    } catch (err: any) {
      const msg = (err.message || '').toLowerCase();
      if (msg.includes('quota') || msg.includes('limit') || msg.includes('status: 403') || msg.includes('status: 402') || msg.includes('forbidden')) {
        setIsQuotaExceeded(true);
      } else {
        setError(err.message || 'Error executing secure link scan.');
      }
    } finally {
      setLoading(false);
    }
  };

  const handleFileChange = (file: File) => {
    if (!file.type.startsWith('image/')) {
      setError('Please upload an image file (PNG, JPG, JPEG, WEBP).');
      return;
    }
    setError(null);
    setImageFile(file);
    const reader = new FileReader();
    reader.onloadend = () => {
      setImagePreview(reader.result as string);
    };
    reader.readAsDataURL(file);
  };

  const handleDragOver = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(true);
  };

  const handleDragLeave = () => {
    setIsDragging(false);
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(false);
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      handleFileChange(e.dataTransfer.files[0]);
    }
  };

  const handleImageScanSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setIsQuotaExceeded(false);

    if (!imageFile || !imagePreview) {
      setError('Please select or drop an image file first.');
      return;
    }

    setLoading(true);
    try {
      const base64Data = imagePreview.split(',')[1];
      const mimeType = imageFile.type;
      const filename = imageFile.name;

      const response = await fetch('/api/scan-image', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify({
          base64Image: base64Data,
          mimeType,
          filename
        })
      });

      let data: any = {};
      const contentType = response.headers.get('content-type');
      if (contentType && contentType.includes('application/json')) {
        data = await response.json();
      } else {
        const textText = await response.text();
        if (response.status === 402 || response.status === 403) {
          setIsQuotaExceeded(true);
          setLoading(false);
          return;
        }
        throw new Error(`Server returned unexpected response (Status: ${response.status}). ${textText.substring(0, 100)}`);
      }

      if (!response.ok) {
        if (data.code === 'QUOTA_EXCEEDED' || response.status === 402 || response.status === 403) {
          setIsQuotaExceeded(true);
          setLoading(false);
          return;
        }
        throw new Error(data.error || 'Visual threat inspection failed.');
      }

      setImageFile(null);
      setImagePreview(null);
      setScans(prev => [data.scan, ...prev]);
      onUserUpdate(data.user);
      onSelectReport(data.scan);
    } catch (err: any) {
      const msg = (err.message || '').toLowerCase();
      if (msg.includes('quota') || msg.includes('limit') || msg.includes('status: 403') || msg.includes('status: 402') || msg.includes('forbidden')) {
        setIsQuotaExceeded(true);
      } else {
        setError(err.message || 'Error executing visual threat scan.');
      }
    } finally {
      setLoading(false);
    }
  };

  // Stats calculation
  const totalAudits = scans.length;
  const criticalExposures = scans.filter(s => s.riskScore >= 70).length;
  const secureScans = scans.filter(s => s.resultCount === 0).length;

  return (
    <div className="space-y-6">
      
      {/* APPLE / MICROSOFT HERO SECURITY BANNER */}
      <div className="bento-card p-6 md:p-8 relative overflow-hidden bg-gradient-to-r from-slate-900/90 via-slate-900/70 to-slate-950 border border-white/10 shadow-[0_10px_40px_-10px_rgba(0,0,0,0.5)]">
        <div className="absolute -top-24 -right-24 w-96 h-96 bg-cyan-500/10 rounded-full blur-3xl pointer-events-none"></div>
        <div className="absolute -bottom-24 -left-24 w-96 h-96 bg-blue-600/10 rounded-full blur-3xl pointer-events-none"></div>

        <div className="relative z-10 flex flex-col lg:flex-row items-start lg:items-center justify-between gap-6">
          <div className="space-y-2.5 max-w-2xl">
            <div className="flex items-center gap-2.5 flex-wrap">
              <span className="px-3 py-1 rounded-full text-[10px] font-mono font-bold bg-cyan-500/10 text-cyan-400 border border-cyan-500/25 flex items-center gap-1.5 shadow-[0_0_15px_rgba(6,182,212,0.15)]">
                <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse"></span>
                CYBERGUARD ASSISTANT PRO LIVE
              </span>
              <span className="px-3 py-1 rounded-full text-[10px] font-mono font-bold bg-slate-800/80 text-slate-300 border border-slate-700">
                100% UNLOCKED ENTERPRISE ACCESS
              </span>
            </div>
            <h2 className="text-2xl md:text-3xl font-extrabold font-display tracking-tight text-white">
              Your Digital Footprint, <span className="bg-gradient-to-r from-cyan-400 via-teal-300 to-blue-400 bg-clip-text text-transparent">Fully Guarded.</span>
            </h2>
            <p className="text-xs md:text-sm text-slate-400 leading-relaxed font-sans max-w-xl">
              Welcome back, <span className="text-slate-200 font-semibold">{user.fullName || user.email}</span>. Your CyberGuard Assistant is continuously auditing breach databases, link threats, and visual vectors in real-time.
            </p>
          </div>

          {/* Quick Metrics Bar */}
          <div className="grid grid-cols-3 gap-3 w-full lg:w-auto shrink-0 font-mono">
            <div className="bg-slate-950/60 border border-slate-800/80 p-3 rounded-xl text-center">
              <span className="text-[9px] uppercase tracking-wider text-slate-500 block">Threat Status</span>
              <span className="text-base font-bold text-emerald-400">0 ACTIVE</span>
            </div>
            <div className="bg-slate-950/60 border border-slate-800/80 p-3 rounded-xl text-center">
              <span className="text-[9px] uppercase tracking-wider text-slate-500 block">Total Audits</span>
              <span className="text-base font-bold text-cyan-400">{totalAudits}</span>
            </div>
            <div className="bg-slate-950/60 border border-slate-800/80 p-3 rounded-xl text-center">
              <span className="text-[9px] uppercase tracking-wider text-slate-500 block">Security Rating</span>
              <span className="text-base font-bold text-white">100 / 100</span>
            </div>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
      
      {/* LEFT & CENTER PANEL (Vulnerability Scanner & Analytics) */}
      <div className="lg:col-span-2 space-y-6">
        
        {/* Core Scanner Card */}
        <div className="bento-card p-6 relative overflow-hidden">
          <div className="absolute top-0 right-0 w-32 h-32 bg-cyan-500/5 rounded-full blur-2xl"></div>
          
          <div className="flex items-start justify-between border-b border-slate-800 pb-4 mb-4">
            <div>
              <span className="text-[10px] uppercase font-mono tracking-wider text-slate-500">Security Core Engine v4</span>
              <h2 className="text-xl font-bold font-display text-white mt-0.5">Integrity Breach Scanner</h2>
            </div>
            <span className="bg-cyan-950/30 border border-cyan-800/30 text-cyan-400 font-mono text-[10px] font-bold px-2.5 py-1 rounded-full flex items-center gap-1.5">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse"></span> 
              Vulnerability Audits: Active
            </span>
          </div>

          {/* Navigation tabs for scanner type */}
          <div className="flex border-b border-slate-800/60 mb-5 gap-1 sm:gap-2 font-mono text-[10px] font-bold overflow-x-auto print:hidden pb-1">
            <button
              type="button"
              onClick={() => { setActiveTab('email'); setError(null); setIsQuotaExceeded(false); }}
              className={`flex items-center gap-1.5 px-3 py-2 border-b-2 transition-all cursor-pointer whitespace-nowrap ${
                activeTab === 'email'
                  ? 'border-cyan-500 text-cyan-400 bg-cyan-950/20'
                  : 'border-transparent text-slate-400 hover:text-slate-200'
              }`}
            >
              <Mail className="w-3.5 h-3.5" />
              <span>EMAIL AUDIT</span>
            </button>
            <button
              type="button"
              onClick={() => { setActiveTab('link'); setError(null); setIsQuotaExceeded(false); }}
              className={`flex items-center gap-1.5 px-3 py-2 border-b-2 transition-all cursor-pointer whitespace-nowrap ${
                activeTab === 'link'
                  ? 'border-cyan-500 text-cyan-400 bg-cyan-950/20'
                  : 'border-transparent text-slate-400 hover:text-slate-200'
              }`}
            >
              <Link2 className="w-3.5 h-3.5" />
              <span>MALICIOUS LINK</span>
            </button>
            <button
              type="button"
              onClick={() => { setActiveTab('image'); setError(null); setIsQuotaExceeded(false); }}
              className={`flex items-center gap-1.5 px-3 py-2 border-b-2 transition-all cursor-pointer whitespace-nowrap ${
                activeTab === 'image'
                  ? 'border-cyan-500 text-cyan-400 bg-cyan-950/20'
                  : 'border-transparent text-slate-400 hover:text-slate-200'
              }`}
            >
              <Image className="w-3.5 h-3.5" />
              <span>IMAGE VECTOR</span>
            </button>
            <button
              type="button"
              onClick={() => { setActiveTab('grounding'); setError(null); setIsQuotaExceeded(false); }}
              className={`flex items-center gap-1.5 px-3 py-2 border-b-2 transition-all cursor-pointer whitespace-nowrap ${
                activeTab === 'grounding'
                  ? 'border-cyan-500 text-cyan-400 bg-cyan-950/20'
                  : 'border-transparent text-slate-400 hover:text-slate-200'
              }`}
            >
              <Globe className="w-3.5 h-3.5 text-cyan-400" />
              <span className="flex items-center gap-1">SEARCH GROUNDING</span>
            </button>
            <button
              type="button"
              onClick={() => { setActiveTab('intelligence'); setError(null); setIsQuotaExceeded(false); }}
              className={`flex items-center gap-1.5 px-3 py-2 border-b-2 transition-all cursor-pointer whitespace-nowrap ${
                activeTab === 'intelligence'
                  ? 'border-cyan-500 text-cyan-400 bg-cyan-950/20'
                  : 'border-transparent text-slate-400 hover:text-slate-200'
              }`}
            >
              <Bot className="w-3.5 h-3.5 text-cyan-400" />
              <span className="flex items-center gap-1">CYBERGUARD ASSISTANT</span>
            </button>
          </div>

          {error && (
            <div className="p-3 bg-rose-500/10 border border-rose-500/25 rounded-xl text-rose-300 text-xs flex gap-2 mb-4">
              <ShieldAlert className="w-4 h-4 shrink-0 mt-0.5" />
              <div className="space-y-1">
                <span className="font-semibold block">Scan Aborted:</span>
                <p>{error}</p>
              </div>
            </div>
          )}



          {activeTab === 'email' && (
            <div className="space-y-6 animate-fade-in">
              {/* Sub-mode selector */}
              <div className="flex bg-slate-950 p-1 rounded-lg border border-slate-900 w-full sm:w-fit font-mono text-[10px] font-bold">
                <button
                  type="button"
                  onClick={() => setGmailMode('breach')}
                  className={`flex-1 sm:flex-none px-4 py-2 rounded-md transition-all cursor-pointer ${
                    gmailMode === 'breach'
                      ? 'bg-slate-900 text-cyan-400 shadow border border-cyan-500/10'
                      : 'text-slate-500 hover:text-slate-300'
                  }`}
                >
                  DATABASE BREACH LOOKUP
                </button>
                <button
                  type="button"
                  onClick={() => setGmailMode('gmail')}
                  className={`flex-1 sm:flex-none px-4 py-2 rounded-md transition-all cursor-pointer flex items-center justify-center gap-1.5 ${
                    gmailMode === 'gmail'
                      ? 'bg-slate-900 text-cyan-400 shadow border border-cyan-500/10'
                      : 'text-slate-500 hover:text-slate-300'
                  }`}
                >
                  <span className="w-2 h-2 rounded-full bg-cyan-400 animate-pulse"></span>
                  GMAIL REAL-TIME AUDIT
                </button>
              </div>

              {gmailMode === 'breach' ? (
                <form onSubmit={handleScanSubmit} className="space-y-4">
                  <div className="flex flex-col sm:flex-row gap-3">
                    <div className="relative flex-1">
                      <span className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none text-slate-500">
                        <Mail className="w-5 h-5" />
                      </span>
                      <input
                        type="email"
                        value={scanEmail}
                        onChange={(e) => setScanEmail(e.target.value)}
                        placeholder="Enter email to scan (e.g. security-officer@domain.com)..."
                        className="w-full bg-slate-950 border border-slate-800 rounded-xl pl-10 pr-4 py-3 text-sm text-white placeholder-slate-600 focus:outline-none focus:border-cyan-500 transition-all font-mono"
                        disabled={loading}
                        required
                      />
                    </div>
                    <button
                      type="submit"
                      disabled={loading}
                      className="bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold text-xs py-3 px-6 rounded-xl border border-cyan-400/20 transition-all shadow-lg shadow-cyan-500/10 flex items-center justify-center gap-1.5 cursor-pointer disabled:opacity-55 shrink-0 font-mono"
                    >
                      {loading ? (
                        <>
                          <RefreshCw className="w-4 h-4 animate-spin" />
                          <span>Auditing archives...</span>
                        </>
                      ) : (
                        <>
                          <Search className="w-4 h-4" />
                          <span>Launch Integrity Audit</span>
                        </>
                      )}
                    </button>
                  </div>
                </form>
              ) : (
                <div className="space-y-4">
                  {gmailError && (
                    <div className="p-3 bg-rose-500/10 border border-rose-500/25 rounded-xl text-rose-300 text-xs">
                      {gmailError}
                    </div>
                  )}

                  {!gmailToken ? (
                    <div className="bg-slate-950/60 border border-slate-900 rounded-2xl p-6 md:p-8 text-center space-y-4 max-w-2xl mx-auto">
                      <div className="w-12 h-12 rounded-full bg-cyan-950/40 border border-cyan-500/30 flex items-center justify-center mx-auto text-cyan-400">
                        <Mail className="w-6 h-6 animate-pulse" />
                      </div>
                      <div className="space-y-1.5">
                        <h4 className="text-base font-bold font-display text-white">Integrate Your Gmail Inbox</h4>
                        <p className="text-xs text-slate-400 leading-relaxed max-w-md mx-auto">
                          Authorize CyberGuard to scan the latest incoming emails directly from your Google primary category inbox. Outsmart active credential harvesters, targeted spear-phishing, or malicious files through Gemini's direct server-side heuristics.
                        </p>
                      </div>
                      <button
                        type="button"
                        onClick={handleConnectGmail}
                        className="mx-auto bg-white hover:bg-slate-100 text-slate-950 font-bold text-xs py-3 px-6 rounded-xl border border-slate-200 transition-all shadow-lg flex items-center gap-2 cursor-pointer hover:scale-[1.01] active:scale-[0.99]"
                      >
                        <svg className="w-4 h-4" viewBox="0 0 24 24">
                          <path
                            fill="#EA4335"
                            d="M20.6 10.3c0-.7-.1-1.3-.2-2H12v3.9h4.8c-.2 1.1-.8 2-1.8 2.6v2.1h2.9c1.7-1.6 2.7-3.9 2.7-6.6z"
                          />
                          <path
                            fill="#4285F4"
                            d="M12 21c2.4 0 4.5-.8 6-2.2l-2.9-2.1c-.8.5-1.9.8-3.1.8-2.4 0-4.4-1.6-5.1-3.8H3.8v2.2C5.3 18.9 8.4 21 12 21z"
                          />
                          <path
                            fill="#FBBC05"
                            d="M6.9 13.7c-.2-.5-.3-1.1-.3-1.7s.1-1.2.3-1.7V8.1H3.8C3.1 9.5 2.7 11.2 2.7 13s.4 3.5 1.1 4.9l3.1-2.2z"
                          />
                          <path
                            fill="#34A853"
                            d="M12 5.1c1.3 0 2.5.5 3.4 1.3l2.6-2.6C16.5 2.5 14.4 1.7 12 1.7 8.4 1.7 5.3 3.8 3.8 6.7l3.1 2.2c.7-2.2 2.7-3.8 5.1-3.8z"
                          />
                        </svg>
                        <span>Connect Gmail via Google Auth</span>
                      </button>
                    </div>
                  ) : (
                    <div className="space-y-4">
                      {/* Connection header */}
                      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 bg-slate-950 p-4 rounded-xl border border-slate-900">
                        <div className="flex items-center gap-2.5">
                          <div className="w-8 h-8 rounded-lg bg-emerald-950/40 border border-emerald-500/25 flex items-center justify-center text-emerald-400">
                            <CheckCircle2 className="w-4 h-4" />
                          </div>
                          <div>
                            <span className="text-xs font-semibold text-white block font-mono">GMAIL INTEGRATION LINKED</span>
                            <span className="text-[10px] text-slate-500 font-mono">Live Session Status: Active</span>
                          </div>
                        </div>
                        <div className="flex gap-2">
                          <button
                            type="button"
                            disabled={gmailLoading}
                            onClick={() => fetchGmailEmails(gmailToken)}
                            className="bg-slate-900 hover:bg-slate-800 text-slate-300 font-bold font-mono text-[10px] py-2 px-4 rounded-lg border border-slate-800 transition-all flex items-center gap-1.5 cursor-pointer disabled:opacity-50"
                          >
                            <RefreshCw className={`w-3 h-3 ${gmailLoading ? 'animate-spin' : ''}`} />
                            <span>REFRESH</span>
                          </button>
                          <button
                            type="button"
                            onClick={() => {
                              setGmailToken(null);
                              setGmailMessages([]);
                            }}
                            className="bg-rose-950/30 hover:bg-rose-950/60 text-rose-300 font-bold font-mono text-[10px] py-2 px-4 rounded-lg border border-rose-500/20 transition-all cursor-pointer"
                          >
                            DISCONNECT
                          </button>
                        </div>
                      </div>

                      {/* Message list container */}
                      {gmailLoading ? (
                        <div className="py-12 text-center space-y-3">
                          <RefreshCw className="w-7 h-7 text-cyan-400 animate-spin mx-auto" />
                          <p className="text-xs text-slate-500 font-mono">Querying real-time inbox messages via Google Workspace API...</p>
                        </div>
                      ) : gmailMessages.length === 0 ? (
                        <div className="py-12 text-center bg-slate-950/30 border border-slate-900 rounded-2xl">
                          <Mail className="w-6 h-6 text-slate-600 mx-auto mb-2" />
                          <p className="text-xs text-slate-500 font-mono">Your primary inbox is empty, or no new messages were returned.</p>
                        </div>
                      ) : (
                        <div className="grid gap-3">
                          {gmailMessages.map((msg) => {
                            const isScanning = activeScanningId === msg.id;
                            return (
                              <div
                                key={msg.id}
                                className="bg-slate-950/40 hover:bg-slate-950 border border-slate-900 rounded-xl p-4 transition-all flex flex-col md:flex-row justify-between items-start md:items-center gap-4 hover:border-slate-800/80"
                              >
                                <div className="space-y-1.5 flex-1 min-w-0">
                                  <div className="flex flex-wrap items-center gap-x-2.5 gap-y-1 font-mono text-[10px]">
                                    <span className="text-cyan-400 font-bold truncate max-w-[200px]">
                                      {msg.from}
                                    </span>
                                    <span className="text-slate-600">|</span>
                                    <span className="text-slate-500">{msg.date}</span>
                                  </div>
                                  <h5 className="text-xs font-bold text-white truncate max-w-xl">
                                    {msg.subject || '(No Subject)'}
                                  </h5>
                                  <p className="text-[11px] text-slate-400 leading-normal line-clamp-2">
                                    {msg.snippet}
                                  </p>
                                </div>
                                <button
                                  type="button"
                                  disabled={activeScanningId !== null}
                                  onClick={() => handleScanGmailMessage(msg)}
                                  className="w-full md:w-auto bg-cyan-500/10 hover:bg-cyan-500 text-cyan-400 hover:text-slate-950 font-bold font-mono text-[10px] py-2 px-4 rounded-lg border border-cyan-500/25 transition-all flex items-center justify-center gap-1.5 cursor-pointer disabled:opacity-40 whitespace-nowrap"
                                >
                                  {isScanning ? (
                                    <>
                                      <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                                      <span>RUNNING NEURAL ASSESS...</span>
                                    </>
                                  ) : (
                                    <>
                                      <Bot className="w-3.5 h-3.5" />
                                      <span>AI THREAT SCAN</span>
                                    </>
                                  )}
                                </button>
                              </div>
                            );
                          })}
                        </div>
                      )}
                    </div>
                  )}
                </div>
              )}
            </div>
          )}

          {activeTab === 'link' && (
            <form onSubmit={handleLinkScanSubmit} className="space-y-4">
              <div className="flex flex-col sm:flex-row gap-3">
                <div className="relative flex-1">
                  <span className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none text-slate-500">
                    <Globe className="w-5 h-5" />
                  </span>
                  <input
                    type="url"
                    value={scanUrl}
                    onChange={(e) => setScanUrl(e.target.value)}
                    placeholder="Enter full URL to scan (e.g. https://paypal-login-verify.xyz)..."
                    className="w-full bg-slate-950 border border-slate-800 rounded-xl pl-10 pr-4 py-3 text-sm text-white placeholder-slate-600 focus:outline-none focus:border-cyan-500 transition-all font-mono"
                    disabled={loading}
                    required
                  />
                </div>
                <button
                  type="submit"
                  disabled={loading}
                  className="bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold text-xs py-3 px-6 rounded-xl border border-cyan-400/20 transition-all shadow-lg shadow-cyan-500/10 flex items-center justify-center gap-1.5 cursor-pointer disabled:opacity-55 shrink-0"
                >
                  {loading ? (
                    <>
                      <RefreshCw className="w-4 h-4 animate-spin" />
                      <span>Analyzing links...</span>
                    </>
                  ) : (
                    <>
                      <Search className="w-4 h-4" />
                      <span>Scan Link Reputation</span>
                    </>
                  )}
                </button>
              </div>
            </form>
          )}

          {activeTab === 'image' && (
            <form onSubmit={handleImageScanSubmit} className="space-y-4">
              <div
                onDragOver={handleDragOver}
                onDragLeave={handleDragLeave}
                onDrop={handleDrop}
                onClick={() => fileInputRef.current?.click()}
                className={`border-2 border-dashed rounded-xl p-6 text-center cursor-pointer transition-all ${
                  isDragging
                    ? 'border-cyan-400 bg-cyan-950/20'
                    : imagePreview
                    ? 'border-slate-700 bg-slate-950/20'
                    : 'border-slate-800 hover:border-cyan-500 bg-slate-950/10'
                }`}
              >
                <input
                  type="file"
                  ref={fileInputRef}
                  onChange={(e) => {
                    if (e.target.files && e.target.files[0]) {
                      handleFileChange(e.target.files[0]);
                    }
                  }}
                  accept="image/*"
                  className="hidden"
                  disabled={loading}
                />
                
                {imagePreview ? (
                  <div className="space-y-3">
                    <div className="w-24 h-24 mx-auto rounded-lg overflow-hidden border border-slate-800 relative group">
                      <img src={imagePreview} alt="Preview" className="w-full h-full object-cover animate-fade-in" />
                      <div className="absolute inset-0 bg-black/60 opacity-0 group-hover:opacity-100 flex items-center justify-center transition-all">
                        <span className="text-[10px] text-slate-400 font-mono">Change Image</span>
                      </div>
                    </div>
                    <div>
                      <span className="text-xs text-slate-300 font-mono block font-semibold truncate max-w-xs mx-auto">{imageFile?.name}</span>
                      <span className="text-[10px] text-slate-500 font-mono block">{( (imageFile?.size || 0) / 1024 ).toFixed(1)} KB • Click to replace</span>
                    </div>
                  </div>
                ) : (
                  <div className="space-y-2 py-2">
                    <UploadCloud className="w-8 h-8 text-slate-500 mx-auto animate-pulse" />
                    <div>
                      <span className="text-xs font-bold text-slate-300 block">Drag & drop visual asset here</span>
                      <span className="text-[10px] text-slate-500 font-mono block mt-1">Supports screenshots, invoice scans, or suspicious QR flyers (Click to Browse)</span>
                    </div>
                  </div>
                )}
              </div>

              {imagePreview && (
                <button
                  type="submit"
                  disabled={loading}
                  className="w-full bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold text-xs py-3 px-6 rounded-xl border border-cyan-400/20 transition-all shadow-lg shadow-cyan-500/10 flex items-center justify-center gap-1.5 cursor-pointer disabled:opacity-55"
                >
                  {loading ? (
                    <>
                      <RefreshCw className="w-4 h-4 animate-spin" />
                      <span>Inspecting visual elements with CyberGuard Visual AI...</span>
                    </>
                  ) : (
                    <>
                      <Eye className="w-4 h-4" />
                      <span>Launch Visual Threat Inspection</span>
                    </>
                  )}
                </button>
              )}
            </form>
          )}

          {/* 4. GOOGLE SEARCH GROUNDING TAB */}
          {activeTab === 'grounding' && (
            <div className="space-y-4 animate-fade-in">
              <form onSubmit={handleGroundingSubmit} className="space-y-3">
                <div className="flex flex-col sm:flex-row gap-3">
                  <div className="relative flex-1">
                    <span className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none text-slate-500">
                      <Globe className="w-5 h-5 text-cyan-400" />
                    </span>
                    <input
                      type="text"
                      value={groundingQuery}
                      onChange={(e) => setGroundingQuery(e.target.value)}
                      placeholder="Ask any cybersecurity query grounded in live Google Search results..."
                      className="w-full bg-slate-950 border border-slate-800 rounded-xl pl-10 pr-4 py-3 text-sm text-white placeholder-slate-600 focus:outline-none focus:border-cyan-500 transition-all font-sans"
                      disabled={groundingLoading}
                      required
                    />
                  </div>
                  <button
                    type="submit"
                    disabled={groundingLoading}
                    className="bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold text-xs py-3 px-6 rounded-xl border border-cyan-400/20 transition-all shadow-lg shadow-cyan-500/10 flex items-center justify-center gap-1.5 cursor-pointer disabled:opacity-55 shrink-0"
                  >
                    {groundingLoading ? (
                      <>
                        <RefreshCw className="w-4 h-4 animate-spin" />
                        <span>Querying Web Intelligence...</span>
                      </>
                    ) : (
                      <>
                        <Search className="w-4 h-4" />
                        <span>Search Web Intel</span>
                      </>
                    )}
                  </button>
                </div>
              </form>

              {groundingResult && (
                <div className="bg-slate-950/60 border border-slate-800/80 rounded-xl p-5 space-y-4 animate-fade-in">
                  <div className="flex items-center justify-between border-b border-slate-800 pb-2.5">
                    <h3 className="text-xs font-bold uppercase tracking-wider text-cyan-400 font-mono">Grounded Intel Report</h3>
                    <span className="text-[10px] text-slate-500 font-mono">Powered by CyberGuard Native Search Engine</span>
                  </div>
                  <div className="text-sm text-slate-300 leading-relaxed font-sans whitespace-pre-wrap">
                    {groundingResult.text}
                  </div>
                  {groundingResult.sources && groundingResult.sources.length > 0 && (
                    <div className="pt-3 border-t border-slate-800/60 space-y-2">
                      <span className="text-[10px] font-mono font-bold text-slate-500 uppercase tracking-wider">Verified Web Citations:</span>
                      <div className="flex flex-wrap gap-2">
                        {groundingResult.sources.map((src, idx) => (
                          <a
                            key={`${idx}-${src.url}`}
                            href={src.url}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="bg-slate-900 hover:bg-slate-800 border border-slate-800 text-xs text-cyan-400 hover:text-cyan-300 px-3 py-1.5 rounded-lg flex items-center gap-1 transition-all"
                          >
                            <span>🔗 {src.title || "Web Source"}</span>
                          </a>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              )}
            </div>
          )}

          {/* 5. TIED AI INTELLIGENCE TAB */}
          {activeTab === 'intelligence' && (
            <div className="space-y-4 animate-fade-in">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2.5 bg-slate-950/40 p-3 rounded-xl border border-slate-800/60">
                <span className="text-xs font-mono font-bold text-slate-400">Select Intelligence Tier:</span>
                <div className="flex gap-1.5">
                  {(['fast', 'general', 'complex'] as const).map((tier) => (
                    <button
                      key={tier}
                      type="button"
                      onClick={() => setIntelTaskType(tier)}
                      className={`text-[10px] font-mono font-bold px-3 py-1.5 rounded-lg border transition-all cursor-pointer uppercase ${
                        intelTaskType === tier
                          ? 'bg-amber-500/10 border-amber-500/30 text-amber-400'
                          : 'bg-slate-950/80 border-slate-800 text-slate-500 hover:text-slate-300'
                      }`}
                    >
                      {tier === 'complex' && 'Pro Analyst (Complex)'}
                      {tier === 'general' && 'Standard (General)'}
                      {tier === 'fast' && 'Lite Operator (Fast)'}
                    </button>
                  ))}
                </div>
              </div>

              {/* Chat History scroll panel */}
              <div className="bg-slate-950/40 border border-slate-800/80 rounded-2xl p-4 h-[320px] overflow-y-auto space-y-4">
                {intelChatHistory.map((msg, idx) => (
                  <div
                    key={idx}
                    className={`flex flex-col max-w-[85%] ${
                      msg.sender === 'user' ? 'ml-auto items-end' : 'mr-auto items-start'
                    }`}
                  >
                    <div
                      className={`p-3.5 rounded-2xl text-xs leading-relaxed ${
                        msg.sender === 'user'
                          ? 'bg-cyan-950/20 border border-cyan-500/30 text-cyan-200 rounded-tr-none'
                          : 'bg-slate-900 border border-slate-800 text-slate-200 rounded-tl-none'
                      }`}
                    >
                      <div className="whitespace-pre-wrap font-sans">{msg.text}</div>
                    </div>
                    <span className="text-[8px] text-slate-600 font-mono mt-1">{msg.timestamp}</span>
                  </div>
                ))}
                {intelLoading && (
                  <div className="flex items-center gap-2 text-slate-500 text-xs font-mono animate-pulse">
                    <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                    <span>Gemini is compiling response...</span>
                  </div>
                )}
              </div>

              {/* Chat Input form */}
              <form onSubmit={handleIntelSubmit} className="flex gap-2.5">
                <input
                  type="text"
                  value={intelMessage}
                  onChange={(e) => setIntelMessage(e.target.value)}
                  placeholder={`Send a query for the ${intelTaskType.toUpperCase()} analyzer...`}
                  className="flex-1 bg-slate-950 border border-slate-800 rounded-xl px-4 py-3 text-xs text-white placeholder-slate-600 focus:outline-none focus:border-amber-500 transition-all font-sans"
                  disabled={intelLoading}
                />
                <button
                  type="submit"
                  disabled={intelLoading || !intelMessage.trim()}
                  className="bg-amber-500 hover:bg-amber-400 text-slate-950 font-bold text-xs px-5 rounded-xl border border-amber-400/20 transition-all shadow-lg shadow-amber-500/10 flex items-center justify-center gap-1.5 cursor-pointer disabled:opacity-55 shrink-0"
                >
                  <span>Query AI</span>
                </button>
              </form>
            </div>
          )}

          {/* Test cases assistance */}
          <div className="mt-4 pt-4 border-t border-slate-800/60 flex flex-col sm:flex-row sm:items-center justify-between gap-2 text-[11px] text-slate-500 font-mono">
            {activeTab === 'email' && (
              <span>💡 Tip: Test <span className="text-emerald-400 select-all font-semibold">secure@cyberguard.com</span> to experience a clean 0-breach status.</span>
            )}
            {activeTab === 'link' && (
              <span>💡 Tip: Try a mock URL like <span className="text-cyan-400 select-all font-semibold">http://paypal-security-update.xyz</span> to test AI-driven link diagnostics.</span>
            )}
            {activeTab === 'image' && (
              <span>💡 Tip: Select any image file to inspect fraud indicators, suspicious QR targets, or tech support scam layouts.</span>
            )}
            {activeTab === 'grounding' && (
              <span>💡 Tip: Search <span className="text-cyan-400 font-semibold select-all">latest active ransomware threats 2026</span> to fetch real-time grounded results.</span>
            )}
            {activeTab === 'intelligence' && (
              <span>💡 Tip: Choose <span className="text-amber-400 font-semibold">Pro Analyst</span> to draft customized security policies or scan smart contract files.</span>
            )}
            {activeTab === 'voice' && (
              <span>💡 Tip: Type your security query and hear CyberGuard's vocal synthesized live feed responses out loud.</span>
            )}
          </div>
        </div>

        {/* Security Metrics row */}
        <div className="grid grid-cols-3 gap-4 text-center">
          <div className="bento-card p-3 flex flex-col justify-center">
            <span className="text-[9px] uppercase font-mono tracking-wider text-slate-500 block">Audits Executed</span>
            <span className="text-lg font-bold font-mono text-white mt-1 block">{totalAudits}</span>
          </div>
          <div className="bento-card p-3 flex flex-col justify-center">
            <span className="text-[9px] uppercase font-mono tracking-wider text-slate-500 block">Critical Leaks</span>
            <span className="text-lg font-bold font-mono text-rose-400 mt-1 block">{criticalExposures}</span>
          </div>
          <div className="bento-card p-3 flex flex-col justify-center">
            <span className="text-[9px] uppercase font-mono tracking-wider text-slate-500 block">Clean Endpoints</span>
            <span className="text-lg font-bold font-mono text-emerald-400 mt-1 block">{secureScans}</span>
          </div>
        </div>

        {/* Usage Audit Trail (Displays complete details, module used, dates, threat levels, and secure data masking) */}
        <UsageAudit scans={scans} onSelectReport={onSelectReport} />

        {/* Interactive Kali Terminal Toggle */}
        <div className="space-y-3">
          <button
            onClick={() => setShowTerminal(!showTerminal)}
            className="w-full bento-card px-4 py-3 rounded-xl flex items-center justify-between text-slate-300 text-xs font-mono transition-all cursor-pointer hover:border-cyan-500"
          >
            <div className="flex items-center gap-2">
              <TerminalIcon className="w-4 h-4 text-emerald-500" />
              <span>{showTerminal ? 'CLOSE KALI LINUX TERMINAL SHELL' : 'LAUNCH SIMULATED KALI LINUX SECURITY SHELL'}</span>
            </div>
            <span className="text-[10px] uppercase font-bold text-cyan-400">Ctrl + ~</span>
          </button>
          
          {showTerminal && <Terminal />}
        </div>

      </div>

      {/* RIGHT PANEL (Payment & Coming Soon transparency) */}
      <div className="space-y-6">
        
        {/* User Account / Admin Panel Launcher */}
        <div className="bento-card p-4 flex items-center justify-between">
          <div className="flex items-center gap-2.5">
            <div className="w-8 h-8 rounded-full bg-slate-800 border border-slate-700 flex items-center justify-center font-bold text-white text-xs">
              {user.email.charAt(0).toUpperCase()}
            </div>
            <div>
              <span className="text-xs font-bold text-white block truncate max-w-[130px]">{user.email}</span>
              <span className="text-[9px] font-mono uppercase text-emerald-400 block tracking-wider font-semibold">Status: Active</span>
            </div>
          </div>
          
          <div className="flex items-center gap-1.5">
            {user.role === 'admin' && (
              <button
                onClick={onNavigateAdmin}
                className="bg-cyan-950/50 hover:bg-cyan-900/50 text-cyan-400 border border-cyan-500/20 px-2.5 py-1 rounded-lg text-[10px] font-bold font-mono cursor-pointer"
              >
                ADMIN CONSOLE
              </button>
            )}
            <button
              onClick={onLogout}
              className="text-slate-500 hover:text-rose-400 transition-colors p-1.5"
              title="Logout session"
            >
              <LogOut className="w-4 h-4" />
            </button>
          </div>
        </div>

        {/* Threat Intelligence Side Panel */}
        <ThreatIntelligence token={token} />

        {/* Razorpay Payments Container moved to bottom */}

        {/* Aspirational Coming Soon Suite (Option A - Honest Transparency) */}
        <div className="bento-card p-5 space-y-4">
          <div className="border-b border-slate-800 pb-2.5">
            <h3 className="font-bold text-xs text-white uppercase tracking-wider font-mono">🎯 CyberGuard Roadmap (Coming Soon)</h3>
            <p className="text-[10px] text-slate-500 mt-0.5">Honest roadmap tracking of advanced features currently in development.</p>
          </div>

          <div className="space-y-3.5">
            {/* Dark Web Monitoring */}
            <div className="flex items-start gap-2.5">
              <div className="w-6 h-6 bg-slate-950 rounded border border-slate-800 flex items-center justify-center text-slate-600 shrink-0 mt-0.5">
                <Cpu className="w-3.5 h-3.5" />
              </div>
              <div className="flex-1 min-w-0">
                <div className="flex items-center justify-between gap-1.5">
                  <h4 className="text-xs font-bold text-slate-300 truncate">24/7 Dark Web Monitor</h4>
                  <span className="shrink-0 status-tag status-soon">Roadmap</span>
                </div>
                <p className="text-[10px] text-slate-500 mt-0.5 leading-relaxed">
                  Automatic background crawlers tracking hacker forums and paste sites for credential dumps.
                </p>
              </div>
            </div>

            {/* Real-time Alerts */}
            <div className="flex items-start gap-2.5">
              <div className="w-6 h-6 bg-slate-950 rounded border border-slate-800 flex items-center justify-center text-slate-600 shrink-0 mt-0.5">
                <Bell className="w-3.5 h-3.5" />
              </div>
              <div className="flex-1 min-w-0">
                <div className="flex items-center justify-between gap-1.5">
                  <h4 className="text-xs font-bold text-slate-300 truncate">Real-time Push Alerts</h4>
                  <span className="shrink-0 status-tag status-soon">Roadmap</span>
                </div>
                <p className="text-[10px] text-slate-500 mt-0.5 leading-relaxed">
                  Push notifications and SMS texts immediately when your scanned address is leaked.
                </p>
              </div>
            </div>

            {/* Developer API */}
            <div className="flex items-start gap-2.5">
              <div className="w-6 h-6 bg-slate-950 rounded border border-slate-800 flex items-center justify-center text-slate-600 shrink-0 mt-0.5">
                <Lock className="w-3.5 h-3.5" />
              </div>
              <div className="flex-1 min-w-0">
                <div className="flex items-center justify-between gap-1.5">
                  <h4 className="text-xs font-bold text-slate-300 truncate">Developer API Keys</h4>
                  <span className="shrink-0 status-tag status-soon">Roadmap</span>
                </div>
                <p className="text-[10px] text-slate-500 mt-0.5 leading-relaxed">
                  Generate secure authorization bearer keys to query our breach endpoint from custom scripts.
                </p>
              </div>
            </div>

            {/* Password Hash analysis */}
            <div className="flex items-start gap-2.5">
              <div className="w-6 h-6 bg-slate-950 rounded border border-slate-800 flex items-center justify-center text-slate-600 shrink-0 mt-0.5">
                <Shield className="w-3.5 h-3.5" />
              </div>
              <div className="flex-1 min-w-0">
                <div className="flex items-center justify-between gap-1.5">
                  <h4 className="text-xs font-bold text-slate-300 truncate">Entropy Hash Analyzer</h4>
                  <span className="shrink-0 status-tag status-soon">Roadmap</span>
                </div>
                <p className="text-[10px] text-slate-500 mt-0.5 leading-relaxed">
                  Evaluate decryption feasibility, hashing salts, and entropy indices for passwords in leaked databases.
                </p>
              </div>
            </div>

            {/* Family Protection */}
            <div className="flex items-start gap-2.5">
              <div className="w-6 h-6 bg-slate-950 rounded border border-slate-800 flex items-center justify-center text-slate-600 shrink-0 mt-0.5">
                <Users className="w-3.5 h-3.5" />
              </div>
              <div className="flex-1 min-w-0">
                <div className="flex items-center justify-between gap-1.5">
                  <h4 className="text-xs font-bold text-slate-300 truncate">Family Protection (3/10)</h4>
                  <span className="shrink-0 status-tag status-soon">Roadmap</span>
                </div>
                <p className="text-[10px] text-slate-500 mt-0.5 leading-relaxed">
                  Register up to 10 email addresses under one family Pro plan to share scan metrics.
                </p>
              </div>
            </div>
          </div>
        </div>

        {/* Trust, Privacy & Compliance Center */}
        <div className="bento-card p-5 space-y-4">
          <div className="border-b border-slate-800 pb-2.5">
            <div className="flex items-center gap-1.5 text-cyan-400 font-mono text-[10px] font-bold">
              <ShieldCheck className="w-4 h-4 text-cyan-400" />
              <span>SECURITY CERTIFICATION CORES</span>
            </div>
            <h3 className="font-bold text-sm text-white font-display mt-1">Trust & Compliance Center</h3>
            <p className="text-[10px] text-slate-500 mt-0.5">Verified details on privacy, database sourcing, SOC2 roadmap, and security controls.</p>
          </div>

          {/* Tab Selector */}
          <div className="grid grid-cols-5 gap-1 border-b border-slate-900 pb-2 text-[9px] font-mono font-bold text-center">
            <button
              type="button"
              onClick={() => setComplianceTab('gmail')}
              className={`pb-1 transition-all border-b cursor-pointer ${complianceTab === 'gmail' ? 'border-cyan-500 text-cyan-400' : 'border-transparent text-slate-500 hover:text-slate-300'}`}
            >
              GMAIL
            </button>
            <button
              type="button"
              onClick={() => setComplianceTab('sourcing')}
              className={`pb-1 transition-all border-b cursor-pointer ${complianceTab === 'sourcing' ? 'border-cyan-500 text-cyan-400' : 'border-transparent text-slate-500 hover:text-slate-300'}`}
            >
              SOURCES
            </button>
            <button
              type="button"
              onClick={() => setComplianceTab('soc2')}
              className={`pb-1 transition-all border-b cursor-pointer ${complianceTab === 'soc2' ? 'border-cyan-500 text-cyan-400' : 'border-transparent text-slate-500 hover:text-slate-300'}`}
            >
              COMPLY
            </button>
            <button
              type="button"
              onClick={() => setComplianceTab('bounty')}
              className={`pb-1 transition-all border-b cursor-pointer ${complianceTab === 'bounty' ? 'border-cyan-500 text-cyan-400' : 'border-transparent text-slate-500 hover:text-slate-300'}`}
            >
              BOUNTY
            </button>
            <button
              type="button"
              onClick={() => setComplianceTab('erasure')}
              className={`pb-1 transition-all border-b cursor-pointer ${complianceTab === 'erasure' ? 'border-cyan-500 text-cyan-400' : 'border-transparent text-slate-500 hover:text-slate-300'}`}
            >
              ERASE
            </button>
          </div>

          {/* Tab Contents */}
          <div className="text-[11px] leading-relaxed text-slate-400 min-h-[140px] flex flex-col justify-between">
            {complianceTab === 'gmail' && (
              <div className="space-y-2">
                <span className="font-semibold text-white font-mono text-[10px] uppercase block text-cyan-400">✉️ Gmail Transient Audit Guidelines</span>
                <p>
                  To secure your confidence, our real-time Gmail inbox vulnerability auditing operates on a **strict zero-retention policy**:
                </p>
                <ul className="list-disc pl-4 space-y-1 text-slate-500 text-[10px]">
                  <li>We **never** store email bodies, attachments, or sender logs on our servers or databases.</li>
                  <li>Gemini API analysis is performed **transiently in-memory** and results are cleared immediately upon session close.</li>
                  <li>No customer data or processed email texts are logged or used for LLM training under Google's enterprise terms.</li>
                </ul>
              </div>
            )}

            {complianceTab === 'sourcing' && (
              <div className="space-y-2">
                <span className="font-semibold text-white font-mono text-[10px] uppercase block text-cyan-400">📂 Certified Legal Sourcing</span>
                <p>
                  Our search and leak-matching query database leverages **simulated, audited static archives** matching schemas of high-profile data breaches:
                </p>
                <ul className="list-disc pl-4 space-y-1 text-slate-500 text-[10px]">
                  <li>Matching sets are calibrated with historical reference files representing public academic datasets (similar to HIBP datasets).</li>
                  <li>We do **not** scrape active dark forums or store plain-text passwords or sensitive identifiers.</li>
                  <li>Database audits are indexed with cryptographic SHA-256 signatures to protect user identities.</li>
                </ul>
              </div>
            )}

            {complianceTab === 'soc2' && (
              <div className="space-y-2">
                <span className="font-semibold text-white font-mono text-[10px] uppercase block text-cyan-400">🛡️ Compliance Certification Roadmap</span>
                <p>
                  We are actively building controls toward official regulatory framework compliance, tracked below:
                </p>
                <div className="space-y-1.5 pt-1">
                  <div className="flex justify-between items-center text-[10px]">
                    <span className="text-slate-300 font-mono">SOC 2 Type II Certification</span>
                    <span className="text-amber-400 bg-amber-500/10 px-1 rounded font-bold text-[8px] uppercase font-mono">In Progress Q4</span>
                  </div>
                  <div className="flex justify-between items-center text-[10px]">
                    <span className="text-slate-300 font-mono">GDPR Right to Erasure (Art. 17)</span>
                    <span className="text-emerald-400 bg-emerald-500/10 px-1 rounded font-bold text-[8px] uppercase font-mono">Fully Compliant</span>
                  </div>
                  <div className="flex justify-between items-center text-[10px]">
                    <span className="text-slate-300 font-mono">256-Bit TLS In-Transit Encryption</span>
                    <span className="text-emerald-400 bg-emerald-500/10 px-1 rounded font-bold text-[8px] uppercase font-mono">ACTIVE</span>
                  </div>
                </div>
              </div>
            )}

            {complianceTab === 'bounty' && (
              <div className="space-y-2">
                <span className="font-semibold text-white font-mono text-[10px] uppercase block text-cyan-400">🐛 Responsible Disclosure Bug Bounty</span>
                <p>
                  CyberGuard maintains a supportive responsible disclosure program for security researchers:
                </p>
                <p className="text-slate-500 text-[10px]">
                  If you discover a potential vulnerability or access bypass, please submit details to <strong className="text-cyan-400 select-all font-mono">hemantkaushal72@gmail.com</strong>.
                </p>
                <p className="text-slate-500 text-[10px]">
                  We commit to validating reports within **48 hours** and offering rewards for verified high-severity disclosures.
                </p>
              </div>
            )}

            {complianceTab === 'erasure' && (
              <div className="space-y-2">
                <span className="font-semibold text-white font-mono text-[10px] uppercase block text-cyan-400">🗑️ User Data Erasure & Transparency</span>
                <p>
                  Under GDPR Article 17, you have the full right to remove your information. Click below to instantly purge your entire threat history logs.
                </p>
                
                {clearScansSuccess ? (
                  <div className="p-2.5 bg-emerald-950/40 border border-emerald-500/20 text-emerald-400 text-[10px] rounded-xl flex items-center gap-1.5 font-bold font-mono">
                    <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                    <span>All scan histories have been purged.</span>
                  </div>
                ) : confirmWipe ? (
                  <div className="space-y-2 bg-rose-950/20 border border-rose-500/25 p-2 rounded-xl">
                    <span className="text-[9px] text-rose-300 font-bold block uppercase tracking-wider text-center">🚨 PERMANENT ERASURE?</span>
                    <div className="flex gap-2">
                      <button
                        type="button"
                        disabled={isClearingScans}
                        onClick={handleWipeScans}
                        className="flex-1 bg-rose-600 hover:bg-rose-500 text-white font-bold text-[10px] py-1 px-2 rounded cursor-pointer disabled:opacity-50"
                      >
                        {isClearingScans ? "Purging..." : "Yes, Purge"}
                      </button>
                      <button
                        type="button"
                        onClick={() => setConfirmWipe(false)}
                        className="bg-slate-900 border border-slate-800 text-slate-300 font-bold text-[10px] py-1 px-2 rounded cursor-pointer"
                      >
                        Cancel
                      </button>
                    </div>
                  </div>
                ) : (
                  <button
                    type="button"
                    onClick={() => setConfirmWipe(true)}
                    className="w-full bg-rose-500/10 hover:bg-rose-500/20 border border-rose-500/25 text-rose-400 font-bold font-mono text-xs py-2 rounded-xl transition-all flex items-center justify-center gap-1.5 cursor-pointer"
                  >
                    <Trash2 className="w-3.5 h-3.5" />
                    <span>Erase All Threat Scan Logs</span>
                  </button>
                )}
              </div>
            )}
          </div>
        </div>

      </div>

    </div>

    {/* Brand Footer with Privacy Statement Option */}
    <footer className="mt-8 pt-6 border-t border-slate-900/80 flex flex-col sm:flex-row items-center justify-between gap-4 text-[10px] text-slate-500 font-mono">
      <span>© 2026 CYBERGUARD SECURITY LABS. ALL RIGHTS RESERVED.</span>
      <div className="flex items-center gap-4">
        <button
          type="button"
          onClick={() => setShowPrivacyModal(true)}
          className="text-cyan-500 hover:text-cyan-400 hover:underline transition-all cursor-pointer font-bold bg-transparent border-none outline-none"
        >
          PRIVACY STATEMENT & DATA RIGHTS
        </button>
        <span>•</span>
        <span>v4.0.12</span>
      </div>
    </footer>

    {/* Privacy & Data Rights Modal Overlay */}
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
