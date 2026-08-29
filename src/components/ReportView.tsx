import React from 'react';
import { Shield, Download, Printer, AlertTriangle, CheckSquare, ShieldCheck, ChevronLeft, FileText, Code } from 'lucide-react';
import { jsPDF } from 'jspdf';
import { ScanResult } from '../types';

interface ReportViewProps {
  scan: ScanResult;
  onBack: () => void;
}

export default function ReportView({ scan, onBack }: ReportViewProps) {
  const getRiskLevel = (score: number) => {
    if (score >= 70) return { label: 'CRITICAL HAZARD', color: 'status-chip-critical' };
    if (score >= 40) return { label: 'MEDIUM RISK', color: 'status-chip-high' };
    return { label: 'LOW / VERIFIED', color: 'status-chip-low' };
  };

  const risk = getRiskLevel(scan.riskScore);

  const handlePrint = () => {
    window.print();
  };

  const handleDownloadPdf = () => {
    const doc = new jsPDF({
      orientation: 'portrait',
      unit: 'mm',
      format: 'a4',
    });

    const primaryColor = [0, 229, 255]; // cyan
    const darkSlate = [9, 13, 20];      // dark charcoal
    const lightGray = [240, 243, 246];  // light gray
    
    // Header Background Accent bar
    doc.setFillColor(darkSlate[0], darkSlate[1], darkSlate[2]);
    doc.rect(0, 0, 210, 40, 'F');

    // Header Title
    doc.setTextColor(255, 255, 255);
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(18);
    doc.text('CYBERGUARD FORENSIC BRIEFING', 15, 18);

    doc.setFont('helvetica', 'normal');
    doc.setFontSize(10);
    doc.setTextColor(0, 200, 255);
    doc.text('REAL-TIME THREAT EXPOSURE & DIAGNOSTICS REPORT', 15, 25);

    doc.setFontSize(9);
    doc.setTextColor(150, 150, 150);
    doc.text(`Report ID: SEC-${scan.id.substring(0, 12).toUpperCase()}   |   Compiled: ${new Date(scan.timestamp).toLocaleString()}`, 15, 32);

    let y = 50;

    // Target Details Box
    doc.setFillColor(lightGray[0], lightGray[1], lightGray[2]);
    doc.roundedRect(15, y, 180, 22, 2, 2, 'F');
    
    doc.setFontSize(9);
    doc.setFont('helvetica', 'bold');
    doc.setTextColor(darkSlate[0], darkSlate[1], darkSlate[2]);
    const targetLabel = scan.scanType === 'link' ? 'TARGET LINK URL' : scan.scanType === 'image' ? 'TARGET SCREENSHOT FILE' : 'TARGET ENDPOINT EMAIL';
    const targetVal = scan.scanType === 'link' ? scan.targetLink : scan.scanType === 'image' ? scan.imageFileName : scan.targetEmail;
    doc.text(targetLabel, 20, y + 8);
    
    doc.setFont('helvetica', 'normal');
    doc.setFontSize(10);
    doc.setTextColor(0, 150, 200);
    
    const targetValClipped = targetVal && targetVal.length > 70 ? targetVal.substring(0, 70) + '...' : targetVal || '';
    doc.text(targetValClipped, 20, y + 15);

    y += 30;

    // Threat Score & Level
    doc.setFillColor(245, 247, 250);
    doc.roundedRect(15, y, 180, 20, 2, 2, 'F');
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(10);
    doc.setTextColor(darkSlate[0], darkSlate[1], darkSlate[2]);
    doc.text('THREAT EXPOSURE SCORE:', 20, y + 12);
    
    doc.setFontSize(14);
    const scoreText = `${scan.riskScore} / 100`;
    doc.setTextColor(scan.riskScore >= 70 ? 220 : scan.riskScore >= 40 ? 217 : 16, scan.riskScore >= 70 ? 38 : scan.riskScore >= 40 ? 119 : 185, scan.riskScore >= 70 ? 38 : scan.riskScore >= 40 ? 6 : 129);
    doc.text(scoreText, 80, y + 13);

    doc.setFontSize(10);
    doc.setFont('helvetica', 'bold');
    doc.text(`[ ${risk.label} ]`, 125, y + 12);

    y += 28;

    doc.setFont('helvetica', 'bold');
    doc.setFontSize(12);
    doc.setTextColor(darkSlate[0], darkSlate[1], darkSlate[2]);
    doc.text('RECOMMENDED SECURITY COUNTERMEASURES', 15, y);
    y += 6;

    doc.setFont('helvetica', 'normal');
    doc.setFontSize(9.5);
    doc.setTextColor(60, 60, 60);

    const items = scan.scanType === 'link' ? [
      'Do Not Authorize Session: Never enter MFA codes or master keys on this domain.',
      'Inspect Host Domain: Manually confirm identical lettering in your browser bar.',
      'Deploy Private Sandbox: Use insulated proxy nodes if accessing unknown TLD portals.'
    ] : scan.scanType === 'image' ? [
      'Independent QR Scanning: Avoid reading QR triggers embedded inside unknown captures.',
      'Confirm Sender Authenticity: Verify urgent payments directly with billing vendors.',
      'Ignore Fake Graphic Prompts: Disregard prompts mimicking OS system crash warnings.'
    ] : [
      'Enforce Unique Passwords: Use non-overlapping passwords managed inside safe vaults.',
      'Setup Hardware MFA: Deploy physical or app authenticators on sensitive emails.',
      'Isolate Secondary Sign-ups: Route transient platform registers to separate mock email addresses.'
    ];

    items.forEach((item, idx) => {
      doc.text(`${idx + 1}. ${item}`, 15, y);
      y += 6;
    });

    doc.setFontSize(8);
    doc.setTextColor(120, 120, 120);
    doc.text('This security threat assessment was generated securely by CyberGuard. Keep credentials private.', 15, 287);

    doc.save(`CyberGuard_Security_Briefing_${scan.id.substring(0, 8).toUpperCase()}.pdf`);
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
      <div className="font-mono text-xs flex flex-wrap items-center gap-3 bg-[#090D14] p-3 border border-[#263147] rounded-sm">
        <span className={colorClass}>[{filledStr}{emptyStr}]</span>
        <span className={`font-bold uppercase tracking-wider ${colorClass}`}>
          SCORE: {score}/100 • {label}
        </span>
      </div>
    );
  };

  return (
    <div className="space-y-4 text-[#ECEFF4] font-sans print:bg-white print:text-black">
      
      {/* ACTION TOOLBAR */}
      <div className="flex flex-col sm:flex-row justify-between sm:items-center gap-3 print:hidden">
        <button
          onClick={onBack}
          className="btn-soc px-3 py-1.5 flex items-center gap-1 text-xs"
        >
          <ChevronLeft className="w-4 h-4 text-[#00E5FF]" />
          <span>RETURN TO WORKSTATION</span>
        </button>
        <div className="flex items-center gap-2">
          <button
            onClick={handleDownloadPdf}
            className="btn-soc btn-soc-primary px-3.5 py-1.5 text-xs flex items-center gap-1.5 cursor-pointer"
          >
            <Download className="w-3.5 h-3.5" />
            <span>DOWNLOAD PDF BRIEFING</span>
          </button>
          <button
            onClick={handlePrint}
            className="btn-soc px-3.5 py-1.5 text-xs flex items-center gap-1.5 cursor-pointer"
          >
            <Printer className="w-3.5 h-3.5" />
            <span>EXPORT / PRINT</span>
          </button>
        </div>
      </div>

      {/* MAIN REPORT CONTAINER */}
      <div id="cyberguard-printable-report" className="soc-panel p-6 sm:p-8 space-y-6 print:border-none print:shadow-none print:p-0">
        
        {/* Header Section */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-[#263147] pb-4 print:border-black">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 bg-[#181F2E] border border-[#263147] rounded-sm flex items-center justify-center text-[#00E5FF] shrink-0">
              <Shield className="w-5 h-5" />
            </div>
            <div>
              <h2 className="text-base font-bold font-display uppercase tracking-wider text-white print:text-black">
                {scan.scanType === 'link' 
                  ? 'CyberGuard Link Reputation Briefing' 
                  : scan.scanType === 'image' 
                  ? 'CyberGuard Visual Artifact Briefing' 
                  : 'CyberGuard Email Breach Briefing'}
              </h2>
              <p className="text-xs font-mono text-[#7E8B9B]">
                ID: SEC-{scan.id.substring(0, 10).toUpperCase()} | COMPILED: {new Date(scan.timestamp).toLocaleString()}
              </p>
            </div>
          </div>
          <div className="text-left sm:text-right font-mono text-xs">
            <span className="text-[10px] uppercase text-[#7E8B9B] block font-bold">
              {scan.scanType === 'link' ? 'TARGET LINK URL' : scan.scanType === 'image' ? 'TARGET SCREENSHOT FILE' : 'TARGET ENDPOINT EMAIL'}
            </span>
            <span className="text-[#00E5FF] font-bold break-all">
              {scan.scanType === 'link' ? scan.targetLink : scan.scanType === 'image' ? scan.imageFileName : scan.targetEmail}
            </span>
          </div>
        </div>

        {/* Hazard Risk Meter & AI Executive Summary */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <div className="soc-panel p-4 flex flex-col justify-between space-y-3 font-mono">
            <span className="text-[10px] uppercase text-[#7E8B9B] font-bold block">
              Threat Exposure Rating
            </span>
            {renderBitDensityMeter(scan.riskScore)}
            <div className="pt-2 border-t border-[#263147] text-[10px] text-[#7E8B9B]">
              Calculated via CyberGuard Rule-Based Forensic Engine
            </div>
          </div>

          <div className="soc-panel p-4 md:col-span-2 space-y-2">
            <div className="flex items-center gap-1.5 text-xs font-bold text-[#00E5FF] font-mono uppercase">
              <ShieldCheck className="w-4 h-4 text-[#00E5FF]" />
              <span>Executive Forensic Summary</span>
            </div>
            <div className="text-xs text-[#ECEFF4] leading-relaxed font-mono whitespace-pre-wrap">
              {scan.forensicSummary || scan.aiSummary || 'Forensic analysis completed.'}
            </div>
          </div>
        </div>

        {/* Breach Leak Instances or URL Threat Flags */}
        <div className="space-y-3">
          <div className="flex items-center gap-2 text-xs font-bold text-[#7E8B9B] font-mono uppercase">
            <AlertTriangle className="w-4 h-4 text-[#FF9900]" />
            <span>
              {scan.scanType === 'link' 
                ? `Malicious URL Indicators (${scan.detectedThreats?.length || 0})` 
                : scan.scanType === 'image' 
                ? `Visual Threat Flags (${scan.detectedThreats?.length || 0})` 
                : `Exposed Database Leaks (${scan.resultCount})`}
            </span>
          </div>

          {scan.scanType === 'email' && scan.breaches.length > 0 && (
            <div className="space-y-3 font-mono">
              {scan.breaches.map((b) => (
                <div key={b.id} className="border border-[#263147] bg-[#090D14] p-4 rounded-sm space-y-2 text-xs">
                  <div className="flex items-center justify-between">
                    <strong className="text-white text-sm">{b.Title} ({b.Domain})</strong>
                    <span className={`status-chip ${b.severity === 'critical' ? 'status-chip-critical' : 'status-chip-high'}`}>
                      {b.severity}
                    </span>
                  </div>
                  <p className="text-[11px] text-[#7E8B9B] leading-relaxed">{b.Description}</p>
                  <div className="flex flex-wrap gap-1 pt-1">
                    {b.DataClasses.map((item, idx) => (
                      <span key={idx} className="bg-[#181F2E] border border-[#263147] text-[#00E5FF] text-[10px] px-2 py-0.5">
                        {item}
                      </span>
                    ))}
                  </div>
                </div>
              ))}
            </div>
          )}

          {scan.scanType !== 'email' && scan.detectedThreats && scan.detectedThreats.length > 0 && (
            <div className="space-y-2 font-mono text-xs">
              {scan.detectedThreats.map((threat, idx) => (
                <div key={idx} className="border border-[#263147] bg-[#090D14] p-3 rounded-sm flex items-center gap-2">
                  <div className="w-1.5 h-1.5 bg-[#00E5FF] shrink-0"></div>
                  <span className="text-[#ECEFF4]">{threat}</span>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Countermeasures Section */}
        <div className="soc-panel p-4 space-y-3 font-mono text-xs">
          <div className="flex items-center gap-2 text-xs font-bold text-[#00E5FF] uppercase border-b border-[#263147] pb-2">
            <CheckSquare className="w-4 h-4 text-[#00E5FF]" />
            <span>Actionable Security Countermeasures</span>
          </div>

          <ul className="space-y-2 text-[11px] text-[#ECEFF4]">
            {scan.scanType === 'link' ? (
              <>
                <li className="flex items-start gap-2">
                  <span className="text-[#00E5FF] font-bold">1.</span>
                  <span><strong>Do Not Authorize Session:</strong> Never type master passwords or MFA passcodes on suspicious domains.</span>
                </li>
                <li className="flex items-start gap-2">
                  <span className="text-[#00E5FF] font-bold">2.</span>
                  <span><strong>Inspect Host Domain:</strong> Manually confirm character spelling in browser address bar.</span>
                </li>
                <li className="flex items-start gap-2">
                  <span className="text-[#00E5FF] font-bold">3.</span>
                  <span><strong>Deploy Private Sandbox:</strong> Test unknown links inside disposable browser containers.</span>
                </li>
              </>
            ) : scan.scanType === 'image' ? (
              <>
                <li className="flex items-start gap-2">
                  <span className="text-[#00E5FF] font-bold">1.</span>
                  <span><strong>Avoid Unknown QR Links:</strong> Do not scan embedded QR codes from unsolicited attachments.</span>
                </li>
                <li className="flex items-start gap-2">
                  <span className="text-[#00E5FF] font-bold">2.</span>
                  <span><strong>Verify Billing Invoices:</strong> Confirm emergency payment requests directly with vendor accounting.</span>
                </li>
              </>
            ) : (
              <>
                <li className="flex items-start gap-2">
                  <span className="text-[#00E5FF] font-bold">1.</span>
                  <span><strong>Enforce Password Vaults:</strong> Rotate compromised credentials using dedicated password managers.</span>
                </li>
                <li className="flex items-start gap-2">
                  <span className="text-[#00E5FF] font-bold">2.</span>
                  <span><strong>Hardware MFA Keys:</strong> Migrate from SMS OTP to hardware-based FIDO2 authenticators.</span>
                </li>
              </>
            )}
          </ul>
        </div>

      </div>

    </div>
  );
}
