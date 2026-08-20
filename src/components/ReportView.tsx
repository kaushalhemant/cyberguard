import React from 'react';
import { Shield, Download, Printer, AlertTriangle, CheckSquare, ShieldCheck, ChevronLeft } from 'lucide-react';
import { jsPDF } from 'jspdf';
import { ScanResult } from '../types';

interface ReportViewProps {
  scan: ScanResult;
  onBack: () => void;
}

export default function ReportView({ scan, onBack }: ReportViewProps) {
  const getRiskLevel = (score: number) => {
    if (score >= 70) return { label: 'CRITICAL HAZARD', color: 'text-rose-400 border-rose-500/20 bg-rose-500/5' };
    if (score >= 40) return { label: 'MEDIUM RISK', color: 'text-amber-400 border-amber-500/20 bg-amber-500/5' };
    return { label: 'LOW VULNERABILITY', color: 'text-emerald-400 border-emerald-500/20 bg-emerald-500/5' };
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

    const primaryColor = [6, 182, 212]; // cyan-500
    const darkSlate = [15, 23, 42];    // slate-900
    const lightGray = [248, 250, 252]; // slate-50
    const textGray = [100, 116, 139];  // slate-500

    // Header Background Accent bar
    doc.setFillColor(darkSlate[0], darkSlate[1], darkSlate[2]);
    doc.rect(0, 0, 210, 40, 'F');

    // Header Title
    doc.setTextColor(255, 255, 255);
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(20);
    doc.text('CYBERGUARD SECURITY BRIEFING', 15, 18);

    doc.setFont('helvetica', 'normal');
    doc.setFontSize(10);
    doc.setTextColor(primaryColor[0], primaryColor[1], primaryColor[2]);
    doc.text('REAL-TIME THREAT EXPOSURE PORTAL', 15, 25);

    doc.setFontSize(9);
    doc.setTextColor(150, 150, 150);
    doc.text(`Report ID: SEC-${scan.id.substring(0, 12).toUpperCase()}   |   Compiled: ${new Date(scan.timestamp).toLocaleString()}`, 15, 32);

    let y = 50;

    // Target Details Box
    doc.setFillColor(lightGray[0], lightGray[1], lightGray[2]);
    doc.roundedRect(15, y, 180, 22, 3, 3, 'F');
    
    doc.setFontSize(9);
    doc.setFont('helvetica', 'bold');
    doc.setTextColor(darkSlate[0], darkSlate[1], darkSlate[2]);
    const targetLabel = scan.scanType === 'link' ? 'TARGET LINK URL' : scan.scanType === 'image' ? 'TARGET SCREENSHOT FILE' : 'TARGET ENDPOINT EMAIL';
    const targetVal = scan.scanType === 'link' ? scan.targetLink : scan.scanType === 'image' ? scan.imageFileName : scan.targetEmail;
    doc.text(targetLabel, 20, y + 8);
    
    doc.setFont('helvetica', 'normal');
    doc.setFontSize(10);
    doc.setTextColor(primaryColor[0], primaryColor[1], primaryColor[2]);
    
    // Safely clip target val if too long
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

    // AI summary section
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(12);
    doc.setTextColor(darkSlate[0], darkSlate[1], darkSlate[2]);
    doc.text('CYBER FORENSIC AUDIT SUMMARY', 15, y);
    y += 5;

    doc.setFont('helvetica', 'normal');
    doc.setFontSize(10);
    doc.setTextColor(50, 50, 50);
    
    // Split text into line-wrapped array for standard page width
    const summaryLines = doc.splitTextToSize(scan.aiSummary || 'No AI Diagnostics summary compiled.', 180);
    doc.text(summaryLines, 15, y);
    y += (summaryLines.length * 5) + 8;

    // If y is close to page end, add a new page
    if (y > 250) {
      doc.addPage();
      y = 20;
    }

    // Threats details section
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(12);
    doc.setTextColor(darkSlate[0], darkSlate[1], darkSlate[2]);
    const threatTitle = scan.scanType === 'link' ? 'DETECTED LINK MALICIOUS THREATS' : scan.scanType === 'image' ? 'DETECTOR SOCIAL ENGINEERING THREATS' : 'DATABASE LEAK INCIDENTS';
    doc.text(threatTitle, 15, y);
    y += 6;

    if (scan.scanType === 'link' || scan.scanType === 'image') {
      const threats = scan.detectedThreats || [];
      if (threats.length === 0) {
        doc.setFont('helvetica', 'normal');
        doc.setFontSize(10);
        doc.setTextColor(70, 70, 70);
        doc.text('✓ No active visual or programmatic threats detected.', 15, y);
        y += 8;
      } else {
        threats.forEach((threat, idx) => {
          if (y > 260) {
            doc.addPage();
            y = 20;
          }
          doc.setFillColor(254, 242, 242);
          doc.roundedRect(15, y, 180, 8, 1, 1, 'F');
          
          doc.setFont('helvetica', 'bold');
          doc.setFontSize(9);
          doc.setTextColor(220, 38, 38);
          doc.text(`[FLAG ${idx + 1}]`, 18, y + 5.5);
          
          doc.setFont('helvetica', 'normal');
          doc.setTextColor(50, 50, 50);
          doc.text(threat.length > 80 ? threat.substring(0, 80) + '...' : threat, 35, y + 5.5);
          y += 11;
        });
      }
    } else {
      const breaches = scan.breaches || [];
      if (breaches.length === 0) {
        doc.setFont('helvetica', 'normal');
        doc.setFontSize(10);
        doc.setTextColor(70, 70, 70);
        doc.text('✓ Integrity sound. Zero matching records identified.', 15, y);
        y += 8;
      } else {
        breaches.forEach((b, idx) => {
          if (y > 240) {
            doc.addPage();
            y = 20;
          }
          doc.setFillColor(245, 247, 250);
          doc.roundedRect(15, y, 180, 24, 2, 2, 'F');
          
          doc.setFont('helvetica', 'bold');
          doc.setFontSize(9);
          doc.setTextColor(darkSlate[0], darkSlate[1], darkSlate[2]);
          doc.text(`${idx + 1}. ${b.Title} (${b.Domain || ''})`, 18, y + 6);
          
          doc.setFontSize(8);
          doc.setTextColor(textGray[0], textGray[1], textGray[2]);
          doc.text(`Breach Date: ${b.BreachDate || 'N/A'}  |  Severity: ${b.severity || 'high'}`, 18, y + 11);
          
          doc.setFont('helvetica', 'normal');
          doc.setFontSize(8.5);
          doc.setTextColor(60, 60, 60);
          const descClipped = b.Description && b.Description.length > 105 ? b.Description.substring(0, 105) + '...' : b.Description || '';
          doc.text(descClipped, 18, y + 16);

          doc.setFont('helvetica', 'bold');
          doc.setFontSize(8);
          doc.setTextColor(110, 120, 130);
          doc.text(`Leaked items: ${(b.DataClasses || []).join(', ')}`, 18, y + 21);
          
          y += 28;
        });
      }
    }

    y += 5;
    if (y > 230) {
      doc.addPage();
      y = 20;
    }

    // Countermeasures Section
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

    // Page footer note
    doc.setFontSize(8);
    doc.setTextColor(120, 120, 120);
    doc.text('This security threat assessment was generated securely by CyberGuard. Keep credentials private.', 15, 287);

    doc.save(`CyberGuard_Security_Briefing_${scan.id.substring(0, 8).toUpperCase()}.pdf`);
  };

  return (
    <div className="space-y-6 print:bg-white print:text-black">
      {/* Back & Export buttons header */}
      <div className="flex flex-col sm:flex-row justify-between sm:items-center gap-3 print:hidden">
        <button
          onClick={onBack}
          className="text-xs text-slate-400 hover:text-white transition-all cursor-pointer flex items-center justify-center gap-1 bg-slate-900 border border-slate-800 px-3 py-1.5 rounded-xl self-start"
        >
          <ChevronLeft className="w-4 h-4" />
          Back to Dashboard
        </button>
        <div className="flex items-center gap-2">
          <button
            onClick={handleDownloadPdf}
            className="flex-1 sm:flex-none bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold text-xs px-3.5 py-1.5 rounded-xl transition-all cursor-pointer flex items-center justify-center gap-1.5 shadow-lg shadow-cyan-500/10"
          >
            <Download className="w-4 h-4" />
            Download PDF Report
          </button>
          <button
            onClick={handlePrint}
            className="flex-1 sm:flex-none bg-slate-900 hover:bg-slate-800 text-slate-300 border border-slate-800 font-bold text-xs px-3.5 py-1.5 rounded-xl transition-all cursor-pointer flex items-center justify-center gap-1.5"
          >
            <Printer className="w-4 h-4" />
            Export / Print
          </button>
        </div>
      </div>

      {/* Main printable report body */}
      <div id="cyberguard-printable-report" className="bento-card p-6 sm:p-8 space-y-8 relative overflow-hidden print:border-none print:shadow-none print:p-0">
        {/* Background watermark */}
        <div className="absolute top-0 right-0 w-80 h-80 bg-cyan-500/5 rounded-full blur-3xl pointer-events-none print:hidden"></div>

        {/* Report Header */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-800 pb-6 print:border-black">
          <div className="flex items-center gap-3">
            <div className="w-12 h-12 bg-cyan-950/50 border border-cyan-500/25 rounded-2xl flex items-center justify-center text-cyan-400 print:bg-slate-100 print:border-black shrink-0">
              <Shield className="w-6 h-6" />
            </div>
            <div>
              <h2 className="text-xl font-bold font-display text-white print:text-black">
                {scan.scanType === 'link' 
                  ? 'CyberGuard Link Safety Report' 
                  : scan.scanType === 'image' 
                  ? 'CyberGuard Visual Threat Report' 
                  : 'CyberGuard Vulnerability Report'}
              </h2>
              <p className="text-xs font-mono text-slate-400 print:text-slate-600">ID: SEC-{scan.id.substring(0, 8).toUpperCase()} | Compiled: {new Date(scan.timestamp).toLocaleString()}</p>
            </div>
          </div>
          <div className="text-left sm:text-right">
            <span className="text-[10px] uppercase font-mono tracking-widest text-slate-500 block">
              {scan.scanType === 'link' ? 'Targeted Link URL' : scan.scanType === 'image' ? 'Target Screenshot File' : 'Target Email Endpoint'}
            </span>
            <span className="font-mono text-sm font-semibold text-cyan-400 print:text-cyan-800 break-all">
              {scan.scanType === 'link' ? scan.targetLink : scan.scanType === 'image' ? scan.imageFileName : scan.targetEmail}
            </span>
          </div>
        </div>

        {/* Hazard assessment grid */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          {/* Risk gauge card */}
          <div className="bg-slate-950/30 border border-slate-800/50 rounded-2xl p-5 flex flex-col items-center justify-center text-center print:border-black print:bg-slate-50">
            <span className="text-[10px] uppercase font-mono tracking-wider text-slate-500 mb-3">Threat Exposure Level</span>
            <div className="relative w-28 h-28 flex items-center justify-center">
              {/* Radial circle */}
              <svg className="absolute w-full h-full -rotate-90">
                <circle
                  cx="56"
                  cy="56"
                  r="48"
                  className="stroke-slate-800 fill-none print:stroke-slate-200"
                  strokeWidth="8"
                />
                <circle
                  cx="56"
                  cy="56"
                  r="48"
                  className="stroke-cyan-500 fill-none"
                  strokeWidth="8"
                  strokeDasharray={2 * Math.PI * 48}
                  strokeDashoffset={2 * Math.PI * 48 * (1 - scan.riskScore / 100)}
                />
              </svg>
              <div className="flex flex-col items-center justify-center">
                <span className="text-3xl font-mono font-extrabold text-white print:text-black">{scan.riskScore}</span>
                <span className="text-[9px] uppercase font-semibold text-slate-500">of 100</span>
              </div>
            </div>
            <span className={`mt-4 px-3 py-0.5 rounded-full text-[10px] font-bold font-mono tracking-wide border uppercase ${risk.color}`}>
              {risk.label}
            </span>
          </div>

          {/* AI generated Summary block */}
          <div className="bg-slate-950/30 border border-slate-800/50 rounded-2xl p-5 md:col-span-2 print:border-black print:bg-slate-50 space-y-3">
            <div className="flex items-center gap-1.5 text-xs font-bold text-cyan-400 font-display print:text-cyan-800">
              <ShieldCheck className="w-4 h-4 shrink-0 text-cyan-400" />
              <span>CyberGuard Executive Threat Summary</span>
            </div>
            <div className="text-xs text-slate-300 leading-relaxed space-y-2 whitespace-pre-wrap font-sans print:text-black">
              {scan.aiSummary || 'AI report generator is performing secure cloud-neural diagnostics...'}
            </div>
          </div>
        </div>

        {/* Found leak timeline details */}
        <div className="space-y-4">
          {scan.scanType === 'link' ? (
            <>
              <div className="flex items-center gap-1.5 text-xs font-bold text-slate-400 font-mono uppercase tracking-wider">
                <AlertTriangle className="w-4 h-4 text-amber-500" />
                <span>Malicious URL Threat Indicators ({scan.detectedThreats?.length || 0})</span>
              </div>

              {(!scan.detectedThreats || scan.detectedThreats.length === 0 || scan.riskScore < 20) ? (
                <div className="bg-emerald-950/10 border border-emerald-500/20 rounded-2xl p-6 text-center">
                  <span className="text-emerald-400 font-semibold block text-sm">✓ Link Assessment Safe</span>
                  <span className="text-xs text-slate-500 mt-1 block">No active brand spoofing, malicious obfuscation, or TLD threats detected on this link.</span>
                </div>
              ) : (
                <div className="space-y-2">
                  {scan.detectedThreats.map((threat, idx) => (
                    <div key={idx} className="bg-slate-950/30 border border-slate-800/40 rounded-2xl p-4 flex items-center gap-3 border-l-2 border-l-cyan-500 print:border-black print:bg-slate-50">
                      <div className="w-2 h-2 rounded-full bg-cyan-400 animate-pulse shrink-0"></div>
                      <span className="text-xs text-slate-300 font-mono print:text-black">{threat}</span>
                    </div>
                  ))}
                </div>
              )}
            </>
          ) : scan.scanType === 'image' ? (
            <>
              <div className="flex items-center gap-1.5 text-xs font-bold text-slate-400 font-mono uppercase tracking-wider">
                <AlertTriangle className="w-4 h-4 text-amber-500" />
                <span>Visual Social Engineering Threat Flags ({scan.detectedThreats?.length || 0})</span>
              </div>

              {(!scan.detectedThreats || scan.detectedThreats.length === 0 || scan.riskScore < 20) ? (
                <div className="bg-emerald-950/10 border border-emerald-500/20 rounded-2xl p-6 text-center">
                  <span className="text-emerald-400 font-semibold block text-sm">✓ Visual Diagnostics Clean</span>
                  <span className="text-xs text-slate-500 mt-1 block">No phishing interfaces, urgent payment text, or malicious QR targets detected in this asset.</span>
                </div>
              ) : (
                <div className="space-y-2">
                  {scan.detectedThreats.map((threat, idx) => (
                    <div key={idx} className="bg-slate-950/30 border border-slate-800/40 rounded-2xl p-4 flex items-center gap-3 border-l-2 border-l-cyan-500 print:border-black print:bg-slate-50">
                      <div className="w-2 h-2 rounded-full bg-cyan-400 animate-pulse shrink-0"></div>
                      <span className="text-xs text-slate-300 font-mono print:text-black">{threat}</span>
                    </div>
                  ))}
                </div>
              )}
            </>
          ) : (
            <>
              <div className="flex items-center gap-1.5 text-xs font-bold text-slate-400 font-mono uppercase tracking-wider">
                <AlertTriangle className="w-4 h-4 text-amber-500" />
                <span>Identified Database Leak Instances ({scan.resultCount})</span>
              </div>

              {scan.breaches.length === 0 ? (
                <div className="bg-emerald-950/10 border border-emerald-500/20 rounded-2xl p-6 text-center">
                  <span className="text-emerald-400 font-semibold block text-sm">✓ Endpoint Integrity Intact</span>
                  <span className="text-xs text-slate-500 mt-1 block">No matches found in known compromise archives. Your endpoint is secure.</span>
                </div>
              ) : (
                <div className="space-y-4">
                  {scan.breaches.map((b) => (
                    <div key={b.id} className="bg-slate-950/30 border border-slate-800/40 rounded-2xl p-5 flex flex-col sm:flex-row gap-4 items-start scan-line border-l-2 !border-slate-800/60 hover:!border-cyan-500 transition-colors print:border-black print:bg-slate-50">
                      {b.LogoPath ? (
                        <img
                          src={b.LogoPath}
                          alt={b.Title}
                          referrerPolicy="no-referrer"
                          className="w-12 h-12 rounded-xl object-cover shrink-0 border border-slate-800/50 print:border-black"
                        />
                      ) : (
                        <div className="w-12 h-12 rounded-xl bg-slate-900 border border-slate-800 flex items-center justify-center font-bold text-slate-400 text-sm">
                          {b.Title.charAt(0)}
                        </div>
                      )}
                      <div className="space-y-2 flex-1">
                        <div className="flex flex-wrap items-center gap-2">
                          <h4 className="font-bold text-white text-sm print:text-black">{b.Title}</h4>
                          <span className="text-[10px] font-mono text-slate-500">• {b.Domain} • Leaked: {b.BreachDate}</span>
                          <span className={`ml-auto font-mono text-[9px] uppercase px-2 py-0.5 rounded-full font-bold border ${
                            b.severity === 'critical'
                              ? 'bg-rose-500/10 text-rose-400 border-rose-500/20'
                              : b.severity === 'high'
                              ? 'bg-amber-500/10 text-amber-400 border-amber-500/20'
                              : 'bg-slate-950 text-slate-400 border-slate-800'
                          }`}>
                            {b.severity} severity
                          </span>
                        </div>
                        <p className="text-xs text-slate-400 leading-relaxed print:text-black">{b.Description}</p>
                        
                        <div className="flex flex-wrap gap-1.5 pt-1">
                          {b.DataClasses.map((item, idx) => (
                            <span key={idx} className="bg-slate-900 text-slate-500 border border-slate-800 font-mono text-[9px] px-2 py-0.5 rounded-lg print:border-black print:text-black">
                              {item}
                            </span>
                          ))}
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </>
          )}
        </div>

        {/* Security checklist footer */}
        <div className="bg-cyan-950/5 border border-cyan-500/10 rounded-2xl p-5 print:border-black print:bg-slate-50">
          <h4 className="font-bold text-xs text-cyan-400 font-display mb-3 flex items-center gap-1.5 print:text-cyan-800">
            <CheckSquare className="w-4 h-4" />
            {scan.scanType === 'link' 
              ? 'Secure URL Navigation Countermeasures' 
              : scan.scanType === 'image' 
              ? 'Deceptive Visual Asset Protocols' 
              : 'Vulnerability Countermeasures Guide'}
          </h4>
          <ul className="text-xs text-slate-400 space-y-2 print:text-black">
            {scan.scanType === 'link' ? (
              <>
                <li className="flex items-start gap-2">
                  <span className="text-cyan-400 font-bold font-mono">1.</span>
                  <span><strong>Do Not Authorize Session:</strong> Never type active API keys, MFA codes, or master credentials into unfamiliar redirect forms.</span>
                </li>
                <li className="flex items-start gap-2">
                  <span className="text-cyan-400 font-bold font-mono">2.</span>
                  <span><strong>Inspect Host Domain:</strong> Always double-check domain spellings manually (e.g. paypaI vs paypal) in your browser address bar.</span>
                </li>
                <li className="flex items-start gap-2">
                  <span className="text-cyan-400 font-bold font-mono">3.</span>
                  <span><strong>Deploy Private Sandbox:</strong> Use private insulated browsers or specialized VPN tunnels if visiting brand-new or zero-reputation domains.</span>
                </li>
              </>
            ) : scan.scanType === 'image' ? (
              <>
                <li className="flex items-start gap-2">
                  <span className="text-cyan-400 font-bold font-mono">1.</span>
                  <span><strong>Independent QR Scanning:</strong> Do not scan QR codes embedded in random screenshots or emails. Use secure link decoders first.</span>
                </li>
                <li className="flex items-start gap-2">
                  <span className="text-cyan-400 font-bold font-mono">2.</span>
                  <span><strong>Confirm Sender Authenticity:</strong> If the screenshot displays an invoice or emergency billing notice, verify with the vendor directly.</span>
                </li>
                <li className="flex items-start gap-2">
                  <span className="text-cyan-400 font-bold font-mono">3.</span>
                  <span><strong>Ignore Prompt Graphics:</strong> Be alert to graphic elements mimicking OS warnings, browser crash popups, or cloud sign-in triggers.</span>
                </li>
              </>
            ) : (
              <>
                <li className="flex items-start gap-2">
                  <span className="text-cyan-400 font-bold font-mono">1.</span>
                  <span><strong>Separate Passwords:</strong> Never reuse master passwords. Use a secure offline password manager.</span>
                </li>
                <li className="flex items-start gap-2">
                  <span className="text-cyan-400 font-bold font-mono">2.</span>
                  <span><strong>Strict MFA policies:</strong> Enforce software-based Authenticator apps rather than standard SMS codes where supported.</span>
                </li>
                <li className="flex items-start gap-2">
                  <span className="text-cyan-400 font-bold font-mono">3.</span>
                  <span><strong>Email Alias isolation:</strong> Use separate address aliases when registering on secondary untrusted websites.</span>
                </li>
              </>
            )}
          </ul>
        </div>

        {/* Printable Footer */}
        <div className="hidden print:block text-center text-[9px] text-slate-500 pt-6 border-t border-dashed border-slate-300">
          CyberGuard Cybersecurity Audit Report. Compiled securely using server-side Gemini threat intelligence pipelines.
        </div>
      </div>
    </div>
  );
}
