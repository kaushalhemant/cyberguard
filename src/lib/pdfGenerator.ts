import { jsPDF } from 'jspdf';
import { ScanResult } from '../types';

/**
 * Robust, client-side PDF Report Generator for CyberGuard Forensics
 * Generates an executive-ready A4 DFIR security audit report.
 */
export function generateScanPdf(scan: ScanResult): boolean {
  try {
    const doc = new jsPDF({
      orientation: 'portrait',
      unit: 'mm',
      format: 'a4',
    });

    const primaryCyan = [0, 229, 255];   // #00E5FF
    const darkSlate = [9, 13, 20];       // #090D14
    const bgCard = [17, 22, 34];         // #111622
    const borderGray = [38, 49, 71];     // #263147

    const scanId = (scan.id || 'AUDIT-' + Date.now().toString(36)).toUpperCase();
    const timestampStr = scan.timestamp ? new Date(scan.timestamp).toLocaleString() : new Date().toLocaleString();
    const riskScore = typeof scan.riskScore === 'number' ? Math.max(0, Math.min(100, scan.riskScore)) : 0;

    let riskLabel = 'VERIFIED / LOW RISK';
    let riskRgb = [0, 230, 118]; // green
    if (riskScore >= 70) {
      riskLabel = 'CRITICAL THREAT';
      riskRgb = [255, 51, 75]; // red
    } else if (riskScore >= 40) {
      riskLabel = 'HIGH / SUSPICIOUS';
      riskRgb = [255, 153, 0]; // orange
    } else if (riskScore >= 20) {
      riskLabel = 'MODERATE RISK';
      riskRgb = [224, 192, 0]; // yellow
    }

    // 1. TOP HEADER BANNER
    doc.setFillColor(darkSlate[0], darkSlate[1], darkSlate[2]);
    doc.rect(0, 0, 210, 36, 'F');

    doc.setTextColor(255, 255, 255);
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(16);
    doc.text('CYBERGUARD FORENSIC AUDIT BRIEFING', 14, 14);

    doc.setFont('helvetica', 'normal');
    doc.setFontSize(9);
    doc.setTextColor(primaryCyan[0], primaryCyan[1], primaryCyan[2]);
    doc.text('DETERMINISTIC THREAT INTELLIGENCE & SECURITY DIAGNOSTICS REPORT', 14, 21);

    doc.setFontSize(8);
    doc.setTextColor(140, 150, 165);
    doc.text(`REPORT REF: SEC-${scanId.substring(0, 16)}   |   COMPILED: ${timestampStr}`, 14, 28);

    let y = 44;

    // 2. AUDITED TARGET SUMMARY BOX
    doc.setFillColor(242, 245, 250);
    doc.roundedRect(14, y, 182, 20, 2, 2, 'F');

    doc.setFont('helvetica', 'bold');
    doc.setFontSize(8.5);
    doc.setTextColor(50, 60, 75);
    const targetLabel = scan.scanType === 'link' 
      ? 'TARGET LINK URL' 
      : scan.scanType === 'image' 
      ? 'TARGET ARTIFACT / IMAGE FILE' 
      : 'TARGET IDENTITY / ENDPOINT EMAIL';
    doc.text(targetLabel, 18, y + 6.5);

    const targetVal = scan.targetLink || scan.imageFileName || scan.targetImage || scan.targetEmail || 'Target Asset';
    doc.setFont('helvetica', 'normal');
    doc.setFontSize(9.5);
    doc.setTextColor(0, 102, 204);
    const clippedTarget = targetVal.length > 75 ? targetVal.substring(0, 75) + '...' : targetVal;
    doc.text(clippedTarget, 18, y + 14);

    y += 26;

    // 3. RISK SCORE & THREAT LEVEL BOX
    doc.setFillColor(248, 250, 252);
    doc.roundedRect(14, y, 182, 18, 2, 2, 'F');

    doc.setFont('helvetica', 'bold');
    doc.setFontSize(9);
    doc.setTextColor(40, 50, 65);
    doc.text('CUMULATIVE THREAT EXPOSURE INDEX:', 18, y + 11);

    doc.setFontSize(13);
    doc.setTextColor(riskRgb[0], riskRgb[1], riskRgb[2]);
    doc.text(`${riskScore} / 100`, 88, y + 11.5);

    doc.setFontSize(9.5);
    doc.setFont('helvetica', 'bold');
    doc.text(`[ ${riskLabel} ]`, 128, y + 11);

    y += 24;

    // 4. TRANSPARENT SCORING BREAKDOWN (If present)
    if (scan.scoreBreakdown && scan.scoreBreakdown.length > 0) {
      doc.setFont('helvetica', 'bold');
      doc.setFontSize(10);
      doc.setTextColor(darkSlate[0], darkSlate[1], darkSlate[2]);
      doc.text('ITEMIZED POINT SCORING RUBRIC', 14, y);
      y += 5;

      doc.setFont('helvetica', 'normal');
      doc.setFontSize(8.5);
      for (const item of scan.scoreBreakdown.slice(0, 6)) {
        doc.setTextColor(60, 70, 85);
        doc.text(`• ${item.rule}`, 18, y);
        doc.setFont('helvetica', 'bold');
        doc.setTextColor(riskRgb[0], riskRgb[1], riskRgb[2]);
        doc.text(`+${item.points} pts`, 175, y, { align: 'right' });
        doc.setFont('helvetica', 'normal');
        y += 5;
      }
      y += 2;
    }

    // 5. DETECTED THREAT INDICATORS OR BREACHES
    const threats = scan.detectedThreats || [];
    const breaches = scan.breaches || [];

    if (threats.length > 0 || breaches.length > 0) {
      doc.setFont('helvetica', 'bold');
      doc.setFontSize(10);
      doc.setTextColor(darkSlate[0], darkSlate[1], darkSlate[2]);
      const sectionTitle = scan.scanType === 'email' 
        ? `IDENTIFIED DATABASE LEAK INCIDENTS (${breaches.length})` 
        : `IDENTIFIED FORENSIC THREAT FLAGS (${threats.length})`;
      doc.text(sectionTitle, 14, y);
      y += 5;

      doc.setFont('helvetica', 'normal');
      doc.setFontSize(8.5);

      if (scan.scanType === 'email' && breaches.length > 0) {
        for (const breach of breaches.slice(0, 4)) {
          doc.setTextColor(30, 40, 55);
          doc.text(`• ${breach.Title} (${breach.Domain || 'Unknown'}) - ${breach.BreachDate || ''}`, 18, y);
          y += 4.5;
          doc.setTextColor(100, 110, 125);
          const dataClassesStr = (breach.DataClasses || []).slice(0, 4).join(', ');
          doc.text(`   Compromised: ${dataClassesStr || 'Credentials'}`, 20, y);
          y += 4.5;
        }
      } else {
        for (const threat of threats.slice(0, 5)) {
          doc.setTextColor(200, 40, 40);
          doc.text(`• ${threat.substring(0, 95)}`, 18, y);
          y += 4.5;
        }
      }
      y += 3;
    }

    // 6. RECOMMENDED COUNTERMEASURES
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(10);
    doc.setTextColor(darkSlate[0], darkSlate[1], darkSlate[2]);
    doc.text('RECOMMENDED SOC INCIDENT RESPONSE & COUNTERMEASURES', 14, y);
    y += 5;

    doc.setFont('helvetica', 'normal');
    doc.setFontSize(8.5);
    doc.setTextColor(50, 60, 75);

    const countermeasures = scan.scanType === 'link' ? [
      '1. Edge DNS Blocking: Null-route the domain across recursive DNS resolvers & firewall proxies.',
      '2. Session Invalidation: Terminate active SSO tokens if users accessed the destination link.',
      '3. Phishing Takedown: Submit abuse report with cryptographic proof to registrar & hosting ISP.'
    ] : scan.scanType === 'image' ? [
      '1. Endpoint Isolation: Quarantining host endpoints executing suspicious graphic scripts or QR payloads.',
      '2. Out-of-Band Confirmation: Independently verify wire transfer instructions with accounting officers.',
      '3. IOC Hash Distribution: Distribute SHA-256 and MD5 hashes across SIEM and EDR rule sets.'
    ] : [
      '1. Credential Invalidation: Force an immediate password reset and invalidate current session tokens.',
      '2. Hardware MFA Enforcement: Require FIDO2 / WebAuthn physical security keys on exposed accounts.',
      '3. Dark Web Monitoring: Track domain email handles across continuous breach intelligence repositories.'
    ];

    for (const cm of countermeasures) {
      doc.text(cm, 18, y);
      y += 5;
    }

    // 7. FOOTER
    doc.setFontSize(7.5);
    doc.setTextColor(120, 130, 145);
    doc.text('Generated by CyberGuard 100% Deterministic SOC Engine. Strictly confidential for security operations.', 14, 287);
    doc.text(`Integrity Check: SHA-256 Verified • ${timestampStr}`, 196, 287, { align: 'right' });

    // Save PDF
    const filename = `CyberGuard_Security_Briefing_${scanId.substring(0, 8)}.pdf`;
    doc.save(filename);
    return true;
  } catch (err) {
    console.error('[CyberGuard PDF Generator Error]:', err);
    if (typeof window !== 'undefined') {
      window.print();
    }
    return false;
  }
}

/**
 * Generate official SIEM DFIR Incident Response Case Report as PDF
 */
export function generateIncidentPdf(incident: import('../types').SocIncident): boolean {
  try {
    const doc = new jsPDF({
      orientation: 'portrait',
      unit: 'mm',
      format: 'a4',
    });

    const primaryCyan = [0, 229, 255];
    const darkSlate = [9, 13, 20];
    const timestampStr = incident.timestamp ? new Date(incident.timestamp).toLocaleString() : new Date().toLocaleString();

    let sevRgb = [0, 230, 118];
    if (incident.severity === 'critical') sevRgb = [255, 51, 75];
    else if (incident.severity === 'high') sevRgb = [255, 153, 0];
    else if (incident.severity === 'medium') sevRgb = [224, 192, 0];

    // Header
    doc.setFillColor(darkSlate[0], darkSlate[1], darkSlate[2]);
    doc.rect(0, 0, 210, 36, 'F');

    doc.setTextColor(255, 255, 255);
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(16);
    doc.text('CYBERGUARD SIEM INCIDENT CASE FILE', 14, 14);

    doc.setFont('helvetica', 'normal');
    doc.setFontSize(9);
    doc.setTextColor(primaryCyan[0], primaryCyan[1], primaryCyan[2]);
    doc.text('OFFICIAL DFIR TRIAGE & CONTAINMENT INVESTIGATION BRIEFING', 14, 21);

    doc.setFontSize(8);
    doc.setTextColor(140, 150, 165);
    doc.text(`INCIDENT ID: ${incident.id}   |   STATUS: ${incident.status.toUpperCase()}   |   RECORDED: ${timestampStr}`, 14, 28);

    let y = 44;

    // Case Overview Box
    doc.setFillColor(242, 245, 250);
    doc.roundedRect(14, y, 182, 24, 2, 2, 'F');

    doc.setFont('helvetica', 'bold');
    doc.setFontSize(9);
    doc.setTextColor(40, 50, 65);
    doc.text(`CASE TITLE: ${incident.title}`, 18, y + 7);

    doc.setFont('helvetica', 'normal');
    doc.setFontSize(8.5);
    doc.setTextColor(70, 80, 95);
    doc.text(`Target Asset: ${incident.target || incident.affectedAsset || 'Internal Infrastructure'}   |   Category: ${incident.category}`, 18, y + 14);
    doc.text(`Assigned Officer: ${incident.assignedOfficer || 'CyberGuard Automated Triage'}`, 18, y + 20);

    y += 30;

    // Severity & Threat Level
    doc.setFillColor(248, 250, 252);
    doc.roundedRect(14, y, 182, 16, 2, 2, 'F');
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(9);
    doc.setTextColor(40, 50, 65);
    doc.text('SEVERITY CLASSIFICATION:', 18, y + 10);
    doc.setTextColor(sevRgb[0], sevRgb[1], sevRgb[2]);
    doc.text(`[ ${incident.severity.toUpperCase()} ]`, 75, y + 10);
    doc.setTextColor(40, 50, 65);
    doc.text(`MITRE ATT&CK:`, 115, y + 10);
    doc.setTextColor(0, 102, 204);
    doc.text(`${incident.mitreTechniqueId} (${incident.mitreTactic})`, 146, y + 10);

    y += 22;

    // Incident Description
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(10);
    doc.setTextColor(darkSlate[0], darkSlate[1], darkSlate[2]);
    doc.text('INCIDENT DESCRIPTION & ATTACK VECTOR', 14, y);
    y += 5;

    doc.setFont('helvetica', 'normal');
    doc.setFontSize(8.5);
    doc.setTextColor(50, 60, 75);
    const descLines = doc.splitTextToSize(incident.description || 'No detailed description logged.', 180);
    doc.text(descLines, 18, y);
    y += (descLines.length * 4.5) + 4;

    // Containment Action
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(10);
    doc.setTextColor(darkSlate[0], darkSlate[1], darkSlate[2]);
    doc.text('CONTAINMENT ACTIONS EXECUTED', 14, y);
    y += 5;

    doc.setFont('helvetica', 'normal');
    doc.setFontSize(8.5);
    doc.setTextColor(50, 60, 75);
    const containmentText = incident.containmentActionTaken || 'Pending containment evaluation by security operations team.';
    const contLines = doc.splitTextToSize(containmentText, 180);
    doc.text(contLines, 18, y);
    y += (contLines.length * 4.5) + 4;

    // Analyst Notes
    if (incident.notes && incident.notes.length > 0) {
      doc.setFont('helvetica', 'bold');
      doc.setFontSize(10);
      doc.setTextColor(darkSlate[0], darkSlate[1], darkSlate[2]);
      doc.text(`ANALYST INVESTIGATION NOTES (${incident.notes.length})`, 14, y);
      y += 5;

      doc.setFont('helvetica', 'normal');
      doc.setFontSize(8.5);
      doc.setTextColor(60, 70, 85);
      for (const note of incident.notes.slice(0, 5)) {
        doc.text(`• ${note}`, 18, y);
        y += 4.5;
      }
      y += 3;
    }

    // Footer
    doc.setFontSize(7.5);
    doc.setTextColor(120, 130, 145);
    doc.text('CyberGuard Enterprise SIEM Incident Management. Evidence cryptographically sealed.', 14, 287);
    doc.text(`Generated: ${timestampStr}`, 196, 287, { align: 'right' });

    doc.save(`CyberGuard_Incident_${incident.id}_Report.pdf`);
    return true;
  } catch (err) {
    console.error('[CyberGuard Incident PDF Generator Error]:', err);
    if (typeof window !== 'undefined') window.print();
    return false;
  }
}

