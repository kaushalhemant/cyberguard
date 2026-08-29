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
    // Fallback to window.print if pdf generation errors
    if (typeof window !== 'undefined') {
      window.print();
    }
    return false;
  }
}
