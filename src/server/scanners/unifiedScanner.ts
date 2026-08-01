import { ScanRiskReport, RiskLevel, TriggeredFlag } from '../../types/scanners';
import { scanUrl } from './urlScanner';
import { scanEmail } from './emailScanner';
import { scanImage } from './imageScanner';

/**
 * UNIFIED MULTI-VECTOR SECURITY SCANNER
 * Combines URL, Email, and Image scanning outputs into a single consolidated report.
 */
export async function scanUnified(params: {
  url?: string;
  email?: string | Buffer;
  image?: { buffer: Buffer; filename: string; mimeType: string };
}): Promise<ScanRiskReport> {
  const timestamp = new Date().toISOString();
  const allReports: ScanRiskReport[] = [];

  if (params.url) {
    try {
      allReports.push(await scanUrl(params.url));
    } catch (e) {}
  }

  if (params.email) {
    try {
      allReports.push(await scanEmail(params.email));
    } catch (e) {}
  }

  if (params.image) {
    try {
      allReports.push(await scanImage(params.image.buffer, params.image.filename, params.image.mimeType));
    } catch (e) {}
  }

  if (allReports.length === 0) {
    return {
      scannerType: 'unified',
      target: 'Multi-Vector Assessment',
      timestamp,
      riskScore: 0,
      riskLevel: 'SAFE',
      triggeredFlags: [],
      details: {}
    };
  }

  // Combine flags and compute peak risk score
  const combinedFlags: TriggeredFlag[] = [];
  const flagIdSet = new Set<string>();

  for (const rep of allReports) {
    for (const flag of rep.triggeredFlags) {
      if (!flagIdSet.has(flag.id)) {
        flagIdSet.add(flag.id);
        combinedFlags.push(flag);
      }
    }
  }

  const maxRiskScore = Math.max(...allReports.map(r => r.riskScore));
  const totalScore = Math.min(maxRiskScore, 100);

  let riskLevel: RiskLevel = 'SAFE';
  if (totalScore >= 70) riskLevel = 'CRITICAL';
  else if (totalScore >= 45) riskLevel = 'HIGH';
  else if (totalScore >= 25) riskLevel = 'MODERATE';
  else if (totalScore > 0) riskLevel = 'LOW';

  return {
    scannerType: 'unified',
    target: params.url || (params.image ? params.image.filename : 'Unified Target'),
    timestamp,
    riskScore: totalScore,
    riskLevel,
    triggeredFlags: combinedFlags,
    details: {
      urlDetails: allReports.find(r => r.scannerType === 'url')?.details.urlDetails,
      emailDetails: allReports.find(r => r.scannerType === 'email')?.details.emailDetails,
      imageDetails: allReports.find(r => r.scannerType === 'image')?.details.imageDetails
    }
  };
}

export { scanUrl, scanEmail, scanImage };
