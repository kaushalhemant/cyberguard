import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import exifr from 'exifr';
import { createWorker } from 'tesseract.js';
import { ScanRiskReport, TriggeredFlag, RiskLevel } from '../../types/scanners';

/**
 * OCR PHISHING & DECEPTIVE TEXT KEYWORDS
 * Scans extracted OCR text for embedded credential harvesting prompts and financial lures.
 */
const OCR_PHISHING_PATTERNS = [
  { pattern: /invoice|receipt|payment\s+due|wire\s+transfer|billing/i, weight: 30, name: 'Embedded Invoice / Payment Scam Text' },
  { pattern: /verify\s+(your\s+)?(identity|account|credentials|password|login)/i, weight: 35, name: 'Embedded Credential Harvester Text' },
  { pattern: /crypto|bitcoin|ethereum|seed\s+phrase|wallet\s+connect|metamask/i, weight: 35, name: 'Embedded Crypto Drainer Lure' },
  { pattern: /scan\s+qr|qr\s+code|scan\s+to\s+pay|scan\s+to\s+verify/i, weight: 25, name: 'Embedded Quishing (QR Phishing) Prompt' },
  { pattern: /call\s+support|helpdesk|customer\s+service|toll\s+free|\+?1-\d{3}-\d{3}-\d{4}/i, weight: 25, name: 'Fake Tech Support Phone Scam Flyer' },
  { pattern: /account\s+suspended|security\s+alert|unauthorized/i, weight: 20, name: 'Embedded Security Coercion Prompt' }
];

/**
 * Load known bad cryptographic hashes from data/known_bad_hashes.json
 * Security Reasoning: Computes cryptographic file signatures (SHA-256/MD5) to detect
 * identical copies of known malware binaries, phishing templates, or threat payloads.
 */
interface KnownHashEntry {
  hash: string;
  algorithm: string;
  threatName: string;
  severity: string;
}

function loadKnownBadHashes(): KnownHashEntry[] {
  try {
    const jsonPath = path.join(process.cwd(), 'data', 'known_bad_hashes.json');
    if (!fs.existsSync(jsonPath)) return [];
    const content = fs.readFileSync(jsonPath, 'utf8');
    const parsed = JSON.parse(content);
    return parsed.hashes || [];
  } catch (e) {
    return [];
  }
}

/**
 * MAIN MODULAR IMAGE & OCR SCANNER SERVICE
 */
export async function scanImage(
  inputBuffer: Buffer,
  filename: string = 'image.png',
  mimeType: string = 'image/png'
): Promise<ScanRiskReport> {
  const timestamp = new Date().toISOString();
  const flags: TriggeredFlag[] = [];
  const knownBadHashes = loadKnownBadHashes();

  // 1. CRYPTOGRAPHIC HASH COMPARISON (SHA-256 & MD5)
  // Security Reasoning: Cryptographic hashes provide a unique 256-bit signature. Matching against known-bad threat databases instantly identifies recurring malware/phishing assets.
  const sha256Hash = crypto.createHash('sha256').update(inputBuffer).digest('hex').toLowerCase();
  const md5Hash = crypto.createHash('md5').update(inputBuffer).digest('hex').toLowerCase();

  let knownBadHashMatch: { threatName: string; hashMatched: string } | null = null;
  for (const entry of knownBadHashes) {
    const targetHash = entry.hash.toLowerCase();
    if (sha256Hash === targetHash || md5Hash === targetHash) {
      knownBadHashMatch = { threatName: entry.threatName, hashMatched: targetHash };
      flags.push({
        id: 'FLAG-KNOWN-BAD-HASH',
        name: 'Known Malicious Image Hash Match',
        severity: entry.severity === 'CRITICAL' ? 'CRITICAL' : 'HIGH',
        weight: entry.severity === 'CRITICAL' ? 50 : 35,
        description: `Cryptographic hash matched known threat signature: "${entry.threatName}".`,
        securityReasoning: 'Cryptographic hash collisions against known threat databases confirm identical copies of verified malicious image assets or payloads.'
      });
      break;
    }
  }

  // 2. EXIF METADATA EXTRACTION
  // Security Reasoning: Audits image EXIF tags for suspicious editing tools, software fingerprints, or hidden metadata payloads.
  let exifMetadata: Record<string, any> | null = null;
  try {
    exifMetadata = await exifr.parse(inputBuffer, {
      tiff: true,
      exif: true,
      gps: true
    });

    if (exifMetadata) {
      if (exifMetadata.Software && (String(exifMetadata.Software).toLowerCase().includes('hack') || String(exifMetadata.Software).toLowerCase().includes('spoof'))) {
        flags.push({
          id: 'FLAG-SUSPICIOUS-EXIF-SOFTWARE',
          name: 'Suspicious Image Editing Tool Fingerprint in EXIF',
          severity: 'HIGH',
          weight: 30,
          description: `EXIF software metadata tag indicates manipulation tool: "${exifMetadata.Software}".`,
          securityReasoning: 'Manipulated EXIF software metadata indicates potential document forgery or image tampering.'
        });
      }
    }
  } catch (e) {
    // EXIF metadata absent or non-JPEG format
  }

  // 3. OPEN-SOURCE OCR TEXT EXTRACTION (TESSERACT.JS)
  // Security Reasoning: Attackers render phishing texts inside images (e.g., fake invoice PDFs converted to PNG) to bypass text-based email filters. Optical Character Recognition (OCR) recovers the hidden text.
  let ocrText = '';
  const ocrPhishingKeywordsFound: string[] = [];

  try {
    const worker = await createWorker('eng');
    const ret = await worker.recognize(inputBuffer);
    ocrText = ret.data.text || '';
    await worker.terminate();

    if (ocrText.trim()) {
      for (const patternObj of OCR_PHISHING_PATTERNS) {
        if (patternObj.pattern.test(ocrText)) {
          ocrPhishingKeywordsFound.push(patternObj.name);
          flags.push({
            id: `FLAG-OCR-${patternObj.name.replace(/\s+/g, '-').toUpperCase()}`,
            name: patternObj.name,
            severity: patternObj.weight >= 30 ? 'HIGH' : 'MEDIUM',
            weight: patternObj.weight,
            description: `OCR text extraction identified phishing lure keyword: "${patternObj.name}".`,
            securityReasoning: 'Phishing kits render text inside image files to defeat static keyword filters. Extracting OCR text uncovers hidden financial and credential harvesting traps.'
          });
        }
      }
    }
  } catch (ocrErr) {
    console.warn('[ImageScanner] OCR extraction notice:', ocrErr);
  }

  // 4. FILENAME PATTERN HEURISTICS
  const lowercaseFilename = filename.toLowerCase();
  if (lowercaseFilename.includes('invoice') || lowercaseFilename.includes('receipt') || lowercaseFilename.includes('payment')) {
    if (!ocrText || ocrPhishingKeywordsFound.length === 0) {
      flags.push({
        id: 'FLAG-FILENAME-INVOICE',
        name: 'Invoice / Payment Filename Heuristic',
        severity: 'MEDIUM',
        weight: 15,
        description: `Filename "${filename}" matches invoice scam lure naming conventions.`,
        securityReasoning: 'Scam emails frequently attach fake invoices to trick accounts payable personnel into processing fraudulent payments.'
      });
    }
  }

  // CALCULATE CUMULATIVE RISK SCORE & LEVEL
  const totalScore = flags.reduce((acc, curr) => acc + curr.weight, 0);
  const riskScore = Math.min(totalScore, 100);

  let riskLevel: RiskLevel = 'SAFE';
  if (riskScore >= 70) riskLevel = 'CRITICAL';
  else if (riskScore >= 45) riskLevel = 'HIGH';
  else if (riskScore >= 25) riskLevel = 'MODERATE';
  else if (riskScore > 0) riskLevel = 'LOW';

  return {
    scannerType: 'image',
    target: filename,
    timestamp,
    riskScore,
    riskLevel,
    triggeredFlags: flags,
    details: {
      imageDetails: {
        filename,
        mimeType,
        fileSizeBytes: inputBuffer.length,
        hashes: { sha256: sha256Hash, md5: md5Hash },
        knownBadHashMatch,
        exifMetadata,
        ocrText: ocrText.trim(),
        ocrPhishingKeywordsFound
      }
    }
  };
}
