export type ScannerType = 'url' | 'email' | 'image' | 'unified';
export type RiskSeverity = 'INFO' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
export type RiskLevel = 'SAFE' | 'LOW' | 'MODERATE' | 'HIGH' | 'CRITICAL';

export interface TriggeredFlag {
  id: string;
  name: string;
  severity: RiskSeverity;
  weight: number; // Contribution score (0-50)
  description: string;
  securityReasoning: string;
}

export interface ScanRiskReport {
  scannerType: ScannerType;
  target: string;
  timestamp: string;
  riskScore: number; // 0 to 100
  riskLevel: RiskLevel;
  triggeredFlags: TriggeredFlag[];
  details: {
    // URL Scanner details
    urlDetails?: {
      originalUrl: string;
      finalUrl?: string;
      redirectChain?: string[];
      isIpLiteral?: boolean;
      domain?: string;
      tld?: string;
      suspiciousTldFlagged?: boolean;
      typosquatMatch?: { targetBrand: string; distance: number } | null;
      blocklistMatch?: { pattern: string; category: string } | null;
      tlsInfo?: {
        valid: boolean;
        issuer?: string;
        validFrom?: string;
        validTo?: string;
        daysUntilExpiration?: number;
        ageDays?: number;
      } | null;
      whoisInfo?: {
        domainAgeDays?: number | null;
        registrar?: string | null;
      } | null;
      urlhausMatch?: {
        matched: boolean;
        queryStatus: string;
        urlStatus?: string;
        threat?: string;
        tags?: string[];
        urlhausReference?: string;
      } | null;
      phishstatsMatch?: {
        matched: boolean;
        score?: number;
        target?: string;
        title?: string;
        ip?: string;
        country?: string;
        host?: string;
        date?: string;
        phishstatsUrl?: string;
      } | null;
    };
    // Email Scanner details
    emailDetails?: {
      senderFrom?: string;
      replyTo?: string;
      returnPath?: string;
      subject?: string;
      authResults?: {
        spf: { status: 'PASS' | 'FAIL' | 'NEUTRAL' | 'NONE'; record?: string; reasoning: string };
        dkim: { status: 'PASS' | 'FAIL' | 'NONE'; reasoning: string };
        dmarc: { status: 'PASS' | 'FAIL' | 'NONE'; record?: string; policy?: string; reasoning: string };
      };
      senderMismatch?: boolean;
      suspiciousAttachments?: { filename: string; extension: string; isDoubleExtension: boolean }[];
      extractedLinksCount?: number;
      nestedUrlReports?: ScanRiskReport[];
      sublimeResults?: {
        totalRulesEvaluated: number;
        flaggedCount: number;
        flaggedRules: {
          name: string;
          severity: string;
          source?: string;
        }[];
      } | null;
    };
    // Image Scanner details
    imageDetails?: {
      filename?: string;
      mimeType?: string;
      fileSizeBytes?: number;
      hashes?: { sha256: string; md5: string };
      knownBadHashMatch?: { threatName: string; hashMatched: string } | null;
      exifMetadata?: Record<string, any> | null;
      ocrText?: string;
      ocrPhishingKeywordsFound?: string[];
    };
  };
}
