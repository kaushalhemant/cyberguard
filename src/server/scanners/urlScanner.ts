import tls from 'tls';
import dns from 'dns/promises';
import fs from 'fs';
import path from 'path';
import { ScanRiskReport, TriggeredFlag, RiskLevel } from '../../types/scanners';
import { checkPhishStats } from './phishstatsScanner';
import { checkVirusTotalUrl } from './virustotalScanner';


/**
 * BRAND TARGET LIST FOR TYPOSQUATTING DETECTION
 * Common high-value targets for credential harvesting and phishing impersonation.
 */
const BRAND_TARGETS = [
  'google', 'paypal', 'microsoft', 'apple', 'amazon',
  'netflix', 'facebook', 'instagram', 'linkedin', 'chase',
  'wellsfargo', 'binance', 'coinbase', 'razorpay', 'cyberguard',
  'twitter', 'github', 'dropbox', 'adobe', 'stripe'
];

/**
 * HIGH-RISK TOP LEVEL DOMAINS (TLDs)
 * TLDs heavily statisticalized in phishing kits and automated malware distribution networks.
 */
const SUSPICIOUS_TLDS = [
  'xyz', 'top', 'zip', 'click', 'kim', 'download', 'work',
  'gq', 'cf', 'ml', 'tk', 'icu', 'monster', 'link', 'country',
  'stream', 'study', 'party', 'trade', 'racing', 'bid', 'asia'
];

/**
 * Calculate Levenshtein Distance between two strings.
 * Security Reasoning: Measures edit distance to detect deliberate character substitutions
 * designed to visually trick victims (e.g. "paypa1" vs "paypal", distance = 1).
 */
function levenshteinDistance(a: string, b: string): number {
  const matrix: number[][] = [];
  for (let i = 0; i <= b.length; i++) matrix[i] = [i];
  for (let j = 0; j <= a.length; j++) matrix[0][j] = j;

  for (let i = 1; i <= b.length; i++) {
    for (let j = 1; j <= a.length; j++) {
      if (b.charAt(i - 1) === a.charAt(j - 1)) {
        matrix[i][j] = matrix[i - 1][j - 1];
      } else {
        matrix[i][j] = Math.min(
          matrix[i - 1][j - 1] + 1, // substitution
          Math.min(matrix[i][j - 1] + 1, matrix[i - 1][j] + 1) // insertion, deletion
        );
      }
    }
  }
  return matrix[b.length][a.length];
}

/**
 * Load local CSV blocklist data from data/blocklist.csv.
 * Security Reasoning: Provides an offline, low-latency pre-screening database that can be
 * manually seeded or updated by local SOC analysts.
 */
interface BlocklistEntry {
  type: string;
  pattern: string;
  category: string;
  severity: string;
  description: string;
}

function loadLocalBlocklist(): BlocklistEntry[] {
  try {
    const csvPath = path.join(process.cwd(), 'data', 'blocklist.csv');
    if (!fs.existsSync(csvPath)) return [];
    
    const fileContent = fs.readFileSync(csvPath, 'utf8');
    const lines = fileContent.split(/\r?\n/).filter(line => line.trim() && !line.startsWith('type,'));
    
    return lines.map(line => {
      const parts = line.split(',');
      return {
        type: parts[0]?.trim() || '',
        pattern: parts[1]?.trim() || '',
        category: parts[2]?.trim() || '',
        severity: parts[3]?.trim() || '',
        description: parts[4]?.trim() || ''
      };
    });
  } catch (err) {
    console.warn('[URLScanner] Blocklist CSV read warning:', err);
    return [];
  }
}

/**
 * Inspect TLS certificate for a hostname using Node.js tls module.
 * Security Reasoning: Phishing domains frequently use short-lived, newly issued TLS certificates
 * or untrusted self-signed issuers. Inspecting cert age and issuer provides vital risk telemetry.
 */
async function inspectTlsCert(hostname: string, port: number = 443): Promise<{
  valid: boolean;
  issuer?: string;
  validFrom?: string;
  validTo?: string;
  daysUntilExpiration?: number;
  ageDays?: number;
} | null> {
  return new Promise((resolve) => {
    try {
      const socket = tls.connect({
        host: hostname,
        port: port,
        servername: hostname,
        rejectUnauthorized: false,
        timeout: 1500
      }, () => {
        const cert = socket.getPeerCertificate(false);
        socket.end();

        if (!cert || !cert.valid_from) {
          return resolve(null);
        }

        const validFrom = new Date(cert.valid_from);
        const validTo = new Date(cert.valid_to);
        const now = new Date();

        const ageDays = Math.max(0, Math.floor((now.getTime() - validFrom.getTime()) / (1000 * 60 * 60 * 24)));
        const daysUntilExpiration = Math.floor((validTo.getTime() - now.getTime()) / (1000 * 60 * 60 * 24));
        const rawIssuer = cert.issuer ? (cert.issuer.O || cert.issuer.CN || 'Unknown') : 'Unknown';
        const issuerName = Array.isArray(rawIssuer) ? rawIssuer.join(', ') : String(rawIssuer);
        const validFromStr = Array.isArray(cert.valid_from) ? cert.valid_from[0] : String(cert.valid_from);
        const validToStr = Array.isArray(cert.valid_to) ? cert.valid_to[0] : String(cert.valid_to);

        resolve({
          valid: socket.authorized,
          issuer: issuerName,
          validFrom: validFromStr,
          validTo: validToStr,
          daysUntilExpiration,
          ageDays
        });
      });

      socket.on('error', () => resolve(null));
      socket.on('timeout', () => {
        socket.destroy();
        resolve(null);
      });
    } catch (e) {
      resolve(null);
    }
  });
}

/**
 * Follow HTTP redirect chain to uncover hidden destination URLs.
 * Security Reasoning: Phishing campaigns use multi-stage URL shorteners and HTTP 301/302 redirects
 * to bypass static email gateway filters before delivering victims to malicious landing pages.
 */
async function followRedirectChain(url: string, maxRedirects: number = 3): Promise<{ finalUrl: string; redirectChain: string[] }> {
  const redirectChain: string[] = [url];
  let currentUrl = url;

  for (let i = 0; i < maxRedirects; i++) {
    try {
      const response = await fetch(currentUrl, {
        method: 'HEAD',
        redirect: 'manual',
        signal: AbortSignal.timeout(1500)
      });

      if (response.status >= 300 && response.status < 400) {
        const location = response.headers.get('location');
        if (location) {
          const nextUrl = new URL(location, currentUrl).toString();
          redirectChain.push(nextUrl);
          currentUrl = nextUrl;
          continue;
        }
      }
      break;
    } catch (e) {
      break;
    }
  }

  return { finalUrl: currentUrl, redirectChain };
}

/**
 * Perform RDAP / DNS query for domain creation metadata.
 * Security Reasoning: Over 70% of malicious phishing domains are registered less than 30 days
 * prior to attack launch. Querying domain age flags brand-new ephemeral infrastructure.
 */
async function lookupDomainAge(domain: string): Promise<{ domainAgeDays: number | null; registrar: string | null }> {
  try {
    const rdapRes = await fetch(`https://rdap.org/domain/${domain}`, {
      headers: { 'Accept': 'application/rdap+json' },
      signal: AbortSignal.timeout(1500)
    });

    if (rdapRes.ok) {
      const data = await rdapRes.json();
      const events = data.events || [];
      const registrationEvent = events.find((e: any) => e.eventAction === 'registration');
      
      if (registrationEvent && registrationEvent.eventDate) {
        const regDate = new Date(registrationEvent.eventDate);
        const ageDays = Math.max(0, Math.floor((Date.now() - regDate.getTime()) / (1000 * 60 * 60 * 24)));
        const registrarEntity = data.entities?.find((e: any) => e.roles?.includes('registrar'));
        const registrarName = registrarEntity?.vcardArray?.[1]?.find((v: any) => v[0] === 'fn')?.[3] || null;
        return { domainAgeDays: ageDays, registrar: registrarName };
      }
    }
  } catch (e) {
    // RDAP query skipped or timed out
  }
  return { domainAgeDays: null, registrar: null };
}

/**
 * Query URLhaus Threat Database (abuse.ch) for active malware distribution links.
 * Security Reasoning: URLhaus tracks real-time malware delivery URLs, payload hashes, and active C2 links.
 */
async function checkUrlhausApi(targetUrl: string): Promise<{
  matched: boolean;
  queryStatus: string;
  urlStatus?: string;
  threat?: string;
  tags?: string[];
  urlhausReference?: string;
} | null> {
  try {
    const apiKey = process.env.URLHAUS_API_KEY || '';
    const formData = new URLSearchParams();
    formData.append('url', targetUrl);

    const headers: Record<string, string> = {
      'Content-Type': 'application/x-www-form-urlencoded'
    };
    if (apiKey) {
      headers['Auth-Key'] = apiKey;
    }

    const response = await fetch('https://urlhaus-api.abuse.ch/v1/url/', {
      method: 'POST',
      headers,
      body: formData.toString(),
      signal: AbortSignal.timeout(1500)
    });

    if (!response.ok) return null;
    const data = await response.json();
    if (data.query_status === 'ok') {
      return {
        matched: true,
        queryStatus: data.query_status,
        urlStatus: data.url_status,
        threat: data.threat,
        tags: Array.isArray(data.tags) ? data.tags : [],
        urlhausReference: data.urlhaus_reference
      };
    }
    return { matched: false, queryStatus: data.query_status };
  } catch (err) {
    return null;
  }
}

/**
 * MAIN MODULAR URL SCANNER SERVICE
 */

export async function scanUrl(inputUrl: string): Promise<ScanRiskReport> {
  const timestamp = new Date().toISOString();
  const flags: TriggeredFlag[] = [];
  let rawUrl = inputUrl.trim();

  if (!rawUrl.startsWith('http://') && !rawUrl.startsWith('https://')) {
    rawUrl = 'http://' + rawUrl;
  }

  let parsedUrl: URL;
  try {
    parsedUrl = new URL(rawUrl);
  } catch (err) {
    return {
      scannerType: 'url',
      target: inputUrl,
      timestamp,
      riskScore: 100,
      riskLevel: 'CRITICAL',
      triggeredFlags: [{
        id: 'FLAG-INVALID-URL',
        name: 'Malformed URL Structure',
        severity: 'CRITICAL',
        weight: 100,
        description: 'Target input could not be parsed as a valid RFC 3986 URL.',
        securityReasoning: 'Malformed URLs are frequently used in exploit payloads to crash parser logic or hide obfuscated commands.'
      }],
      details: { urlDetails: { originalUrl: inputUrl } }
    };
  }

  const hostname = parsedUrl.hostname.toLowerCase();
  const pathAndQuery = parsedUrl.pathname + parsedUrl.search;
  const tld = hostname.includes('.') ? hostname.split('.').pop() || '' : '';

  // 1. IP-LITERAL HOST CHECK
  // Security Reasoning: Attackers use raw IP addresses (e.g., http://192.168.1.1/login) to bypass domain registration checks and WHOIS tracking.
  const isIpLiteral = /^(\d{1,3}\.){3}\d{1,3}$/.test(hostname) || hostname.startsWith('[') || hostname === 'localhost';
  if (isIpLiteral) {
    flags.push({
      id: 'FLAG-IP-LITERAL',
      name: 'Raw IP Address Host (IP-Literal)',
      severity: 'HIGH',
      weight: 35,
      description: `Target host "${hostname}" uses a raw IP address instead of a registered domain name.`,
      securityReasoning: 'Legitimate organizations host customer services under domain names with SSL certificates. Raw IP hosts lack standard identity verification and bypass domain-based security filters.'
    });
  }

  // 2. SUSPICIOUS TLD CHECK
  // Security Reasoning: Low-cost or unrestricted TLDs (.xyz, .top, .zip, .click) are statistically overrepresented in phishing kits.
  let suspiciousTldFlagged = false;
  if (SUSPICIOUS_TLDS.includes(tld)) {
    suspiciousTldFlagged = true;
    flags.push({
      id: 'FLAG-SUSPICIOUS-TLD',
      name: 'High-Risk Top-Level Domain (TLD)',
      severity: 'MEDIUM',
      weight: 25,
      description: `The TLD ".${tld}" has a high statistical correlation with malicious phishing campaigns.`,
      securityReasoning: 'Unrestricted TLDs are heavily abused for disposable attack infrastructure due to low registration costs and minimal identity verification requirements.'
    });
  }

  // 3. TYPOSQUATTING DETECTION
  // Security Reasoning: Typosquatting uses subtle spelling alterations (e.g., "paypa1" vs "paypal") to trick users into disclosing passwords on counterfeit portals.
  let typosquatMatch: { targetBrand: string; distance: number } | null = null;
  if (!isIpLiteral) {
    const domainLabels = hostname.split('.');
    const sld = domainLabels.length >= 2 ? domainLabels[domainLabels.length - 2] : hostname;

    const compoundTyposquats = [
      { pattern: /paypa1|paypaI|pay-pal|paypa1l/i, brand: 'paypal' },
      { pattern: /g00gle|gogle|goog1e|gooogle/i, brand: 'google' },
      { pattern: /m1crosoft|micros0ft|micro-soft/i, brand: 'microsoft' },
      { pattern: /amaz0n|amzn-verify|amazn/i, brand: 'amazon' },
      { pattern: /netfl1x|netf1ix|netfllx/i, brand: 'netflix' },
      { pattern: /app1e|appie|apple-verify/i, brand: 'apple' },
      { pattern: /binance-verify|coinbase-auth/i, brand: 'binance/coinbase' }
    ];

    for (const item of compoundTyposquats) {
      if (item.pattern.test(hostname)) {
        typosquatMatch = { targetBrand: item.brand, distance: 1 };
        flags.push({
          id: 'FLAG-TYPOSQUATTING',
          name: 'Brand Typosquatting Impersonation Detected',
          severity: 'CRITICAL',
          weight: 45,
          description: `Domain "${hostname}" contains brand impersonation pattern mimicking "${item.brand}".`,
          securityReasoning: 'Typosquatting is a high-confidence indicator of brand spoofing intended for credential harvesting or credential phishing.'
        });
        break;
      }
    }

    if (!typosquatMatch) {
      for (const brand of BRAND_TARGETS) {
        if (sld !== brand) {
          const distance = levenshteinDistance(sld, brand);
          if (distance >= 1 && distance <= 2 && Math.abs(sld.length - brand.length) <= 2) {
            typosquatMatch = { targetBrand: brand, distance };
            flags.push({
              id: 'FLAG-TYPOSQUATTING',
              name: 'Brand Typosquatting Impersonation Detected',
              severity: 'CRITICAL',
              weight: 45,
              description: `Domain label "${sld}" is visually similar to registered brand "${brand}" (Levenshtein distance: ${distance}).`,
              securityReasoning: 'Typosquatting is a high-confidence indicator of brand spoofing intended for credential harvesting or credential phishing.'
            });
            break;
          }
        }
      }
    }
  }

  // 4. LOCAL CSV BLOCKLIST MATCH
  // Security Reasoning: Cross-references target against offline local SOC analyst blocklist database.
  const blocklist = loadLocalBlocklist();
  let blocklistMatch: { pattern: string; category: string } | null = null;
  for (const entry of blocklist) {
    if (entry.pattern && (hostname === entry.pattern || rawUrl.includes(entry.pattern))) {
      blocklistMatch = { pattern: entry.pattern, category: entry.category };
      flags.push({
        id: 'FLAG-LOCAL-BLOCKLIST',
        name: 'Local SOC Blocklist Match',
        severity: entry.severity === 'CRITICAL' ? 'CRITICAL' : 'HIGH',
        weight: entry.severity === 'CRITICAL' ? 50 : 35,
        description: `Target matched active blocklist entry: "${entry.pattern}" (${entry.category} - ${entry.description}).`,
        securityReasoning: 'Local blocklists reflect confirmed malicious indicators seeded by security analysts.'
      });
      break;
    }
  }

  // 5-10. PARALLEL NETWORK & THREAT INTELLIGENCE LOOKUPS (INCLUDING VIRUSTOTAL)
  const [redirectRes, tlsRes, whoisRes, urlhausRes, phishstatsRes, vtRes] = await Promise.allSettled([
    followRedirectChain(rawUrl),
    (parsedUrl.protocol === 'https:' && !isIpLiteral) ? inspectTlsCert(hostname, parsedUrl.port ? parseInt(parsedUrl.port, 10) : 443) : Promise.resolve(null),
    (!isIpLiteral && hostname.includes('.')) ? lookupDomainAge(hostname) : Promise.resolve({ domainAgeDays: null, registrar: null }),
    checkUrlhausApi(rawUrl),
    checkPhishStats(rawUrl),
    checkVirusTotalUrl(rawUrl)
  ]);

  const redirectInfo = redirectRes.status === 'fulfilled' ? redirectRes.value : { finalUrl: rawUrl, redirectChain: [rawUrl] };
  const tlsInfo = tlsRes.status === 'fulfilled' ? tlsRes.value : null;
  const whoisInfo = whoisRes.status === 'fulfilled' ? whoisRes.value : { domainAgeDays: null, registrar: null };
  const urlhausMatch = urlhausRes.status === 'fulfilled' ? urlhausRes.value : null;
  const phishstatsMatch = phishstatsRes.status === 'fulfilled' ? phishstatsRes.value : null;
  const vtMatch = vtRes.status === 'fulfilled' ? vtRes.value : null;

  if (redirectInfo.redirectChain.length > 2) {
    flags.push({
      id: 'FLAG-REDIRECT-CHAIN',
      name: 'Multi-Stage Redirect Chain Detected',
      severity: 'MEDIUM',
      weight: 20,
      description: `URL executed ${redirectInfo.redirectChain.length - 1} HTTP redirects leading to final target: "${redirectInfo.finalUrl}".`,
      securityReasoning: 'Multi-hop redirects are frequently used in phishing campaigns to obscure final payload targets and bypass automated scanners.'
    });
  }

  if (tlsInfo) {
    if (!tlsInfo.valid) {
      flags.push({
        id: 'FLAG-TLS-INVALID',
        name: 'Invalid or Self-Signed TLS Certificate',
        severity: 'HIGH',
        weight: 30,
        description: 'The target HTTPS connection failed certificate authority validation.',
        securityReasoning: 'Invalid TLS certificates allow Man-in-the-Middle (MitM) inspection or indicate unverified server infrastructure.'
      });
    }
    if (tlsInfo.ageDays !== undefined && tlsInfo.ageDays < 14) {
      flags.push({
        id: 'FLAG-TLS-NEW-CERT',
        name: 'Recently Issued TLS Certificate (<14 Days)',
        severity: 'MEDIUM',
        weight: 20,
        description: `TLS certificate was issued only ${tlsInfo.ageDays} days ago (Issuer: ${tlsInfo.issuer}).`,
        securityReasoning: 'Attackers generate free, short-lived TLS certificates immediately prior to launching phishing campaigns.'
      });
    }
  }

  if (whoisInfo && whoisInfo.domainAgeDays !== null && whoisInfo.domainAgeDays < 30) {
    flags.push({
      id: 'FLAG-NEWLY-REGISTERED-DOMAIN',
      name: 'Newly Registered Domain (<30 Days Old)',
      severity: 'HIGH',
      weight: 35,
      description: `Domain registration age is only ${whoisInfo.domainAgeDays} days old.`,
      securityReasoning: 'Newly registered domains represent high-risk ephemeral infrastructure commonly abandoned after phishing campaigns.'
    });
  }

  if (urlhausMatch && urlhausMatch.matched) {
    flags.push({
      id: 'FLAG-URLHAUS-MALWARE-MATCH',
      name: 'URLhaus Confirmed Malicious URL Match',
      severity: 'CRITICAL',
      weight: 65,
      description: `Target is listed in the URLhaus malware database (Threat: "${urlhausMatch.threat || 'malware_download'}", Status: ${urlhausMatch.urlStatus || 'active'}${urlhausMatch.tags?.length ? `, Tags: ${urlhausMatch.tags.join(', ')}` : ''}).`,
      securityReasoning: 'URLhaus is an official cybersecurity threat intelligence repository documenting active malware distribution URLs and payloads.'
    });
  }

  if (phishstatsMatch && phishstatsMatch.matched) {
    flags.push({
      id: 'FLAG-PHISHSTATS-ZERO-DAY-MATCH',
      name: 'PhishStats Zero-Day Phishing Target Flagged',
      severity: 'CRITICAL',
      weight: 60,
      description: `Target matched active zero-day phishing campaign (Target: "${phishstatsMatch.target || 'Brand Impersonation'}", Host IP: ${phishstatsMatch.ip || 'N/A'}, Country: ${phishstatsMatch.country || 'N/A'}).`,
      securityReasoning: 'PhishStats monitors active phishing host deployments and zero-day brand impersonation URLs.'
    });
  }

  if (vtMatch && vtMatch.matched) {
    const isCritical = vtMatch.maliciousCount >= 3;
    flags.push({
      id: 'FLAG-VIRUSTOTAL-MALICIOUS-MATCH',
      name: `VirusTotal Flagged Malicious (${vtMatch.maliciousCount}/${vtMatch.totalEngines} AV Engines)`,
      severity: isCritical ? 'CRITICAL' : 'HIGH',
      weight: isCritical ? 70 : 45,
      description: `Target was flagged as malicious or suspicious by ${vtMatch.maliciousCount} global antivirus engines${vtMatch.flaggedEngines.length ? ` (Top Flagged: ${vtMatch.flaggedEngines.join(', ')})` : ''}.`,
      securityReasoning: 'VirusTotal aggregates real-time threat intelligence from over 70 leading antivirus scanners and URL reputation engines.'
    });
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
    scannerType: 'url',
    target: inputUrl,
    timestamp,
    riskScore,
    riskLevel,
    triggeredFlags: flags,
    details: {
      urlDetails: {
        originalUrl: inputUrl,
        finalUrl: redirectInfo.finalUrl,
        redirectChain: redirectInfo.redirectChain,
        isIpLiteral,
        domain: hostname,
        tld,
        suspiciousTldFlagged,
        typosquatMatch,
        blocklistMatch,
        tlsInfo,
        whoisInfo,
        urlhausMatch,
        phishstatsMatch
      }
    }
  };
}

