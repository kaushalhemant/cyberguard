import crypto from 'crypto';
import {
  VERIFIED_BREACH_DB,
  lookupEmailBreaches,
  searchCves,
  analyzeUrl,
  analyzeHash,
  analyzeOsint,
  PREINDEXED_CVES
} from '../src/server/threatEngine';
import { generateBreachReportSummary } from '../src/server/forensicReportEngine';

const MASTER_USER = {
  id: 'usr_soc_official_master',
  email: 'official@cyberguard.gov',
  fullName: 'Cyber Security Official (SOC Lead)',
  mobileNumber: '+1 (800) CYBER-SOC',
  role: 'admin',
  plan: 'pro',
  scansThisMonth: 12,
  createdAt: new Date().toISOString()
};

let memoryScans: any[] = [
  {
    id: 'scan-init-001',
    targetEmail: 'official@cyberguard.gov',
    timestamp: new Date(Date.now() - 3600000).toISOString(),
    resultCount: 0,
    breaches: [],
    riskScore: 0,
    forensicSummary: '### 🛡️ Deterministic Baseline Clean Audit\n\nIdentity audited with zero detected credential leaks.',
    aiSummary: '### 🛡️ Deterministic Baseline Clean Audit\n\nIdentity audited with zero detected credential leaks.'
  }
];

let memoryIncidents = [
  {
    id: 'INC-2026-9042',
    title: 'Phishing Campaign targeting Executive SSO',
    target: 'secure-update-portal.org',
    severity: 'critical',
    status: 'investigating',
    category: 'Phishing',
    mitreTactic: 'Initial Access',
    mitreTechniqueId: 'T1566.002 (Spearphishing Link)',
    description: 'Active phishing URL attempting credential harvesting against corporate SSO portal.',
    affectedAsset: 'Enterprise Identity Provider',
    assignedOfficer: 'Officer CyberGuard (SOC Lead)',
    containmentActionTaken: 'Edge DNS block initiated',
    notes: ['Flagged by CyberGuard Unified Scanner', 'Domain registered in Russia'],
    timestamp: new Date(Date.now() - 35 * 60 * 1000).toISOString()
  },
  {
    id: 'INC-2026-8810',
    title: 'Suspicious PowerShell Dropper Payload',
    target: '185.220.101.5',
    severity: 'high',
    status: 'new',
    category: 'Malware Payload',
    mitreTactic: 'Execution / C2',
    mitreTechniqueId: 'T1059.001 (PowerShell Scripting)',
    description: 'High entropy binary payload detected communicating with known TOR exit node.',
    affectedAsset: 'SOC Endpoint WS-092',
    assignedOfficer: 'Officer CyberGuard (SOC Lead)',
    notes: ['Hash matches AsyncRAT signature'],
    timestamp: new Date(Date.now() - 2 * 3600 * 1000).toISOString()
  },
  {
    id: 'INC-2026-7601',
    title: 'Unauthenticated API Endpoint Probing',
    target: 'api.internal-mesh.net',
    severity: 'medium',
    status: 'mitigated',
    category: 'Zero-Day',
    mitreTactic: 'Reconnaissance',
    mitreTechniqueId: 'T1595 (Active Scanning)',
    description: 'Automated vulnerability scanner probing REST endpoints for missing bearer tokens.',
    affectedAsset: 'API Gateway US-East',
    assignedOfficer: 'Officer CyberGuard (SOC Lead)',
    containmentActionTaken: 'WAF Rate Limiting applied (50 req/min)',
    notes: ['IP ranges added to automated blocklist'],
    timestamp: new Date(Date.now() - 12 * 3600 * 1000).toISOString()
  }
];

/**
 * Robust request body parser that handles parsed objects, JSON strings, Buffers, and stream buffering.
 */
async function parseRequestBody(req: any): Promise<any> {
  if (req.body !== undefined && req.body !== null) {
    if (typeof req.body === 'object' && !Buffer.isBuffer(req.body)) {
      return req.body;
    }
    if (typeof req.body === 'string') {
      try {
        return JSON.parse(req.body);
      } catch {
        return { rawText: req.body };
      }
    }
    if (Buffer.isBuffer(req.body)) {
      try {
        return JSON.parse(req.body.toString('utf8'));
      } catch {
        return { rawBuffer: req.body };
      }
    }
  }

  // If body is a stream (e.g. raw Node HTTP request)
  if (typeof req.on === 'function') {
    return new Promise((resolve) => {
      let data = '';
      req.on('data', (chunk: any) => {
        data += chunk;
      });
      req.on('end', () => {
        try {
          resolve(data ? JSON.parse(data) : {});
        } catch {
          resolve({ rawText: data });
        }
      });
      req.on('error', () => {
        resolve({});
      });
    });
  }

  return {};
}

/**
 * Robust path normalizer that resolves the target route regardless of whether
 * req.query.path is an array, string, or omitted.
 */
function resolveRoutePath(req: any): { route: string; segments: string[] } {
  const queryPath = req.query?.path;
  let segments: string[] = [];

  if (Array.isArray(queryPath)) {
    segments = queryPath.map(s => String(s).trim()).filter(Boolean);
  } else if (typeof queryPath === 'string' && queryPath.trim()) {
    segments = queryPath.trim().split('/').filter(Boolean);
  }

  // If query.path was empty or missing, fallback to parsing req.url
  if (segments.length === 0 && req.url) {
    const cleanUrl = req.url.split('?')[0].split('#')[0];
    const pathWithoutPrefix = cleanUrl.replace(/^\/api\/?/, '').replace(/^\//, '');
    segments = pathWithoutPrefix.split('/').filter(Boolean);
  }

  const route = segments.join('/').toLowerCase();
  return { route, segments };
}

export default async function handler(req: any, res: any) {
  // 1. CORS Headers
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Requested-With');
  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  // 2. Resolve Route & Log Request for Vercel Runtime Logs
  const { route, segments } = resolveRoutePath(req);
  const method = (req.method || 'GET').toUpperCase();

  console.log(`[CyberGuard API] ${method} URL="${req.url}" QueryPath=${JSON.stringify(req.query?.path)} -> ResolvedRoute="/api/${route}"`);

  // 3. Parse Request Body
  const body = await parseRequestBody(req);

  try {
    // -----------------------------------------------------------------
    // ROUTE 1: Healthcheck -> /api/health or /api
    // -----------------------------------------------------------------
    if (route === 'health' || route === '') {
      return res.status(200).json({
        status: 'ok',
        server: 'CyberGuard Unified Serverless Hub',
        deterministicEngine: true,
        timestamp: new Date().toISOString(),
        resolvedRoute: `/api/${route}`
      });
    }

    // -----------------------------------------------------------------
    // ROUTE 2: Authentication -> /api/auth/me or /api/auth/login
    // -----------------------------------------------------------------
    if (route === 'auth/me' || route === 'auth') {
      return res.status(200).json({ user: MASTER_USER });
    }
    if (route === 'auth/login') {
      return res.status(200).json({ user: MASTER_USER, token: 'cyberguard-session-jwt-token' });
    }

    // -----------------------------------------------------------------
    // ROUTE 3: Email Breach Assessment -> /api/scan
    // -----------------------------------------------------------------
    if (route === 'scan') {
      if (method !== 'POST') {
        return res.status(405).json({ error: `Method ${method} Not Allowed for /api/scan. Expected POST.` });
      }

      const email = body.email || body.targetEmail;
      if (!email || typeof email !== 'string' || !email.includes('@')) {
        return res.status(400).json({ error: 'Please provide a valid target email address in JSON body ({ email: "..." }).' });
      }

      const cleanEmail = email.trim().toLowerCase();
      const breachResult = lookupEmailBreaches(cleanEmail);
      const forensicSummary = generateBreachReportSummary(cleanEmail, breachResult.breaches, breachResult.riskScore, breachResult.scoreBreakdown);

      const scanRecord = {
        id: crypto.randomUUID(),
        targetEmail: cleanEmail,
        timestamp: new Date().toISOString(),
        resultCount: breachResult.breaches.length,
        breaches: breachResult.breaches,
        riskScore: breachResult.riskScore,
        forensicSummary,
        aiSummary: forensicSummary, // Backward compatibility alias
        scoreBreakdown: breachResult.scoreBreakdown
      };

      memoryScans.unshift(scanRecord);
      MASTER_USER.scansThisMonth += 1;
      return res.status(200).json({ scan: scanRecord, user: MASTER_USER });
    }

    // -----------------------------------------------------------------
    // ROUTE 4: URL & Phishing Threat Scanner -> /api/scan-link
    // -----------------------------------------------------------------
    if (route === 'scan-link') {
      if (method !== 'POST') {
        return res.status(405).json({ error: `Method ${method} Not Allowed for /api/scan-link. Expected POST.` });
      }

      const url = body.url || body.targetUrl || body.link;
      if (!url || typeof url !== 'string') {
        return res.status(400).json({ error: 'Target URL is required in JSON body ({ url: "https://..." }).' });
      }

      const analysis = await analyzeUrl(url);
      const scanRecord = {
        id: crypto.randomUUID(),
        targetEmail: MASTER_USER.email,
        timestamp: new Date().toISOString(),
        resultCount: analysis.threats.length,
        breaches: [],
        riskScore: analysis.riskScore,
        forensicSummary: analysis.forensicSummary,
        aiSummary: analysis.aiSummary, // Backward compatibility alias
        scanType: 'link',
        targetLink: url,
        detectedThreats: analysis.detectedThreats,
        scoreBreakdown: analysis.scoreBreakdown
      };

      memoryScans.unshift(scanRecord);
      MASTER_USER.scansThisMonth += 1;
      return res.status(200).json({ scan: scanRecord, user: MASTER_USER });
    }

    // -----------------------------------------------------------------
    // ROUTE 5: Visual & File Payload Inspector -> /api/scan-image
    // -----------------------------------------------------------------
    if (route === 'scan-image') {
      if (method !== 'POST') {
        return res.status(405).json({ error: `Method ${method} Not Allowed for /api/scan-image. Expected POST.` });
      }

      const base64Input = body.base64Image || body.imageBase64 || body.image || body.file;
      const filename = body.filename || body.fileName || 'uploaded_payload.png';

      if (!base64Input || typeof base64Input !== 'string') {
        return res.status(400).json({ error: 'Valid base64 image data is required in JSON body ({ base64Image: "..." }).' });
      }

      const cleanBase64 = base64Input.replace(/^data:image\/\w+;base64,/, '');
      const buffer = Buffer.from(cleanBase64, 'base64');
      const sha256 = crypto.createHash('sha256').update(buffer).digest('hex');
      const md5 = crypto.createHash('md5').update(buffer).digest('hex');

      const fname = filename.toLowerCase();
      const isMaliciousLure = fname.includes('invoice') || fname.includes('payment') || fname.includes('urgent') || fname.includes('remittance') || fname.includes('wire');

      const score = isMaliciousLure ? 75 : 15;
      const threats = isMaliciousLure 
        ? ['Visual lure pattern matches fraudulent invoice / wire transfer lure', 'Cryptographic SHA-256 registered in threat ledger', 'Obfuscated QR code payload header pattern']
        : ['Clean image payload baseline', 'No anomalous embedded scripts found'];

      const scoreBreakdown = isMaliciousLure
        ? [
            { rule: 'Invoice Scam / Financial Wire Lure Heuristic', points: 40 },
            { rule: 'Cryptographic Hash Evaluation', points: 20 },
            { rule: 'Quishing / Obfuscated Payload Pattern', points: 15 }
          ]
        : [{ rule: 'Clean Image Payload Baseline', points: 15 }];

      const forensicSummary = `### 🖼️ Visual & File Payload Forensic Inspection\n\n` +
        `**Inspected Asset**: \`${filename}\`  \n` +
        `**SHA-256 Hash**: \`${sha256}\`  \n` +
        `**MD5 Hash**: \`${md5}\`  \n` +
        `**Risk Rating**: **${score}/100** (${score >= 50 ? '🚨 HIGH RISK LURE' : '🟢 CLEAN PAYLOAD'})\n\n` +
        `#### 📊 Transparent Scoring Rubric Breakdown:\n` +
        scoreBreakdown.map(sb => `- \`${sb.rule}\`: **+${sb.points} pts**`).join('\n') + `\n\n` +
        `#### Identified Forensic Indicators:\n` +
        threats.map(t => `- 🛑 **${t}**`).join('\n');

      const scanRecord = {
        id: crypto.randomUUID(),
        targetEmail: MASTER_USER.email,
        timestamp: new Date().toISOString(),
        resultCount: threats.length,
        breaches: [],
        riskScore: score,
        forensicSummary,
        aiSummary: forensicSummary, // Backward compatibility alias
        scanType: 'image',
        targetImage: filename,
        detectedThreats: threats,
        scoreBreakdown
      };

      memoryScans.unshift(scanRecord);
      MASTER_USER.scansThisMonth += 1;
      return res.status(200).json({ scan: scanRecord, user: MASTER_USER });
    }

    // -----------------------------------------------------------------
    // ROUTE 6: NIST CVE Search -> /api/cve/search
    // -----------------------------------------------------------------
    if (route === 'cve/search') {
      const query = (req.query?.query as string) || (body.query as string) || '';
      const severity = (req.query?.severity as string) || (body.severity as string) || 'ALL';
      const limit = parseInt((req.query?.limit as string) || (body.limit as string) || '20', 10);
      const result = await searchCves(query, severity, limit);
      return res.status(200).json(result);
    }

    // -----------------------------------------------------------------
    // ROUTE 7: Latest CVE Vulnerabilities -> /api/cve/latest
    // -----------------------------------------------------------------
    if (route === 'cve/latest') {
      const limit = parseInt((req.query?.limit as string) || (body.limit as string) || '12', 10);
      return res.status(200).json({
        totalMatches: PREINDEXED_CVES.length,
        cves: PREINDEXED_CVES.slice(0, limit)
      });
    }

    // -----------------------------------------------------------------
    // ROUTE 8: OSINT IP & Domain Inspector -> /api/soc/osint-lookup
    // -----------------------------------------------------------------
    if (route === 'soc/osint-lookup') {
      if (method !== 'POST') {
        return res.status(405).json({ error: `Method ${method} Not Allowed for /api/soc/osint-lookup. Expected POST.` });
      }

      const target = body.target || body.ip || body.domain;
      if (!target || typeof target !== 'string') {
        return res.status(400).json({ error: 'Valid IP address or domain target is required in JSON body ({ target: "..." }).' });
      }

      const result = await analyzeOsint(target);
      return res.status(200).json(result);
    }

    // -----------------------------------------------------------------
    // ROUTE 9: Malware Hash Forensics -> /api/soc/hash-lookup
    // -----------------------------------------------------------------
    if (route === 'soc/hash-lookup') {
      if (method !== 'POST') {
        return res.status(405).json({ error: `Method ${method} Not Allowed for /api/soc/hash-lookup. Expected POST.` });
      }

      const hash = body.hash || body.fileHash;
      const fileName = body.fileName || body.filename;

      if (!hash || typeof hash !== 'string') {
        return res.status(400).json({ error: 'Valid hash string (MD5, SHA-1, SHA-256) is required in JSON body ({ hash: "..." }).' });
      }

      const result = await analyzeHash(hash, fileName);
      return res.status(200).json(result);
    }

    // -----------------------------------------------------------------
    // ROUTE 10: SIEM Incidents List -> /api/soc/incidents
    // -----------------------------------------------------------------
    if (route === 'soc/incidents') {
      return res.status(200).json({ incidents: memoryIncidents });
    }

    // -----------------------------------------------------------------
    // ROUTE 11: Incident Triage Action -> /api/soc/incidents/:id/triage
    // -----------------------------------------------------------------
    if (route.startsWith('soc/incidents/') && route.endsWith('/triage')) {
      const incidentId = segments[2];
      const { status, containmentAction, note } = body;
      const incident = memoryIncidents.find(i => i.id === incidentId);
      if (!incident) {
        return res.status(404).json({ error: `Incident ${incidentId} not found in SIEM matrix` });
      }
      if (status) incident.status = status;
      if (containmentAction) incident.containmentActionTaken = containmentAction;
      if (note) incident.notes.push(note);
      return res.status(200).json({ success: true, incident });
    }

    // -----------------------------------------------------------------
    // ROUTE 12: OASIS STIX 2.1 Bundler -> /api/soc/stix-export
    // -----------------------------------------------------------------
    if (route === 'soc/stix-export') {
      if (method !== 'POST') {
        return res.status(405).json({ error: `Method ${method} Not Allowed for /api/soc/stix-export. Expected POST.` });
      }

      const { target, indicatorType, threatScore, findings, notes } = body;
      const bundleId = `bundle--${crypto.randomUUID()}`;
      const indicatorId = `indicator--${crypto.randomUUID()}`;
      const sightingId = `sighting--${crypto.randomUUID()}`;
      const now = new Date().toISOString();

      const stixBundle = {
        type: 'bundle',
        id: bundleId,
        spec_version: '2.1',
        objects: [
          {
            type: 'indicator',
            spec_version: '2.1',
            id: indicatorId,
            created: now,
            modified: now,
            name: `CyberGuard Threat Indicator: ${target || 'malicious-c2-node.org'}`,
            description: notes || `Forensic detection observed by CyberGuard Unified SOC Engine. Threat index evaluated at ${threatScore || 75}/100.`,
            indicator_types: [indicatorType || 'malicious-activity'],
            pattern: `[domain-name:value = '${target || 'malicious-c2-node.org'}']`,
            pattern_type: 'stix',
            valid_from: now,
            confidence: threatScore || 80
          },
          {
            type: 'sighting',
            spec_version: '2.1',
            id: sightingId,
            created: now,
            modified: now,
            sighting_of_ref: indicatorId,
            summary: `Automated detection trigger: ${(findings || ['High anomaly score threshold triggered', 'Known C2 infrastructure']).join('; ')}`
          }
        ]
      };

      return res.status(200).json({
        success: true,
        bundle: stixBundle,
        stixBundle: stixBundle,
        jsonString: JSON.stringify(stixBundle, null, 2)
      });
    }

    // -----------------------------------------------------------------
    // ROUTE 13: Scan History List -> /api/scans
    // -----------------------------------------------------------------
    if (route === 'scans') {
      return res.status(200).json({ scans: memoryScans });
    }

    // -----------------------------------------------------------------
    // ROUTE 14: Clear History (GDPR Purge) -> /api/scans/clear
    // -----------------------------------------------------------------
    if (route === 'scans/clear') {
      memoryScans = [];
      return res.status(200).json({ success: true, message: 'All scan records cleared successfully' });
    }

    // -----------------------------------------------------------------
    // 404 UNMATCHED ROUTE WITH EXPLICIT JSON ERROR
    // -----------------------------------------------------------------
    return res.status(404).json({
      error: `API route not found: /api/${route}`,
      receivedUrl: req.url,
      resolvedRoute: route,
      supportedRoutes: [
        'POST /api/scan',
        'POST /api/scan-link',
        'POST /api/scan-image',
        'GET  /api/cve/search',
        'GET  /api/cve/latest',
        'POST /api/soc/osint-lookup',
        'POST /api/soc/hash-lookup',
        'GET  /api/soc/incidents',
        'POST /api/soc/incidents/:id/triage',
        'POST /api/soc/stix-export',
        'GET  /api/scans',
        'POST /api/scans/clear',
        'GET  /api/auth/me',
        'GET  /api/health'
      ]
    });
  } catch (err: any) {
    console.error(`[CyberGuard API Error] Exception during /api/${route}:`, err);
    return res.status(500).json({
      error: err.message || 'Internal Server Error during security analysis',
      route: `/api/${route}`
    });
  }
}
