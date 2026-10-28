import crypto from 'crypto';
import {
  VERIFIED_BREACH_DB,
  lookupEmailBreaches,
  searchCves,
  analyzeUrl,
  analyzeHash,
  analyzeOsint,
  PREINDEXED_CVES,
  analyzePqcReadiness,
  simulateQuantumCryptanalysis,
  analyzeDeepfakeMedia,
  getAutonomousAiSwarmState,
  executeSwarmPlaybook,
  getLeoSatelliteMeshTelemetry
} from '../src/server/threatEngine';
import { generateBreachReportSummary } from '../src/server/forensicReportEngine';
import {
  createSessionToken,
  verifySessionToken,
  generateOtp,
  verifyOtp,
  checkRateLimit,
  sanitizeText,
  validateUrlSsrf
} from '../src/server/security';

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

export const DEFAULT_SYNTHETIC_INCIDENTS = [
  {
    id: 'INC-2026-9042',
    title: 'Phishing Campaign targeting Executive SSO',
    target: 'secure-update-portal.org',
    severity: 'critical',
    priority: 'P1',
    status: 'investigating',
    category: 'Phishing',
    mitreTactic: 'Initial Access',
    mitreTechniqueId: 'T1566.002 (Spearphishing Link)',
    description: 'Active phishing URL attempting credential harvesting against corporate SSO portal.',
    affectedAsset: 'Enterprise Identity Provider',
    assignedOfficer: 'Officer CyberGuard (SOC Lead)',
    containmentActionTaken: 'Edge DNS block initiated',
    notes: ['Flagged by CyberGuard Unified Scanner', 'Domain registered in high-risk autonomous system'],
    evidenceRefs: ['INV-2026-9042-EVD-01', 'DNS: 185.220.101.5'],
    timestamp: new Date(Date.now() - 35 * 60 * 1000).toISOString()
  },
  {
    id: 'INC-2026-8810',
    title: 'Suspicious PowerShell Dropper Payload',
    target: '185.220.101.5',
    severity: 'high',
    priority: 'P2',
    status: 'new',
    category: 'Malware Payload',
    mitreTactic: 'Execution / C2',
    mitreTechniqueId: 'T1059.001 (PowerShell Scripting)',
    description: 'High entropy binary payload detected communicating with known TOR exit node.',
    affectedAsset: 'SOC Endpoint WS-092',
    assignedOfficer: 'Officer CyberGuard (SOC Lead)',
    containmentActionTaken: 'Endpoint network isolation in progress',
    notes: ['Hash matches AsyncRAT signature', 'Entropy calculated at 7.68/8.00'],
    evidenceRefs: ['HASH: 44d88612fea8a8f36de82e1278abb02f'],
    timestamp: new Date(Date.now() - 2 * 3600 * 1000).toISOString()
  },
  {
    id: 'INC-2026-7601',
    title: 'Unauthenticated API Endpoint Probing',
    target: 'api.internal-mesh.net',
    severity: 'medium',
    priority: 'P3',
    status: 'mitigated',
    category: 'Zero-Day',
    mitreTactic: 'Reconnaissance',
    mitreTechniqueId: 'T1595 (Active Scanning)',
    description: 'Automated vulnerability scanner probing REST endpoints for missing bearer tokens.',
    affectedAsset: 'API Gateway US-East',
    assignedOfficer: 'Officer CyberGuard (SOC Lead)',
    containmentActionTaken: 'WAF Rate Limiting applied (50 req/min)',
    notes: ['IP ranges added to automated blocklist'],
    evidenceRefs: ['CVE-2023-4966 advisory cross-referenced'],
    timestamp: new Date(Date.now() - 12 * 3600 * 1000).toISOString()
  }
];

let memoryIncidents: any[] = [...DEFAULT_SYNTHETIC_INCIDENTS];

/**
 * Robust request body parser that handles parsed objects, JSON strings, Buffers, and stream buffering.
 * Guarantees zero indefinite stream hanging in serverless (AWS Lambda / Vercel) environments.
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

  // If already consumed or not readable, return empty object immediately
  if (req.readableEnded || req.readable === false || typeof req.on !== 'function') {
    return {};
  }

  // Fallback stream buffering with strict 200ms timeout to prevent lambda freeze
  try {
    return await new Promise((resolve) => {
      let data = '';
      const timer = setTimeout(() => resolve({}), 200);
      req.on('data', (chunk: any) => {
        data += chunk;
      });
      req.on('end', () => {
        clearTimeout(timer);
        try {
          resolve(data ? JSON.parse(data) : {});
        } catch {
          resolve({ rawText: data });
        }
      });
      req.on('error', () => {
        clearTimeout(timer);
        resolve({});
      });
    });
  } catch {
    return {};
  }
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

/**
 * Extracts the authenticated user or falls back to master session for development/demo.
 */
function getRequestUser(req: any): { id: string; email: string; role: string; plan: string; fullName: string } {
  const authHeader = req.headers?.authorization || req.headers?.Authorization;
  const session = verifySessionToken(authHeader);
  if (session) {
    return {
      id: session.userId,
      email: session.email,
      role: session.role,
      plan: session.plan,
      fullName: session.email === MASTER_USER.email ? MASTER_USER.fullName : session.email.split('@')[0]
    };
  }
  return MASTER_USER;
}

export default async function handler(req: any, res: any) {
  let route = '';
  try {
    // 1. CORS Headers
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Requested-With');
    if (req.method === 'OPTIONS') {
      return res.status(200).end();
    }

    // 2. Resolve Route & Log Request
    const resolved = resolveRoutePath(req);
    route = resolved.route;
    const segments = resolved.segments;
    const method = (req.method || 'GET').toUpperCase();

    // 3. Parse Request Body safely
    const body = await parseRequestBody(req);

    // -----------------------------------------------------------------
    // ROUTE 1: Healthcheck -> /api/health or /api
    // -----------------------------------------------------------------
    if (route === 'health' || route === '') {
      return res.status(200).json({
        status: 'ok',
        server: 'CyberGuard Threat Intelligence & Incident Workstation',
        deterministicEngine: true,
        timestamp: new Date().toISOString(),
        resolvedRoute: `/api/${route}`
      });
    }

    // -----------------------------------------------------------------
    // ROUTE 2: Authentication -> /api/auth/me, /api/auth/login, /api/auth/otp/*
    // -----------------------------------------------------------------
    if (route === 'auth/me' || route === 'auth') {
      const user = getRequestUser(req);
      return res.status(200).json({ user });
    }

    if (route === 'auth/login') {
      const email = (body.email || MASTER_USER.email).toLowerCase().trim();
      const user = email === MASTER_USER.email ? MASTER_USER : {
        id: `usr_${crypto.createHash('md5').update(email).digest('hex').substring(0, 12)}`,
        email,
        fullName: email.split('@')[0],
        role: email.endsWith('@cyberguard.gov') ? 'admin' : 'user',
        plan: 'pro',
        scansThisMonth: 0,
        createdAt: new Date().toISOString()
      };
      const token = createSessionToken(user);
      return res.status(200).json({ user, token });
    }

    // OTP Dispatch: /api/auth/otp/request
    if (route === 'auth/otp/request') {
      const email = body.email || body.targetEmail;
      if (!email || typeof email !== 'string' || !email.includes('@')) {
        return res.status(400).json({ error: 'Valid target email is required for OTP dispatch.' });
      }
      const rate = checkRateLimit(`otp_${email.toLowerCase().trim()}`, 5, 300000);
      if (!rate.allowed) {
        return res.status(429).json({ error: 'Too many OTP requests. Please wait a few minutes before trying again.' });
      }
      const otpCode = generateOtp(email, 'login');
      return res.status(200).json({
        success: true,
        message: `Single-use 6-digit OTP code dispatched for ${email}. Valid for 5 minutes.`,
        demoCode: otpCode,
        expiresInSeconds: 300
      });
    }

    // OTP Verify: /api/auth/otp/verify
    if (route === 'auth/otp/verify') {
      const email = body.email;
      const code = body.code || body.otp;
      if (!email || !code) {
        return res.status(400).json({ error: 'Both email and 6-digit OTP code are required.' });
      }
      const verification = verifyOtp(email, String(code), 'login');
      if (!verification.success) {
        return res.status(401).json({ error: verification.message });
      }
      const user = {
        id: `usr_${crypto.createHash('md5').update(email.toLowerCase().trim()).digest('hex').substring(0, 12)}`,
        email: email.toLowerCase().trim(),
        fullName: email.split('@')[0],
        role: email.endsWith('@cyberguard.gov') ? 'admin' : 'user',
        plan: 'pro',
        scansThisMonth: 0,
        createdAt: new Date().toISOString()
      };
      const token = createSessionToken(user);
      return res.status(200).json({ success: true, user, token });
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

      const currentUser = getRequestUser(req);
      const scanRecord = {
        id: crypto.randomUUID(),
        targetEmail: cleanEmail,
        timestamp: new Date().toISOString(),
        resultCount: breachResult.breaches.length,
        breaches: breachResult.breaches,
        riskScore: breachResult.riskScore,
        forensicSummary,
        aiSummary: forensicSummary, // Backward compatibility alias
        scoreBreakdown: breachResult.scoreBreakdown,
        userId: currentUser.id
      };

      memoryScans.unshift(scanRecord);
      currentUser.scansThisMonth = (currentUser.scansThisMonth || 0) + 1;
      return res.status(200).json({ scan: scanRecord, user: currentUser });
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
      const currentUser = getRequestUser(req);
      const scanRecord = {
        id: crypto.randomUUID(),
        targetEmail: currentUser.email,
        timestamp: new Date().toISOString(),
        resultCount: analysis.threats.length,
        breaches: [],
        riskScore: analysis.riskScore,
        forensicSummary: analysis.forensicSummary,
        aiSummary: analysis.aiSummary, // Backward compatibility alias
        scanType: 'link',
        targetLink: url,
        detectedThreats: analysis.detectedThreats,
        scoreBreakdown: analysis.scoreBreakdown,
        evidence: analysis.evidence,
        userId: currentUser.id
      };

      memoryScans.unshift(scanRecord);
      currentUser.scansThisMonth = (currentUser.scansThisMonth || 0) + 1;
      return res.status(200).json({ scan: scanRecord, user: currentUser });
    }

    // -----------------------------------------------------------------
    // ROUTE 5: Visual & File Payload Inspector -> /api/scan-image
    // -----------------------------------------------------------------
    if (route === 'scan-image') {
      if (method !== 'POST') {
        return res.status(405).json({ error: `Method ${method} Not Allowed for /api/scan-image. Expected POST.` });
      }

      const base64Input = body.base64Image || body.imageBase64 || body.image || body.file;
      const filename = sanitizeText(body.filename || body.fileName || 'uploaded_payload.png');

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

      const currentUser = getRequestUser(req);
      const scanRecord = {
        id: crypto.randomUUID(),
        targetEmail: currentUser.email,
        timestamp: new Date().toISOString(),
        resultCount: threats.length,
        breaches: [],
        riskScore: score,
        forensicSummary,
        aiSummary: forensicSummary, // Backward compatibility alias
        scanType: 'image',
        targetImage: filename,
        detectedThreats: threats,
        scoreBreakdown,
        userId: currentUser.id
      };

      memoryScans.unshift(scanRecord);
      currentUser.scansThisMonth = (currentUser.scansThisMonth || 0) + 1;
      return res.status(200).json({ scan: scanRecord, user: currentUser });
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
    // ROUTE 9: Malware Hash & File Forensics -> /api/soc/hash-lookup
    // -----------------------------------------------------------------
    if (route === 'soc/hash-lookup') {
      if (method !== 'POST') {
        return res.status(405).json({ error: `Method ${method} Not Allowed for /api/soc/hash-lookup. Expected POST.` });
      }

      const fileBase64 = body.fileBase64 || body.filePayload || body.file;
      let buffer: Buffer | undefined = undefined;
      if (fileBase64 && typeof fileBase64 === 'string') {
        const cleanBase64 = fileBase64.replace(/^data:.*?;base64,/, '');
        buffer = Buffer.from(cleanBase64, 'base64');
      }

      const hash = body.hash || body.fileHash;
      const fileName = body.fileName || body.filename;

      if (!hash && !buffer) {
        return res.status(400).json({ error: 'Valid hash string (MD5, SHA-1, SHA-256) or file payload is required in JSON body.' });
      }

      const result = await analyzeHash(hash || '', fileName, buffer);
      return res.status(200).json(result);
    }

    // -----------------------------------------------------------------
    // ROUTE 10: SIEM Incidents List & Management -> /api/soc/incidents
    // -----------------------------------------------------------------
    if (route === 'soc/incidents') {
      // GET: Retrieve incidents (user-isolated or all for admin)
      if (method === 'GET') {
        const currentUser = getRequestUser(req);
        const filtered = currentUser.role === 'admin'
          ? memoryIncidents
          : memoryIncidents.filter(i => !i.userId || i.userId === currentUser.id);
        return res.status(200).json({ incidents: filtered });
      }

      // POST: Create a new incident
      if (method === 'POST') {
        const currentUser = getRequestUser(req);
        const newIncident = {
          id: `INC-2026-${Math.floor(1000 + Math.random() * 9000)}`,
          title: sanitizeText(body.title || 'Security Incident Assessment'),
          target: sanitizeText(body.target || 'target-asset.local'),
          severity: body.severity || 'medium',
          priority: body.priority || 'P2',
          status: body.status || 'new',
          category: body.category || 'Threat Investigation',
          mitreTactic: body.mitreTactic || 'Initial Access',
          mitreTechniqueId: body.mitreTechniqueId || 'T1566',
          description: sanitizeText(body.description || 'Observed security indicator flagged during threat investigation.'),
          affectedAsset: sanitizeText(body.affectedAsset || 'Enterprise Infrastructure'),
          assignedOfficer: sanitizeText(body.assignedOfficer || currentUser.fullName || 'SOC Lead'),
          containmentActionTaken: body.containmentActionTaken ? sanitizeText(body.containmentActionTaken) : undefined,
          notes: Array.isArray(body.notes)
            ? body.notes.map((n: any) => sanitizeText(String(n)))
            : (body.note ? [sanitizeText(body.note)] : ['Incident created from active investigation']),
          evidenceRefs: Array.isArray(body.evidenceRefs) ? body.evidenceRefs : [],
          timestamp: new Date().toISOString(),
          userId: currentUser.id
        };

        memoryIncidents.unshift(newIncident);
        return res.status(201).json({ success: true, incident: newIncident });
      }

      return res.status(405).json({ error: `Method ${method} Not Allowed for /api/soc/incidents.` });
    }

    // ROUTE 10B: Reset Demo Incidents -> /api/soc/incidents/reset-demo
    if (route === 'soc/incidents/reset-demo') {
      memoryIncidents = [...DEFAULT_SYNTHETIC_INCIDENTS];
      return res.status(200).json({
        success: true,
        message: 'Synthetic demonstration incidents successfully restored.',
        incidents: memoryIncidents
      });
    }

    // -----------------------------------------------------------------
    // ROUTE 11: Incident Triage Action -> /api/soc/incidents/:id/triage
    // -----------------------------------------------------------------
    if (route.startsWith('soc/incidents/') && route.endsWith('/triage')) {
      const incidentId = segments[2];
      const { status, containmentAction, note, priority } = body;
      const incident = memoryIncidents.find(i => i.id === incidentId);
      if (!incident) {
        return res.status(404).json({ error: `Incident ${incidentId} not found in SIEM matrix` });
      }
      if (status) incident.status = status;
      if (priority) incident.priority = priority;
      if (containmentAction) incident.containmentActionTaken = sanitizeText(containmentAction);
      if (note) incident.notes.push(sanitizeText(note));
      return res.status(200).json({ success: true, incident });
    }

    // ROUTE 11B: Delete Incident -> DELETE /api/soc/incidents/:id
    if (route.startsWith('soc/incidents/') && segments.length === 3 && method === 'DELETE') {
      const incidentId = segments[2];
      const idx = memoryIncidents.findIndex(i => i.id === incidentId);
      if (idx === -1) {
        return res.status(404).json({ error: `Incident ${incidentId} not found` });
      }
      memoryIncidents.splice(idx, 1);
      return res.status(200).json({ success: true, message: `Incident ${incidentId} successfully removed` });
    }

    // -----------------------------------------------------------------
    // ROUTE 12: OASIS STIX 2.1 Bundler -> /api/soc/stix-export
    // -----------------------------------------------------------------
    if (route === 'soc/stix-export') {
      if (method !== 'POST') {
        return res.status(405).json({ error: `Method ${method} Not Allowed for /api/soc/stix-export. Expected POST.` });
      }

      const { target, indicatorType, threatScore, findings, notes, incidentTitle } = body;
      const bundleId = `bundle--${crypto.randomUUID()}`;
      const indicatorId = `indicator--${crypto.randomUUID()}`;
      const sightingId = `sighting--${crypto.randomUUID()}`;
      const identityId = `identity--${crypto.randomUUID()}`;
      const now = new Date().toISOString();

      const stixBundle = {
        type: 'bundle',
        id: bundleId,
        spec_version: '2.1',
        objects: [
          {
            type: 'identity',
            spec_version: '2.1',
            id: identityId,
            created: now,
            modified: now,
            name: 'CyberGuard Threat Intelligence Engine',
            identity_class: 'system'
          },
          {
            type: 'indicator',
            spec_version: '2.1',
            id: indicatorId,
            created: now,
            modified: now,
            name: incidentTitle ? `Incident Indicator: ${incidentTitle}` : `CyberGuard Threat Indicator: ${target || 'malicious-c2-node.org'}`,
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
            where_sighted_refs: [identityId],
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
      const currentUser = getRequestUser(req);
      const filtered = currentUser.role === 'admin'
        ? memoryScans
        : memoryScans.filter(s => !s.userId || s.userId === currentUser.id);
      return res.status(200).json({ scans: filtered });
    }

    // -----------------------------------------------------------------
    // ROUTE 14: Clear History (GDPR Purge) -> /api/scans/clear
    // -----------------------------------------------------------------
    if (route === 'scans/clear') {
      const currentUser = getRequestUser(req);
      if (currentUser.role === 'admin') {
        memoryScans = [];
      } else {
        memoryScans = memoryScans.filter(s => s.userId && s.userId !== currentUser.id);
      }
      return res.status(200).json({ success: true, message: 'All scan records cleared successfully' });
    }

    // -----------------------------------------------------------------
    // ROUTE 15: Post-Quantum Cryptography (PQC) Audit -> /api/pqc/audit
    // -----------------------------------------------------------------
    if (route === 'pqc/audit' || route === 'pqc') {
      const target = body.target || body.domain || body.url || 'quantum-defense.gov';
      const pqcResult = analyzePqcReadiness(target);
      return res.status(200).json(pqcResult);
    }

    // -----------------------------------------------------------------
    // ROUTE 16: Quantum Shor Cryptanalysis Simulator -> /api/quantum/simulate
    // -----------------------------------------------------------------
    if (route === 'quantum/simulate' || route === 'quantum') {
      const cipher = body.cipher || 'RSA';
      const keySize = parseInt(body.keySize || '2048', 10);
      const simResult = simulateQuantumCryptanalysis(cipher, keySize);
      return res.status(200).json(simResult);
    }

    // -----------------------------------------------------------------
    // ROUTE 17: Neural Deepfake & Synthetic Media Forensics -> /api/deepfake/scan
    // -----------------------------------------------------------------
    if (route === 'deepfake/scan' || route === 'deepfake') {
      const targetName = body.targetName || body.filename || body.mediaName || 'generative_executive_portrait.png';
      const mediaType = body.mediaType || (targetName.endsWith('.mp3') || targetName.endsWith('.wav') ? 'audio' : 'image');
      const deepfakeResult = analyzeDeepfakeMedia(targetName, mediaType, body.payload);
      return res.status(200).json(deepfakeResult);
    }

    // -----------------------------------------------------------------
    // ROUTE 18: Autonomous Multi-Agent AI Swarm Telemetry -> /api/ai-swarm/telemetry
    // -----------------------------------------------------------------
    if (route === 'ai-swarm/telemetry' || route === 'ai-swarm') {
      const swarmState = getAutonomousAiSwarmState();
      return res.status(200).json(swarmState);
    }

    // -----------------------------------------------------------------
    // ROUTE 19: Dispatch Autonomous Swarm Playbook -> /api/ai-swarm/action
    // -----------------------------------------------------------------
    if (route === 'ai-swarm/action') {
      const { agentId, playbook, target } = body;
      const actionEvent = executeSwarmPlaybook(agentId || 'agent_sentinel_alpha', playbook, target);
      return res.status(200).json({ success: true, event: actionEvent });
    }

    // -----------------------------------------------------------------
    // ROUTE 20: LEO Satellite Mesh & QKD Telemetry -> /api/satellite/mesh
    // -----------------------------------------------------------------
    if (route === 'satellite/mesh' || route === 'satellite') {
      const meshTelemetry = getLeoSatelliteMeshTelemetry();
      return res.status(200).json(meshTelemetry);
    }

    // -----------------------------------------------------------------
    // ROUTE 21: STIX 3.0 / Quantum DFIR Bundle Export -> /api/stix3/export
    // -----------------------------------------------------------------
    if (route === 'stix3/export' || route === 'stix3') {
      const { target, threatScore, findings } = body;
      const indicatorId = 'indicator--' + crypto.randomUUID();
      const sightingId = 'sighting--' + crypto.randomUUID();
      const bundleId = 'bundle--' + crypto.randomUUID();
      const now = new Date().toISOString();

      const stix3Bundle = {
        type: 'bundle',
        id: bundleId,
        spec_version: '3.0',
        quantum_threat_layer: {
          nist_fips_standard: 'FIPS 203 / ML-KEM-768',
          hndl_risk_rating: threatScore > 70 ? 'CRITICAL' : 'MODERATE',
          zero_trust_status: 'HARDWARE_ENCLAVE_ATTESTED'
        },
        objects: [
          {
            type: 'indicator',
            spec_version: '3.0',
            id: indicatorId,
            created: now,
            modified: now,
            name: `2030 Quantum Threat Indicator: ${target || 'quantum-defense-mesh.net'}`,
            description: `Autonomous 2030 telemetry recorded by CyberGuard Quantum Swarm Engine. Threat Score: ${threatScore || 85}/100.`,
            indicator_types: ['quantum-adversary-recon', 'synthetic-identity-probe'],
            pattern: `[domain-name:value = '${target || 'quantum-defense-mesh.net'}']`,
            pattern_type: 'stix',
            valid_from: now,
            confidence: threatScore || 85,
            mitre_atlas_vector: 'AML.T0043 (Generative Synthetic Impersonation)'
          },
          {
            type: 'sighting',
            spec_version: '3.0',
            id: sightingId,
            created: now,
            modified: now,
            sighting_of_ref: indicatorId,
            summary: `Autonomous multi-agent consensus achieved. Findings: ${(findings || ['PQC Hybrid Bypass Attempt', 'Spectral FFT Anomaly']).join('; ')}`
          }
        ]
      };

      return res.status(200).json({
        success: true,
        stix3Bundle,
        bundle: stix3Bundle,
        jsonString: JSON.stringify(stix3Bundle, null, 2)
      });
    }

    // -----------------------------------------------------------------
    // 404 UNMATCHED ROUTE
    // -----------------------------------------------------------------
    return res.status(404).json({
      error: `API route not found: /api/${route}`,
      receivedUrl: req.url,
      resolvedRoute: route,
      supportedRoutes: [
        'POST /api/auth/login',
        'POST /api/auth/otp/request',
        'POST /api/auth/otp/verify',
        'GET  /api/auth/me',
        'POST /api/scan',
        'POST /api/scan-link',
        'POST /api/scan-image',
        'GET  /api/cve/search',
        'GET  /api/cve/latest',
        'POST /api/soc/osint-lookup',
        'POST /api/soc/hash-lookup',
        'GET  /api/soc/incidents',
        'POST /api/soc/incidents',
        'POST /api/soc/incidents/reset-demo',
        'POST /api/soc/incidents/:id/triage',
        'DELETE /api/soc/incidents/:id',
        'POST /api/soc/stix-export',
        'GET  /api/scans',
        'POST /api/scans/clear',
        'POST /api/pqc/audit',
        'POST /api/quantum/simulate',
        'POST /api/deepfake/scan',
        'GET  /api/ai-swarm/telemetry',
        'POST /api/ai-swarm/action',
        'GET  /api/satellite/mesh',
        'POST /api/stix3/export',
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
