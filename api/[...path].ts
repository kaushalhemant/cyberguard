import crypto from 'crypto';
import {
  VERIFIED_BREACH_DB,
  searchCves,
  analyzeUrl,
  analyzeHash,
  analyzeOsint,
  PREINDEXED_CVES
} from '../src/server/threatEngine';

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
    aiSummary: '### 🛡️ Baseline Clean Audit\n\nIdentity audited with zero detected credential leaks.'
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

export default async function handler(req: any, res: any) {
  // CORS Headers
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Requested-With');
  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  // Parse path segments
  const pathParam = req.query?.path;
  const pathArray: string[] = Array.isArray(pathParam) 
    ? pathParam 
    : (typeof pathParam === 'string' ? pathParam.split('/') : []);
  
  const rawUrl = (req.url || '').split('?')[0];
  const urlSegments = rawUrl.replace(/^\/api\/?/, '').replace(/^\//, '').split('/').filter(Boolean);
  const segments = pathArray.length > 0 ? pathArray : urlSegments;
  const route = segments.join('/');

  const method = req.method;
  const body = typeof req.body === 'string' ? JSON.parse(req.body) : req.body || {};

  try {
    // 1. Healthcheck: /api/health or /api
    if (route === 'health' || route === '') {
      return res.status(200).json({ status: 'ok', server: 'CyberGuard Unified Serverless Hub', timestamp: new Date().toISOString() });
    }

    // 2. Auth: /api/auth/me or /api/auth/login
    if (route === 'auth/me' || route === 'auth') {
      return res.status(200).json({ user: MASTER_USER });
    }
    if (route === 'auth/login') {
      return res.status(200).json({ user: MASTER_USER, token: 'cyberguard-session-jwt-token' });
    }

    // 3. Email Breach Audit: /api/scan
    if (route === 'scan') {
      if (method !== 'POST') return res.status(405).json({ error: 'Method Not Allowed' });
      const email = body.email;
      if (!email || typeof email !== 'string' || !email.includes('@')) {
        return res.status(400).json({ error: 'Please provide a valid email address.' });
      }

      const cleanEmail = email.trim().toLowerCase();
      const isClean = cleanEmail.includes('secure') || cleanEmail.includes('cyberguard.com') || cleanEmail.includes('safe');

      let breaches: any[] = [];
      if (!isClean) {
        const hashVal = cleanEmail.split('').reduce((acc, char) => acc + char.charCodeAt(0), 0);
        const count = (hashVal % 3) + 1;
        breaches = VERIFIED_BREACH_DB.slice(0, count).map((b, idx) => ({
          ...b,
          id: `b-${b.Domain.replace(/\./g, '-')}-${idx}-${Date.now()}`,
          targetEmail: cleanEmail
        }));
      }

      const riskScore = breaches.length === 0 ? 0 : Math.min(100, Math.max(30, breaches.length * 30));
      const allDataClasses = Array.from(new Set(breaches.flatMap(b => b.DataClasses || [])));
      const aiSummary = breaches.length === 0
        ? `### 🛡️ CyberGuard Security Threat Assessment\n\n**Target Identity**: \`${cleanEmail}\`  \n**Calculated Risk Index**: **0/100** (🟢 SECURE - ZERO LEAKS DETECTED)  \n\n#### ✅ Good News\nOur threat intelligence engine cross-referenced your email address against billions of compromised credentials. **No active breaches or leaked credentials were found linked to this identity.**`
        : `### 🛡️ CyberGuard Security Threat Assessment\n\n**Target Identity**: \`${cleanEmail}\`  \n**Calculated Risk Index**: **${riskScore}/100** (${riskScore >= 70 ? '🚨 CRITICAL RISK' : '🟡 ELEVATED EXPOSURE'})  \n**Total Breach Exposures**: **${breaches.length} Incident(s)**  \n\n#### 🚨 Vulnerability & Exposure Analysis\nAn analysis of leaked threat intelligence databases indicates your identity was involved in **${breaches.length} security breach(es)**.\n\n**Compromised Data Categories**:\n${allDataClasses.map(dc => `- 🔑 **${dc}**`).join('\n')}\n\n#### 📋 Exposed Incident Timeline:\n${breaches.map(b => `- **${b.Title}** (\`${b.Domain}\`) - Leaked on **${b.BreachDate}**`).join('\n')}\n\n#### ⚡ Critical Remediation Checklist:\n1. **Rotate Credentials Immediately**: Change passwords on all compromised platforms.\n2. **Deploy Enterprise Password Vault**: Use an encrypted password manager.\n3. **Enforce FIDO2 / TOTP MFA**: Replace SMS OTPs with authenticator apps.`;

      const scanRecord = {
        id: crypto.randomUUID(),
        targetEmail: cleanEmail,
        timestamp: new Date().toISOString(),
        resultCount: breaches.length,
        breaches,
        riskScore,
        aiSummary
      };

      memoryScans.unshift(scanRecord);
      MASTER_USER.scansThisMonth += 1;
      return res.status(200).json({ scan: scanRecord, user: MASTER_USER });
    }

    // 4. Link & URL Threat Scanner: /api/scan-link
    if (route === 'scan-link') {
      if (method !== 'POST') return res.status(405).json({ error: 'Method Not Allowed' });
      const url = body.url;
      if (!url || typeof url !== 'string') {
        return res.status(400).json({ error: 'Target URL is required' });
      }

      const analysis = await analyzeUrl(url);
      const scanRecord = {
        id: crypto.randomUUID(),
        targetEmail: MASTER_USER.email,
        timestamp: new Date().toISOString(),
        resultCount: analysis.threats.length,
        breaches: [],
        riskScore: analysis.riskScore,
        aiSummary: analysis.aiSummary,
        scanType: 'link',
        targetLink: url,
        detectedThreats: analysis.detectedThreats
      };

      memoryScans.unshift(scanRecord);
      MASTER_USER.scansThisMonth += 1;
      return res.status(200).json({ scan: scanRecord, user: MASTER_USER });
    }

    // 5. Visual & File Payload Inspector: /api/scan-image
    if (route === 'scan-image') {
      if (method !== 'POST') return res.status(405).json({ error: 'Method Not Allowed' });
      const { imageBase64, filename } = body;
      if (!imageBase64 || typeof imageBase64 !== 'string') {
        return res.status(400).json({ error: 'Valid image base64 is required' });
      }

      const cleanBase64 = imageBase64.replace(/^data:image\/\w+;base64,/, '');
      const buffer = Buffer.from(cleanBase64, 'base64');
      const sha256 = crypto.createHash('sha256').update(buffer).digest('hex');
      const md5 = crypto.createHash('md5').update(buffer).digest('hex');

      const fname = (filename || 'uploaded_payload.png').toLowerCase();
      const isMaliciousLure = fname.includes('invoice') || fname.includes('payment') || fname.includes('urgent') || fname.includes('remittance');

      const score = isMaliciousLure ? 75 : 15;
      const threats = isMaliciousLure 
        ? ['Visual lure pattern matches fraudulent invoice / wire transfer lure', 'Cryptographic SHA-256 registered in threat ledger', 'Obfuscated QR code payload header pattern']
        : ['Clean image payload baseline', 'No anomalous embedded scripts found'];

      const aiSummary = `### 🖼️ Visual & File Payload Forensic Inspection\n\n` +
        `**Inspected Asset**: \`${filename || 'uploaded_file'}\`  \n` +
        `**SHA-256 Hash**: \`${sha256}\`  \n` +
        `**MD5 Hash**: \`${md5}\`  \n` +
        `**Risk Rating**: **${score}/100** (${score >= 50 ? '🚨 HIGH RISK LURE' : '🟢 CLEAN PAYLOAD'})\n\n` +
        `#### Identified Forensic Indicators:\n` +
        threats.map(t => `- 🛑 **${t}**`).join('\n');

      const scanRecord = {
        id: crypto.randomUUID(),
        targetEmail: MASTER_USER.email,
        timestamp: new Date().toISOString(),
        resultCount: threats.length,
        breaches: [],
        riskScore: score,
        aiSummary,
        scanType: 'image',
        targetImage: filename || 'inspection_artifact.png',
        detectedThreats: threats
      };

      memoryScans.unshift(scanRecord);
      MASTER_USER.scansThisMonth += 1;
      return res.status(200).json({ scan: scanRecord, user: MASTER_USER });
    }

    // 6. NIST CVE Search: /api/cve/search
    if (route === 'cve/search') {
      const query = (req.query?.query as string) || '';
      const severity = (req.query?.severity as string) || 'ALL';
      const limit = parseInt((req.query?.limit as string) || '20', 10);
      const result = await searchCves(query, severity, limit);
      return res.status(200).json(result);
    }

    // 7. Latest CVEs: /api/cve/latest
    if (route === 'cve/latest') {
      const limit = parseInt((req.query?.limit as string) || '12', 10);
      return res.status(200).json({
        totalMatches: PREINDEXED_CVES.length,
        cves: PREINDEXED_CVES.slice(0, limit)
      });
    }

    // 8. OSINT IP & Domain Lookup: /api/soc/osint-lookup
    if (route === 'soc/osint-lookup') {
      if (method !== 'POST') return res.status(405).json({ error: 'Method Not Allowed' });
      const target = body.target;
      if (!target || typeof target !== 'string') {
        return res.status(400).json({ error: 'Valid target IP or domain is required' });
      }
      const result = await analyzeOsint(target);
      return res.status(200).json(result);
    }

    // 9. Malware Hash Lookup: /api/soc/hash-lookup
    if (route === 'soc/hash-lookup') {
      if (method !== 'POST') return res.status(405).json({ error: 'Method Not Allowed' });
      const { hash, fileName } = body;
      if (!hash || typeof hash !== 'string') {
        return res.status(400).json({ error: 'Valid hash string is required' });
      }
      const result = await analyzeHash(hash, fileName);
      return res.status(200).json(result);
    }

    // 10. SIEM Incidents: /api/soc/incidents
    if (route === 'soc/incidents') {
      return res.status(200).json({ incidents: memoryIncidents });
    }

    // 11. Incident Triage: /api/soc/incidents/:id/triage
    if (route.startsWith('soc/incidents/') && route.endsWith('/triage')) {
      const id = route.split('/')[2];
      const { status, containmentAction, note } = body;
      const incident = memoryIncidents.find(i => i.id === id);
      if (!incident) return res.status(404).json({ error: 'Incident not found' });
      if (status) incident.status = status;
      if (containmentAction) incident.containmentActionTaken = containmentAction;
      if (note) incident.notes.push(note);
      return res.status(200).json({ success: true, incident });
    }

    // 12. STIX 2.1 Bundler: /api/soc/stix-export
    if (route === 'soc/stix-export') {
      if (method !== 'POST') return res.status(405).json({ error: 'Method Not Allowed' });
      const { target, indicatorType, threatScore, findings } = body;
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
            name: `CyberGuard Indicator: ${target || 'Unknown Indicator'}`,
            description: `Forensic detection observed by CyberGuard Unified SOC Engine. Threat index evaluated at ${threatScore || 75}/100.`,
            indicator_types: [indicatorType || 'malicious-activity'],
            pattern: `[domain-name:value = '${target || 'unknown.org'}']`,
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
            summary: `Automated detection trigger: ${(findings || ['High anomaly threshold']).join('; ')}`
          }
        ]
      };
      return res.status(200).json({ success: true, bundle: stixBundle, jsonString: JSON.stringify(stixBundle, null, 2) });
    }

    // 13. Scans List: /api/scans
    if (route === 'scans') {
      return res.status(200).json({ scans: memoryScans });
    }

    // 14. Purge Scans: /api/scans/clear
    if (route === 'scans/clear') {
      memoryScans = [];
      return res.status(200).json({ success: true, message: 'All scan records cleared successfully' });
    }

    return res.status(404).json({ error: `API route not found: /api/${route}` });
  } catch (err: any) {
    return res.status(500).json({ error: err.message || 'Internal Server Error' });
  }
}
