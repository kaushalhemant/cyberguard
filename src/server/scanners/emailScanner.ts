import dns from 'dns/promises';
import { simpleParser, ParsedMail } from 'mailparser';
import { ScanRiskReport, TriggeredFlag, RiskLevel } from '../../types/scanners';
import { scanUrl } from './urlScanner';
import { runSublimeAnalysis } from './sublimeScanner';


/**
 * DOUBLE EXTENSION SUSPICIOUS PATTERNS
 * Common deceptive attachment filenames designed to hide executable payloads under benign document icons.
 */
const DOUBLE_EXTENSION_REGEX = /\.(pdf|docx?|xlsx?|txt|jpg|png|zip|rar)\.(exe|vbs|bat|cmd|ps1|js|scr|jar|pif|hta)$/i;

/**
 * URGENCY & PHISHING COERCION KEYWORDS
 * Psychological triggers used in spear-phishing campaigns to bypass victim critical thinking.
 */
const PHISHING_KEYWORDS = [
  { pattern: /account\s+suspended/i, weight: 20, name: 'Account Suspension Threat' },
  { pattern: /verify\s+(your\s+)?(identity|account|credentials|password)/i, weight: 25, name: 'Credential Verification Request' },
  { pattern: /urgent|immediate\s+action|within\s+24\s+hours/i, weight: 15, name: 'Fabricated Time Urgency' },
  { pattern: /wire\s+transfer|gift\s+card|direct\s+deposit|payroll/i, weight: 20, name: 'Financial Transaction Keyword' },
  { pattern: /unauthorized\s+(login|access|activity)/i, weight: 20, name: 'Fake Unauthorized Access Alert' },
  { pattern: /security\s+alert|password\s+expir/i, weight: 15, name: 'Security Alarm Coercion' }
];

/**
 * Extract domain from email address (e.g. "John <john@example.com>" -> "example.com")
 */
function extractDomainFromEmail(emailStr: string): string | null {
  if (!emailStr) return null;
  const match = emailStr.match(/@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/);
  return match ? match[1].toLowerCase() : null;
}

/**
 * Perform live DNS TXT lookup for SPF (v=spf1) record.
 * Security Reasoning: SPF (Sender Policy Framework) specifies authorized mail servers for a domain.
 */
async function checkSpfDns(domain: string): Promise<{ status: 'PASS' | 'FAIL' | 'NEUTRAL' | 'NONE'; record?: string; reasoning: string }> {
  try {
    const txtRecords = await dns.resolveTxt(domain);
    const flatRecords = txtRecords.map(r => r.join(''));
    const spfRecord = flatRecords.find(r => r.startsWith('v=spf1'));

    if (spfRecord) {
      if (spfRecord.includes('-all')) {
        return { status: 'PASS', record: spfRecord, reasoning: 'Domain enforces strict SPF protection (-all).' };
      } else if (spfRecord.includes('~all')) {
        return { status: 'NEUTRAL', record: spfRecord, reasoning: 'Domain enforces soft-fail SPF (~all).' };
      }
      return { status: 'PASS', record: spfRecord, reasoning: 'Valid SPF record configured.' };
    }
  } catch (e) {
    // DNS TXT query failed or domain lacks SPF record
  }
  return { status: 'NONE', reasoning: 'No SPF (v=spf1) record found in domain DNS TXT records.' };
}

/**
 * Perform live DNS TXT lookup for DMARC (v=DMARC1) record.
 * Security Reasoning: DMARC (Domain-based Message Authentication, Reporting & Conformance)
 * dictates how mail servers should handle unauthorized emails claiming to originate from the domain.
 */
async function checkDmarcDns(domain: string): Promise<{ status: 'PASS' | 'FAIL' | 'NONE'; record?: string; policy?: string; reasoning: string }> {
  try {
    const dmarcDomain = `_dmarc.${domain}`;
    const txtRecords = await dns.resolveTxt(dmarcDomain);
    const flatRecords = txtRecords.map(r => r.join(''));
    const dmarcRecord = flatRecords.find(r => r.startsWith('v=DMARC1'));

    if (dmarcRecord) {
      let policy = 'none';
      if (dmarcRecord.includes('p=reject')) policy = 'reject';
      else if (dmarcRecord.includes('p=quarantine')) policy = 'quarantine';

      return {
        status: 'PASS',
        record: dmarcRecord,
        policy,
        reasoning: `Domain enforces DMARC policy (p=${policy}).`
      };
    }
  } catch (e) {
    // DNS TXT query failed or domain lacks DMARC record
  }
  return { status: 'NONE', reasoning: 'No DMARC (_dmarc) record found in domain DNS TXT records.' };
}

/**
 * Extract all URLs from email body content.
 */
function extractLinksFromBody(bodyText: string): string[] {
  if (!bodyText) return [];
  const urlRegex = /(https?:\/\/[^\s<>"']+|www\.[^\s<>"']+)/gi;
  const matches = bodyText.match(urlRegex) || [];
  const cleanMatches = matches.map(u => u.replace(/[.,;)]+$/, ''));
  return Array.from(new Set(cleanMatches));
}

/**
 * MAIN MODULAR EMAIL HEADER & CONTENT SCANNER SERVICE
 */
export async function scanEmail(input: string | Buffer): Promise<ScanRiskReport> {
  const timestamp = new Date().toISOString();
  const flags: TriggeredFlag[] = [];

  let parsed: ParsedMail | null = null;
  let rawHeadersText = '';
  let bodyContent = '';
  let senderFrom = '';
  let replyTo = '';
  let returnPath = '';
  let subject = '';
  let attachmentsList: { filename: string; contentType: string }[] = [];

  // Parse raw EML / Buffer / Header String
  try {
    if (Buffer.isBuffer(input) || (typeof input === 'string' && (input.includes('From:') || input.includes('MIME-Version')))) {
      parsed = await simpleParser(input);
      senderFrom = parsed.from?.text || '';
      replyTo = Array.isArray(parsed.replyTo) ? parsed.replyTo.map(r => r.text).join(', ') : (parsed.replyTo?.text || '');
      returnPath = (parsed.headers.get('return-path') as string) || '';
      subject = parsed.subject || '';
      bodyContent = parsed.text || parsed.html || '';
      
      if (parsed.attachments) {
        attachmentsList = parsed.attachments.map(a => ({
          filename: a.filename || 'attachment.dat',
          contentType: a.contentType || 'application/octet-stream'
        }));
      }
    } else {
      // Input is plain body/header text
      bodyContent = String(input);
      const fromMatch = bodyContent.match(/From:\s*(.+)/i);
      const replyToMatch = bodyContent.match(/Reply-To:\s*(.+)/i);
      const subjectMatch = bodyContent.match(/Subject:\s*(.+)/i);
      if (fromMatch) senderFrom = fromMatch[1].trim();
      if (replyToMatch) replyTo = replyToMatch[1].trim();
      if (subjectMatch) subject = subjectMatch[1].trim();
    }
  } catch (err) {
    bodyContent = String(input);
  }

  const fromDomain = extractDomainFromEmail(senderFrom);
  const replyToDomain = extractDomainFromEmail(replyTo);
  const returnPathDomain = extractDomainFromEmail(returnPath);

  // 1. SENDER VS REPLY-TO / RETURN-PATH MISMATCH (SPOOFING CHECK)
  // Security Reasoning: Attackers spoof legitimate From addresses (e.g. From: support@bank.com)
  // while routing replies or bounces to attacker-controlled domains (Reply-To: hacker@evil.com).
  let senderMismatch = false;
  if (fromDomain && replyToDomain && fromDomain !== replyToDomain) {
    senderMismatch = true;
    flags.push({
      id: 'FLAG-SENDER-MISMATCH',
      name: 'Sender / Reply-To Domain Mismatch (Spoofing Alert)',
      severity: 'CRITICAL',
      weight: 45,
      description: `Header "From" domain ("${fromDomain}") differs from "Reply-To" domain ("${replyToDomain}").`,
      securityReasoning: 'Sender mismatch is a high-confidence phishing indicator. Attackers display a trusted brand name in the From field while capturing victim replies on external mail servers.'
    });
  }

  if (fromDomain && returnPathDomain && fromDomain !== returnPathDomain) {
    flags.push({
      id: 'FLAG-RETURN-PATH-MISMATCH',
      name: 'Return-Path Domain Mismatch',
      severity: 'HIGH',
      weight: 30,
      description: `Header "From" domain ("${fromDomain}") differs from envelope "Return-Path" domain ("${returnPathDomain}").`,
      securityReasoning: 'Mismatched envelope Return-Path addresses indicate third-party relay or forged sender headers.'
    });
  }

  // 2. DNS SPF / DKIM / DMARC AUTHENTICATION LOOKUPS
  // Security Reasoning: Evaluates domain-level DNS email protection records.
  let authResults: {
    spf: { status: 'PASS' | 'FAIL' | 'NEUTRAL' | 'NONE'; record?: string; reasoning: string };
    dkim: { status: 'PASS' | 'FAIL' | 'NONE'; reasoning: string };
    dmarc: { status: 'PASS' | 'FAIL' | 'NONE'; record?: string; policy?: string; reasoning: string };
  } = {
    spf: { status: 'NONE', reasoning: 'Not checked' },
    dkim: { status: 'NONE', reasoning: 'DKIM signature headers evaluated on gateway' },
    dmarc: { status: 'NONE', reasoning: 'Not checked' }
  };

  if (fromDomain) {
    const spfRes = await checkSpfDns(fromDomain);
    const dmarcRes = await checkDmarcDns(fromDomain);
    authResults.spf = spfRes;
    authResults.dmarc = dmarcRes;

    if (spfRes.status === 'NONE') {
      flags.push({
        id: 'FLAG-SPF-MISSING',
        name: 'Missing SPF DNS Record',
        severity: 'MEDIUM',
        weight: 20,
        description: `Domain "${fromDomain}" does not publish an SPF (v=spf1) record.`,
        securityReasoning: 'Domains without SPF allow unauthorized mail servers to send forged emails using their identity.'
      });
    }

    if (dmarcRes.status === 'NONE') {
      flags.push({
        id: 'FLAG-DMARC-MISSING',
        name: 'Missing DMARC Policy Record',
        severity: 'MEDIUM',
        weight: 20,
        description: `Domain "${fromDomain}" does not enforce a DMARC policy.`,
        securityReasoning: 'Without DMARC enforcement (p=reject / p=quarantine), recipient servers cannot verify sender legitimacy.'
      });
    } else if (dmarcRes.policy === 'none') {
      flags.push({
        id: 'FLAG-DMARC-NONE-POLICY',
        name: 'Weak DMARC Policy (p=none)',
        severity: 'LOW',
        weight: 10,
        description: `Domain "${fromDomain}" specifies DMARC policy "p=none", which takes no protective action on failed emails.`,
        securityReasoning: 'A DMARC policy of p=none provides zero active blocking against unauthorized email spoofing.'
      });
    }
  }

  // 3. DOUBLE EXTENSION ATTACHMENT CHECK
  // Security Reasoning: Attackers append benign extensions (e.g. invoice.pdf.exe) to trick users who have "Hide extensions for known file types" enabled in Windows Explorer.
  const suspiciousAttachments: { filename: string; extension: string; isDoubleExtension: boolean }[] = [];
  for (const att of attachmentsList) {
    const isDoubleExt = DOUBLE_EXTENSION_REGEX.test(att.filename);
    if (isDoubleExt) {
      suspiciousAttachments.push({ filename: att.filename, extension: att.contentType, isDoubleExtension: true });
      flags.push({
        id: 'FLAG-DOUBLE-EXTENSION',
        name: 'Deceptive Double-Extension Attachment Flagged',
        severity: 'CRITICAL',
        weight: 50,
        description: `Attachment "${att.filename}" uses a double-extension pattern (e.g., .pdf.exe).`,
        securityReasoning: 'Double-extension filenames are designed specifically to disguise executable malware payloads under familiar document icons.'
      });
    }
  }

  // 4. URGENCY & PHISHING KEYWORD SCORING
  // Security Reasoning: Detects coercive psychological triggers commonly found in phishing lures.
  const fullTextToScan = `${subject} ${bodyContent}`;
  for (const kw of PHISHING_KEYWORDS) {
    if (kw.pattern.test(fullTextToScan)) {
      flags.push({
        id: `FLAG-KEYWORD-${kw.name.replace(/\s+/g, '-').toUpperCase()}`,
        name: kw.name,
        severity: kw.weight >= 20 ? 'HIGH' : 'MEDIUM',
        weight: kw.weight,
        description: `Phishing coercion keyword pattern detected: "${kw.name}".`,
        securityReasoning: 'Phishing attacks rely on urgent, coercive messaging to pressure victims into revealing credentials or approving unauthorized wire transfers.'
      });
    }
  }

  // 5. RECURSIVE LINK EXTRACTION & URL SCANNING
  // Security Reasoning: Extracts all embedded hyperlinks and evaluates them using the modular URL scanner.
  const extractedLinks = extractLinksFromBody(bodyContent);
  const nestedUrlReports: ScanRiskReport[] = [];

  for (const link of extractedLinks.slice(0, 5)) { // Scan top 5 extracted links
    try {
      const urlReport = await scanUrl(link);
      nestedUrlReports.push(urlReport);

      if (urlReport.riskLevel === 'CRITICAL' || urlReport.riskLevel === 'HIGH') {
        flags.push({
          id: 'FLAG-MALICIOUS-EMBEDDED-LINK',
          name: `Malicious Embedded Link Flagged: ${urlReport.details.urlDetails?.domain || link}`,
          severity: urlReport.riskLevel === 'CRITICAL' ? 'CRITICAL' : 'HIGH',
          weight: urlReport.riskLevel === 'CRITICAL' ? 45 : 30,
          description: `Embedded link "${link}" triggered ${urlReport.triggeredFlags.length} security flags (Risk Score: ${urlReport.riskScore}/100).`,
          securityReasoning: 'Emails containing high-risk or typosquatted links are confirmed phishing delivery vectors.'
        });
      }
    } catch (e) {
      // URL scan skip
    }
  }

  // 6. SUBLIME SECURITY YML THREAT RULE ANALYSIS
  // Security Reasoning: Evaluates 1,100+ detection rules (credential theft, BEC, brand impersonation).
  const sublimeResults = await runSublimeAnalysis(input);
  if (sublimeResults && sublimeResults.flaggedCount > 0) {
    for (const rule of sublimeResults.flaggedRules) {
      const isHigh = rule.severity === 'high' || rule.severity === 'critical';
      flags.push({
        id: `FLAG-SUBLIME-${rule.name.replace(/[^a-zA-Z0-9]/g, '-').toUpperCase()}`,
        name: `Sublime Rule Flagged: ${rule.name}`,
        severity: isHigh ? 'CRITICAL' : 'HIGH',
        weight: isHigh ? 50 : 35,
        description: `Sublime Security detection rule "${rule.name}" triggered on message telemetry (Severity: ${rule.severity.toUpperCase()}).`,
        securityReasoning: 'Sublime Security MQL detection rules identify sophisticated spear phishing and BEC patterns.'
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
    scannerType: 'email',
    target: senderFrom || 'Raw Email Content',
    timestamp,
    riskScore,
    riskLevel,
    triggeredFlags: flags,
    details: {
      emailDetails: {
        senderFrom,
        replyTo,
        returnPath,
        subject,
        authResults,
        senderMismatch,
        suspiciousAttachments,
        extractedLinksCount: extractedLinks.length,
        nestedUrlReports,
        sublimeResults
      }
    }
  };
}

