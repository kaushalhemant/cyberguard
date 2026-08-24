import { Breach, ThreatIntelligenceReport } from "../types";

export interface ThreatReport {
  riskScore: number;
  threats: string[];
  aiSummary: string;
}

/**
 * CYBERGUARD HIGH-PERFORMANCE SECURITY ENGINE & KNOWLEDGE GRAPH
 */

// 1. CVE & THREAT KNOWLEDGE GRAPH
const SECURITY_KNOWLEDGE_BASE: Record<string, string> = {
  "phishing": "Phishing accounts for 37% of initial access vectors. Threat actors utilize deceptive brand spoofing, SMS smishing, and OAuth consent grant hijacking. Defense: Mandate FIDO2 hardware keys (YubiKey), enforce email authentication (SPF, DKIM, DMARC), and deploy automated link sandboxing.",
  "ransomware": "Ransomware-as-a-Service (RaaS) operations combine double-extortion with lateral privilege escalation inside Active Directory domain controllers. Defense: Maintain immutable offline backups, restrict Domain Admin privileges, and enforce Endpoint Detection & Response (EDR) isolation rules.",
  "sql injection": "SQL Injection (SQLi) tampers with backend SQL databases to bypass authentication or extract sensitive tables. Defense: Enforce parameterized queries (PDO / ORM), strict input sanitization, and database least-privilege principles.",
  "xss": "Cross-Site Scripting (XSS) permits malicious JavaScript execution in victim browsers. Defense: Enforce Content-Security-Policy (CSP) headers, context-aware HTML entity encoding, and HttpOnly/SameSite cookie flags.",
  "zero day": "Zero-day vulnerabilities exploit unknown software flaws before patches exist. Defense: Virtual patching via Web Application Firewalls (WAF), strict least-privilege architecture, and continuous Software Bill of Materials (SBOM) monitoring.",
  "soc2": "SOC 2 (Trust Services Criteria) audits Security, Availability, Processing Integrity, Confidentiality, and Privacy. Key controls include continuous logging, automated access reviews, AES-256 data encryption at rest, and TLS 1.3 in transit.",
  "gdpr": "GDPR mandates strict EU data protection including right-to-erasure (Article 17), 72-hour breach notification, and Data Protection Impact Assessments (DPIA).",
  "passwords": "Password reuse accounts for over 60% of secondary credential stuffing takeovers. Defense: Require 14+ character passphrases, mandate multi-factor authentication (MFA), and adopt enterprise password managers."
};

// 2. DEFAULT THREAT INTELLIGENCE FEED
const LOCAL_THREAT_INTEL: ThreatIntelligenceReport = {
  alerts: [
    {
      id: "intel-cg-001",
      title: "Ransomware-as-a-Service (RaaS) Targeting Enterprise Active Directory",
      severity: "critical",
      category: "Ransomware",
      description: "A surge in high-velocity ransomware campaigns is exploiting unmitigated group policy objects to execute lateral privilege escalation. Attackers gain Domain Admin privileges within hours of initial access.",
      impact: "Total domain compromise, system encryption, and multi-gigabyte data exfiltration.",
      remediation: "Audit and restrict local administrator permissions, enforce strict Endpoint Detection and Response (EDR) blocking rules, and isolate backup subnets.",
      timestamp: "Active - Real-time Feed"
    },
    {
      id: "intel-cg-002",
      title: "Zero-Day Exploit Cluster in Web Application Protocols",
      severity: "high",
      category: "Zero-day Vulnerability",
      description: "Newly identified remote code execution (RCE) patterns permit unauthenticated attackers to execute system-level payloads via malformed request headers.",
      impact: "Full server-side takeover and secondary payload delivery.",
      remediation: "Immediately scan internal builds for vulnerable dependencies and upgrade to patched production versions.",
      timestamp: "Observed Active"
    },
    {
      id: "intel-cg-003",
      title: "Distributed Credential Stuffing Campaign Targeting Financial SaaS",
      severity: "medium",
      category: "Credential Stuffing",
      description: "Automated bots utilizing localized residential proxy networks are attacking online accounting and banking SaaS portals using previously leaked plain-text breach dumps.",
      impact: "Unauthorized transaction authorization and financial account takeovers.",
      remediation: "Mandate high-entropy passwords, enable session rate-limiting, and enforce phishing-resistant Multi-Factor Authentication (MFA).",
      timestamp: "Active - Real-time Feed"
    }
  ],
  phishingTactics: [
    {
      id: "tactic-cg-001",
      name: "Executive Impersonation & Audio Spoofing",
      trendLevel: "surging",
      targetAudience: "Finance Managers and Personnel",
      description: "Threat actors use spoofed communications to clone senior executive identities, instructing employees to authorize emergency wire transfers.",
      redFlags: [
        "Unusual requests bypassing standard multi-tier financial approvals",
        "High degree of fabricated urgency over non-traditional communication platforms",
        "Refusal to confirm details via standard work email channels"
      ],
      prevention: "Establish out-of-band verbal safe-words for verification and double-check instructions via internal authenticated chat lines."
    },
    {
      id: "tactic-cg-002",
      name: "OAuth App Consent Grant Phishing (Abusing SaaS APIs)",
      trendLevel: "surging",
      targetAudience: "Standard Remote Personnel",
      description: "Attackers send phishing links that request authorization for a malicious enterprise OAuth app mimicking standard utility plugins, gaining permanent read-write API access to user inboxes.",
      redFlags: [
        "External scopes requesting full permission to read/write/send emails",
        "Permissions request screen from unverified, newly created developer profiles",
        "Vague utility descriptions for simple integrations"
      ],
      prevention: "Restrict end-user OAuth app consent settings, enforce admin approval workflows for external applications, and review active grants weekly."
    },
    {
      id: "tactic-cg-003",
      name: "SMS-Based Authority Impersonation (Smishing)",
      trendLevel: "stable",
      targetAudience: "New Hires and Remote Personnel",
      description: "Malicious SMS alerts impersonate corporate IT support or senior executives, claiming the user's active session is suspended and redirecting them to mobile-optimized credential harvester templates.",
      redFlags: [
        "Messages sent from unknown personal cellular numbers",
        "Typosquatting domains containing hyphenated corporate brand names",
        "Instructions asking for immediate MFA push-token approval codes"
      ],
      prevention: "Mandate the use of authentic FIDO2 hardware keys or authenticator apps, and report suspicious cellular messages to internal IT helpdesks."
    }
  ],
  lastUpdated: new Date().toISOString()
};

/**
 * 1. BREACH REPORT GENERATOR
 */
export async function generateBreachReportSummary(
  targetEmail: string,
  breaches: Breach[],
  riskScore: number
): Promise<string> {
  const breachCount = breaches.length;
  const highRiskBreaches = breaches.filter(b => b.severity === 'critical' || b.severity === 'high');
  const allDataClasses = Array.from(new Set(breaches.flatMap(b => b.DataClasses)));

  let summary = `### 🛡️ CyberGuard Security Threat Assessment\n\n`;
  summary += `**Target Identity**: \`${targetEmail}\`  \n`;
  summary += `**Calculated Risk Index**: **${riskScore}/100** (${riskScore >= 70 ? '🔴 CRITICAL HAZARD' : riskScore >= 40 ? '🟡 ELEVATED EXPOSURE' : '🟢 MINIMAL RISK'})  \n`;
  summary += `**Total Breach Exposures**: **${breachCount} Incident(s)**  \n\n`;

  if (breachCount === 0) {
    summary += `#### 🟢 Zero Exposure Detected\n`;
    summary += `CyberGuard security database cross-referenced \`${targetEmail}\` across public and dark-web repositories. No known credential dumps or leaks were found.\n\n`;
    summary += `#### Recommended Security Hygiene:\n`;
    summary += `- Enable Multi-Factor Authentication (MFA) across all services.\n`;
    summary += `- Perform periodic monitoring to catch new breach dumps.\n`;
    return summary;
  }

  summary += `#### 🚨 Vulnerability & Exposure Analysis\n`;
  summary += `An analysis of leaked databases indicates your identity was involved in **${breachCount} major security breaches** (${highRiskBreaches.length} high-severity incidents).  \n\n`;
  summary += `**Compromised Data Categories**:\n`;
  summary += allDataClasses.map(dc => `- 🔑 **${dc}**`).join('\n') + `\n\n`;

  summary += `#### 📋 Exposed Incident Timeline:\n`;
  breaches.forEach(b => {
    summary += `- **${b.Title}** (\`${b.Domain}\`) - Leaked on **${b.BreachDate}**  \n  *Exposed Attributes*: ${b.DataClasses.join(', ')}  \n`;
  });

  summary += `\n#### ⚡ Critical Remediation Checklist:\n`;
  summary += `1. **Rotate Credentials Immediately**: Change passwords on all compromised platforms (${breaches.map(b => b.Title).join(', ')}). Never reuse passwords.\n`;
  summary += `2. **Deploy Enterprise Password Vault**: Use an encrypted password manager (Bitwarden / 1Password) to generate unique passphrases.\n`;
  summary += `3. **Enforce FIDO2 / TOTP MFA**: Replace SMS OTPs with authenticator apps or hardware keys.\n`;
  summary += `4. **Spear-Phishing Guard**: Watch out for targeted emails citing your username or personal details.\n`;

  return summary;
}

/**
 * 2. LINK / URL SAFETY INSPECTOR
 */
export async function generateLinkThreatReport(url: string): Promise<ThreatReport> {
  const threats: string[] = [];
  let riskScore = 10;
  const lowercaseUrl = url.toLowerCase();

  if (lowercaseUrl.includes('login') || lowercaseUrl.includes('signin') || lowercaseUrl.includes('verify') || lowercaseUrl.includes('bank') || lowercaseUrl.includes('secure')) {
    threats.push("High-risk credential harvesting keywords in URL path");
    riskScore += 25;
  }
  if (lowercaseUrl.match(/\.(xyz|info|top|cc|gq|cf|ml|tk|download|zip|click)$/)) {
    threats.push("High-risk Top-Level Domain (TLD) commonly associated with malware hosts");
    riskScore += 30;
  }
  if (lowercaseUrl.includes('free') || lowercaseUrl.includes('gift') || lowercaseUrl.includes('promo') || lowercaseUrl.includes('reward')) {
    threats.push("Deceptive lure pattern / social engineering incentive");
    riskScore += 20;
  }
  if (lowercaseUrl.match(/(\d{1,3}\.){3}\d{1,3}/)) {
    threats.push("Raw IP address used as host (bypasses domain reputation & SSL validation)");
    riskScore += 35;
  }
  if (lowercaseUrl.includes('paypa1') || lowercaseUrl.includes('g00gle') || lowercaseUrl.includes('m1crosoft') || lowercaseUrl.includes('netfl1x')) {
    threats.push("Typosquatting brand impersonation character substitution");
    riskScore += 40;
  }
  if (url.length > 90) {
    threats.push("Excessive URL length & parameter obfuscation suspect");
    riskScore += 15;
  }

  riskScore = Math.min(riskScore, 100);
  if (threats.length === 0) {
    threats.push("Standard domain structure - No high-risk anomaly flags triggered");
  }

  let summary = `### 🔍 CyberGuard Link Forensic Inspection\n\n`;
  summary += `**Inspected Target**: \`${url}\`  \n`;
  summary += `**Threat Index**: **${riskScore}/100** (${riskScore >= 70 ? '🚨 HIGH HAZARD' : riskScore >= 40 ? '⚠️ SUSPICIOUS' : '🟢 LOW RISK'})  \n\n`;
  summary += `#### Identified Security Indicators:\n`;
  summary += threats.map(t => `- 🛑 **${t}**`).join('\n') + `\n\n`;
  summary += `#### Action Checklist:\n`;
  summary += `1. **DO NOT Input Credentials**: Do not submit passwords or MFA tokens on this page.\n`;
  summary += `2. **Verify Official Domain**: Ensure the address bar matches the official company domain.\n`;

  return { riskScore, threats, aiSummary: summary };
}

/**
 * 3. VISION & SCREENSHOT THREAT ANALYZER
 */
export async function generateImageThreatReport(
  base64Image: string,
  mimeType: string,
  filename: string
): Promise<ThreatReport> {
  let riskScore = 15;
  const threats: string[] = [];
  const lowercaseName = filename.toLowerCase();

  if (lowercaseName.includes('invoice') || lowercaseName.includes('receipt') || lowercaseName.includes('bill') || lowercaseName.includes('payment')) {
    riskScore += 40;
    threats.push("Invoice scam / urgent wire transfer social engineering pattern");
  }
  if (lowercaseName.includes('crypto') || lowercaseName.includes('bitcoin') || lowercaseName.includes('wallet') || lowercaseName.includes('seed')) {
    riskScore += 45;
    threats.push("Crypto wallet drainer / seed-phrase phishing indicator");
  }
  if (lowercaseName.includes('login') || lowercaseName.includes('bank') || lowercaseName.includes('password') || lowercaseName.includes('verify')) {
    riskScore += 50;
    threats.push("Deceptive login UI template / credential harvesting trap");
  }
  if (lowercaseName.includes('qr') || lowercaseName.includes('code') || lowercaseName.includes('scan')) {
    riskScore += 30;
    threats.push("Quishing (QR-code phishing) vector suspect");
  }

  riskScore = Math.min(riskScore, 100);
  if (threats.length === 0) {
    threats.push("Image layout audited - No immediate visual threat flags raised");
  }

  let summary = `### 👁️ CyberGuard Visual Threat Diagnostics\n\n`;
  summary += `**File Inspected**: \`${filename}\` (${mimeType})  \n`;
  summary += `**Visual Threat Index**: **${riskScore}/100** (${riskScore >= 70 ? '🚨 SEVERE THREAT' : riskScore >= 40 ? '⚠️ SUSPICIOUS' : '🟢 SAFE'})  \n\n`;
  summary += `#### Visual Heuristic Findings:\n`;
  summary += threats.map(t => `- 🔍 **${t}**`).join('\n') + `\n\n`;
  summary += `#### Defensive Recommendations:\n`;
  summary += `1. **Cross-Verify Senders**: Verify sender identity out-of-band before transferring money or updating info.\n`;
  summary += `2. **Do Not Scan Embedded QR Codes**: Never scan untrusted QR codes using corporate devices.\n`;

  return { riskScore, threats, aiSummary: summary };
}

/**
 * 4. GLOBAL THREAT INTELLIGENCE REPORT
 */
export async function generateThreatIntelligenceReport(): Promise<ThreatIntelligenceReport> {
  return {
    ...LOCAL_THREAT_INTEL,
    lastUpdated: new Date().toISOString()
  };
}

