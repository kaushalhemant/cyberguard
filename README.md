# 🛡️ CyberGuard — Threat Monitoring & Breach Intelligence Workstation

[![TypeScript](https://img.shields.io/badge/TypeScript-5.8-3178C6?style=for-the-badge&logo=typescript&logoColor=white)](https://www.typescriptlang.org/)
[![React](https://img.shields.io/badge/React-19-61DAFB?style=for-the-badge&logo=react&logoColor=black)](https://react.dev/)
[![Vite](https://img.shields.io/badge/Vite-6.2-646CFF?style=for-the-badge&logo=vite&logoColor=white)](https://vitejs.dev/)
[![Express](https://img.shields.io/badge/Express-4.21-000000?style=for-the-badge&logo=express&logoColor=white)](https://expressjs.com/)
[![TailwindCSS](https://img.shields.io/badge/Tailwind_CSS-4.0-06B6D4?style=for-the-badge&logo=tailwindcss&logoColor=white)](https://tailwindcss.com/)
[![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)](LICENSE)

> **CyberGuard** is an evidence-first, deterministic Cyber Threat Intelligence, Data Breach Investigation, and SIEM Incident Management Workstation. Built for enterprise security operations (SOC), incident response teams (DFIR), and compliance-critical environments.

---

## 🏛️ Verified Architecture & System Design

CyberGuard is engineered as a unified full-stack cybersecurity workstation:

```
cyberguard/
├── api/
│   └── [...path].ts             # Unified Express/Vercel serverless API router
├── src/
│   ├── components/
│   │   ├── Dashboard.tsx        # SOC Analyst Workstation, Presets Toolbar & Modals
│   │   ├── ThreatIntel.tsx      # Threat Feeds & Phishing Tactics Dashboard
│   │   ├── Terminal.tsx         # Interactive In-Browser Security Diagnostics Console
│   │   ├── UsageAudit.tsx       # Audit Trail & Session Activity Logger
│   │   └── PrivacyStatementModal.tsx # Zero-Retention & GDPR Compliance Notice
│   ├── lib/
│   │   ├── clientThreatEngine.ts # Offline-resilient deterministic threat scoring
│   │   ├── pdfGenerator.ts      # Executive A4 Briefing & SIEM DFIR PDF Exporter
│   │   └── api.ts               # Safe API client with resilient error boundaries
│   ├── server/
│   │   ├── security.ts          # SSRF Defense, HMAC Session Tokens, Single-Use OTPs
│   │   ├── threatEngine.ts      # Evidence Engine: URL, Hash, CVE, Breach, OSINT
│   │   ├── db.ts                # Local JSON state store with payment verification
│   │   └── scanners/
│   │       └── urlScanner.ts    # SSRF-guarded URL fetcher & redirect inspector
│   ├── types.ts                 # Authoritative TypeScript interfaces & models
│   ├── App.tsx                  # Main App with Session Auth & Tab Routing
│   └── index.css                # Midnight/Slate SOC Theme & Glassmorphism Design
├── tests/
│   └── api_integration_suite.ts # Comprehensive 25-test End-to-End API Suite
├── server.ts                    # Local Express development server
├── supabase_schema.sql          # Hardened Supabase SQL schema with Row-Level Security
└── package.json                 # Project scripts and dependencies
```

---

## 🔍 Threat Intelligence & Investigation Capabilities

### 1. 🌐 URL & Domain Investigation (`/api/scan-link`)
- **Server-Side Request Forgery (SSRF) Defense**: Pre-resolves domain hostnames via DNS and rejects private/reserved IP blocks (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `127.0.0.0/8`, `0.0.0.0/8`, IPv6 loopbacks) and cloud metadata targets (`169.254.169.254`).
- **Typosquatting Engine**: Evaluates brand impersonation against high-value targets (PayPal, Google, Apple, Microsoft, Amazon, etc.) using normalized homoglyph substitution and Levenshtein distance metrics.
- **Safe TLS & DNS Observation**: Inspects TLS certificate validity, issuer, cipher suites, and DNS A records through native Node.js network sockets with strict connection timeouts.

### 2. ⚡ Malware Binary & File Hash Forensics (`/api/soc/hash-lookup`)
- **Cryptographic Hash Computation**: Evaluates SHA-256, SHA-1, and MD5 signatures.
- **True Shannon Byte Entropy**: Computes exact entropy ($H = -\sum p_i \log_2 p_i$, scale 0.0 to 8.00) directly from binary payloads to identify encrypted or packed overlays.
- **Magic Byte Identification**: Validates actual binary file headers (PE32+ MZ, ELF, PDF `%PDF-`, ZIP PK, PNG, scripts).
- **Truthful Unknown Classification**: Unobserved hashes are explicitly classified as `unknown` rather than falsely clean, accompanied by an evidence limitation notice that dynamic sandboxing or file payload is required.

### 3. 🛡️ NIST CVE Vulnerability Research (`/api/cve/search`, `/api/cve/latest`)
- **Authoritative Database Query**: Live NVD API v2.0 queries with pre-indexed vulnerability fallback.
- **CVSS v3.1 Metrics**: Itemized base scores, severity levels (CRITICAL, HIGH, MEDIUM, LOW), and CVSS vector strings.
- **Advisory Disclaimer**: Clearly differentiates general vulnerability intelligence from confirmed vulnerabilities on user endpoints.

### 4. 📧 Breach & Exposure Intelligence (`/api/scan`)
- **Deterministic Leak Auditing**: Matches target emails against verified corporate breach databases (Adobe, Canva, LinkedIn, Dropbox, Yahoo).
- **Zero-Leak Baseline**: Returns a clean 0-exposure baseline for verified safe accounts (no synthetic modulo generation).
- **Risk Attribution**: Itemizes compromised data classes (passwords, PII, financial information) with clear point rubrics.

### 5. 🚨 SIEM Incident Management & Case Triage (`/api/soc/incidents`)
- **Full Case Lifecycle**: Create custom incidents, assign severity (Critical, High, Medium, Low), SLA Priority (P1–P4), and MITRE ATT&CK tactic/technique mappings.
- **Interactive Triage**: Record analyst triage notes, change case status (`investigating`, `mitigated`, `escalated`, `false_positive`), and log containment actions.
- **One-Click Escalation**: Convert any URL, Hash, CVE, or Breach scan result directly into an active SIEM case file.
- **Demo Reset**: Reset incident cases to baseline state without wiping persistent audit history.

### 6. 📑 PDF Briefings & STIX 2.1 Bundler (`/api/soc/stix-export`, `pdfGenerator.ts`)
- **Executive DFIR PDF Reports**: Download printable, executive-ready A4 briefing documents for scans and incident case files with itemized point scores, MITRE tags, and containment records.
- **OASIS STIX 2.1 & 3.0 Export**: Download JSON-formatted Structured Threat Information Expression bundles for seamless SIEM integration (Splunk, Microsoft Sentinel, QRadar).

---

## 🔒 Security & Authorization Architecture

- **HMAC Session Tokens**: Cryptographically signed SHA-256 session tokens with 24-hour expiration and constant-time signature validation (`crypto.timingSafeEqual`).
- **Single-Use 6-Digit OTPs**: Time-limited (5-minute expiration) authentication codes with automated replay prevention (invalidated upon first use) and maximum 5-attempt brute-force lockouts.
- **SSRF Network Boundary**: Comprehensive IP validation preventing requests to internal subnets, localhost, and cloud metadata services (`http://169.254.169.254/latest/meta-data`).
- **Database Row-Level Security**: Hardened PostgreSQL/Supabase schema ensuring user records, scans, and incidents are isolated to authenticated account owners (`auth.uid() = id`).
- **Payment Verification**: Razorpay server-side signature validation (`razorpay_signature = hmac_sha256(order_id + payment_id, secret)`) blocking client-side approval bypasses.

---

## 🚀 Windows-Compatible Run Commands

### 1. Installation
Open PowerShell in the project directory:
```powershell
npm install
```

### 2. Environment Configuration
Create or update your `.env` file in the root directory:
```env
PORT=3000
NODE_ENV=development
JWT_SECRET=super_secret_cyberguard_hmac_key_2026_change_in_production
SESSION_SECRET=secure_session_token_signing_key_32_bytes_minimum
```

### 3. Run Development Server
```powershell
npm run dev
```
Open your browser and navigate to: **`http://localhost:3000`**

### 4. Run API Integration Test Suite
```powershell
npx tsx tests/api_integration_suite.ts
```
*Expected result: 25 PASSED | 0 FAILED*

---

## 🎯 Reproducible Demonstration Workflow

CyberGuard includes a dedicated **Investigation Demonstration Presets** bar at the top of the workstation for interviews and client demonstrations:

1. **Typosquat Phishing URL**:
   - Click `[🚨 Typosquat URL]` in the toolbar.
   - Evaluates `https://paypa1-secure-login.xyz/verify`.
   - **Observed Result**: 75/100 High Hazard score, typosquatting flag targeting `paypal`, high-risk `.xyz` TLD flag, and credential path keyword detection.
2. **Clean Domain Baseline**:
   - Click `[🟢 Clean Domain]`.
   - Evaluates `https://cloudflare.com`.
   - **Observed Result**: 5/100 Low Risk score with verified TLS 1.3 certificate.
3. **Malware Hash Forensics**:
   - Click `[🦠 Malware Hash]`.
   - Evaluates EICAR AV Test MD5 (`44d88612fea8a8f36de82e1278abb02f`).
   - **Observed Result**: Classified as `MALICIOUS`, identifies EICAR test family, flags PE header signatures.
4. **Truthful Unknown Hash Isolation**:
   - Click `[❓ Unknown Hash]`.
   - Evaluates unindexed hash `a1b2c3d4e5f67890123456789abcdef0123456789abcdef0123456789abcdef0`.
   - **Observed Result**: Classified as `UNKNOWN` (never falsely marked clean), displays evidence limitation notice, and prompts for binary file upload.
5. **NIST CVE Log4Shell**:
   - Click `[🐞 Critical CVE]`.
   - Searches `CVE-2021-44228`.
   - **Observed Result**: CVSS 10.0 Critical score, remote code execution attack vector description, and mitigation advisory.
6. **Breach Identity Audit**:
   - Click `[👤 Leaked Account]`.
   - Audits `user@yahoo.com`.
   - **Observed Result**: Confirmed exposures in Yahoo and Adobe leaks with itemized credential breakdown.
7. **Escalate to SIEM Case**:
   - Click `[ESCALATE TO SIEM CASE]` on any scan result.
   - Automatically switches to the **SIEM Incidents** tab with a newly opened case.
8. **Export Official DFIR PDF**:
   - Click `[EXPORT DFIR PDF]` to download the cryptographic briefing report.
9. **Reset Demo Cases**:
   - Click `[RESET DEMO CASES]` to restore the original incident queue.

---

## 🔑 External Providers & Key Configuration

| Provider | Purpose | Status in Local Mode | Environment Variable |
| :--- | :--- | :--- | :--- |
| **NIST NVD API v2.0** | Live CVE intelligence | Functional (Live + Fallback) | `NVD_API_KEY` (Optional, raises rate limit) |
| **VirusTotal v3** | Multi-engine AV file hash lookups | Requires API Key | `VIRUSTOTAL_API_KEY` |
| **Shodan / AbuseIPDB** | Advanced IP reputation | Requires API Key | `ABUSEIPDB_API_KEY` |
| **Razorpay** | SaaS payment processing | Server Signature Guarded | `RAZORPAY_KEY_ID`, `RAZORPAY_KEY_SECRET` |
| **Supabase** | Cloud Postgres with RLS | Schema Ready | `SUPABASE_URL`, `SUPABASE_ANON_KEY` |

*Note: CyberGuard remains 100% operational in offline/demo mode without any paid API keys through its deterministic threat engine and pre-indexed databases.*

---

## 📄 License
This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.
