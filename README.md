# 🛡️ CyberGuard — Cyber Threat Intelligence & Breach Scanner

[![Live Demo](https://img.shields.io/badge/LIVE_DEMO-GITHUB_PAGES-00E5FF?style=for-the-badge&logo=githubpages&logoColor=black)](https://kaushalhemant.github.io/cyberguard/)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.8-3178C6?style=for-the-badge&logo=typescript&logoColor=white)](https://www.typescriptlang.org/)
[![React](https://img.shields.io/badge/React-19-61DAFB?style=for-the-badge&logo=react&logoColor=black)](https://react.dev/)
[![Vite](https://img.shields.io/badge/Vite-6.2-646CFF?style=for-the-badge&logo=vite&logoColor=white)](https://vitejs.dev/)
[![Express](https://img.shields.io/badge/Express-4.21-000000?style=for-the-badge&logo=express&logoColor=white)](https://expressjs.com/)
[![TailwindCSS](https://img.shields.io/badge/Tailwind_CSS-4.0-06B6D4?style=for-the-badge&logo=tailwindcss&logoColor=white)](https://tailwindcss.com/)
[![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)](LICENSE)

> 🌐 **Live Web Workstation**: [https://kaushalhemant.github.io/cyberguard/](https://kaushalhemant.github.io/cyberguard/)  
> **100% Client-Side Ready**: Runs directly in any web browser with zero serverless dependency, instant deterministic threat scoring, and 1-click PDF briefing downloads.

**CyberGuard** is an all-in-one **100% Deterministic, Rule-Based** Cyber Threat Intelligence, Data Breach Detection, and DFIR Workstation. Built specifically for compliance-critical environments (finance, healthcare, government, and enterprise SOCs), **CyberGuard uses zero AI/ML inference or black-box classifiers**. All risk scores, classifications, and detections are backed by transparent, mathematically auditable rules, cryptographic signatures, Shannon entropy analysis, homoglyph typosquatting tables, and authoritative threat intelligence feeds.

---

## 🔒 100% Deterministic & Auditable (Zero AI/ML)

- **Zero Black-Box Outputs**: Every risk score is computed through an inspectable point rubric with full signal-by-signal attribution.
- **Repeatable & Verifiable**: Identical inputs always yield identical results with zero non-deterministic variance.
- **Shannon Entropy Engine**: $H = -\sum p_i \log_2 p_i$ analysis for packed and encrypted malware binary detection.
- **Enterprise Typosquatting Matrix**: Multi-brand homoglyph replacement mapping with normalized Levenshtein distance evaluation.

---

## ✨ Key Features

- **📧 Email Breach & Exposure Auditor**: Verifies identities against curated leak repositories with point weights for credential types, financial exposure, and leak recency.
- **🔗 Link & Phishing Threat Inspector**: Real-time URL reputation scoring, 50+ brand typosquatting checks, 40+ high-risk TLD filters, and VirusTotal v3 verification.
- **🖼️ Visual & Document Payload Forensics**: SHA-256/MD5 cryptographic signature matching, EXIF metadata tampering audits, and raw Tesseract OCR keyword extraction.
- **📚 NIST NVD CVE Vulnerability Intelligence**: Live NIST NVD API v2.0 search and pre-indexed vulnerability database with CVSS v3.1 scoring.
- **🌐 OSINT IP & Domain Inspector**: Resolves ASNs, open management ports (RDP, SSH, Telnet), DNS security (SPF, DMARC), and blacklist status (Spamhaus, AbuseIPDB, Quad9).
- **🧬 Malware Hash Forensics**: Shannon entropy calculations, PE header magic byte inspection, and YARA-style signature mapping.
- **🚨 SIEM Incident Response Matrix**: MITRE ATT&CK categorized incident queue with triage workflows, containment rules, and officer assignment.
- **📦 OASIS STIX 2.1 Bundler**: Exports forensic findings to standard STIX 2.1 bundles for ingestion into enterprise SIEMs (Splunk, QRadar, Sentinel).
- **💻 Interactive Security Terminal**: Built-in CLI command interface for executing network diagnostics and security queries.
- **📑 Executive PDF Report Generator**: Generate and export downloadable security audit reports powered by `jsPDF`.

---

## 🛠️ Technology Stack

| Layer | Technology |
| :--- | :--- |
| **Frontend Framework** | [React 19](https://react.dev/) with [TypeScript](https://www.typescriptlang.org/) |
| **Build Tool & Bundler** | [Vite 6](https://vitejs.dev/) |
| **Styling** | [Tailwind CSS 4](https://tailwindcss.com/) & [Lucide Icons](https://lucide.dev/) |
| **Animations** | [Motion](https://motion.dev/) |
| **Backend Server** | [Express.js](https://expressjs.com/) running on [Node.js](https://nodejs.org/) via `tsx` |
| **OCR & Metadata** | [Tesseract.js](https://tesseract.projectnaptha.com/) & [Exifr](https://github.com/MikeKoval/exifr) |
| **PDF Generation** | [jsPDF](https://github.com/parallax/jsPDF) |

---

## 🚀 Getting Started

### Prerequisites

- **Node.js**: v18.0.0 or higher
- **npm** or **bun**: Package manager installed

### 📥 Installation

1. **Clone the Repository**
   ```bash
   git clone https://github.com/your-username/cyberguard.git
   cd cyberguard
   ```

2. **Install Dependencies**
   ```bash
   npm install
   ```

3. **Configure Environment Variables**
   Create a `.env` file in the root directory:
   ```env
   PORT=3000
   NODE_ENV=development
   ```

4. **Start Development Server**
   ```bash
   # Main Security Dashboard Application
   npm run dev

   # Admin Portal (Optional)
   npm run dev:admin
   ```

5. **Open in Browser**
   Access the dashboard at `http://localhost:3000`

---

## 📜 Available Scripts

| Command | Description |
| :--- | :--- |
| `npm run dev` | Launches the main application and Express API server in development mode |
| `npm run dev:admin` | Launches the standalone Admin Portal server |
| `npm run build` | Compiles frontend static assets with Vite and packages backend server bundle |
| `npm run start` | Runs the production-compiled backend server |
| `npm run lint` | Performs TypeScript type checking without emitting files |

---

## 📂 Project Architecture

```
cyberguard/
├── admin-portal/        # Standalone Admin Management Portal
├── data/                # Database models and data store files
├── src/
│   ├── components/      # React UI Components (Dashboard, ThreatIntel, Terminal, Auth, etc.)
│   ├── lib/             # Utility helpers and API clients
│   ├── server/          # Backend service helpers and DB adapters
│   ├── types/           # TypeScript interface definitions
│   ├── App.tsx          # Main Application Entry Component
│   ├── index.css        # Core Design Tokens & Tailwind Directives
│   └── main.tsx         # React DOM Render Entrypoint
├── adminServer.ts       # Standalone Express Admin Server
├── server.ts            # Main Express Backend & API Router
├── vite.config.ts       # Vite Configuration
└── package.json         # Dependencies and Build Scripts
```

---

## 🛡️ Security & Privacy Notice

CyberGuard performs local metadata analysis and client-side processing where possible. Ensure all deployed API endpoints are properly secured behind HTTPS and firewall policies in production environments.

---

## 📄 License

This project is open-source and available under the [MIT License](LICENSE).
