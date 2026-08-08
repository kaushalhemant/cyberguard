# 🛡️ CyberGuard — Cyber Threat Intelligence & Breach Scanner

[![TypeScript](https://img.shields.io/badge/TypeScript-5.8-3178C6?style=for-the-badge&logo=typescript&logoColor=white)](https://www.typescriptlang.org/)
[![React](https://img.shields.io/badge/React-19-61DAFB?style=for-the-badge&logo=react&logoColor=black)](https://react.dev/)
[![Vite](https://img.shields.io/badge/Vite-6.2-646CFF?style=for-the-badge&logo=vite&logoColor=white)](https://vitejs.dev/)
[![Express](https://img.shields.io/badge/Express-4.21-000000?style=for-the-badge&logo=express&logoColor=white)](https://expressjs.com/)
[![TailwindCSS](https://img.shields.io/badge/Tailwind_CSS-4.0-06B6D4?style=for-the-badge&logo=tailwindcss&logoColor=white)](https://tailwindcss.com/)
[![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)](LICENSE)

**CyberGuard** is an all-in-one Cyber Threat Intelligence, Data Breach Detection, and Security Analysis Suite. Designed for security analysts, IT administrators, and privacy-conscious users, CyberGuard provides real-time phishing link evaluation, email breach lookups, optical OCR document threat analysis, and automated PDF compliance reports.

---

## ✨ Key Features

- **📧 Email Breach & Leak Scanner**: Scans database records for compromised credentials, leak dates, severity metrics, and exposed data classes.
- **🔗 Link & Phishing Threat Inspector**: Real-time URL reputation scoring, domain analysis, red-flag indicators, and phishing tactic identification.
- **🖼️ Image & Document Threat OCR**: Uses EXIF metadata parsing and Tesseract OCR to scan screenshots, documents, and credentials for hidden metadata and security risks.
- **🧠 Real-Time Threat Intelligence**: Live global alert feeds, surging phishing tactics, risk scoring algorithms, and remediation guidelines.
- **💻 Interactive Security Terminal**: Built-in CLI command interface for executing quick network diagnostics and security commands.
- **📑 Executive PDF Report Generator**: Generate and export downloadable security audit reports powered by `jsPDF`.
- **🔐 Enterprise Access & Admin Portal**: Multi-role authentication, user session management, audit log monitoring, and subscription management.

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
