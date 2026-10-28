import handler from '../src/server/apiHandler';

interface MockResponse {
  statusCode: number;
  headers: Record<string, string>;
  data: any;
  setHeader: (k: string, v: string) => void;
  status: (code: number) => MockResponse;
  json: (body: any) => void;
  end: () => void;
}

function createMockRes(): MockResponse {
  const res: MockResponse = {
    statusCode: 200,
    headers: {},
    data: null,
    setHeader(k, v) { res.headers[k] = v; },
    status(code) { res.statusCode = code; return res; },
    json(body) { res.data = body; },
    end() {}
  };
  return res;
}

async function runFullIntegrationSuite() {
  console.log('=====================================================');
  console.log('CYBERGUARD API END-TO-END INTEGRATION TEST SUITE');
  console.log('=====================================================\n');

  let passed = 0;
  let failed = 0;

  const testCases = [
    {
      name: 'GET /api/health',
      req: { method: 'GET', url: '/api/health', query: { path: ['health'] } },
      validator: (data: any) => data.status === 'ok' && data.deterministicEngine === true
    },
    {
      name: 'GET /api/auth/me',
      req: { method: 'GET', url: '/api/auth/me', query: { path: ['auth', 'me'] } },
      validator: (data: any) => !!data.user && data.user.email === 'official@cyberguard.gov'
    },
    {
      name: 'POST /api/scan (Email Breach Check - Compromised)',
      req: { method: 'POST', url: '/api/scan', query: { path: ['scan'] }, body: { email: 'test@example.com' } },
      validator: (data: any) => !!data.scan && typeof data.scan.riskScore === 'number' && data.scan.breaches.length > 0 && Array.isArray(data.scan.scoreBreakdown)
    },
    {
      name: 'POST /api/scan (Email Breach Check - Clean)',
      req: { method: 'POST', url: '/api/scan', query: { path: ['scan'] }, body: { email: 'clean_officer@cyberguard.gov' } },
      validator: (data: any) => !!data.scan && data.scan.riskScore === 0 && data.scan.breaches.length === 0
    },
    {
      name: 'POST /api/scan-link (URL Typosquatting Check)',
      req: { method: 'POST', url: '/api/scan-link', query: { path: ['scan-link'] }, body: { url: 'https://paypa1-security-login.xyz/login' } },
      validator: (data: any) => !!data.scan && data.scan.riskScore >= 60 && data.scan.detectedThreats.length > 0 && Array.isArray(data.scan.scoreBreakdown)
    },
    {
      name: 'POST /api/scan-image (Visual Artifact Audit)',
      req: {
        method: 'POST',
        url: '/api/scan-image',
        query: { path: ['scan-image'] },
        body: {
          base64Image: 'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII=',
          filename: 'suspicious_invoice_receipt.png'
        }
      },
      validator: (data: any) => !!data.scan && typeof data.scan.riskScore === 'number' && Array.isArray(data.scan.detectedThreats)
    },
    {
      name: 'GET /api/cve/latest',
      req: { method: 'GET', url: '/api/cve/latest', query: { path: ['cve', 'latest'], limit: '5' } },
      validator: (data: any) => Array.isArray(data.cves) && data.cves.length > 0
    },
    {
      name: 'GET /api/cve/search (Log4j CVE Query)',
      req: { method: 'GET', url: '/api/cve/search', query: { path: ['cve', 'search'], query: 'log4j' } },
      validator: (data: any) => Array.isArray(data.cves) && data.cves.length > 0
    },
    {
      name: 'POST /api/soc/osint-lookup (Target IP)',
      req: { method: 'POST', url: '/api/soc/osint-lookup', query: { path: ['soc', 'osint-lookup'] }, body: { target: '185.220.101.5' } },
      validator: (data: any) => typeof data.reputationScore === 'number' && Array.isArray(data.blacklists) && Array.isArray(data.scoreBreakdown)
    },
    {
      name: 'POST /api/soc/hash-lookup (Known Bad Hash)',
      req: { method: 'POST', url: '/api/soc/hash-lookup', query: { path: ['soc', 'hash-lookup'] }, body: { hash: '44d88612fea8a8f36de82e1278abb02f' } },
      validator: (data: any) => data.malwareClassification === 'malicious' && Array.isArray(data.matchedYaraRules) && Array.isArray(data.scoreBreakdown)
    },
    {
      name: 'GET /api/soc/incidents (SIEM Incident Queue)',
      req: { method: 'GET', url: '/api/soc/incidents', query: { path: ['soc', 'incidents'] } },
      validator: (data: any) => Array.isArray(data.incidents) && data.incidents.length > 0
    },
    {
      name: 'POST /api/soc/stix-export (OASIS STIX 2.1 Bundle)',
      req: { method: 'POST', url: '/api/soc/stix-export', query: { path: ['soc', 'stix-export'] }, body: { target: 'malicious-c2.org', threatScore: 85 } },
      validator: (data: any) => (data.type === 'bundle' || data.bundle?.type === 'bundle' || data.stixBundle?.type === 'bundle') && (Array.isArray(data.objects) || Array.isArray(data.bundle?.objects))
    },
    {
      name: 'GET /api/scans (Audit History)',
      req: { method: 'GET', url: '/api/scans', query: { path: ['scans'] } },
      validator: (data: any) => Array.isArray(data.scans)
    },
    {
      name: 'POST /api/pqc/audit (NIST FIPS 203 Post-Quantum Audit)',
      req: { method: 'POST', url: '/api/pqc/audit', query: { path: ['pqc', 'audit'] }, body: { target: 'quantum-defense.gov' } },
      validator: (data: any) => typeof data.quantumReadinessScore === 'number' && Array.isArray(data.ciphers) && !!data.kemAlgorithm
    },
    {
      name: 'POST /api/quantum/simulate (Shor Algorithm Simulator)',
      req: { method: 'POST', url: '/api/quantum/simulate', query: { path: ['quantum', 'simulate'] }, body: { cipher: 'RSA', keySize: 2048 } },
      validator: (data: any) => data.cipher === 'RSA-2048' && typeof data.estimatedLogicalQubits === 'number' && !!data.recommendedPqcAlternative
    },
    {
      name: 'POST /api/deepfake/scan (Generative Media Forensics)',
      req: { method: 'POST', url: '/api/deepfake/scan', query: { path: ['deepfake', 'scan'] }, body: { targetName: 'synthetic_ceo_stream.mp4', mediaType: 'video' } },
      validator: (data: any) => (data.syntheticConfidence === null || typeof data.syntheticConfidence === 'number') && Array.isArray(data.forensicEvidence)
    },
    {
      name: 'GET /api/ai-swarm/telemetry (Autonomous AI SOC Swarm - Unconfigured Truth)',
      req: { method: 'GET', url: '/api/ai-swarm/telemetry', query: { path: ['ai-swarm', 'telemetry'] } },
      validator: (data: any) => data.swarmStatus === 'INFRASTRUCTURE_NOT_CONFIGURED' && Array.isArray(data.activeAgents) && data.totalThreatsNeutralized === 0
    },
    {
      name: 'POST /api/ai-swarm/action (Dispatch Autonomous Playbook - Honest Refusal)',
      req: { method: 'POST', url: '/api/ai-swarm/action', query: { path: ['ai-swarm', 'action'] }, body: { agentId: 'agent_sentinel_alpha', playbook: 'Kernel Trap', target: 'WS-092' } },
      validator: (data: any) => data.success === false && data.configured === false && typeof data.error === 'string'
    },
    {
      name: 'GET /api/satellite/mesh (LEO Constellation & QKD Telemetry)',
      req: { method: 'GET', url: '/api/satellite/mesh', query: { path: ['satellite', 'mesh'] } },
      validator: (data: any) => Array.isArray(data.activeNodes) && typeof data.constellationHealthScore === 'number'
    },
    {
      name: 'POST /api/stix3/export (STIX 3.0 DFIR Bundle)',
      req: { method: 'POST', url: '/api/stix3/export', query: { path: ['stix3', 'export'] }, body: { target: 'quantum-mesh.net', threatScore: 90 } },
      validator: (data: any) => data.stix3Bundle?.spec_version === '3.0' && !!data.stix3Bundle?.quantum_threat_layer
    },
    {
      name: 'POST /api/scan-link (SSRF Cloud Metadata Protection)',
      req: { method: 'POST', url: '/api/scan-link', query: { path: ['scan-link'] }, body: { url: 'http://169.254.169.254/latest/meta-data/' } },
      validator: (data: any) => !!data.scan && data.scan.riskScore >= 90 && data.scan.detectedThreats.some((t: string) => t.includes('SSRF'))
    },
    {
      name: 'POST /api/scan-link (SSRF Integer Decimal IP Bypass Prevention)',
      req: { method: 'POST', url: '/api/scan-link', query: { path: ['scan-link'] }, body: { url: 'http://2130706433/' } },
      validator: (data: any) => !!data.scan && data.scan.detectedThreats.some((t: string) => t.includes('SSRF') || t.includes('private'))
    },
    {
      name: 'POST /api/scan-link (SSRF CGNAT 100.64.0.0/10 Prevention)',
      req: { method: 'POST', url: '/api/scan-link', query: { path: ['scan-link'] }, body: { url: 'http://100.64.0.1/admin' } },
      validator: (data: any) => !!data.scan && data.scan.detectedThreats.some((t: string) => t.includes('SSRF') || t.includes('Carrier-Grade NAT'))
    },
    {
      name: 'POST /api/soc/osint-lookup (Full URL with Credentials and Port Extraction)',
      req: { method: 'POST', url: '/api/soc/osint-lookup', query: { path: ['soc', 'osint-lookup'] }, body: { target: 'https://admin:secret@cloudflare.com:8443/cdn-cgi/trace' } },
      validator: (data: any) => data.target === 'cloudflare.com' && data.isCdnOrProxy === true
    },
    {
      name: 'POST /api/soc/osint-lookup (IPv6 Target Normalization & ASN)',
      req: { method: 'POST', url: '/api/soc/osint-lookup', query: { path: ['soc', 'osint-lookup'] }, body: { target: '2001:4860:4860::8888' } },
      validator: (data: any) => data.ipVersion === 'IPv6' && data.target === '2001:4860:4860::8888'
    },
    {
      name: 'POST /api/deepfake/scan (Zero Fake Scores & Honest Forensic Evidence Check)',
      req: { method: 'POST', url: '/api/deepfake/scan', query: { path: ['deepfake', 'scan'] }, body: { targetName: 'test_sample.png', mediaType: 'image' } },
      validator: (data: any) => Array.isArray(data.forensicEvidence) && data.forensicEvidence.some((e: any) => e.status === 'not_checked')
    },
    {
      name: 'POST /api/soc/hash-lookup (Unknown Hash Truthful Isolation)',
      req: { method: 'POST', url: '/api/soc/hash-lookup', query: { path: ['soc', 'hash-lookup'] }, body: { hash: '7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069' } },
      validator: (data: any) => data.malwareClassification === 'unknown' && data.evidence?.verdict === 'unknown'
    },
    {
      name: 'POST /api/soc/incidents (Case Creation & MITRE Mapping)',
      req: {
        method: 'POST',
        url: '/api/soc/incidents',
        query: { path: ['soc', 'incidents'] },
        body: {
          title: 'Automated Test Incident Case',
          target: 'test-c2.malicious.net',
          severity: 'high',
          priority: 'P1',
          category: 'Phishing',
          mitreTactic: 'Initial Access',
          mitreTechniqueId: 'T1566'
        }
      },
      validator: (data: any) => data.success === true && !!data.incident?.id && data.incident.severity === 'high' && data.incident.priority === 'P1'
    },
    {
      name: 'POST /api/auth/otp/request (Single-Use OTP Generation)',
      req: { method: 'POST', url: '/api/auth/otp/request', query: { path: ['auth', 'otp', 'request'] }, body: { email: 'secops@cyberguard.gov' } },
      validator: (data: any) => data.success === true && !!data.demoCode && data.expiresInSeconds === 300
    },
    {
      name: 'GET /api/cve/search (Exact CVE Lookup with Advisory Disclaimer)',
      req: { method: 'GET', url: '/api/cve/search', query: { path: ['cve', 'search'], query: 'CVE-2021-44228' } },
      validator: (data: any) => Array.isArray(data.cves) && data.cves.some((c: any) => c.id === 'CVE-2021-44228' && !!c.advisoryDisclaimer)
    }
  ];

  for (const test of testCases) {
    const res = createMockRes();
    try {
      await handler(test.req, res);
      const isStatusOk = res.statusCode >= 200 && res.statusCode < 300;
      const isShapeOk = test.validator(res.data);

      if (isStatusOk && isShapeOk) {
        console.log(`✅ [PASS ${res.statusCode}] ${test.name}`);
        passed++;
      } else {
        console.error(`❌ [FAIL ${res.statusCode}] ${test.name}`);
        console.error('   Body:', JSON.stringify(res.data));
        failed++;
      }
    } catch (err: any) {
      console.error(`❌ [EXCEPTION 500] ${test.name}:`, err.message);
      failed++;
    }
  }

  console.log('\n=====================================================');
  console.log(`INTEGRATION SUITE SUMMARY: ${passed} PASSED | ${failed} FAILED`);
  console.log('=====================================================');

  if (failed > 0) {
    process.exit(1);
  }
}

runFullIntegrationSuite().catch(e => {
  console.error('Fatal test error:', e);
  process.exit(1);
});
