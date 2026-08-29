import handler from '../api/[...path]';

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
      req: { method: 'POST', url: '/api/scan', query: { path: ['scan'] }, body: { email: 'compromised@adobe.com' } },
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
