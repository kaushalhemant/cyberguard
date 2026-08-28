export default async function handler(req: any, res: any) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  const scans = [
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

  return res.status(200).json({ scans });
}
