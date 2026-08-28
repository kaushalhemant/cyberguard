export default async function handler(req: any, res: any) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  const incidents = [
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

  return res.status(200).json({ incidents });
}
