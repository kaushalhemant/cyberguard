import crypto from 'crypto';

export default async function handler(req: any, res: any) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method Not Allowed' });
  }

  const body = typeof req.body === 'string' ? JSON.parse(req.body) : req.body || {};
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
