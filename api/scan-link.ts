import crypto from 'crypto';
import { analyzeUrl } from '../src/server/threatEngine';

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

  try {
    const body = typeof req.body === 'string' ? JSON.parse(req.body) : req.body || {};
    const url = body.url;
    if (!url || typeof url !== 'string') {
      return res.status(400).json({ error: 'Target URL is required' });
    }

    const analysis = await analyzeUrl(url);

    const scanRecord = {
      id: crypto.randomUUID(),
      targetEmail: 'official@cyberguard.gov',
      timestamp: new Date().toISOString(),
      resultCount: analysis.threats.length,
      breaches: [],
      riskScore: analysis.riskScore,
      aiSummary: analysis.aiSummary,
      scanType: 'link',
      targetLink: url,
      detectedThreats: analysis.detectedThreats
    };

    const user = {
      id: 'usr_soc_official_master',
      email: 'official@cyberguard.gov',
      fullName: 'Cyber Security Official (SOC Lead)',
      mobileNumber: '+1 (800) CYBER-SOC',
      role: 'admin',
      plan: 'pro',
      scansThisMonth: 14,
      createdAt: new Date().toISOString()
    };

    return res.status(200).json({ scan: scanRecord, user });
  } catch (err: any) {
    return res.status(500).json({ error: err.message || 'Link threat inspection failed' });
  }
}
