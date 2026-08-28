import { PREINDEXED_CVES } from '../../src/server/threatEngine';

export default async function handler(req: any, res: any) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  const limit = parseInt((req.query?.limit as string) || '12', 10);
  return res.status(200).json({
    totalMatches: PREINDEXED_CVES.length,
    cves: PREINDEXED_CVES.slice(0, limit)
  });
}
