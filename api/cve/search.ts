import { searchCves } from '../../src/server/threatEngine';

export default async function handler(req: any, res: any) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  const query = (req.query?.query as string) || '';
  const severity = (req.query?.severity as string) || 'ALL';
  const limit = parseInt((req.query?.limit as string) || '20', 10);

  const result = await searchCves(query, severity, limit);
  return res.status(200).json(result);
}
