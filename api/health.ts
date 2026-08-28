export default async function handler(req: any, res: any) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  return res.status(200).json({ status: 'ok', server: 'CyberGuard Serverless Vercel Engine', timestamp: new Date().toISOString() });
}
