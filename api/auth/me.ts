export default async function handler(req: any, res: any) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  const user = {
    id: 'usr_soc_official_master',
    email: 'official@cyberguard.gov',
    fullName: 'Cyber Security Official (SOC Lead)',
    mobileNumber: '+1 (800) CYBER-SOC',
    role: 'admin',
    plan: 'pro',
    scansThisMonth: 18,
    createdAt: new Date().toISOString()
  };

  return res.status(200).json({ user });
}
