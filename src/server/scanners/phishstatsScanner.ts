export interface PhishStatsMatch {
  matched: boolean;
  score?: number;
  target?: string;
  title?: string;
  ip?: string;
  country?: string;
  host?: string;
  date?: string;
  phishstatsUrl?: string;
}

/**
 * Query PhishStats Zero-Day Phishing Threat Database.
 * Security Reasoning: PhishStats aggregates real-time zero-day phishing URLs, targeting brands, hosting IPs, and malicious infrastructure.
 */
export async function checkPhishStats(targetUrl: string): Promise<PhishStatsMatch | null> {
  const apiKey = process.env.PHISHSTATS_API_KEY || 'psk_7912f275d308_3bbdf4c418160a3caee8b879276ef8774e3b20711c2dddd6';

  let hostname = targetUrl;
  try {
    const parsed = new URL(targetUrl.startsWith('http') ? targetUrl : `http://${targetUrl}`);
    hostname = parsed.hostname;
  } catch (e) {}

  try {
    const headers: Record<string, string> = {
      'Accept': 'application/json'
    };
    if (apiKey) {
      headers['api-key'] = apiKey;
      headers['Authorization'] = `Bearer ${apiKey}`;
    }

    const queryUrl = `https://phishstats.info/api/v2/phishing?_where=(host,like,~${hostname}~)&_size=1`;
    const response = await fetch(queryUrl, {
      method: 'GET',
      headers,
      signal: AbortSignal.timeout(3500)
    });

    if (!response.ok) return null;
    const data = await response.json();
    
    if (Array.isArray(data) && data.length > 0) {
      const match = data[0];
      return {
        matched: true,
        score: match.score || 8,
        target: match.target || 'Brand Impersonation',
        title: match.title || '',
        ip: match.ip || '',
        country: match.country || '',
        host: match.host || hostname,
        date: match.date || new Date().toISOString(),
        phishstatsUrl: match.url || targetUrl
      };
    }

    return { matched: false };
  } catch (err) {
    console.warn('[PhishStatsScanner] API query warning:', err);
    return null;
  }
}
