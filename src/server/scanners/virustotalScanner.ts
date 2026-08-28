/**
 * CYBERGUARD VIRUSTOTAL INTELLIGENCE SCANNER
 * Interfaces with VirusTotal REST API v3 to cross-reference URLs, File Hashes, and IPs/Domains
 * against 70+ global antivirus engines and threat intelligence feeds.
 */

const DEFAULT_VT_KEY = '75ec30cd732a5b21ab05e4384e89e79b771a07b6cab6580b25275e8d358038cf';

export function getVirusTotalApiKey(): string {
  const envKey = process.env.VIRUSTOTAL_API_KEY;
  if (envKey && envKey.trim().length > 10) {
    return envKey.trim().replace(/^["']|["']$/g, '');
  }
  return DEFAULT_VT_KEY;
}

export interface VtUrlResult {
  matched: boolean;
  maliciousCount: number;
  suspiciousCount: number;
  totalEngines: number;
  flaggedEngines: string[];
  threatCategories?: string[];
  reputation?: number;
  permalink?: string;
}

export interface VtHashResult {
  matched: boolean;
  maliciousCount: number;
  suspiciousCount: number;
  totalEngines: number;
  threatFamily?: string;
  meaningfulName?: string;
  typeDescription?: string;
  magicBytes?: string;
  tags?: string[];
  flaggedEngines: { engine: string; category: string; result: string }[];
  permalink?: string;
}

export interface VtIpResult {
  matched: boolean;
  maliciousCount: number;
  suspiciousCount: number;
  totalEngines: number;
  asOwner?: string;
  asn?: string;
  country?: string;
  network?: string;
  reputation?: number;
}

/**
 * Live VirusTotal v3 URL / Domain Threat Query
 */
export async function checkVirusTotalUrl(targetUrl: string, timeoutMs: number = 2000): Promise<VtUrlResult | null> {
  const apiKey = getVirusTotalApiKey();
  if (!apiKey) return null;

  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);

    // Encode URL into VirusTotal URL identifier (base64url format)
    const urlId = Buffer.from(targetUrl).toString('base64url');
    const res = await fetch(`https://www.virustotal.com/api/v3/urls/${urlId}`, {
      headers: { 'x-apikey': apiKey },
      signal: controller.signal
    });
    clearTimeout(timer);

    if (res.ok) {
      const json = await res.json();
      const attr = json.data?.attributes;
      if (!attr) return null;

      const stats = attr.last_analysis_stats || {};
      const malicious = stats.malicious || 0;
      const suspicious = stats.suspicious || 0;
      const harmless = stats.harmless || 0;
      const undetected = stats.undetected || 0;
      const total = malicious + suspicious + harmless + undetected;

      const flaggedEngines: string[] = [];
      const analysisResults = attr.last_analysis_results || {};
      for (const [engineName, engData] of Object.entries<any>(analysisResults)) {
        if (engData.category === 'malicious' || engData.category === 'suspicious') {
          flaggedEngines.push(`${engineName} (${engData.result || engData.category})`);
          if (flaggedEngines.length >= 8) break;
        }
      }

      return {
        matched: malicious > 0 || suspicious > 0,
        maliciousCount: malicious,
        suspiciousCount: suspicious,
        totalEngines: total || 70,
        flaggedEngines,
        threatCategories: attr.categories ? Object.values(attr.categories).map(String) : [],
        reputation: attr.reputation || 0,
        permalink: `https://www.virustotal.com/gui/url/${urlId}`
      };
    }
  } catch (err) {
    // Timeout or network fallback
  }

  // Domain fallback if URL query returns 404 or unsubmitted
  try {
    const domain = new URL(targetUrl).hostname;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);

    const res = await fetch(`https://www.virustotal.com/api/v3/domains/${domain}`, {
      headers: { 'x-apikey': apiKey },
      signal: controller.signal
    });
    clearTimeout(timer);

    if (res.ok) {
      const json = await res.json();
      const attr = json.data?.attributes;
      if (attr) {
        const stats = attr.last_analysis_stats || {};
        const malicious = stats.malicious || 0;
        const suspicious = stats.suspicious || 0;
        const total = (stats.malicious || 0) + (stats.suspicious || 0) + (stats.harmless || 0) + (stats.undetected || 0);

        return {
          matched: malicious > 0 || suspicious > 0,
          maliciousCount: malicious,
          suspiciousCount: suspicious,
          totalEngines: total || 70,
          flaggedEngines: [],
          threatCategories: attr.categories ? Object.values(attr.categories).map(String) : [],
          reputation: attr.reputation || 0,
          permalink: `https://www.virustotal.com/gui/domain/${domain}`
        };
      }
    }
  } catch {}

  return null;
}

/**
 * Live VirusTotal v3 File Hash Threat Forensics
 */
export async function checkVirusTotalHash(hash: string, timeoutMs: number = 2000): Promise<VtHashResult | null> {
  const apiKey = getVirusTotalApiKey();
  if (!apiKey || !hash) return null;

  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);

    const res = await fetch(`https://www.virustotal.com/api/v3/files/${hash.trim()}`, {
      headers: { 'x-apikey': apiKey },
      signal: controller.signal
    });
    clearTimeout(timer);

    if (res.ok) {
      const json = await res.json();
      const attr = json.data?.attributes;
      if (!attr) return null;

      const stats = attr.last_analysis_stats || {};
      const malicious = stats.malicious || 0;
      const suspicious = stats.suspicious || 0;
      const harmless = stats.harmless || 0;
      const undetected = stats.undetected || 0;
      const total = malicious + suspicious + harmless + undetected;

      const flaggedEngines: { engine: string; category: string; result: string }[] = [];
      const analysisResults = attr.last_analysis_results || {};
      for (const [engineName, engData] of Object.entries<any>(analysisResults)) {
        if (engData.category === 'malicious' || engData.category === 'suspicious') {
          flaggedEngines.push({
            engine: engineName,
            category: engData.category,
            result: engData.result || 'Malicious Payload'
          });
          if (flaggedEngines.length >= 10) break;
        }
      }

      return {
        matched: true,
        maliciousCount: malicious,
        suspiciousCount: suspicious,
        totalEngines: total || 70,
        threatFamily: attr.popular_threat_classification?.suggested_threat_label || attr.type_description || 'Trojan / Malware',
        meaningfulName: attr.meaningful_name,
        typeDescription: attr.type_description,
        magicBytes: attr.magic,
        tags: attr.tags || [],
        flaggedEngines,
        permalink: `https://www.virustotal.com/gui/file/${hash.trim()}`
      };
    }
  } catch (err) {
    // Timeout or network fallback
  }

  return null;
}

/**
 * Live VirusTotal v3 IP / Domain OSINT Query
 */
export async function checkVirusTotalIp(target: string, timeoutMs: number = 2000): Promise<VtIpResult | null> {
  const apiKey = getVirusTotalApiKey();
  if (!apiKey || !target) return null;

  const isIp = /^(\d{1,3}\.){3}\d{1,3}$/.test(target.trim());
  const endpoint = isIp 
    ? `https://www.virustotal.com/api/v3/ip_addresses/${target.trim()}`
    : `https://www.virustotal.com/api/v3/domains/${target.trim()}`;

  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);

    const res = await fetch(endpoint, {
      headers: { 'x-apikey': apiKey },
      signal: controller.signal
    });
    clearTimeout(timer);

    if (res.ok) {
      const json = await res.json();
      const attr = json.data?.attributes;
      if (!attr) return null;

      const stats = attr.last_analysis_stats || {};
      const malicious = stats.malicious || 0;
      const suspicious = stats.suspicious || 0;
      const total = (stats.malicious || 0) + (stats.suspicious || 0) + (stats.harmless || 0) + (stats.undetected || 0);

      return {
        matched: malicious > 0 || suspicious > 0,
        maliciousCount: malicious,
        suspiciousCount: suspicious,
        totalEngines: total || 70,
        asOwner: attr.as_owner || attr.registrar,
        asn: attr.asn ? `AS${attr.asn}` : undefined,
        country: attr.country,
        network: attr.network,
        reputation: attr.reputation
      };
    }
  } catch (err) {
    // Timeout or fallback
  }

  return null;
}
