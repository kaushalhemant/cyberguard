import dns from 'dns/promises';
import { isPrivateOrReservedIpv4, isPrivateOrReservedIpv6 } from '../security';
import { checkVirusTotalIp, getVirusTotalApiKey } from '../scanners/virustotalScanner';

export interface GeoIpResult {
  ip: string;
  country: string;
  countryCode: string;
  region: string;
  city: string;
  postalCode?: string;
  latitude?: number;
  longitude?: number;
  timezone?: string;
  asn?: string;
  asOwner?: string;
  isp?: string;
  organization?: string;
  reverseDns?: string;
  flag?: string;
  isHostingOrCdn: boolean;
  cdnProvider?: string;
  source: string;
  timestamp: string;
  limitations: string;
}

// Known CDN & Major Anycast Cloud ASNs
const KNOWN_CDN_ASNS: Record<string, string> = {
  '13335': 'Cloudflare Anycast CDN',
  '209242': 'Cloudflare Anycast CDN',
  '16509': 'Amazon Web Services (AWS CloudFront / EC2)',
  '14618': 'Amazon Web Services (AWS)',
  '54113': 'Fastly CDN',
  '20940': 'Akamai Technologies CDN',
  '16625': 'Akamai Technologies CDN',
  '15169': 'Google Cloud / Google Infrastructure',
  '8075': 'Microsoft Azure Anycast Infrastructure',
  '2635': 'Automattic / WordPress VIP CDN',
  '60068': 'Datacamp Limited / CDN77'
};

/**
 * Perform authoritative IP geolocation lookup using multiple external sources with fallback.
 * Strictly distinguishes IP location, ISP, ASN, reverse DNS, and CDN indicators.
 */
export async function lookupIpIntelligence(ip: string): Promise<GeoIpResult> {
  const cleanIp = ip.trim();
  const timestamp = new Date().toISOString();

  // 1. SSRF & Private / Loopback range check
  if (isPrivateOrReservedIpv4(cleanIp) || isPrivateOrReservedIpv6(cleanIp) || cleanIp === '127.0.0.1' || cleanIp === 'localhost') {
    return {
      ip: cleanIp,
      country: 'Private / Reserved Network',
      countryCode: 'XX',
      region: 'Internal',
      city: 'RFC 1918 / Loopback',
      flag: '🔒',
      isHostingOrCdn: false,
      source: 'CyberGuard Local RFC Guard',
      timestamp,
      limitations: 'Private non-routable IP address. Geolocation cannot be resolved for local or intranet addresses.'
    };
  }

  // 2. Real Reverse DNS PTR Query
  let reverseHost: string | undefined = undefined;
  try {
    const ptrs = await dns.reverse(cleanIp);
    if (ptrs && ptrs.length > 0) {
      reverseHost = ptrs[0];
    }
  } catch {
    // Reverse DNS query failed or no PTR record exists
  }

  // 3. Primary Source: ipwho.is (HTTPS, authoritative GeoIP, no API key needed)
  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 3500);

    const response = await fetch(`https://ipwho.is/${encodeURIComponent(cleanIp)}`, {
      headers: { 'Accept': 'application/json' },
      signal: controller.signal
    });
    clearTimeout(timeoutId);

    if (response.ok) {
      const data = await response.json();
      if (data && data.success) {
        const rawAsnNum = String(data.connection?.asn || '').replace(/^AS/i, '');
        const cdnName = KNOWN_CDN_ASNS[rawAsnNum] || (data.connection?.isp?.toLowerCase().includes('cloudflare') ? 'Cloudflare CDN' : undefined);
        const isHosting = !!(data.connection?.hosting || cdnName);

        return {
          ip: cleanIp,
          country: data.country || 'Unknown Country',
          countryCode: (data.country_code || '').toUpperCase(),
          region: data.region || '',
          city: data.city || '',
          postalCode: data.postal || undefined,
          latitude: typeof data.latitude === 'number' ? data.latitude : undefined,
          longitude: typeof data.longitude === 'number' ? data.longitude : undefined,
          timezone: data.timezone?.id || undefined,
          asn: data.connection?.asn ? `AS${data.connection.asn}` : undefined,
          asOwner: data.connection?.org || data.connection?.isp || undefined,
          isp: data.connection?.isp || undefined,
          organization: data.connection?.org || undefined,
          reverseDns: reverseHost || (data.connection?.domain ? data.connection.domain : undefined),
          flag: data.flag?.emoji || (data.country_code ? getCountryFlagEmoji(data.country_code) : '🌐'),
          isHostingOrCdn: isHosting,
          cdnProvider: cdnName,
          source: 'ipwho.is Authoritative GeoIP Registry',
          timestamp,
          limitations: cdnName 
            ? `IP belongs to ${cdnName}. Reported coordinates represent the edge PoP (Point of Presence), not necessarily the origin server.`
            : 'IP geolocation estimates the geographic region of the network edge gateway. Accuracy is typically city-level for fixed broadband and country-level for mobile networks.'
        };
      }
    }
  } catch (err) {
    // ipwho.is timed out or failed, try secondary fallback
  }

  // 4. Secondary Fallback: ip-api.com
  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 3500);

    const response = await fetch(
      `http://ip-api.com/json/${encodeURIComponent(cleanIp)}?fields=status,message,country,countryCode,regionName,city,zip,lat,lon,timezone,isp,org,as,asname,reverse,hosting,query`,
      { signal: controller.signal }
    );
    clearTimeout(timeoutId);

    if (response.ok) {
      const data = await response.json();
      if (data && data.status === 'success') {
        const asnMatch = (data.as || '').match(/AS(\d+)/i);
        const asnNum = asnMatch ? asnMatch[1] : '';
        const cdnName = KNOWN_CDN_ASNS[asnNum];
        const isHosting = !!(data.hosting || cdnName);

        return {
          ip: cleanIp,
          country: data.country || 'Unknown Country',
          countryCode: (data.countryCode || '').toUpperCase(),
          region: data.regionName || '',
          city: data.city || '',
          postalCode: data.zip || undefined,
          latitude: typeof data.lat === 'number' ? data.lat : undefined,
          longitude: typeof data.lon === 'number' ? data.lon : undefined,
          timezone: data.timezone || undefined,
          asn: data.as ? data.as.split(' ')[0] : undefined,
          asOwner: data.asname || data.org || data.isp,
          isp: data.isp || undefined,
          organization: data.org || undefined,
          reverseDns: reverseHost || data.reverse || undefined,
          flag: getCountryFlagEmoji(data.countryCode),
          isHostingOrCdn: isHosting,
          cdnProvider: cdnName,
          source: 'ip-api.com Geolocation Service',
          timestamp,
          limitations: cdnName 
            ? `IP belongs to ${cdnName}. Reported coordinates represent the Anycast edge node.`
            : 'IP geolocation estimates the network allocation region. Accuracy is typically city-level.'
        };
      }
    }
  } catch (err) {
    // ip-api failed
  }

  // 5. Tertiary Fallback: VirusTotal v3 IP endpoint
  try {
    const vtResult = await checkVirusTotalIp(cleanIp, 3000);
    if (vtResult && vtResult.country) {
      return {
        ip: cleanIp,
        country: vtResult.country,
        countryCode: vtResult.country.length === 2 ? vtResult.country.toUpperCase() : 'XX',
        region: 'Unspecified Region',
        city: 'Unspecified City',
        asn: vtResult.asn || undefined,
        asOwner: vtResult.asOwner || undefined,
        isp: vtResult.asOwner || undefined,
        reverseDns: reverseHost,
        flag: getCountryFlagEmoji(vtResult.country),
        isHostingOrCdn: false,
        source: 'VirusTotal v3 IP Network Registry',
        timestamp,
        limitations: 'Geolocation obtained via VirusTotal AS database. City-level resolution unavailable.'
      };
    }
  } catch {}

  // 6. Graceful Truthful Fallback: No fake locations!
  return {
    ip: cleanIp,
    country: 'Location Unavailable',
    countryCode: 'XX',
    region: 'Unknown',
    city: 'Unknown',
    reverseDns: reverseHost,
    flag: '🌐',
    isHostingOrCdn: false,
    source: 'None (External GeoIP lookups timed out or unavailable)',
    timestamp,
    limitations: 'All authoritative GeoIP providers were unreachable or returned no record for this IP. Location was NOT fabricated.'
  };
}

/**
 * Converts a 2-letter ISO country code (e.g. "IN", "US", "DE") into the standard Unicode flag emoji.
 */
export function getCountryFlagEmoji(countryCode: string | undefined): string {
  if (!countryCode || countryCode.length !== 2) return '🌐';
  const code = countryCode.toUpperCase();
  const offset = 127397;
  return String.fromCodePoint(code.charCodeAt(0) + offset, code.charCodeAt(1) + offset);
}
