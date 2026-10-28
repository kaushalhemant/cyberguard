import fs from 'fs';
import path from 'path';

export interface NormalizedCve {
  id: string;
  sourceIdentifier: string;
  published: string;
  lastModified: string;
  vulnStatus: string;
  description: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'UNKNOWN';
  score: number;
  vectorString?: string;
  vectorExplanation?: Record<string, string>;
  source: string;
  advisoryDisclaimer?: string;
}

let memoryCveIndex: NormalizedCve[] | null = null;
let isIndexing = false;

function parseCvssVector(vectorString?: string): Record<string, string> {
  if (!vectorString) return {};
  const parsed: Record<string, string> = {};
  const parts = vectorString.split('/');
  for (const p of parts) {
    const [k, v] = p.split(':');
    if (k === 'AV') parsed['Attack Vector'] = v === 'N' ? 'Network (Remote)' : (v === 'A' ? 'Adjacent Network' : (v === 'L' ? 'Local System' : 'Physical'));
    if (k === 'AC') parsed['Attack Complexity'] = v === 'L' ? 'Low (Trivial)' : 'High (Special Conditions)';
    if (k === 'PR') parsed['Privileges Required'] = v === 'N' ? 'None (Unauthenticated)' : (v === 'L' ? 'Low (User)' : 'High (Admin)');
    if (k === 'UI') parsed['User Interaction'] = v === 'N' ? 'None (Autonomous)' : 'Required (Victim Interaction)';
    if (k === 'S') parsed['Scope'] = v === 'C' ? 'Changed (Cross-Boundary)' : 'Unchanged';
    if (k === 'C') parsed['Confidentiality Impact'] = v === 'H' ? 'High (Full Exposure)' : (v === 'L' ? 'Low' : 'None');
    if (k === 'I') parsed['Integrity Impact'] = v === 'H' ? 'High (Data Modification)' : (v === 'L' ? 'Low' : 'None');
    if (k === 'A') parsed['Availability Impact'] = v === 'H' ? 'High (Total Denial of Service)' : (v === 'L' ? 'Low' : 'None');
  }
  return parsed;
}

/**
 * Loads and caches all verified CVE vulnerabilities from the local NIST NVD archive.
 */
export function getLocalNvdDatabase(): NormalizedCve[] {
  if (memoryCveIndex && memoryCveIndex.length > 0) return memoryCveIndex;
  if (isIndexing) return [];

  isIndexing = true;
  try {
    const filePath = path.join(process.cwd(), 'nvdcve-2.0-modified.json');
    if (fs.existsSync(filePath)) {
      const rawContent = fs.readFileSync(filePath, 'utf8');
      const rawJson = JSON.parse(rawContent);
      const vulnerabilities = rawJson.vulnerabilities || [];

      const records: NormalizedCve[] = [];
      for (const item of vulnerabilities) {
        const cve = item.cve;
        if (!cve || !cve.id) continue;

        const descObj = cve.descriptions?.find((d: any) => d.lang === 'en') || cve.descriptions?.[0];
        const description = descObj?.value || 'No detailed vulnerability description provided.';

        const cvss = cve.metrics?.cvssMetricV31?.[0]?.cvssData || 
                     cve.metrics?.cvssMetricV30?.[0]?.cvssData || 
                     cve.metrics?.cvssMetricV2?.[0]?.cvssData;

        const score = typeof cvss?.baseScore === 'number' ? cvss.baseScore : 0;
        let severity: NormalizedCve['severity'] = 'UNKNOWN';
        if (cvss?.baseSeverity) {
          severity = cvss.baseSeverity.toUpperCase() as NormalizedCve['severity'];
        } else if (score >= 9.0) {
          severity = 'CRITICAL';
        } else if (score >= 7.0) {
          severity = 'HIGH';
        } else if (score >= 4.0) {
          severity = 'MEDIUM';
        } else if (score > 0) {
          severity = 'LOW';
        }

        records.push({
          id: cve.id,
          sourceIdentifier: cve.sourceIdentifier || 'nvd@nist.gov',
          published: cve.published || '',
          lastModified: cve.lastModified || '',
          vulnStatus: cve.vulnStatus || 'Analyzed',
          description,
          severity,
          score,
          vectorString: cvss?.vectorString || '',
          vectorExplanation: parseCvssVector(cvss?.vectorString),
          source: 'NIST NVD Verified Archive (Local Dataset: 7,107 Records)',
          advisoryDisclaimer: 'Official cataloged vulnerability entry in NIST National Vulnerability Database. CVSS base score reflects standard algorithmic severity.'
        });
      }

      memoryCveIndex = records;
      return memoryCveIndex;
    }
  } catch (err: any) {
    console.warn('[CveIndexService] Failed to load local NIST JSON:', err.message);
  } finally {
    isIndexing = false;
  }

  memoryCveIndex = [];
  return memoryCveIndex;
}

/**
 * Searches CVE intelligence by querying live NIST NVD v2.0 API first,
 * falling back gracefully to the verified 7,107-record local NIST archive.
 */
export async function searchCveIntelligence(
  query: string,
  severityFilter: string = 'ALL',
  limit: number = 20
): Promise<{
  totalMatches: number;
  cves: NormalizedCve[];
  source: string;
  limitations: string;
}> {
  const cleanQ = (query || '').trim().toLowerCase();
  const isExactCve = /^cve-\d{4}-\d{4,7}$/i.test(cleanQ);

  // 1. Live NIST NVD REST API query with 8-second timeout
  if (cleanQ) {
    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 8000);

      const endpoint = isExactCve
        ? `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${encodeURIComponent(cleanQ.toUpperCase())}`
        : `https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=${encodeURIComponent(cleanQ)}&resultsPerPage=${limit}`;

      const res = await fetch(endpoint, {
        headers: { 'Accept': 'application/json' },
        signal: controller.signal
      });
      clearTimeout(timeoutId);

      if (res.ok) {
        const json = await res.json();
        const vulns = json.vulnerabilities || [];
        const liveRecords: NormalizedCve[] = [];

        for (const item of vulns) {
          const cve = item.cve;
          if (!cve || !cve.id) continue;

          const descObj = cve.descriptions?.find((d: any) => d.lang === 'en') || cve.descriptions?.[0];
          const description = descObj?.value || 'No description available.';

          const cvss = cve.metrics?.cvssMetricV31?.[0]?.cvssData || 
                       cve.metrics?.cvssMetricV30?.[0]?.cvssData || 
                       cve.metrics?.cvssMetricV2?.[0]?.cvssData;

          const score = typeof cvss?.baseScore === 'number' ? cvss.baseScore : 0;
          let severity: NormalizedCve['severity'] = 'UNKNOWN';
          if (cvss?.baseSeverity) {
            severity = cvss.baseSeverity.toUpperCase() as NormalizedCve['severity'];
          } else if (score >= 9.0) severity = 'CRITICAL';
          else if (score >= 7.0) severity = 'HIGH';
          else if (score >= 4.0) severity = 'MEDIUM';
          else if (score > 0) severity = 'LOW';

          liveRecords.push({
            id: cve.id,
            sourceIdentifier: cve.sourceIdentifier || 'nvd@nist.gov',
            published: cve.published || '',
            lastModified: cve.lastModified || '',
            vulnStatus: cve.vulnStatus || 'Analyzed',
            description,
            severity,
            score,
            vectorString: cvss?.vectorString || '',
            vectorExplanation: parseCvssVector(cvss?.vectorString),
            source: 'NIST NVD Live API (services.nvd.nist.gov)',
            advisoryDisclaimer: 'Official cataloged vulnerability entry in NIST National Vulnerability Database. CVSS base score reflects standard algorithmic severity.'
          });
        }

        let filtered = liveRecords;
        if (severityFilter && severityFilter.toUpperCase() !== 'ALL') {
          filtered = filtered.filter(c => c.severity === severityFilter.toUpperCase());
        }

        if (filtered.length > 0) {
          return {
            totalMatches: filtered.length,
            cves: filtered.slice(0, limit),
            source: 'NIST NVD Live v2.0 REST API',
            limitations: 'Live vulnerability records retrieved directly from NIST NVD. Applicable patch status depends on system architecture.'
          };
        }
      }
    } catch {
      // Live NIST API failed or timed out, gracefully search verified local archive
    }
  }

  // 2. Query Local NIST Database (7,107 records)
  const localDb = getLocalNvdDatabase();
  let matches = localDb;

  if (cleanQ) {
    matches = matches.filter(c => 
      c.id.toLowerCase().includes(cleanQ) ||
      c.description.toLowerCase().includes(cleanQ) ||
      c.sourceIdentifier.toLowerCase().includes(cleanQ)
    );
  }

  if (severityFilter && severityFilter.toUpperCase() !== 'ALL') {
    matches = matches.filter(c => c.severity === severityFilter.toUpperCase());
  }

  return {
    totalMatches: matches.length,
    cves: matches.slice(0, limit),
    source: `NIST NVD Verified Archive (Local Dataset: ${localDb.length} Records)`,
    limitations: 'Retrieved from verified local NIST NVD archive. Live NIST API query was bypassed or timed out.'
  };
}
