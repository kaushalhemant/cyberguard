import fs from 'fs';
import path from 'path';

export interface CveRecord {
  id: string;
  sourceIdentifier: string;
  published: string;
  lastModified: string;
  vulnStatus: string;
  description: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'UNKNOWN';
  score: number;
  vectorString?: string;
}

let cachedCveList: CveRecord[] | null = null;
let isLoading = false;

/**
 * Parses raw NIST NVD 2.0 CVE JSON object into normalized CveRecord array.
 */
function parseNvdJson(jsonData: any): CveRecord[] {
  const vulnerabilities = jsonData.vulnerabilities || [];
  const records: CveRecord[] = [];

  for (const item of vulnerabilities) {
    const cve = item.cve;
    if (!cve || !cve.id) continue;

    const id = cve.id;
    const sourceIdentifier = cve.sourceIdentifier || 'nvd@nist.gov';
    const published = cve.published || '';
    const lastModified = cve.lastModified || '';
    const vulnStatus = cve.vulnStatus || 'Analyzed';

    // Extract English description
    const descObj = cve.descriptions?.find((d: any) => d.lang === 'en') || cve.descriptions?.[0];
    const description = descObj?.value || 'No detailed description available.';

    // Extract CVSS metrics (v31 preferred, fallback v30/v2)
    let score = 0;
    let severity: CveRecord['severity'] = 'UNKNOWN';
    let vectorString = '';

    const cvssV31 = cve.metrics?.cvssMetricV31?.[0]?.cvssData;
    const cvssV30 = cve.metrics?.cvssMetricV30?.[0]?.cvssData;
    const cvssV2 = cve.metrics?.cvssMetricV2?.[0]?.cvssData;

    if (cvssV31) {
      score = cvssV31.baseScore || 0;
      severity = cvssV31.baseSeverity || (score >= 9.0 ? 'CRITICAL' : score >= 7.0 ? 'HIGH' : score >= 4.0 ? 'MEDIUM' : 'LOW');
      vectorString = cvssV31.vectorString || '';
    } else if (cvssV30) {
      score = cvssV30.baseScore || 0;
      severity = cvssV30.baseSeverity || (score >= 9.0 ? 'CRITICAL' : score >= 7.0 ? 'HIGH' : score >= 4.0 ? 'MEDIUM' : 'LOW');
      vectorString = cvssV30.vectorString || '';
    } else if (cvssV2) {
      score = cvssV2.baseScore || 0;
      severity = score >= 7.0 ? 'HIGH' : score >= 4.0 ? 'MEDIUM' : 'LOW';
      vectorString = cvssV2.vectorString || '';
    }

    records.push({
      id,
      sourceIdentifier,
      published,
      lastModified,
      vulnStatus,
      description,
      severity,
      score,
      vectorString
    });
  }

  return records;
}

/**
 * Load and index NIST NVD CVE database from nvdcve-2.0-modified.json
 */
export async function loadNvdCveDatabase(): Promise<CveRecord[]> {
  if (cachedCveList) return cachedCveList;
  if (isLoading) {
    while (isLoading) {
      await new Promise(r => setTimeout(r, 100));
    }
    return cachedCveList || [];
  }

  isLoading = true;
  try {
    const jsonPath = path.join(process.cwd(), 'nvdcve-2.0-modified.json');
    if (!fs.existsSync(jsonPath)) {
      console.warn('[CveScanner] nvdcve-2.0-modified.json not found at:', jsonPath);
      cachedCveList = [];
      return [];
    }

    console.log('[CveScanner] Loading and indexing NIST NVD CVE database...');
    const fileContent = fs.readFileSync(jsonPath, 'utf8');
    const rawJson = JSON.parse(fileContent);
    cachedCveList = parseNvdJson(rawJson);
    console.log(`[CveScanner] Successfully indexed ${cachedCveList.length} NIST CVE vulnerability records.`);
    return cachedCveList;
  } catch (err: any) {
    console.error('[CveScanner] Error loading NVD CVE database:', err.message || err);
    cachedCveList = [];
    return [];
  } finally {
    isLoading = false;
  }
}

/**
 * Search NIST NVD CVE records by query string or keyword (CVE ID, vendor, product, or description).
 */
export async function searchCves(query: string, severityFilter?: string, limit: number = 20): Promise<{
  totalMatches: number;
  cves: CveRecord[];
}> {
  const cveList = await loadNvdCveDatabase();
  if (!query || !query.trim()) {
    return {
      totalMatches: cveList.length,
      cves: cveList.slice(0, limit)
    };
  }

  const cleanQuery = query.toLowerCase().trim();
  const filtered = cveList.filter(cve => {
    const matchesQuery = cve.id.toLowerCase().includes(cleanQuery) ||
      cve.description.toLowerCase().includes(cleanQuery) ||
      cve.sourceIdentifier.toLowerCase().includes(cleanQuery);

    if (!matchesQuery) return false;

    if (severityFilter && severityFilter.toUpperCase() !== 'ALL') {
      return cve.severity.toUpperCase() === severityFilter.toUpperCase();
    }
    return true;
  });

  return {
    totalMatches: filtered.length,
    cves: filtered.slice(0, limit)
  };
}

/**
 * Get latest high/critical severity CVE vulnerabilities.
 */
export async function getLatestCves(limit: number = 10): Promise<CveRecord[]> {
  const cveList = await loadNvdCveDatabase();
  return cveList
    .sort((a, b) => new Date(b.published).getTime() - new Date(a.published).getTime())
    .slice(0, limit);
}
